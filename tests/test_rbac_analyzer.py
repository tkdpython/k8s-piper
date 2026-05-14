"""Tests for k8s_piper.rbac_analyzer."""

import pytest
import yaml

from k8s_piper.k8s_manifest import K8sManifest
from k8s_piper.rbac_analyzer import (
    RBAC_KINDS,
    RBACInfo,
    _analyse_rule,
    extract_rbac_info,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _role(name="myrole", namespace="default", rules=None):
    doc = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {"name": name, "namespace": namespace},
        "rules": rules or [],
    }
    return yaml.dump(doc)


def _cluster_role(name="myclusterrole", rules=None):
    doc = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": {"name": name},
        "rules": rules or [],
    }
    return yaml.dump(doc)


def _role_binding(name="myrb", namespace="default", role_ref=None, subjects=None):
    doc = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": {"name": name, "namespace": namespace},
        "roleRef": role_ref or {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "Role",
            "name": "myrole",
        },
        "subjects": subjects or [],
    }
    return yaml.dump(doc)


def _cluster_role_binding(name="mycrb", role_ref=None, subjects=None):
    doc = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": {"name": name},
        "roleRef": role_ref or {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "ClusterRole",
            "name": "myclusterrole",
        },
        "subjects": subjects or [],
    }
    return yaml.dump(doc)


# ---------------------------------------------------------------------------
# _analyse_rule
# ---------------------------------------------------------------------------


class TestAnalyseRule:
    def test_normal_rule(self):
        rule = _analyse_rule({
            "apiGroups": [""],
            "resources": ["pods"],
            "verbs": ["get", "list", "watch"],
        })
        assert rule["api_groups"] == [""]
        assert rule["resources"] == ["pods"]
        assert rule["verbs"] == ["get", "list", "watch"]
        assert rule["wildcard_verb"] is False
        assert rule["wildcard_resource"] is False
        assert rule["is_dangerous"] is False

    def test_wildcard_verb(self):
        rule = _analyse_rule({"apiGroups": [""], "resources": ["pods"], "verbs": ["*"]})
        assert rule["wildcard_verb"] is True
        assert rule["is_dangerous"] is False  # resource not wildcard

    def test_wildcard_resource(self):
        rule = _analyse_rule({"apiGroups": [""], "resources": ["*"], "verbs": ["get"]})
        assert rule["wildcard_resource"] is True
        assert rule["is_dangerous"] is False  # verb not wildcard

    def test_fully_dangerous(self):
        rule = _analyse_rule({"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]})
        assert rule["wildcard_verb"] is True
        assert rule["wildcard_resource"] is True
        assert rule["is_dangerous"] is True

    def test_empty_rule(self):
        rule = _analyse_rule({})
        assert rule["api_groups"] == []
        assert rule["resources"] == []
        assert rule["verbs"] == []
        assert rule["is_dangerous"] is False

    def test_resource_names(self):
        rule = _analyse_rule({
            "apiGroups": [""],
            "resources": ["configmaps"],
            "verbs": ["get"],
            "resourceNames": ["my-config"],
        })
        assert rule["resource_names"] == ["my-config"]

    def test_non_resource_urls(self):
        rule = _analyse_rule({
            "nonResourceURLs": ["/healthz"],
            "verbs": ["get"],
        })
        assert rule["non_resource_urls"] == ["/healthz"]


# ---------------------------------------------------------------------------
# extract_rbac_info — Role
# ---------------------------------------------------------------------------


class TestExtractRbacRole:
    def test_role_kind(self):
        info = extract_rbac_info(K8sManifest(_role()))
        assert info.kind == "Role"
        assert info.name == "myrole"
        assert info.namespace == "default"

    def test_role_rules_extracted(self):
        rules = [
            {"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]},
            {"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["*"]},
        ]
        info = extract_rbac_info(K8sManifest(_role(rules=rules)))
        assert len(info.rules) == 2
        assert info.rules[0]["resources"] == ["pods"]
        assert info.rules[1]["wildcard_verb"] is True

    def test_role_no_subjects(self):
        info = extract_rbac_info(K8sManifest(_role()))
        assert info.subjects == []
        assert info.role_ref is None

    def test_role_empty_rules(self):
        info = extract_rbac_info(K8sManifest(_role(rules=[])))
        assert info.rules == []


# ---------------------------------------------------------------------------
# extract_rbac_info — ClusterRole
# ---------------------------------------------------------------------------


class TestExtractRbacClusterRole:
    def test_cluster_role_kind(self):
        info = extract_rbac_info(K8sManifest(_cluster_role()))
        assert info.kind == "ClusterRole"

    def test_cluster_role_rules(self):
        rules = [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]
        info = extract_rbac_info(K8sManifest(_cluster_role(rules=rules)))
        assert len(info.rules) == 1
        assert info.rules[0]["is_dangerous"] is True


# ---------------------------------------------------------------------------
# extract_rbac_info — RoleBinding
# ---------------------------------------------------------------------------


class TestExtractRbacRoleBinding:
    def test_role_binding_kind(self):
        info = extract_rbac_info(K8sManifest(_role_binding()))
        assert info.kind == "RoleBinding"

    def test_role_ref_extracted(self):
        info = extract_rbac_info(K8sManifest(_role_binding()))
        assert info.role_ref is not None
        assert info.role_ref["kind"] == "Role"
        assert info.role_ref["name"] == "myrole"
        assert info.role_ref["api_group"] == "rbac.authorization.k8s.io"

    def test_subjects_extracted(self):
        subjects = [
            {"kind": "ServiceAccount", "name": "myapp-sa", "namespace": "default"},
            {"kind": "User", "name": "alice", "apiGroup": "rbac.authorization.k8s.io"},
        ]
        info = extract_rbac_info(K8sManifest(_role_binding(subjects=subjects)))
        assert len(info.subjects) == 2
        assert info.subjects[0]["kind"] == "ServiceAccount"
        assert info.subjects[0]["name"] == "myapp-sa"
        assert info.subjects[1]["kind"] == "User"

    def test_no_rules_in_binding(self):
        info = extract_rbac_info(K8sManifest(_role_binding()))
        assert info.rules == []


# ---------------------------------------------------------------------------
# extract_rbac_info — ClusterRoleBinding
# ---------------------------------------------------------------------------


class TestExtractRbacClusterRoleBinding:
    def test_cluster_role_binding_kind(self):
        info = extract_rbac_info(K8sManifest(_cluster_role_binding()))
        assert info.kind == "ClusterRoleBinding"

    def test_role_ref_cluster(self):
        info = extract_rbac_info(K8sManifest(_cluster_role_binding()))
        assert info.role_ref["kind"] == "ClusterRole"
        assert info.role_ref["name"] == "myclusterrole"

    def test_cluster_subjects(self):
        subjects = [
            {"kind": "Group", "name": "system:masters", "apiGroup": "rbac.authorization.k8s.io"},
        ]
        info = extract_rbac_info(K8sManifest(_cluster_role_binding(subjects=subjects)))
        assert info.subjects[0]["kind"] == "Group"
        assert info.subjects[0]["name"] == "system:masters"
        assert info.subjects[0]["namespace"] is None


# ---------------------------------------------------------------------------
# RBAC_KINDS constant
# ---------------------------------------------------------------------------


class TestRbacKinds:
    def test_role_in_kinds(self):
        assert "Role" in RBAC_KINDS

    def test_cluster_role_in_kinds(self):
        assert "ClusterRole" in RBAC_KINDS

    def test_role_binding_in_kinds(self):
        assert "RoleBinding" in RBAC_KINDS

    def test_cluster_role_binding_in_kinds(self):
        assert "ClusterRoleBinding" in RBAC_KINDS

    def test_deployment_not_in_kinds(self):
        assert "Deployment" not in RBAC_KINDS
