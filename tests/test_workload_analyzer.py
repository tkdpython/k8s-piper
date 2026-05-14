"""Tests for k8s_piper.workload_analyzer."""

import pytest
import yaml

from k8s_piper.k8s_manifest import K8sManifest
from k8s_piper.workload_analyzer import (
    WORKLOAD_KINDS,
    ContainerInfo,
    WorkloadInfo,
    _parse_image,
    extract_workload_info,
)


# ---------------------------------------------------------------------------
# _parse_image
# ---------------------------------------------------------------------------


class TestParseImage:
    def test_name_and_tag(self):
        name, tag, digest = _parse_image("nginx:1.21")
        assert name == "nginx"
        assert tag == "1.21"
        assert digest is False

    def test_name_only_no_tag(self):
        name, tag, digest = _parse_image("nginx")
        assert name == "nginx"
        assert tag is None
        assert digest is False

    def test_latest_tag(self):
        name, tag, digest = _parse_image("nginx:latest")
        assert name == "nginx"
        assert tag == "latest"
        assert digest is False

    def test_digest(self):
        name, tag, digest = _parse_image("nginx@sha256:abc123")
        assert name == "nginx"
        assert tag is None
        assert digest is True

    def test_registry_with_port(self):
        name, tag, digest = _parse_image("registry.example.com:5000/myapp:v1.2.3")
        assert name == "registry.example.com:5000/myapp"
        assert tag == "v1.2.3"
        assert digest is False

    def test_registry_no_tag(self):
        name, tag, digest = _parse_image("registry.example.com:5000/myapp")
        assert name == "registry.example.com:5000/myapp"
        assert tag is None
        assert digest is False

    def test_empty_string(self):
        name, tag, digest = _parse_image("")
        assert name == ""
        assert tag is None
        assert digest is False

    def test_scoped_image_with_tag(self):
        name, tag, digest = _parse_image("docker.io/library/nginx:1.25")
        assert name == "docker.io/library/nginx"
        assert tag == "1.25"
        assert digest is False


# ---------------------------------------------------------------------------
# Helpers to build test YAML
# ---------------------------------------------------------------------------


def _deployment(name="myapp", namespace="default", containers=None, init_containers=None,
                pod_security_context=None):
    """Build a minimal Deployment YAML string."""
    containers = containers or [{"name": "app", "image": "nginx:1.21"}]
    spec_containers = []
    for c in containers:
        spec_containers.append(c)

    template_spec = {"containers": spec_containers}
    if init_containers:
        template_spec["initContainers"] = init_containers
    if pod_security_context:
        template_spec["securityContext"] = pod_security_context

    doc = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "template": {
                "spec": template_spec,
            }
        },
    }
    return yaml.dump(doc)


def _pod(name="mypod", namespace="default", containers=None, pod_security_context=None):
    """Build a minimal Pod YAML string."""
    containers = containers or [{"name": "app", "image": "nginx:1.21"}]
    spec = {"containers": containers}
    if pod_security_context:
        spec["securityContext"] = pod_security_context
    doc = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "namespace": namespace},
        "spec": spec,
    }
    return yaml.dump(doc)


def _cronjob(name="myjob", namespace="default", containers=None):
    """Build a minimal CronJob YAML string."""
    containers = containers or [{"name": "batch", "image": "busybox:1.36"}]
    doc = {
        "apiVersion": "batch/v1",
        "kind": "CronJob",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "schedule": "0 * * * *",
            "jobTemplate": {
                "spec": {
                    "template": {
                        "spec": {"containers": containers}
                    }
                }
            },
        },
    }
    return yaml.dump(doc)


# ---------------------------------------------------------------------------
# extract_workload_info — basic
# ---------------------------------------------------------------------------


class TestExtractWorkloadInfoBasic:
    def test_deployment_kind(self):
        info = extract_workload_info(K8sManifest(_deployment()))
        assert info.kind == "Deployment"
        assert info.name == "myapp"
        assert info.namespace == "default"

    def test_deployment_containers_count(self):
        yaml_str = _deployment(
            containers=[
                {"name": "app", "image": "nginx:1.21"},
                {"name": "sidecar", "image": "envoyproxy/envoy:v1.28"},
            ]
        )
        info = extract_workload_info(K8sManifest(yaml_str))
        assert len(info.containers) == 2

    def test_pod_kind(self):
        info = extract_workload_info(K8sManifest(_pod()))
        assert info.kind == "Pod"
        assert len(info.containers) == 1

    def test_cronjob_containers(self):
        info = extract_workload_info(K8sManifest(_cronjob()))
        assert info.kind == "CronJob"
        assert len(info.containers) == 1
        assert info.containers[0].name == "batch"

    def test_init_containers_extracted(self):
        yaml_str = _deployment(
            containers=[{"name": "app", "image": "nginx:1.21"}],
            init_containers=[{"name": "init", "image": "busybox:1.36"}],
        )
        info = extract_workload_info(K8sManifest(yaml_str))
        assert len(info.init_containers) == 1
        assert info.init_containers[0].name == "init"
        assert info.init_containers[0].is_init is True
        assert info.containers[0].is_init is False

    def test_no_containers(self):
        doc = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "empty"},
            "spec": {"template": {"spec": {}}},
        }
        info = extract_workload_info(K8sManifest(yaml.dump(doc)))
        assert info.containers == []
        assert info.init_containers == []


# ---------------------------------------------------------------------------
# Container image fields
# ---------------------------------------------------------------------------


class TestContainerImage:
    def _get_container(self, image):
        yaml_str = _deployment(containers=[{"name": "app", "image": image}])
        return extract_workload_info(K8sManifest(yaml_str)).containers[0]

    def test_pinned_tag(self):
        c = self._get_container("nginx:1.21")
        assert c.image_tag == "1.21"
        assert c.has_digest is False

    def test_latest_tag(self):
        c = self._get_container("nginx:latest")
        assert c.image_tag == "latest"

    def test_no_tag(self):
        c = self._get_container("nginx")
        assert c.image_tag is None
        assert c.has_digest is False

    def test_digest(self):
        c = self._get_container("nginx@sha256:abc123")
        assert c.image_tag is None
        assert c.has_digest is True

    def test_pull_policy(self):
        yaml_str = _deployment(
            containers=[{"name": "app", "image": "nginx:1.21", "imagePullPolicy": "Always"}]
        )
        c = extract_workload_info(K8sManifest(yaml_str)).containers[0]
        assert c.pull_policy == "Always"

    def test_pull_policy_unset(self):
        c = self._get_container("nginx:1.21")
        assert c.pull_policy == ""


# ---------------------------------------------------------------------------
# Resource requests / limits
# ---------------------------------------------------------------------------


class TestContainerResources:
    def _get_container(self, resources_dict):
        yaml_str = _deployment(
            containers=[{"name": "app", "image": "nginx:1.21", "resources": resources_dict}]
        )
        return extract_workload_info(K8sManifest(yaml_str)).containers[0]

    def test_full_resources(self):
        c = self._get_container({
            "requests": {"cpu": "100m", "memory": "128Mi"},
            "limits": {"cpu": "500m", "memory": "256Mi"},
        })
        assert c.resources["cpu_request"] == "100m"
        assert c.resources["memory_request"] == "128Mi"
        assert c.resources["cpu_limit"] == "500m"
        assert c.resources["memory_limit"] == "256Mi"

    def test_no_resources(self):
        c = self._get_container({})
        assert c.resources["cpu_request"] is None
        assert c.resources["cpu_limit"] is None

    def test_requests_only_no_limits(self):
        c = self._get_container({"requests": {"cpu": "100m"}})
        assert c.resources["cpu_request"] == "100m"
        assert c.resources["cpu_limit"] is None


# ---------------------------------------------------------------------------
# Security context
# ---------------------------------------------------------------------------


class TestContainerSecurityContext:
    def _get_container(self, sc_dict):
        yaml_str = _deployment(
            containers=[{"name": "app", "image": "nginx:1.21", "securityContext": sc_dict}]
        )
        return extract_workload_info(K8sManifest(yaml_str)).containers[0]

    def test_privileged(self):
        c = self._get_container({"privileged": True})
        assert c.security_context["privileged"] is True

    def test_not_privileged(self):
        c = self._get_container({"privileged": False})
        assert c.security_context["privileged"] is False

    def test_allow_privilege_escalation(self):
        c = self._get_container({"allowPrivilegeEscalation": False})
        assert c.security_context["allow_privilege_escalation"] is False

    def test_read_only_root_fs(self):
        c = self._get_container({"readOnlyRootFilesystem": True})
        assert c.security_context["read_only_root_filesystem"] is True

    def test_run_as_user(self):
        c = self._get_container({"runAsUser": 1000, "runAsNonRoot": True})
        assert c.security_context["run_as_user"] == 1000
        assert c.security_context["run_as_non_root"] is True

    def test_capabilities(self):
        c = self._get_container({
            "capabilities": {"add": ["NET_ADMIN"], "drop": ["ALL"]}
        })
        assert c.security_context["capabilities_add"] == ["NET_ADMIN"]
        assert c.security_context["capabilities_drop"] == ["ALL"]

    def test_empty_security_context(self):
        c = self._get_container({})
        assert c.security_context["privileged"] is None
        assert c.security_context["capabilities_add"] == []
        assert c.security_context["capabilities_drop"] == []


class TestPodSecurityContext:
    def test_pod_sc_extracted(self):
        yaml_str = _deployment(
            pod_security_context={
                "runAsNonRoot": True,
                "runAsUser": 1000,
                "fsGroup": 2000,
            }
        )
        info = extract_workload_info(K8sManifest(yaml_str))
        psc = info.pod_security_context
        assert psc["run_as_non_root"] is True
        assert psc["run_as_user"] == 1000
        assert psc["fs_group"] == 2000

    def test_pod_sc_missing(self):
        info = extract_workload_info(K8sManifest(_deployment()))
        psc = info.pod_security_context
        assert psc["run_as_non_root"] is None
        assert psc["run_as_user"] is None


# ---------------------------------------------------------------------------
# WORKLOAD_KINDS constant
# ---------------------------------------------------------------------------


class TestWorkloadKinds:
    def test_pod_in_kinds(self):
        assert "Pod" in WORKLOAD_KINDS

    def test_deployment_in_kinds(self):
        assert "Deployment" in WORKLOAD_KINDS

    def test_statefulset_in_kinds(self):
        assert "StatefulSet" in WORKLOAD_KINDS

    def test_daemonset_in_kinds(self):
        assert "DaemonSet" in WORKLOAD_KINDS

    def test_job_in_kinds(self):
        assert "Job" in WORKLOAD_KINDS

    def test_cronjob_in_kinds(self):
        assert "CronJob" in WORKLOAD_KINDS

    def test_role_not_in_kinds(self):
        assert "Role" not in WORKLOAD_KINDS
