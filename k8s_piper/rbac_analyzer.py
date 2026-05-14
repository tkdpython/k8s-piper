"""Extract and analyse RBAC information from Kubernetes manifests.

Supports: Role, ClusterRole, RoleBinding, ClusterRoleBinding.
"""

from typing import Dict, List, Optional

RBAC_KINDS = frozenset({
    "Role",
    "ClusterRole",
    "RoleBinding",
    "ClusterRoleBinding",
})

# Kinds that carry policy rules
_RULE_KINDS = frozenset({"Role", "ClusterRole"})

# Kinds that bind a role to subjects
_BINDING_KINDS = frozenset({"RoleBinding", "ClusterRoleBinding"})


class RBACInfo:
    """RBAC information extracted from a Kubernetes manifest."""

    def __init__(
        self,
        kind,       # type: str
        name,       # type: str
        namespace,  # type: str
        rules,      # type: List[dict]
        subjects,   # type: List[dict]
        role_ref,   # type: Optional[dict]
    ):
        self.kind = kind
        self.name = name
        self.namespace = namespace
        self.rules = rules          # non-empty for Role / ClusterRole
        self.subjects = subjects    # non-empty for RoleBinding / ClusterRoleBinding
        self.role_ref = role_ref    # present for binding kinds


def _analyse_rule(rule):
    # type: (dict) -> dict
    """Convert a raw rule dict into an enriched form with danger flags."""
    api_groups = list(rule.get("apiGroups") or [])
    resources = list(rule.get("resources") or [])
    verbs = list(rule.get("verbs") or [])
    resource_names = list(rule.get("resourceNames") or [])
    non_resource_urls = list(rule.get("nonResourceURLs") or [])

    wildcard_verb = "*" in verbs
    wildcard_resource = "*" in resources
    wildcard_group = "*" in api_groups

    # A rule is considered dangerous when it grants all verbs on all resources.
    is_dangerous = wildcard_verb and wildcard_resource

    return {
        "api_groups": api_groups,
        "resources": resources,
        "verbs": verbs,
        "resource_names": resource_names,
        "non_resource_urls": non_resource_urls,
        "wildcard_verb": wildcard_verb,
        "wildcard_resource": wildcard_resource,
        "wildcard_group": wildcard_group,
        "is_dangerous": is_dangerous,
    }


def extract_rbac_info(manifest):
    # type: (object) -> RBACInfo
    """Extract RBACInfo from a parsed K8sManifest."""
    doc = manifest.doc
    kind = manifest.kind

    rules = []      # type: List[dict]
    subjects = []   # type: List[dict]
    role_ref = None  # type: Optional[dict]

    if kind in _RULE_KINDS:
        for raw in (doc.get("rules") or []):
            rules.append(_analyse_rule(raw))

    if kind in _BINDING_KINDS:
        for s in (doc.get("subjects") or []):
            subjects.append({
                "kind": s.get("kind", ""),
                "name": s.get("name", ""),
                "namespace": s.get("namespace"),
                "api_group": s.get("apiGroup", ""),
            })
        raw_ref = doc.get("roleRef") or {}
        if raw_ref:
            role_ref = {
                "api_group": raw_ref.get("apiGroup", ""),
                "kind": raw_ref.get("kind", ""),
                "name": raw_ref.get("name", ""),
            }

    return RBACInfo(
        kind=kind,
        name=manifest.name,
        namespace=manifest.namespace,
        rules=rules,
        subjects=subjects,
        role_ref=role_ref,
    )
