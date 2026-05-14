"""Extract and analyse workload information from Kubernetes manifests.

Supports: Pod, Deployment, StatefulSet, DaemonSet, Job, CronJob, ReplicaSet.
Extracts container images, resource requests/limits, and security contexts.
"""

from typing import Dict, List, Optional, Tuple

WORKLOAD_KINDS = frozenset({
    "Pod",
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "Job",
    "CronJob",
    "ReplicaSet",
})


class ContainerInfo:
    """Information extracted from a single container spec."""

    def __init__(
        self,
        name,           # type: str
        image,          # type: str
        image_name,     # type: str
        image_tag,      # type: Optional[str]
        has_digest,     # type: bool
        pull_policy,    # type: str
        resources,      # type: dict
        security_context,  # type: dict
        is_init,        # type: bool
    ):
        self.name = name
        self.image = image
        self.image_name = image_name
        self.image_tag = image_tag      # None if untagged / digest-only
        self.has_digest = has_digest    # True when @sha256:... present
        self.pull_policy = pull_policy
        self.resources = resources
        self.security_context = security_context
        self.is_init = is_init


class WorkloadInfo:
    """Workload information extracted from a Kubernetes manifest."""

    def __init__(
        self,
        kind,                   # type: str
        name,                   # type: str
        namespace,              # type: str
        containers,             # type: List[ContainerInfo]
        init_containers,        # type: List[ContainerInfo]
        pod_security_context,   # type: dict
    ):
        self.kind = kind
        self.name = name
        self.namespace = namespace
        self.containers = containers
        self.init_containers = init_containers
        self.pod_security_context = pod_security_context


def _parse_image(image_str):
    # type: (str) -> Tuple[str, Optional[str], bool]
    """Parse an image reference.

    Returns (image_name, tag_or_none, has_digest).
    Examples:
      "nginx:1.21"           -> ("nginx", "1.21", False)
      "nginx"                -> ("nginx", None, False)
      "nginx:latest"         -> ("nginx", "latest", False)
      "nginx@sha256:abc123"  -> ("nginx", None, True)
      "reg:5000/app:v1"      -> ("reg:5000/app", "v1", False)
    """
    if not image_str:
        return "", None, False

    # Digest reference takes precedence over tag
    if "@" in image_str:
        name = image_str.rsplit("@", 1)[0]
        return name, None, True

    # Find the last colon; treat what follows as a tag only when there is
    # no slash after the colon (to avoid treating registry:port as a tag)
    last_colon = image_str.rfind(":")
    if last_colon != -1 and "/" not in image_str[last_colon:]:
        return image_str[:last_colon], image_str[last_colon + 1:], False

    return image_str, None, False


def _analyse_container(c, is_init=False):
    # type: (dict, bool) -> ContainerInfo
    """Build a ContainerInfo from a raw container spec dict."""
    name = c.get("name") or "unknown"
    image = c.get("image") or ""
    image_name, image_tag, has_digest = _parse_image(image)
    pull_policy = c.get("imagePullPolicy") or ""

    res = c.get("resources") or {}
    requests = res.get("requests") or {}
    limits = res.get("limits") or {}
    resources = {
        "cpu_request": requests.get("cpu"),
        "memory_request": requests.get("memory"),
        "cpu_limit": limits.get("cpu"),
        "memory_limit": limits.get("memory"),
    }

    sc = c.get("securityContext") or {}
    caps = sc.get("capabilities") or {}
    security_context = {
        "privileged": sc.get("privileged"),
        "allow_privilege_escalation": sc.get("allowPrivilegeEscalation"),
        "run_as_non_root": sc.get("runAsNonRoot"),
        "run_as_user": sc.get("runAsUser"),
        "run_as_group": sc.get("runAsGroup"),
        "read_only_root_filesystem": sc.get("readOnlyRootFilesystem"),
        "capabilities_add": list(caps.get("add") or []),
        "capabilities_drop": list(caps.get("drop") or []),
    }

    return ContainerInfo(
        name=name,
        image=image,
        image_name=image_name,
        image_tag=image_tag,
        has_digest=has_digest,
        pull_policy=pull_policy,
        resources=resources,
        security_context=security_context,
        is_init=is_init,
    )


def _get_pod_spec(doc, kind):
    # type: (dict, str) -> dict
    """Return the pod spec dict (the one containing 'containers')."""
    spec = doc.get("spec") or {}
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        job_spec = (spec.get("jobTemplate") or {}).get("spec") or {}
        template = job_spec.get("template") or {}
        return template.get("spec") or {}
    # Deployment, StatefulSet, DaemonSet, Job, ReplicaSet
    template = spec.get("template") or {}
    return template.get("spec") or {}


def extract_workload_info(manifest):
    # type: (object) -> WorkloadInfo
    """Extract WorkloadInfo from a parsed K8sManifest."""
    doc = manifest.doc
    kind = manifest.kind

    pod_spec = _get_pod_spec(doc, kind)

    containers = [
        _analyse_container(c, is_init=False)
        for c in (pod_spec.get("containers") or [])
    ]
    init_containers = [
        _analyse_container(c, is_init=True)
        for c in (pod_spec.get("initContainers") or [])
    ]

    psc = pod_spec.get("securityContext") or {}
    pod_security_context = {
        "run_as_non_root": psc.get("runAsNonRoot"),
        "run_as_user": psc.get("runAsUser"),
        "run_as_group": psc.get("runAsGroup"),
        "fs_group": psc.get("fsGroup"),
        "seccomp_profile": psc.get("seccompProfile"),
        "supplemental_groups": list(psc.get("supplementalGroups") or []),
        "sysctls": list(psc.get("sysctls") or []),
    }

    return WorkloadInfo(
        kind=kind,
        name=manifest.name,
        namespace=manifest.namespace,
        containers=containers,
        init_containers=init_containers,
        pod_security_context=pod_security_context,
    )
