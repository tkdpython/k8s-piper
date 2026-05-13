# k8s-piper

A tool for extracting key information from kubectl commands and displaying it in an easy-to-digest way.

k8s-piper automatically detects the Kubernetes resource type from piped `kubectl` output and runs the appropriate analysis — no flags required.

---

## Supported Resources

| Resource Kind | Analysis |
|---|---|
| `ConfigMap`, `Secret` | X.509 certificate extraction and analysis |
| `Deployment`, `StatefulSet`, `DaemonSet`, `Pod`, `Job`, `CronJob`, `ReplicaSet` | Container images, resource requests/limits, security contexts |
| `Role`, `ClusterRole` | RBAC policy rules with wildcard/danger highlighting |
| `RoleBinding`, `ClusterRoleBinding` | Role reference and subject bindings |

---

## Usage

Pipe any supported `kubectl` resource into k8s-piper — the kind is detected automatically:

```bash
# Certificate analysis (ConfigMap or Secret)
kubectl get cm ca -n mynamespace -o yaml | k8s-piper
kubectl get secret mycerts -n mynamespace -o yaml | k8s-piper

# Workload analysis — images, resources, security (Deployment, Pod, StatefulSet, …)
kubectl get deploy myapp -n mynamespace -o yaml | k8s-piper
kubectl get pod mypod-abc123 -n mynamespace -o yaml | k8s-piper
kubectl get statefulset mydb -n mynamespace -o yaml | k8s-piper

# RBAC analysis (Role, ClusterRole, RoleBinding, ClusterRoleBinding)
kubectl get clusterrole cluster-admin -o yaml | k8s-piper
kubectl get rolebinding myrb -n mynamespace -o yaml | k8s-piper
```

---

## What Each Analysis Shows

### Certificates (`ConfigMap` / `Secret`)
- Subject, Issuer, and Subject Alternative Names
- Validity period with expiry warnings (⚠ < 30 days, 🔴 < 7 days)
- Key type, size, and signature algorithm
- Key Usage and Extended Key Usage
- OCSP / CRL revocation URLs and Must-Staple flag
- SHA-256 and SHA-1 fingerprints
- CA / self-signed status, path length constraint

### Workloads (`Deployment`, `Pod`, `StatefulSet`, etc.)
- **Images** — full image reference, tag or digest, pull policy; flags `latest` and untagged images
- **Resources** — CPU and memory requests/limits per container; flags missing limits
- **Security Contexts** — pod-level and per-container security settings; flags dangerous values such as `privileged: true`, `allowPrivilegeEscalation: true`, and added capabilities

### RBAC (`Role` / `ClusterRole`)
- Policy rules table: API groups × resources × verbs
- Wildcard verbs (`*`) and wildcard resources highlighted in red
- Rules granting full wildcard access flagged as dangerous

### RBAC (`RoleBinding` / `ClusterRoleBinding`)
- Role reference (kind and name)
- Subjects table: service accounts, users, and groups

---

## Installation

```bash
pip install k8s-piper
```

Or install from source:

```bash
git clone https://github.com/tkdpython/k8s-piper.git
cd k8s-piper
pip install -e .
```
