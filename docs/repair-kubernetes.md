# Restricted Kubernetes Deployment recovery

Kubernetes repair is disabled until an administrator installs an exact profile,
selects the `kubernetes` helper, and confirms `ENABLE`. The controller and target
must independently register the same profile. Model requests have no parameters:
only `restart` and `restore-image` exist. Existing signature, expiry, replay,
resource lock, cooldown, and HIGH-risk authorization apply.

A resource has four exact components: `cluster-id/namespace/deployment/uid`.
Deleting and recreating the same Deployment name requires new registration.
The profile binds a canonical numeric HTTPS endpoint with an explicit port,
credential ID, container name, known image digest, rollout policy bounds,
capacity ceiling, and registered independent HTTP or TCP business checks.

Example profile constraints (replace all deployment-specific values):

```json
{
  "endpoint": "https://10.0.0.10:6443",
  "credential_id": "production-app",
  "container_name": "web",
  "known_image": "registry.example/app@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "min_available": 1,
  "max_unavailable": 0,
  "capacity_replicas": 2,
  "rollout_timeout_seconds": 120,
  "verification_window_seconds": 60,
  "sample_interval_seconds": 5
}
```

Before enabling the helper, provision a root-owned, non-symlink JSON file at
`/etc/a4diag-target/kubernetes/production-app.json`, mode0600, with exactly
`endpoint`, `ca_pem` (PEM CA certificate contents), and `token` (scoped
ServiceAccount bearer token). Ancestors must be root-owned and not writable by
other users. Endpoint must exactly match the profile. Refresh credentials through
administrator-controlled provisioning. Never put tokens in profiles, model
messages, command output, or evidence. Kubeconfig, exec plugins, environment proxy
settings, redirects, caller-selected paths, and disabled TLS verification are
unsupported.

`deploy/kubernetes/repair-agent.yaml` is a minimum ServiceAccount/Role/RoleBinding
example. Edit its namespace and exact Deployment resourceName before applying it
as an administrator. It grants get/patch for that Deployment; namespace list of
ReplicaSets, Pods, events and ResourceQuota; and Pod logs get. No Secret reads,
exec, create, delete, update, wildcard resources or ClusterRole are granted.
Kubernetes RBAC cannot restrict individual patch fields: the trusted adapter
builds the field-restricted JSON Patch, while RBAC restricts its object scope.
Namespace-level read grants can see other workloads; adapter evidence filters
exact owner UID lineage and never emits Pod spec, environment or secret refs.

The helper retains an empty capability set, strict filesystem protections, and a
private read-only `/run` so the worker cannot access manager sockets. Only this
adapter gets IPv4/IPv6 socket families, `IPAddressDeny=any`, and the exact API
address allow rule. systemd cgroup IP filtering requires kernel/systemd support;
verify enforcement on the deployment host before enabling repair. Address rules
do not filter ports: the closed TLS client fixes the registered port and paths.
No configurable network namespace is provided in production.

Prepare rejects zero replicas, paused/deleting Deployments, known Argo/Flux
ownership, PVC/hostPath volumes, unobserved generations, unsupported strategies,
invalid rollout budgets and known insufficient capacity. Percentage unavailable
rounds down; surge rounds up. The declared capacity ceiling is not a physical
scheduler guarantee. Pod quota headroom and owned Unschedulable Pods are checked.
Resource quotas other than bounded Pod/ReplicaSet/Deployment counts are currently
unsupported and fail closed, including CPU/memory quotas. PDB is not used as a
rolling update safeguard. Future scheduler fragmentation, quota races or a later
capacity loss can still prevent rollout; the finite job then reports partial.

Apply tests UID, resourceVersion and the original field before changing one image
or the fixed `a4diag.io/restart-transaction` annotation. No full-spec restoration
or forced retry occurs. Both HTTP409 and HTTP422 rejected preconditions stop the
operation. Admission reads and patch share one short operation deadline; an
acknowledged patch gets one separate finite rollout observation deadline.
A root-private durable intent prevents repeated annotation refreshes. An uncertain
patch result remains unknown and keeps the resource reservation.

Rollout completion requires the accepted generation, updated/available replicas,
exact current ReplicaSet lineage, ready Pods, and exit of every old Pod including
terminating Pods. A persisted controller observation then requires at least60
measured seconds of stable Pod UID/generation/restart count and independent
business health, with at most5seconds between samples. CrashLoop or relapse is
partial/manual and does not trigger repeated patches. A controller restart begins
a new uninterrupted window within the original persisted deadline.

Explicit image compensation restores only the transaction's image field while
current UID/name/image and resourceVersion still match. Concurrent changes are
reported as conflicts. It never restores arbitrary template content. Restart
cannot restore old Pods or process memory. Field compensation alone does not
prove restored business health, and the automated fault-recovery loop does not
silently compensate after failed sustained observation.

Read access uses separately revocable `allowed_kubernetes_profiles` grants.
`kubernetes_state` returns sanitized status; `kubernetes_evidence` returns bounded,
redacted events/logs marked untrusted. Callers supply only an installed profile
ID and output limit. Evidence is diagnostic data, never instructions or patch
permission. Re-register/drain helpers using the existing installer workflow.

Validation scope: source-staged helpers and real detached systemd workers in a
D-backed isolated k3s lab. See the task report for exact pinned versions and test
runs; this is distinct from built-package SSH, model/provider or release testing.
