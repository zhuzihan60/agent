# Registered Docker and Podman recovery

Installation remains read-only by default. Administrators may register the
`docker` or `podman` helper, an expiring `containers` repair profile, independent
controller/target grants, and `confirm_repair_helpers: "ENABLE"`. Operations
are `start` and `restart`, always HIGH risk. They require ordinary approval or
explicit standing authorization. Model parameters are empty; models cannot
choose a socket, UID, executable, image, container name, or new grant.

The canonical resource is `docker/0/<full-64-hex-container-ID>` or
`podman/<owner-UID>/<full-64-hex-container-ID>`. Constraints pin `image_digest`
to the exact `sha256:` image ID returned by inspect (the local image config
digest, not an interchangeable registry manifest digest). Container names and
short IDs are not authority. UID, runtime, full ID and image must all match.

For example, an administrator can add this profile using actual pinned values:

```json
{
  "id": "podman-web", "target_id": "host-1", "capability": "containers",
  "resource": "podman/22001/<full-container-ID>", "actions": ["start", "restart"],
  "constraints": {"image_digest": "sha256:<image-config-digest>"},
  "recovery_check_ids": ["web-http"], "expires_at": 1800000000,
  "standing_authorization": false
}
```

Replace both digest placeholders with 64 lowercase hexadecimal characters.
Use `repair_helpers: [{"profile_id":"podman-web","adapter":"podman"}]`.
The installer also registers `allowed_container_profiles` for independent read
authorization. `container_state` accepts only the installed profile ID. Removing
mutation grants does not silently revoke accepted observation; current read and
target identity policy still applies. Removing a read grant makes evidence
unavailable, never healthy.

## Socket and owner boundary

Docker uses only `/run/docker.sock` and compatibility API v1.44. Podman uses API
v1.40 at `/run/podman/podman.sock` (UID 0) or
`/run/user/<UID>/podman/podman.sock`. Lifecycle uses only inspect/start/restart;
there is no remote/TLS endpoint, exec, image pull, or arbitrary daemon API.
Requests have a total deadline, bounded response size and peer credential
checks. Tested versions are Docker 29.1.3 and Podman 4.9.3 on the disposable
Ubuntu lab; broader manager/version compatibility is not implied.

The separate read-only `container_logs` evidence kind accepts the same installed
profile ID and current read grant. Its one fixed GET request selects stdout and
stderr, `follow=false`, and `tail=100`; no caller log options are accepted. It
reads at most 32 KiB of wire data and returns at most 16 KiB of decoded text
(or the smaller registered evidence limit), explicitly marking truncation.
Docker multiplex framing and TTY mode are validated; malformed/truncated
frames and unsupported logging drivers return unavailable. Identity is checked
before and after the read. Podman logs use the same owner-bound child and
registered endpoint. Configure an initial `container_logs` evidence source to
collect it once; sustained health samples do not fetch logs. The existing
evidence collector redacts secret-shaped content. Logs remain untrusted data,
never commands, authorization, or proof of business recovery.

The Podman broker and durable policy, key, replay, job and operation stores stay
root-private. A fixed installed Python child drops supplementary groups and
switches to the registered UID/GID before connecting; it clears all effective,
permitted, inheritable and ambient capabilities. Only frozen operation scope
and protected endpoint identity pass through its private bounded pipe. The
worker keeps ProtectHome and a private read-only `/run`, binding only the fixed
socket to `/run/a4diag-podman-<UID>.sock`; no user bus or directory is exposed.

At installation, the socket and all ancestors must pass no-symlink/ownership
checks. The root-protected binding records socket device, inode and owner.
Every API connection checks this registered endpoint plus peer UID and full
container identity. Missing sockets or mismatches fail closed; a recreated
socket requires an explicit drain and administrative re-registration. The
runtime never refreshes the recorded inode automatically or falls back to root.
The source path may be hidden by systemd's leaf bind: a later same-UID source
symlink to the *same registered inode* is not distinguishable inside the alias.
This does not authorize a different endpoint; universal live source-path
symlink detection is not claimed.

## Durable effects and business observation

Prepare freezes the identity and prior state. Apply rechecks them, durably
records intent, then performs at most one action within the existing operation
budget. Interrupted/timeout intent remains unknown; running alone cannot prove
that a particular restart completed. There is no automatic effect retry and no
promise to restore the previous process after a restart.

The shared SERVICE observer requires the same container identity, start time
and restart count across a default 60-second healthy window, with samples no
more than five seconds apart and at least one registered HTTP or TCP business
check. Missing Docker Health is `unknown`, requiring business checks. Known
Health `starting` before the first healthy sample can wait within the original
deadline; identity/restart baselines remain fixed and no healthy time accrues.
Relapse, identity replacement, OOM, restart count changes, or failed business
checks do not become success merely because start returned successfully.
Results describe recovery during the measured window, not a proven root-cause
fix. Default resource admission remains once per ten minutes and twice hourly;
the canonical resource includes runtime and owner UID.

## systemd-managed containers

Known swarm/Kubernetes/systemd/autoupdate metadata is rejected by the standalone
container adapter. An administrator can explicitly link `service_unit` and
`service_profile_id` to a separately registered, authorized system service.
Before policy, approval and ticket freezing, the controller creates the normal
HIGH-risk SERVICE operation bound to that exact unit and its recovery checks.
A signed container operation is rejected with `service_route_required`; it is
never rewritten into a service effect. Admission and cooldown use the actual
service unit, so repeated container alerts cannot bypass its limits.

Only an explicit administrator link selects a service. Metadata or a matching
name never grants authority to a system unit. Native rootless Quadlet user
manager units are unsupported/manual; an explicitly registered system unit
wrapping a user workload can use the existing system SERVICE path. No user bus
access or universal Quadlet detection is provided. For ambiguous management,
the administrator must supply the explicit link.

SERVICE retains its existing readiness semantics: a Type=exec wrapper can
report active before the application listens. Its first failed post-effect
business check yields a truthful partial outcome without another action. Units
that declare application/listener readiness can proceed to the same sustained
business observation; listener readiness itself is not business success.

Live tests exercise signed source-staged helpers, real systemd workers, Docker,
rootful/rootless Podman, and the production observation loop. They do not stand
in for the later built-package SSH installation or live-model V1/V2 acceptance
matrix.
