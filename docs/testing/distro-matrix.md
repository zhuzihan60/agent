# Supported distribution matrix

A4Diag 0.4.0 is tested on every supported distribution in CI
(`.github/workflows/test.yml`, `release.yml`):

| Distribution | Version | Container image |
| --- | --- | --- |
| Alibaba Cloud Linux | 3 | `langfarm/alinux3@sha256:c5c67ed6e33dc967e9a05ec3cec680abaf24bc2ea0fb23ee0d1470750882c6b1` |
| Rocky Linux | 8, 9 | `rockylinux:8`, `rockylinux:9` |
| AlmaLinux | 8, 9 | `almalinux:8`, `almalinux:9` |
| Ubuntu | 22.04, 24.04 | `ubuntu:22.04`, `ubuntu:24.04` |
| Debian | 12 | `debian:12` |

RHEL is covered by the equivalent AlmaLinux/Rocky evidence plus a separately
configured licensed runner; no credentials appear in the workflow files.

The Alibaba Cloud Linux CI container is a digest-pinned, Alibaba Linux 3-based
test image with the archive tools required by GitHub Actions already present.
This avoids a network-dependent package-manager bootstrap before checkout.
Production support remains keyed to the official `ID=alinux`, major version 3
operating-system identity rather than to this CI image name.

## Gates per matrix job

- **unit** (Python 3.11 on Linux): full `pytest -q -rs` — unit, contract,
  integration, and acceptance suites. Windows is not a supported runtime or
  release gate.
- **build**: builds the exact `a4diag-0.4.0-py3-none-any.whl` and
  `a4diag_builtin_plugins-0.4.0-py3-none-any.whl`, runs
  `verify-source` (no fixed-target literals) and `verify-release`.
- **distro** (privileged container per image): `distro_smoke.sh` performs an
  offline install of the assembled release, confirms read-only defaults
  (`global_mode: read_only`, `targets: []`), the offline `self-check`, and
  that the systemd units never permit writing `/etc/a4diag/config.yaml`.
- **release**: triggers only on `v*` tags, rebuilds from lockfiles, signs the
  release manifest with repository secret material, re-verifies the signature,
  runs the distro smoke on the signed release, and publishes only after all
  required jobs succeed.

## Linux-only gates

- AF_UNIX socket tests (contract harness)
- symlink creation tests
- POSIX file mode 0600 / owner checks
- init-config POSIX mode gate
- the bash installer harness and systemd isolation checks

## Explicitly not executed

- Real external servers, mail delivery, model APIs, or FlashDuty calls are
  never made by the CI matrix; every transport test uses injected fakes.
