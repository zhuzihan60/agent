# Supported distribution matrix

A4Diag 0.4.0 is tested on every supported distribution in CI
(`.github/workflows/test.yml`, `release.yml`):

| Distribution | Version | Container image |
| --- | --- | --- |
| Rocky Linux | 8, 9 | `rockylinux:8`, `rockylinux:9` |
| AlmaLinux | 8, 9 | `almalinux:8`, `almalinux:9` |
| Ubuntu | 22.04, 24.04 | `ubuntu:22.04`, `ubuntu:24.04` |
| Debian | 12 | `debian:12` |

RHEL is covered by the equivalent AlmaLinux/Rocky evidence plus a separately
configured licensed runner; no credentials appear in the workflow files.

## Gates per matrix job

- **unit** (Python 3.11): full `pytest -q -rs` — unit, contract, integration,
  acceptance suites. Windows runs the same suite; only documented POSIX skips
  are allowed (AF_UNIX, symlink privilege, mode/owner, and the bash installer
  harness), each carrying an explicit reason.
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

## POSIX-only gates (skipped on Windows with documented reasons)

- AF_UNIX socket tests (contract harness)
- symlink creation tests
- POSIX file mode 0600 / owner checks
- init-config POSIX mode gate
- the bash installer harness (msys2 bash cannot start under the Windows file
  sandbox); the installer's static contract is asserted on all platforms and
  the full harness runs on the Linux matrix

## Explicitly not executed

- Real external servers, mail delivery, model APIs, or FlashDuty calls are
  never made by the CI matrix; every transport test uses injected fakes.
