# A4Diag 0.4.0 installation

The installer is atomic and fail-closed: it verifies the release before
extraction, stages into `/opt/a4diag/releases/<version>`, creates an isolated
Python 3.11 virtual environment from the locked wheelhouse, runs the offline
self-check, and only then atomically switches the `/opt/a4diag/current`
symlink. A service-start failure rolls back to the previous version.

## Requirements

- One of: Rocky/AlmaLinux/RHEL 8 or 9, Ubuntu 22.04/24.04, Debian 12
- systemd, Python 3.11, `sha256sum`, `openssl`, `curl` (online mode only)
- root

## Offline install (air-gapped)

```bash
# 1. Copy the verified release directory onto the host (USB / internal mirror).
sudo ./install.sh --offline /path/to/release-dir
```

The installer verifies `SHA256SUMS` for every artifact. If the release carries
`MANIFEST.sig`, provide the trusted RSA public key:

```bash
sudo A4DIAG_TRUSTED_KEY=/path/to/a4diag-release-public.pem ./install.sh --offline /path/to/release-dir
```

Unsigned releases are refused unless explicitly accepted with
`A4DIAG_ALLOW_UNSIGNED=1` (development only).

## Online install

```bash
curl -fsSL https://github.com/zhuzihan60/agent/releases/latest/download/install-a4diag.sh | sudo bash
```

The bootstrap downloads `a4diag.tar.gz` and its detached signature from the
latest GitHub Release. It verifies the archive before extraction using its
pinned RSA public key, then the offline installer verifies every internal hash
and the signed `MANIFEST.json` again.

The `curl | sudo bash` convenience form trusts the first HTTPS response from
GitHub and control of this repository. For a stricter first install, download
`install-a4diag.sh`, inspect it, and run the saved file; all later archive
contents are still authenticated by the public key embedded in that script.

## What the installer does

1. Requires root and a supported distribution (`/etc/os-release`).
2. Verifies the release `VERSION` lock and every `SHA256SUMS` digest (and the
   RSA/SHA-256 `MANIFEST.sig` when present).
3. Stages `/opt/a4diag/releases/<version>`, creates the venv, and installs
   the locked wheels with `--no-index --find-links <wheelhouse>` — no network
   is ever consulted.
4. Runs `a4diag self-check --offline` from the staged release.
5. Installs the hardened systemd units.
6. Atomically switches `/opt/a4diag/current` (temporary symlink + `mv -T`).
7. Starts `a4diag-core.service`; on failure, restores the previous `current`
   symlink and restarts the previous version.

## Never overwritten

`/etc/a4diag/config.yaml`, secrets, plugin pins, approvals, transactions,
audit log, and reports are never touched. The default configuration is created
only when absent, with read-only defaults (`global_mode: read_only`,
`targets: []`, `plugins: []`).

## After install

```bash
sudo a4diag init                # register targets (see docs/migration/v0.3-to-v0.4.md)
sudo a4diag self-check --offline
sudo systemctl status a4diag-core.service
```

## Rollback and uninstall

- Rollback is automatic on service-start failure. To roll back manually,
  switch the symlink and restart:

  ```bash
  sudo ln -s releases/0.4.0 /opt/a4diag/current.new
  sudo mv -T /opt/a4diag/current.new /opt/a4diag/current
  sudo systemctl daemon-reload && sudo systemctl restart a4diag-core.service
  ```

- Failed or previous releases are never deleted automatically; remove them
  explicitly once the running version is healthy.
- Uninstall:

  ```bash
  sudo systemctl disable --now a4diag-core.service
  sudo rm -rf /opt/a4diag/releases /opt/a4diag/current
  # optionally remove state (keep /etc/a4diag for audit) after an explicit decision
  ```
