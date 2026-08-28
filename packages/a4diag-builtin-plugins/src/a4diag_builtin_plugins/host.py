"""Plugin supervisor entry point.

``a4diag-plugin --instance <name>`` loads the instance configuration
(``/etc/a4diag/plugins/<name>.yaml``), constructs the plugin behind its
manifest, and serves its socket over the bounded RPC protocol.  Instance
configuration is strict and contains secret references, never secret values.
"""

from __future__ import annotations

import argparse
import asyncio
import re
import os
import socket
import sys
from pathlib import Path
from typing import Any

import yaml

from a4diag.plugin_api.protocol import PluginHost
from a4diag.plugin_api.ticket import TicketVerifier
from a4diag.runtime import RuntimeFailure
from a4diag.transaction_store import TransactionStore

from a4diag_builtin_plugins.capability_common import (
    LocalFileAdapter,
    build_capability_bindings,
)
from a4diag_builtin_plugins.capability_files import FilesPlugin
from a4diag_builtin_plugins.capability_packages import PackagesPlugin
from a4diag_builtin_plugins.capability_services import ServicesPlugin
from a4diag_builtin_plugins.model_openai import (
    ModelConfig,
    ModelPlugin,
    build_model_bindings,
)
from a4diag_builtin_plugins.notification_cli import CliNotification
from a4diag_builtin_plugins.notification_common import build_notification_bindings
from a4diag_builtin_plugins.notification_flashduty import (
    FlashDutyConfig,
    FlashDutyNotification,
)
from a4diag_builtin_plugins.notification_smtp import SmtpConfig, SmtpNotification
from a4diag_builtin_plugins.notification_webhook import (
    WebhookConfig,
    WebhookNotification,
)
from a4diag_builtin_plugins.production_adapters import (
    HttpxTransport,
    ReusableSmtpClient,
    StringSecretResolver,
)
from a4diag_builtin_plugins.transport_common import build_transport_bindings
from a4diag_builtin_plugins.transport_local import LocalTransport
from a4diag_builtin_plugins.transport_ssh import SshTargetConfig, SshTransport

INSTANCE_CONFIG_DIR = "/etc/a4diag/plugins"
REPLAY_STORE_DIR = "/run/a4diag"
_SAFE_INSTANCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


def load_instance_config(path: Path) -> dict[str, object]:
    """Strictly parse one plugin instance configuration file."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as error:
        raise RuntimeFailure("instance_config_unreadable", str(path)) from error
    if not isinstance(raw, dict):
        raise RuntimeFailure("instance_config_invalid", "must be a mapping")
    unknown = set(raw) - {"manifest", "socket", "ticket_key_ref", "config"}
    if unknown:
        raise RuntimeFailure(
            "instance_config_invalid", f"unknown field: {sorted(unknown)[0]}"
        )
    manifest = raw.get("manifest")
    socket = raw.get("socket")
    ticket_key_ref = raw.get("ticket_key_ref")
    for name, value in (("manifest", manifest), ("socket", socket), ("ticket_key_ref", ticket_key_ref)):
        if not isinstance(value, str) or not value:
            raise RuntimeFailure("instance_config_invalid", f"{name} must be a nonblank string")
    if not _SAFE_INSTANCE.fullmatch(manifest):
        raise RuntimeFailure("instance_config_invalid", "manifest must be a safe identifier")
    config = raw.get("config", {})
    if not isinstance(config, dict):
        raise RuntimeFailure("instance_config_invalid", "config must be a mapping")
    return {
        "manifest": manifest,
        "socket": socket,
        "ticket_key_ref": ticket_key_ref,
        "config": config,
    }


def build_plugin(manifest_name: str, config: dict[str, object] | None = None) -> object:
    """Construct one strictly configured built-in plugin instance."""
    config = dict(config or {})
    if manifest_name == "capability-files":
        if config:
            raise RuntimeFailure("instance_config_invalid", "capability-files config")
        return FilesPlugin(transport=LocalFileAdapter())
    if manifest_name == "capability-services":
        if config:
            raise RuntimeFailure("instance_config_invalid", "capability-services config")
        return ServicesPlugin(transport=LocalFileAdapter())
    if manifest_name == "capability-packages":
        if config:
            raise RuntimeFailure("instance_config_invalid", "capability-packages config")
        return PackagesPlugin(transport=LocalFileAdapter())
    if manifest_name == "transport-local":
        if config:
            raise RuntimeFailure("instance_config_invalid", "transport-local config")
        return LocalTransport()
    if manifest_name == "transport-ssh":
        try:
            return SshTransport(config=SshTargetConfig.model_validate(config))
        except ValueError as error:
            raise RuntimeFailure("instance_config_invalid", "transport-ssh") from error
    secrets = StringSecretResolver()
    http = HttpxTransport()
    if manifest_name == "model-openai-compatible":
        try:
            model_config = ModelConfig.model_validate(config)
        except ValueError as error:
            raise RuntimeFailure("instance_config_invalid", manifest_name) from error
        return ModelPlugin(http=http, secrets=secrets, config=model_config)
    if manifest_name == "notification-cli":
        unknown = set(config) - {"event_dir"}
        event_dir = config.get("event_dir", "/var/lib/a4diag/approval-events")
        if unknown or not isinstance(event_dir, str) or not event_dir.startswith("/"):
            raise RuntimeFailure("instance_config_invalid", manifest_name)
        return CliNotification(event_dir=Path(event_dir))
    if manifest_name == "notification-flashduty":
        try:
            notification_config = FlashDutyConfig.model_validate(config)
        except ValueError as error:
            raise RuntimeFailure("instance_config_invalid", manifest_name) from error
        return FlashDutyNotification(
            http=http, secrets=secrets, config=notification_config
        )
    if manifest_name == "notification-webhook":
        try:
            webhook_config = WebhookConfig.model_validate(config)
        except ValueError as error:
            raise RuntimeFailure("instance_config_invalid", manifest_name) from error
        return WebhookNotification(http=http, secrets=secrets, config=webhook_config)
    if manifest_name == "notification-smtp":
        try:
            smtp_config = SmtpConfig.model_validate(config)
        except ValueError as error:
            raise RuntimeFailure("instance_config_invalid", manifest_name) from error
        client = ReusableSmtpClient(
            host=smtp_config.host,
            port=smtp_config.port,
            tls_mode=smtp_config.tls_mode,
            timeout_seconds=float(smtp_config.timeout_seconds),
        )
        return SmtpNotification(client=client, secrets=secrets, config=smtp_config)
    raise RuntimeFailure(
        "plugin_host_not_wired",
        f"plugin type for {manifest_name!r} has no host implementation yet",
    )


def build_bindings(manifest_name: str, plugin: object) -> dict[str, Any]:
    if manifest_name.startswith("capability-"):
        return build_capability_bindings(plugin)  # type: ignore[arg-type]
    if manifest_name.startswith("transport-"):
        return build_transport_bindings(plugin)  # type: ignore[arg-type]
    if manifest_name == "model-openai-compatible":
        return build_model_bindings(plugin)  # type: ignore[arg-type]
    if manifest_name.startswith("notification-"):
        return build_notification_bindings(plugin)  # type: ignore[arg-type]
    raise RuntimeFailure("plugin_host_not_wired", manifest_name)


def _resolve_ticket_key(ticket_key_ref: str) -> bytes:
    from a4diag.secrets import SecretError, SecretResolver

    try:
        value = SecretResolver().resolve(ticket_key_ref).value
    except SecretError as error:
        raise RuntimeFailure("ticket_key_unavailable", str(error)) from error
    key = value.encode("utf-8")
    if len(key) < 32:
        raise RuntimeFailure("ticket_key_unavailable", "key must be at least 32 bytes")
    return key


def inherited_systemd_socket() -> socket.socket | None:
    """Return systemd's single inherited socket, or None for manual startup."""
    if os.environ.get("LISTEN_PID") != str(os.getpid()):
        return None
    if os.environ.get("LISTEN_FDS") != "1":
        raise RuntimeFailure("socket_activation_invalid", "expected exactly one socket")
    try:
        inherited = socket.socket(fileno=3)
    except OSError as error:
        raise RuntimeFailure("socket_activation_invalid", "fd 3 unavailable") from error
    if inherited.family != socket.AF_UNIX or inherited.type & socket.SOCK_STREAM == 0:
        inherited.close()
        raise RuntimeFailure("socket_activation_invalid", "fd 3 is not AF_UNIX stream")
    return inherited


async def _serve_forever(host: PluginHost, socket_path: str) -> None:
    inherited = inherited_systemd_socket()
    server = (
        await host.start_activated(inherited)
        if inherited is not None
        else await host.start(socket_path)
    )
    try:
        await server.serve_forever()
    finally:
        host.cleanup_socket()


def serve_instance(instance_config: dict[str, object], *, instance_name: str | None = None) -> int:
    """Start one plugin instance and serve until interrupted."""
    import time

    manifest_name = str(instance_config["manifest"])
    plugin = build_plugin(manifest_name, instance_config.get("config"))  # type: ignore[arg-type]
    bindings = build_bindings(manifest_name, plugin)
    key = _resolve_ticket_key(str(instance_config["ticket_key_ref"]))
    replay_name = instance_name or manifest_name
    replay_store = TransactionStore(
        f"{REPLAY_STORE_DIR}/replay-{replay_name}.sqlite3"
    )
    verifier = TicketVerifier(
        key, replay_store=replay_store, clock=lambda: int(time.time())
    )
    host = PluginHost(bindings, ticket_verifier=verifier)
    asyncio.run(_serve_forever(host, str(instance_config["socket"])))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="a4diag-plugin")
    parser.add_argument("--instance", required=True)
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    if not _SAFE_INSTANCE.fullmatch(args.instance):
        print("a4diag-plugin: instance name is not a safe identifier", file=sys.stderr)
        return 64
    config_path = Path(INSTANCE_CONFIG_DIR) / f"{args.instance}.yaml"
    try:
        instance_config = load_instance_config(config_path)
        return serve_instance(instance_config, instance_name=args.instance)
    except RuntimeFailure as error:
        print(f"a4diag-plugin: {error}", file=sys.stderr)
        return 69


if __name__ == "__main__":
    raise SystemExit(main())
