from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Protocol

from .config import Config
from .dsh_runner import DshRunner
from .report import cleanup_expired


CONFIG_PATH = Path("/etc/a4diag/config.yaml")
REPORT_ROOT = Path("/var/lib/a4diag/reports")


def _config_path() -> Path:
    return Path(os.environ.get("A4DIAG_CONFIG", str(CONFIG_PATH)))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="a4diag")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("cleanup", help="remove expired diagnostic reports")
    subcommands.add_parser("verify-profile", help="validate restricted DSH profile")
    self_check_parser = subcommands.add_parser(
        "self-check", help="report version, mode and registered targets without network"
    )
    self_check_parser.add_argument(
        "--offline", action="store_true", help="assert the check requires no network"
    )
    serve_parser = subcommands.add_parser(
        "serve", help="run the runtime controller (systemd a4diag-core.service)"
    )
    serve_parser.add_argument(
        "--once",
        action="store_true",
        help="poll the alert source once and exit (no persistent loop)",
    )
    init_parser = subcommands.add_parser(
        "init", help="initialize generic agent configuration"
    )
    init_parser.add_argument(
        "--input",
        metavar="FILE",
        help="strict canonical JSON request file (non-interactive mode)",
    )
    init_parser.add_argument(
        "--output",
        metavar="FILE",
        help="config destination (default $A4DIAG_CONFIG or /etc/a4diag/config.yaml)",
    )
    plugin_parser = subcommands.add_parser(
        "plugin", help="administrator plugin lifecycle"
    )
    plugin_sub = plugin_parser.add_subparsers(dest="action", required=True)
    list_parser = plugin_sub.add_parser("list", help="list installed plugin pins")
    list_parser.add_argument("--json", action="store_true")
    verify_parser = plugin_sub.add_parser("verify", help="verify a plugin package")
    verify_parser.add_argument("package")
    verify_parser.add_argument("--json", action="store_true")
    install_parser = plugin_sub.add_parser("install", help="install a plugin package")
    install_parser.add_argument("package")
    install_parser.add_argument("--json", action="store_true")
    disable_parser = plugin_sub.add_parser("disable", help="disable an installed plugin")
    disable_parser.add_argument("name")
    disable_parser.add_argument("--json", action="store_true")
    approvals_parser = subcommands.add_parser(
        "approvals", help="digest-bound local CLI approval"
    )
    approvals_sub = approvals_parser.add_subparsers(dest="action", required=True)
    approvals_list = approvals_sub.add_parser("list", help="list approval records")
    approvals_list.add_argument("--json", action="store_true")
    approvals_show = approvals_sub.add_parser("show", help="show an approval in full")
    approvals_show.add_argument("transaction")
    approvals_show.add_argument("--json", action="store_true")
    approvals_approve = approvals_sub.add_parser("approve", help="approve a transaction")
    approvals_approve.add_argument("transaction")
    approvals_approve.add_argument("--digest", required=True)
    approvals_approve.add_argument("--non-interactive-approval-file", metavar="FILE")
    approvals_approve.add_argument("--json", action="store_true")
    approvals_reject = approvals_sub.add_parser("reject", help="reject a transaction")
    approvals_reject.add_argument("transaction")
    approvals_reject.add_argument("--reason", required=True)
    approvals_reject.add_argument("--non-interactive-approval-file", metavar="FILE")
    approvals_reject.add_argument("--json", action="store_true")
    resume_parser = subcommands.add_parser(
        "resume", help="resume one durable approved or recoverable transaction"
    )
    resume_parser.add_argument("transaction")
    resume_parser.add_argument("--json", action="store_true")
    return parser


def _build_plugin_admin() -> object:
    """Return the plugin admin; paths default to the production layout."""
    from .plugin_admin import Authorizer, PluginAdmin

    return PluginAdmin(
        authorizer=Authorizer(),
        service_manager=SystemdServiceManager(),
        plugin_root=Path("/opt/a4diag/plugins"),
        registry_path=Path("/etc/a4diag/plugin-registry.json"),
        signing_key=_signing_key(),
    )


def _signing_key() -> bytes:
    from .secrets import SecretError, SecretResolver

    try:
        return SecretResolver().resolve("file:release-signing.key").value.encode("utf-8")
    except SecretError as error:
        raise RuntimeError(f"plugin signing key unavailable: {error}") from error


class SystemdServiceManager:
    """Stops/start plugin instances through systemctl (production path)."""

    def stop(self, plugin_name: str) -> None:
        _run_systemctl("stop", f"a4diag-plugin@{plugin_name}.service")

    def start(self, plugin_name: str) -> None:
        _run_systemctl("start", f"a4diag-plugin@{plugin_name}.service")


def _run_systemctl(action: str, unit: str) -> None:
    import subprocess

    subprocess.run(
        ["/usr/bin/systemctl", action, unit],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
    )


def _cmd_approvals(args: argparse.Namespace) -> int:
    from .approval_cli import AdminRequired, ApprovalCliError, IdentityError
    from pathlib import Path as _Path

    cli = _build_approval_cli()
    try:
        if args.action == "list":
            print(json.dumps({"approvals": list(cli.list())}, sort_keys=True))
            return 0
        if args.action == "show":
            result = cli.show(args.transaction)
            print(json.dumps(result.redacted, sort_keys=True))
            return 0
        if args.action == "approve":
            receipt = cli.approve(
                args.transaction,
                args.digest,
                approval_file=(
                    _Path(args.non_interactive_approval_file)
                    if args.non_interactive_approval_file
                    else None
                ),
            )
            print(
                json.dumps(
                    {
                        "transaction_id": receipt.transaction_id,
                        "status": receipt.status,
                        "required_action": f"a4diag resume {receipt.transaction_id}",
                    },
                    sort_keys=True,
                )
            )
            return 0
        if args.action == "reject":
            receipt = cli.reject(
                args.transaction,
                args.reason,
                approval_file=(
                    _Path(args.non_interactive_approval_file)
                    if args.non_interactive_approval_file
                    else None
                ),
            )
            print(
                json.dumps(
                    {
                        "transaction_id": receipt.transaction_id,
                        "status": receipt.status,
                    },
                    sort_keys=True,
                )
            )
            return 0
        return 64
    except AdminRequired as error:
        print(str(error), file=sys.stderr)
        return 77
    except IdentityError as error:
        print(str(error), file=sys.stderr)
        return 65
    except ApprovalCliError as error:
        code = {
            "not_found": 64,
            "invalid_input": 64,
            "non_tty_rejected": 64,
            "identity_changed": 65,
            "identity_unavailable": 65,
            "digest_mismatch": 65,
            "expired": 65,
            "state_changed": 65,
            "signature_invalid": 65,
            "notification_not_delivered": 69,
        }.get(error.code, 64)
        print(str(error), file=sys.stderr)
        return code


def _build_approval_cli(runtime: object | None = None) -> object:
    """Return the approval CLI backed by a runtime when one is available.

    The runtime supplies the plan snapshot, the live identity probe, and the
    notification sink; until production plugin sockets are wired (Phase 4) the
    default wiring keeps the unavailable-plan barrier so approvals can never
    proceed against an empty plan source.
    """
    from .approval_cli import ApprovalCli, Authorizer, IdentityError, PlanSource
    from .secrets import SecretError, SecretResolver

    signing_key = _signing_key()
    if runtime is None:
        runtime = _production_runtime()
    from .runtime import RuntimeIdentityProbe, RuntimeNotifier, RuntimePlanSource

    approvals = runtime.approvals  # type: ignore[attr-defined]
    plans: PlanSource = RuntimePlanSource(runtime)  # type: ignore[assignment]
    identity: object = RuntimeIdentityProbe(runtime)
    notifier: object = RuntimeNotifier(runtime)

    return ApprovalCli(
        approvals=approvals,
        plans=plans,
        notifier=notifier,  # type: ignore[arg-type]
        identity=identity,  # type: ignore[arg-type]
        authorizer=Authorizer(),
        clock=lambda: int(time.time()),
        signing_key=signing_key,
    )


def _cmd_resume(args: argparse.Namespace) -> int:
    from .runtime import RuntimeFailure

    try:
        runtime = _production_runtime()
        result = runtime.resume(args.transaction)
        runtime.close()
    except (RuntimeFailure, RuntimeError) as error:
        print(f"a4diag resume: {error}", file=sys.stderr)
        return 65
    print(
        json.dumps(
            {
                "transaction_id": result.transaction_id,
                "status": result.status,
                "report": result.report,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


def _cmd_plugin(args: argparse.Namespace) -> int:
    from .plugin_admin import AdminRequired, PluginAdminError

    admin = _build_plugin_admin()
    try:
        if args.action == "list":
            pins = admin.list()  # type: ignore[attr-defined]
            payload = [
                {
                    "name": pin.name,
                    "version": pin.version,
                    "api_version": pin.api_version,
                    "artifact_path": pin.artifact_path,
                    "enabled": pin.enabled,
                }
                for pin in pins
            ]
            print(json.dumps({"plugins": payload}, sort_keys=True))
            return 0
        if args.action == "verify":
            result = admin.verify(Path(args.package))  # type: ignore[attr-defined]
            if not result.ok:
                print(result.reason or "verification_failed", file=sys.stderr)
                return 65
            print(
                json.dumps(
                    {
                        "name": result.manifest.name,
                        "version": result.manifest.version,
                        "ok": True,
                    },
                    sort_keys=True,
                )
            )
            return 0
        if args.action == "install":
            pin = admin.install(Path(args.package))  # type: ignore[attr-defined]
            print(
                json.dumps(
                    {
                        "name": pin.name,
                        "version": pin.version,
                        "artifact_path": pin.artifact_path,
                        "enabled": pin.enabled,
                    },
                    sort_keys=True,
                )
            )
            return 0
        if args.action == "disable":
            pin = admin.disable(args.name)  # type: ignore[attr-defined]
            print(
                json.dumps(
                    {
                        "name": pin.name,
                        "enabled": pin.enabled,
                    },
                    sort_keys=True,
                )
            )
            return 0
        return 64
    except AdminRequired as error:
        print(str(error), file=sys.stderr)
        return 77
    except PluginAdminError as error:
        code = {
            "verification_failed": 65,
            "unavailable_dependency": 69,
            "not_found": 64,
            "registry_corrupt": 64,
        }.get(error.code, 64)
        print(str(error), file=sys.stderr)
        return code


def _build_init_service() -> object:
    """Return plugin-backed, fail-closed production initialization probes."""
    from .init_config import InitService, ProductionModelProbe, ProductionTargetProbe

    return InitService(
        transport=ProductionTargetProbe(),
        model=ProductionModelProbe(),
    )


def _cmd_init(args: argparse.Namespace) -> int:
    from .init_config import (
        InitError,
        InitRequest,
        interactive_init_request,
        load_init_request,
    )

    service = _build_init_service()
    try:
        if args.input:
            request = load_init_request(Path(args.input))
        else:
            request = interactive_init_request(input_fn=input)
        assert isinstance(request, InitRequest)
        result = service.write_atomic(  # type: ignore[attr-defined]
            request, Path(args.output or _config_path())
        )
    except InitError as error:
        print(str(error), file=sys.stderr)
        return 65
    print(
        json.dumps(
            {
                "global_mode": result.settings.global_mode,
                "targets": [target.id for target in result.settings.targets],
                "fingerprints": dict(result.fingerprints),
                "auto_execute_low": result.settings.auto_execute_low,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


def _cmd_self_check(args: argparse.Namespace) -> int:
    from . import __version__
    from .settings import load_settings

    try:
        settings = load_settings(_config_path())
    except Exception as error:
        print(
            json.dumps(
                {"ok": False, "version": __version__, "error": f"{type(error).__name__}: {error}"},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 65
    payload = {
        "ok": True,
        "version": __version__,
        "global_mode": settings.global_mode,
        "auto_execute_low": settings.auto_execute_low,
        "targets": [target.id for target in settings.targets],
        "offline": bool(getattr(args, "offline", False)),
    }
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0


def run_serve_loop(
    runtime: object,
    stop_event: threading.Event,
    *,
    poller: object | None = None,
    poll_interval_seconds: float = 1.0,
) -> int:
    """Run the controller loop until the stop event is set.

    ``poller`` (a RuntimePoller with an alert source) is polled each
    iteration; without one the loop idles so a default read-only install
    stays healthy. Failures are reported on stderr and never crash the loop.
    """
    while not stop_event.is_set():
        if poller is not None:
            try:
                poller.poll_once()
            except Exception as error:
                print(
                    f"serve poll failed: {type(error).__name__}: {error}",
                    file=sys.stderr,
                    flush=True,
                )
        stop_event.wait(poll_interval_seconds)
    return 0


def _production_runtime() -> object:
    """Compose the production runtime from the installed release layout."""
    import json

    from .plugin_ports import build_rpc_plugin_ports
    from .plugin_registry import PluginPin
    from .runtime import build_runtime
    from .secrets import SecretError, SecretResolver

    registry_path = Path("/etc/a4diag/plugin-registry.json")
    manifest_root = Path("/opt/a4diag/plugins")
    try:
        raw_registry = json.loads(registry_path.read_text(encoding="utf-8"))
        if type(raw_registry) is not dict or type(raw_registry.get("plugins")) is not list:
            raise ValueError("registry must contain a plugins list")
        pins = tuple(PluginPin(**pin) for pin in raw_registry["plugins"])
    except (OSError, ValueError, TypeError) as error:
        raise RuntimeError(f"plugin registry unreadable: {error}") from error

    def key(ref: str) -> bytes:
        try:
            return SecretResolver().resolve(ref).value.encode("utf-8")
        except SecretError as error:
            raise RuntimeError(f"secret unavailable ({ref}): {error}") from error

    return build_runtime(
        _config_path(),
        audit_path=Path("/var/lib/a4diag/audit/audit.jsonl"),
        checkpoints_path=Path("/var/lib/a4diag/checkpoints/checkpoints.sqlite3"),
        transactions_path=Path("/var/lib/a4diag/transactions/transactions.sqlite3"),
        approvals_path=Path("/var/lib/a4diag/approvals/approvals.sqlite3"),
        registry_pins=pins,
        manifest_root=manifest_root,
        plugin_ports_factory=build_rpc_plugin_ports,
        ticket_key=key("file:core-ticket.key"),
        policy_key=key("file:core-policy.key"),
    )


def _cmd_serve(args: argparse.Namespace) -> int:
    from .poller import RuntimePoller
    from .runtime import RuntimeFailure

    try:
        runtime = _production_runtime()
    except (RuntimeFailure, RuntimeError) as error:
        print(f"a4diag serve: {error}", file=sys.stderr)
        return 65

    stop_event = threading.Event()

    def stop(_signum: int, _frame: object) -> None:
        stop_event.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    from .settings import load_settings

    settings = load_settings(_config_path())
    poller = None
    if settings.alertmanager is not None:
        from .alertmanager import AlertmanagerClient
        poller = RuntimePoller(
            runtime,
            alert_source=AlertmanagerClient(
                settings.alertmanager, runtime.registered_target_ids
            ),
            poll_interval_seconds=settings.alertmanager.poll_interval_seconds,
            state_path=Path("/var/lib/a4diag/poller.sqlite3"),
            report_root=REPORT_ROOT,
        )
    if args.once:
        if poller is not None:
            poller.poll_once()
        runtime.close()
        return 0
    return run_serve_loop(runtime, stop_event, poller=poller)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "verify-profile":
        DshRunner().verify_profile()
        print("restricted DSH profile: OK")
        return 0
    if args.command == "self-check":
        return _cmd_self_check(args)
    if args.command == "serve":
        return _cmd_serve(args)
    if args.command == "init":
        return _cmd_init(args)
    if args.command == "plugin":
        return _cmd_plugin(args)
    if args.command == "approvals":
        return _cmd_approvals(args)
    if args.command == "resume":
        return _cmd_resume(args)
    if args.command == "cleanup":
        from .settings import load_settings

        config = load_settings(_config_path())
        deleted = cleanup_expired(
            REPORT_ROOT,
            normal_days=config.retention.normal_days,
            abnormal_days=config.retention.abnormal_days,
        )
        print(json.dumps({"deleted": len(deleted)}, sort_keys=True))
        return 0
    return 64


if __name__ == "__main__":
    raise SystemExit(main())
