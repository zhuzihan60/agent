"""Select the strict pytest path set for a v0.4.2 validation suite."""

from __future__ import annotations

import sys


SUITES: dict[str, tuple[str, ...]] = {
    "core": ("tests/test_core_security_acceptance.py",),
    "catalog": (
        "tests/test_builtin_catalog.py",
        "tests/test_plugin_admin.py",
        "tests/test_plugin_instances.py",
        "tests/test_plugin_host_and_ports.py",
        "tests/test_systemd_units_v3.py",
        "tests/integration/test_installer.py",
        "tests/test_cli.py",
    ),
    "target-protocol": (
        "tests/test_target_protocol.py",
        "tests/test_target_bootstrap.py",
    ),
    "target-runtime": (
        "tests/target_runtime",
        "tests/integration/test_target_installer.py",
        "tests/test_release_build.py",
    ),
    "remote-routing": (
        "tests/test_plugin_ports_remote.py",
        "tests/contract/test_transport_plugins.py",
    ),
    "init": ("tests/test_init_transaction.py", "tests/test_init_config.py"),
    "e2e": ("tests/e2e",),
    "full": ("tests",),
}


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1 or args[0] not in SUITES:
        print("usage: select_v042_tests.py SUITE", file=sys.stderr)
        return 64
    for path in SUITES[args[0]]:
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
