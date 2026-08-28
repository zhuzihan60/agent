"""Generic v3 read-only MCP surface.

Every tool call must name a REGISTERED target id — never an IP address and
never a fallback to the first configured target — and a REGISTERED capability
operation from the pinned plugin registry. Evidence is collected through the
runtime's collector port (verify_identity, acquire_read_view, collect) and
redacted before it leaves the process. Nothing is ever executed or written.
"""

from __future__ import annotations

from mcp.server import MCPServer

from .plugin_registry import PluginRegistry, PluginRegistryError
from .redaction import redact
from .runtime import Runtime


def build_server(
    *,
    runtime: Runtime,
    registry: PluginRegistry,
) -> MCPServer:
    if not isinstance(runtime, Runtime):
        raise TypeError("runtime must be Runtime")
    if not isinstance(registry, PluginRegistry):
        raise TypeError("registry must be PluginRegistry")

    server = MCPServer(
        "a4diag",
        version="0.4.1",
        instructions=(
            "Read-only diagnostics through registered capability plugins and "
            "registered targets. Never claim that a repair, restart, or "
            "configuration change was performed."
        ),
        log_level="ERROR",
    )

    def invoke(target: str, capability: str, action: str) -> dict[str, object]:
        if not isinstance(target, str) or target not in runtime.registered_target_ids:
            raise ValueError("POLICY_DENIED: target is not a registered target id")
        if (
            not isinstance(capability, str)
            or not capability
            or not isinstance(action, str)
            or not action
        ):
            raise ValueError("POLICY_DENIED: capability.action is required")
        try:
            registry.require_operation(capability, action)
        except PluginRegistryError as error:
            raise ValueError(f"POLICY_DENIED: {error}") from error
        target_config = runtime.target(target)
        fingerprint = runtime.probe_fingerprint(target)
        read_view = runtime.plugins.collector.acquire_read_view(
            target_config, fingerprint
        )
        evidence = runtime.plugins.collector.collect(target_config, read_view)
        return redact(
            {
                "target": target,
                "fingerprint": fingerprint,
                "capability": capability,
                "action": action,
                "evidence": evidence,
            }
        )

    @server.tool(
        description=(
            "Collect read-only diagnostic evidence for one registered target "
            "through one registered capability operation. The target must be a "
            "registered target id (an IP address never matches); "
            "capability.action must be registered in the pinned plugin "
            "registry. Nothing is executed or written."
        )
    )
    def diagnose(target: str, capability: str, action: str) -> dict[str, object]:
        return invoke(target, capability, action)

    return server


def main() -> None:
    # Production wiring (plugin sockets, RPC-backed ports, config path) lands
    # in Phase 4; refuse to start a half-wired read-only surface.
    raise RuntimeError(
        "a4diag.mcp_server requires a composed v3 Runtime; "
        "production wiring lands in Phase 4"
    )


if __name__ == "__main__":
    main()
