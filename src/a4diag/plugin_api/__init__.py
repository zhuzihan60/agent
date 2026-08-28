from __future__ import annotations

from importlib import import_module

from a4diag.plugin_api.manifest import (
    NetworkAccess,
    OperationContract,
    PermissionDeclaration,
    PluginManifest,
    PluginType,
    SecretReference,
    TargetCompatibility,
)


_PROTOCOL_EXPORTS = frozenset(
    {
        "MethodBinding",
        "MethodKind",
        "PluginHost",
        "RpcClientError",
        "RpcRequest",
        "RpcResponse",
        "RpcSuccess",
        "TicketedEffectParams",
        "VerifiedInvocation",
    }
)


def __getattr__(name: str) -> object:
    if name not in _PROTOCOL_EXPORTS:
        raise AttributeError(name)
    return getattr(import_module("a4diag.plugin_api.protocol"), name)

__all__ = [
    "MethodBinding",
    "MethodKind",
    "NetworkAccess",
    "OperationContract",
    "PermissionDeclaration",
    "PluginHost",
    "PluginManifest",
    "PluginType",
    "RpcClientError",
    "RpcRequest",
    "RpcResponse",
    "RpcSuccess",
    "SecretReference",
    "TargetCompatibility",
    "TicketedEffectParams",
    "VerifiedInvocation",
]
