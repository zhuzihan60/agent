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

_TARGET_PROTOCOL_EXPORTS = frozenset(
    {
        "SignedTargetRequest",
        "TargetLifecycle",
        "TargetProtocolError",
        "TargetRequest",
        "TargetSigner",
        "TargetVerifier",
    }
)


def __getattr__(name: str) -> object:
    if name in _PROTOCOL_EXPORTS:
        return getattr(import_module("a4diag.plugin_api.protocol"), name)
    if name in _TARGET_PROTOCOL_EXPORTS:
        return getattr(import_module("a4diag.plugin_api.target_protocol"), name)
    raise AttributeError(name)

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
    "SignedTargetRequest",
    "TargetLifecycle",
    "TargetProtocolError",
    "TargetRequest",
    "TargetSigner",
    "TargetVerifier",
    "TicketedEffectParams",
    "VerifiedInvocation",
]
