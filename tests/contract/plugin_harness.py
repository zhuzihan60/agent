from __future__ import annotations

import asyncio
import errno
import json
import socket
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest

from a4diag.plugin_api.protocol import MethodBinding, PluginHost


_AF_UNIX_UNSUPPORTED_ERRNOS = frozenset(
    value
    for value in (
        getattr(errno, "EAFNOSUPPORT", None),
        getattr(errno, "EPROTONOSUPPORT", None),
        getattr(errno, "ENOSYS", None),
    )
    if value is not None
)
_AF_UNIX_UNSUPPORTED_WINERRORS = frozenset({10043, 10047})


def is_af_unix_unavailable(error: BaseException, *, api: str) -> bool:
    """Recognize only evidence that the requested AF_UNIX API is unavailable."""

    if isinstance(error, NotImplementedError):
        return True
    if isinstance(error, AttributeError):
        owner_name, attribute = api.split(".", maxsplit=1)
        owner = {"asyncio": asyncio, "socket": socket}.get(owner_name)
        return owner is not None and not hasattr(owner, attribute)
    if isinstance(error, OSError):
        return (
            error.errno in _AF_UNIX_UNSUPPORTED_ERRNOS
            or getattr(error, "winerror", None) in _AF_UNIX_UNSUPPORTED_WINERRORS
        )
    return False


class PluginContractHarness:
    def __init__(self, host: PluginHost, socket_path: Path) -> None:
        self.host = host
        self.socket_path = socket_path

    async def call(
        self, method: str, params: Mapping[str, Any], ticket: str | None = None
    ) -> dict[str, Any]:
        request: dict[str, object] = {
            "jsonrpc": "2.0",
            "api_version": "1.0",
            "id": "contract-request",
            "method": method,
            "params": dict(params),
        }
        if ticket is not None:
            request["ticket"] = ticket
        return await self.raw(request)

    async def raw(self, request: object) -> dict[str, Any]:
        payload = json.dumps(request, separators=(",", ":")).encode() + b"\n"
        return await self.raw_bytes(payload)

    async def raw_bytes(self, payload: bytes) -> dict[str, Any]:
        reader, writer = await asyncio.open_unix_connection(str(self.socket_path))
        writer.write(payload)
        await writer.drain()
        if writer.can_write_eof():
            writer.write_eof()
        response = await asyncio.wait_for(reader.read(), timeout=2)
        writer.close()
        await writer.wait_closed()
        return json.loads(response)

    async def raw_chunks(self, chunks: list[bytes]) -> dict[str, Any]:
        reader, writer = await asyncio.open_unix_connection(str(self.socket_path))
        for chunk in chunks:
            writer.write(chunk)
            await writer.drain()
            await asyncio.sleep(0)
        if writer.can_write_eof():
            writer.write_eof()
        response = await asyncio.wait_for(reader.read(), timeout=2)
        writer.close()
        await writer.wait_closed()
        return json.loads(response)


@asynccontextmanager
async def running_harness(
    tmp_path: Path,
    bindings: Mapping[str, MethodBinding[Any, Any]],
    *,
    ticket_verifier: object | None = None,
) -> AsyncIterator[PluginContractHarness]:
    socket_path = tmp_path / "p.sock"
    host = PluginHost(bindings, ticket_verifier=ticket_verifier)
    try:
        server = await host.start(socket_path)
    except (AttributeError, NotImplementedError, OSError) as error:
        if is_af_unix_unavailable(error, api="asyncio.start_unix_server"):
            pytest.skip(
                f"runtime AF_UNIX asyncio setup unsupported; mandatory Linux Phase 4 gate: {type(error).__name__}"
            )
        raise
    try:
        yield PluginContractHarness(host, socket_path)
    finally:
        server.close()
        await server.wait_closed()
        host.cleanup_socket()


__all__ = ["PluginContractHarness", "is_af_unix_unavailable", "running_harness"]
