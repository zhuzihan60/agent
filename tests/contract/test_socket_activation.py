from __future__ import annotations

import asyncio
import os
import socket

import pytest

from a4diag.plugin_api.protocol import PluginHost


@pytest.mark.skipif(os.name != "posix", reason="AF_UNIX activation gate requires POSIX")
def test_plugin_host_accepts_prebound_systemd_socket_without_unlinking(tmp_path) -> None:
    path = tmp_path / "plugin.sock"
    inherited = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    inherited.bind(str(path))
    inherited.listen(8)

    async def scenario() -> None:
        host = PluginHost({})
        server = await host.start_activated(inherited)
        server.close()
        await server.wait_closed()
        host.cleanup_socket()

    asyncio.run(scenario())
    assert path.exists()
