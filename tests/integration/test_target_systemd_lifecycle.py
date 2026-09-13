"""Opt-in regression against real systemd; uses uniquely named temporary units.

Run as root on a disposable Linux host with A4DIAG_TEST_SYSTEMD=1.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import uuid

import pytest


ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.environ.get("A4DIAG_TEST_SYSTEMD") != "1",
    reason="requires opt-in disposable Linux systemd host as root",
)


def test_executor_socket_survives_service_restart_and_stop_start() -> None:
    assert os.geteuid() == 0
    name = "a4diag-lifecycle-" + uuid.uuid4().hex[:12]
    runtime = Path("/run") / name
    fixture = Path("/run") / (name + "-fixture")
    unit_dir = Path("/run/systemd/system")
    service_path = unit_dir / (name + ".service")
    socket_path = unit_dir / (name + ".socket")

    def systemctl(*args: str) -> None:
        result = subprocess.run(
            ["systemctl", *args], capture_output=True, text=True, timeout=30
        )
        assert result.returncode == 0, result.stdout + result.stderr

    def roundtrip() -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(10)
            client.connect(str(runtime / "executor.sock"))
            client.sendall(b"ping")
            assert client.recv(4) == b"ping"

    try:
        fixture.mkdir(mode=0o755)
        responder = fixture / "responder.py"
        responder.write_text(
            "import socket\n"
            "listener = socket.socket(fileno=3)\n"
            "while True:\n"
            "    connection, _ = listener.accept()\n"
            "    with connection:\n"
            "        connection.sendall(connection.recv(4))\n",
            encoding="utf-8",
        )
        service = (ROOT / "deploy/a4diag-target-executor.service").read_text("utf-8")
        service = service.replace("a4diag-target-executor.socket", name + ".socket")
        service = service.replace("Group=a4diag-target", "Group=root")
        service = service.replace(
            "ExecStart=/opt/a4diag-target/current/venv/bin/a4diag-target-executor",
            f"ExecStart={sys.executable} {responder}",
        )
        service = service.replace(
            "ReadOnlyPaths=/etc/a4diag-target /opt/a4diag-target/current",
            f"ReadOnlyPaths={fixture}",
        )
        service = service.replace(
            "ReadWritePaths=/run/a4diag-target /var/lib/a4diag-target/executor",
            f"ReadWritePaths={runtime}",
        )
        service = service.replace("RuntimeDirectory=a4diag-target", f"RuntimeDirectory={name}")
        service_path.write_text(service, encoding="utf-8")
        socket_unit = (ROOT / "deploy/a4diag-target-executor.socket").read_text("utf-8")
        socket_unit = socket_unit.replace("/run/a4diag-target/", f"{runtime}/")
        socket_unit = socket_unit.replace("SocketGroup=a4diag-target", "SocketGroup=root")
        socket_path.write_text(socket_unit, encoding="utf-8")
        systemctl("daemon-reload")
        systemctl("start", name + ".socket")
        roundtrip()
        systemctl("restart", name + ".service")
        roundtrip()
        systemctl("stop", name + ".service")
        # The socket stays active and must be able to reactivate the executor.
        roundtrip()
    finally:
        subprocess.run(
            ["systemctl", "stop", name + ".socket", name + ".service"],
            capture_output=True, timeout=30,
        )
        service_path.unlink(missing_ok=True)
        socket_path.unlink(missing_ok=True)
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True, timeout=30)
        for directory in (runtime, fixture):
            if directory.exists():
                shutil.rmtree(directory)
