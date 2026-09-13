"""Contract and adversarial tests for target-owned Linux probe readers."""
import asyncio
import hashlib
import json
import os
from pathlib import Path

import pytest

from a4diag.linux_probes import LinuxProbe
from a4diag_builtin_plugins.transport_common import RunOutcome
from a4diag_target import linux_probes as readers
from a4diag_target import probe_network

secure_fs = pytest.mark.skipif(os.open not in os.supports_dir_fd, reason="requires Linux directory fd operations")


def run(root, kind, resource="host", runner=None, max_bytes=1048576):
    return asyncio.run(readers.run_probe(root, LinuxProbe(id="test", kind=kind, resource=resource, max_bytes=max_bytes), runner))


class Runner:
    def __init__(self, stdout="", stderr="", returncode=0, **kwargs):
        self.outcome = RunOutcome(started=True, timed_out=False, returncode=returncode, stdout=stdout, stderr=stderr, **kwargs)
        self.calls = []

    async def run(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        return self.outcome


@secure_fs
def test_file_attributes_missing_and_hash_limit(tmp_path):
    target = tmp_path / "config"
    target.write_bytes(b"hello")
    target.chmod(0o640)
    assert run(tmp_path, "file", "/config") == {"exists": True, "mode": 0o640, "size_bytes": 5, "sha256": hashlib.sha256(b"hello").hexdigest()}
    assert run(tmp_path, "file", "/config", max_bytes=4)["sha256"] == ""
    assert run(tmp_path, "file", "/missing") == {"exists": False, "mode": 0, "size_bytes": 0, "sha256": ""}


@secure_fs
def test_symlinks_and_fifo_fail_without_blocking(tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "real" / "config").write_text("secret")
    (tmp_path / "link").symlink_to(tmp_path / "real", target_is_directory=True)
    (tmp_path / "filelink").symlink_to(tmp_path / "real" / "config")
    os.mkfifo(tmp_path / "fifo")
    for path in ("/link/config", "/filelink", "/fifo", "/real"):
        with pytest.raises((ValueError, OSError)):
            run(tmp_path, "file", path)
    with pytest.raises(OSError):
        run(tmp_path, "filesystem", "/link")


@secure_fs
def test_filesystem_uses_open_directory(tmp_path):
    result = run(tmp_path, "filesystem", "/")
    expected = os.statvfs(tmp_path)
    assert result["total_bytes"] == expected.f_blocks * expected.f_frsize
    assert 0 <= result["used_percent"] <= 100
    assert all(type(value) is int for value in result.values())


@pytest.mark.parametrize("text", ["MemTotal: 100 kB\n", "MemTotal: 100 kB\nMemAvailable: 200 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n", "MemTotal: 100 MB\nMemAvailable: 20 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n"])
def test_memory_missing_or_malformed_fails(monkeypatch, text):
    monkeypatch.setattr(readers, "_read", lambda *args: text)
    with pytest.raises(ValueError):
        run(Path("/"), "memory")


@secure_fs
def test_memory_and_load_fixed_proc_files(tmp_path):
    (tmp_path / "proc").mkdir()
    (tmp_path / "proc/meminfo").write_text("MemTotal: 100 kB\nMemAvailable: 25 kB\nSwapTotal: 20 kB\nSwapFree: 10 kB\n")
    (tmp_path / "proc/loadavg").write_text("1.25 0.50 2.00 1/55 902\n")
    (tmp_path / "proc/stat").write_text("cpu 0 0 0 0\ncpu0 0 0 0 0\ncpu1 0 0 0 0\n")
    assert run(tmp_path, "memory") == {"total_bytes": 102400, "available_bytes": 25600, "used_percent": 75, "swap_total_bytes": 20480, "swap_free_bytes": 10240}
    assert run(tmp_path, "load") == {"load_1_milli": 1250, "load_5_milli": 500, "load_15_milli": 2000, "cpu_count": 2}
    with pytest.raises(ValueError, match="truncated"):
        run(tmp_path, "memory", max_bytes=2)


@pytest.mark.parametrize("distribution,stdout,exe", [("debian", "curl\tinstalled\t1.0\n", "/usr/bin/dpkg-query"), ("fedora", "curl\t1.0\n", "/usr/bin/rpm")])
def test_package_fixed_command(monkeypatch, distribution, stdout, exe):
    monkeypatch.setattr(readers, "_read", lambda *args: "ID=" + distribution)
    runner = Runner(stdout)
    assert run(Path("/"), "package", "curl", runner) == {"installed": True, "version": "1.0"}
    argv, kwargs = runner.calls[0]
    assert argv[0] == exe and argv[-2:] == ["--", "curl"]
    assert kwargs["payload"] == b""


@pytest.mark.parametrize("distribution,stdout,stderr", [("debian", "", "dpkg-query: no packages found matching curl\n"), ("fedora", "package curl is not installed\n", "")])
def test_package_absence_distinguished_from_database_error(monkeypatch, distribution, stdout, stderr):
    monkeypatch.setattr(readers, "_read", lambda *args: "ID=" + distribution)
    assert run(Path("/"), "package", "curl", Runner(stdout, stderr, 1)) == {"installed": False, "version": ""}
    with pytest.raises(ValueError):
        run(Path("/"), "package", "curl", Runner("", "database corrupt", 1))


@pytest.mark.parametrize("kwargs", [{"stdout_truncated": True}, {"stderr_truncated": True}, {"stderr": "warning"}, {"returncode": 1}])
def test_network_process_failure_fails_closed(kwargs):
    with pytest.raises(ValueError):
        run(Path("/"), "tcp", "tcp://localhost:80", Runner('{"reachable":true}', **kwargs))


@pytest.mark.parametrize("value", [{"resolved": True, "addresses": []}, {"resolved": True, "addresses": ["::0001"]}, {"resolved": True, "addresses": ["127.0.0.1"] * 17}, {"resolved": "true", "addresses": ["127.0.0.1"]}, {"resolved": True, "addresses": ["not-an-ip"]}])
def test_dns_output_validation(value):
    with pytest.raises(ValueError):
        run(Path("/"), "dns", "example.com", Runner(json.dumps(value)))


def test_network_fixed_argv_and_success():
    runner = Runner('{"resolved":true,"addresses":["127.0.0.1","::1"]}')
    assert run(Path("/"), "dns", "example.com", runner)["addresses"] == ["127.0.0.1", "::1"]
    assert runner.calls[0][0][1:] == ["-m", "a4diag_target.probe_network", "dns", "example.com"]


def test_network_timeout(monkeypatch):
    class SlowRunner:
        async def run(self, *args, **kwargs):
            await asyncio.Event().wait()
    monkeypatch.setattr(readers, "PROBE_TIMEOUT_SECONDS", 0.01)
    with pytest.raises(asyncio.TimeoutError):
        run(Path("/"), "tcp", "tcp://localhost:80", SlowRunner())


def test_helper_validates_and_canonicalizes(monkeypatch, capsys):
    assert probe_network.main(["dns", "--bad"]) == 2
    monkeypatch.setattr(probe_network.socket, "getaddrinfo", lambda *args, **kwargs: [(None, None, None, None, ("0:0:0:0:0:0:0:1", 0)), (None, None, None, None, ("::1", 0))])
    assert probe_network.main(["dns", "example.com"]) == 0
    assert json.loads(capsys.readouterr().out) == {"resolved": True, "addresses": ["::1"]}


def test_duplicate_network_fields_rejected():
    with pytest.raises(ValueError):
        run(Path("/"), "tcp", "tcp://localhost:80", Runner('{"reachable":false,"reachable":true}'))


@secure_fs
def test_os_release_vendor_fallback_does_not_follow_symlink(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "usr/lib").mkdir(parents=True)
    (tmp_path / "usr/lib/os-release").write_text("ID=debian\n")
    (tmp_path / "etc/os-release").symlink_to("/untrusted/os-release")
    assert run(tmp_path, "package", "curl", Runner("curl\tinstalled\t1.0\n"))["installed"] is True


@pytest.mark.parametrize("text", ["1.00 2.00", "nan 0.0 1.0 1/2 3", "-1.0 0.0 1.0 1/2 3", "0.0 0.0 0.0 bad 3"])
def test_malformed_load_fails(monkeypatch, text):
    monkeypatch.setattr(readers, "_read", lambda *args: text)
    with pytest.raises(ValueError):
        run(Path("/"), "load")


def test_helper_dns_caps_addresses_and_distinguishes_resolver_failure(monkeypatch, capsys):
    monkeypatch.setattr(probe_network.socket, "getaddrinfo", lambda *args, **kwargs: [(None, None, None, None, (f"192.0.2.{index}", 0)) for index in range(1, 40)])
    assert probe_network.main(["dns", "example.com"]) == 0
    assert len(json.loads(capsys.readouterr().out)["addresses"]) == 16

    def no_name(*args, **kwargs):
        raise probe_network.socket.gaierror(probe_network.socket.EAI_NONAME, "no such name")
    monkeypatch.setattr(probe_network.socket, "getaddrinfo", no_name)
    assert probe_network.main(["dns", "example.com"]) == 0
    assert json.loads(capsys.readouterr().out) == {"resolved": False, "addresses": []}

    def temporary_failure(*args, **kwargs):
        raise probe_network.socket.gaierror(probe_network.socket.EAI_AGAIN, "temporary failure")
    monkeypatch.setattr(probe_network.socket, "getaddrinfo", temporary_failure)
    assert probe_network.main(["dns", "example.com"]) == 1
    assert capsys.readouterr().out == ""


def test_helper_tcp_has_socket_timeout(monkeypatch, capsys):
    class Connection:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
    calls = []
    def connect(address, timeout):
        calls.append((address, timeout))
        return Connection()
    monkeypatch.setattr(probe_network.socket, "create_connection", connect)
    assert probe_network.main(["tcp", "tcp://localhost:80"]) == 0
    assert calls == [(("localhost", 80), 3.0)]
    assert json.loads(capsys.readouterr().out) == {"reachable": True}


@pytest.mark.parametrize("stdout", ["curl\tinstalled\t\n", "different\tinstalled\t1.0\n", "curl\thalf-installed\t1.0\n", "curl\tinstalled\t1.0\ncurl\tinstalled\t2.0\n"])
def test_malformed_package_status_fails(monkeypatch, stdout):
    monkeypatch.setattr(readers, "_read", lambda *args: "ID=debian")
    with pytest.raises(ValueError):
        run(Path("/"), "package", "curl", Runner(stdout))
