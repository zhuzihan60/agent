"""Tests for deterministic generic initialization.

Only fake model probes, fake transport probes, and temporary directories are
used; no real model API, SSH connection, target, or server is touched. The
written config must parse through the Phase 1 settings loader and stay
byte-for-byte unchanged when any probe or write fails.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Callable

import pytest
from pydantic import ValidationError

from a4diag.cli import main as cli_main
from a4diag.domain import TargetMode
from a4diag.init_config import (
    CapabilityInit,
    InitError,
    InitRequest,
    InitService,
    ModelInit,
    NotificationInit,
    TargetInit,
    interactive_init_request,
    load_init_request,
)
from a4diag.settings import load_settings


class FakeTransport:
    def __init__(self) -> None:
        self.probe_error: Exception | str | None = None
        self.probed: list[str] = []

    def probe(self, target: TargetInit) -> str:
        if self.probe_error is not None:
            if isinstance(self.probe_error, str):
                from a4diag.init_config import IdentityError

                raise IdentityError(self.probe_error)
            raise self.probe_error
        self.probed.append(target.id)
        return "sha256:" + "a" * 64


class FakeModel:
    def __init__(self) -> None:
        self.probe_error: Exception | str | None = None
        self.probed: list[str] = []

    def probe(self, config: ModelInit) -> None:
        if self.probe_error is not None:
            if isinstance(self.probe_error, str):
                from a4diag.init_config import ModelProbeError

                raise ModelProbeError(self.probe_error)
            raise self.probe_error
        self.probed.append(config.model)


def service(
    transport: FakeTransport | None = None,
    model: FakeModel | None = None,
) -> InitService:
    return InitService(transport=transport or FakeTransport(), model=model or FakeModel())


def empty_request() -> InitRequest:
    return InitRequest(model=None, targets=())


def local_request(
    *,
    target_id: str = "lab",
    write_enabled: bool = False,
    auto_execute_low: bool = False,
    capabilities: tuple[CapabilityInit, ...] = (),
) -> InitRequest:
    return InitRequest(
        model=None,
        targets=(
            TargetInit(
                id=target_id,
                mode=TargetMode.LOCAL,
                write_enabled=write_enabled,
                auto_execute_low=auto_execute_low,
                capabilities=capabilities,
            ),
        ),
        write_confirmation="ENABLE" if write_enabled else None,
    )


def ssh_request(
    *,
    target_id: str = "lab",
    write_enabled: bool = False,
    host: str = "192.0.2.10",
    user: str = "diag",
) -> InitRequest:
    return InitRequest(
        model=None,
        targets=(
            TargetInit(
                id=target_id,
                mode=TargetMode.SSH,
                host=host,
                port=2222,
                user=user,
                write_enabled=write_enabled,
            ),
        ),
        write_confirmation="ENABLE" if write_enabled else None,
    )


def test_noninteractive_write_requires_literal_confirmation() -> None:
    with pytest.raises(ValueError, match="write_confirmation=ENABLE"):
        InitRequest(
            targets=(
                TargetInit(id="lab", mode=TargetMode.LOCAL, write_enabled=True),
            )
        )


def model_request() -> InitRequest:
    return InitRequest(
        model=ModelInit(
            base_url="https://api.deepseek.com/v1",
            api_key_ref="model:api-key",
            model="deepseek-chat",
        ),
        targets=(),
    )


def write_json(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Defaults and registration
# ---------------------------------------------------------------------------


def test_init_without_target_writes_read_only_config(tmp_path: Path) -> None:
    service_instance = service()
    result = service_instance.write_atomic(empty_request(), tmp_path / "config.yaml")

    assert result.settings.targets == ()
    assert result.settings.global_mode == "read_only"
    assert service_instance.transport.probed == []
    loaded = load_settings(tmp_path / "config.yaml")
    assert loaded.targets == ()
    assert loaded.global_mode == "read_only"


def test_init_local_target_registration(tmp_path: Path) -> None:
    transport = FakeTransport()
    result = service(transport=transport).write_atomic(
        local_request(capabilities=(CapabilityInit(name="services", actions=("restart",), resources=("example.service",)),)),
        tmp_path / "config.yaml",
    )

    assert transport.probed == ["lab"]
    assert result.fingerprints == {"lab": "sha256:" + "a" * 64}
    assert len(result.settings.targets) == 1
    target = result.settings.targets[0]
    assert target.id == "lab"
    assert target.mode is TargetMode.LOCAL
    assert target.identity_ref == "target/lab"
    assert target.capabilities[0].name == "services"
    loaded = load_settings(tmp_path / "config.yaml")
    assert loaded.targets[0].id == "lab"


def test_init_ssh_target_registration(tmp_path: Path) -> None:
    transport = FakeTransport()
    result = service(transport=transport).write_atomic(
        ssh_request(),
        tmp_path / "config.yaml",
    )

    target = result.settings.targets[0]
    assert target.mode is TargetMode.SSH
    assert result.fingerprints == {"lab": "sha256:" + "a" * 64}
    loaded = load_settings(tmp_path / "config.yaml")
    assert loaded.targets[0].mode is TargetMode.SSH


def test_global_mode_read_write_when_target_writes_enabled(tmp_path: Path) -> None:
    result = service().write_atomic(local_request(write_enabled=True), tmp_path / "config.yaml")

    assert result.settings.global_mode == "read_write"
    assert result.settings.targets[0].write_enabled is True


def test_auto_execute_low_is_derived_from_targets(tmp_path: Path) -> None:
    result = service().write_atomic(
        local_request(auto_execute_low=True), tmp_path / "config.yaml"
    )

    assert result.settings.auto_execute_low is True


# ---------------------------------------------------------------------------
# Probe failures never touch the previous config
# ---------------------------------------------------------------------------


def test_ssh_identity_probe_failure_blocks_write() -> None:
    transport = FakeTransport()
    transport.probe_error = "host_key_mismatch"
    service_instance = service(transport=transport)

    with pytest.raises(InitError, match="host_key_mismatch"):
        service_instance.validate(ssh_request(write_enabled=True))


def test_model_probe_failure_blocks_write() -> None:
    model = FakeModel()
    model.probe_error = "structured_output_failed"
    service_instance = service(model=model)

    with pytest.raises(InitError, match="structured_output_failed"):
        service_instance.validate(model_request())


def test_probe_failure_leaves_previous_config_unchanged(tmp_path: Path) -> None:
    destination = tmp_path / "config.yaml"
    destination.write_bytes(b"original-config-bytes")
    transport = FakeTransport()
    transport.probe_error = "host_key_mismatch"
    service_instance = service(transport=transport)

    with pytest.raises(InitError, match="host_key_mismatch"):
        service_instance.write_atomic(ssh_request(), destination)

    assert destination.read_bytes() == b"original-config-bytes"


def test_write_failure_leaves_previous_config_unchanged(tmp_path: Path) -> None:
    destination = tmp_path / "config.yaml"
    destination.write_bytes(b"original-config-bytes")
    # The parent of the destination is a regular file, so no temp file can be
    # created next to it and the original stays untouched.
    blocker = tmp_path / "blocker"
    blocker.write_text("", encoding="utf-8")
    broken_destination = blocker / "config.yaml"
    service_instance = service()

    with pytest.raises(InitError, match="write_failed"):
        service_instance.write_atomic(empty_request(), broken_destination)

    assert destination.read_bytes() == b"original-config-bytes"


def test_write_is_atomic_and_leaves_no_temp_files(tmp_path: Path) -> None:
    service().write_atomic(local_request(), tmp_path / "config.yaml")

    names = [path.name for path in tmp_path.iterdir()]
    assert names == ["config.yaml"]


def test_written_config_is_mode_0600(tmp_path: Path) -> None:
    if os.name != "posix":
        pytest.skip("POSIX mode 0600 enforcement is a mandatory Linux Phase 4 gate")
    destination = tmp_path / "config.yaml"
    service().write_atomic(local_request(), destination)

    assert (destination.stat().st_mode & 0o777) == 0o600


# ---------------------------------------------------------------------------
# Strict request validation
# ---------------------------------------------------------------------------


def test_request_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        InitRequest.model_validate({"model": None, "targets": [], "surprise": True})


def test_request_rejects_ssh_without_host() -> None:
    with pytest.raises(ValidationError):
        TargetInit.model_validate(
            {"id": "lab", "mode": "ssh", "port": 22, "user": "diag"}
        )


def test_request_rejects_local_with_ssh_fields() -> None:
    with pytest.raises(ValidationError):
        TargetInit.model_validate(
            {"id": "lab", "mode": "local", "host": "192.0.2.10"}
        )


def test_request_rejects_unsafe_target_id() -> None:
    with pytest.raises(ValidationError):
        TargetInit.model_validate({"id": "not safe", "mode": "local"})


def test_request_rejects_duplicate_target_ids(tmp_path: Path) -> None:
    service_instance = service()
    duplicate = InitRequest(
        targets=(
            TargetInit(id="lab", mode=TargetMode.LOCAL),
            TargetInit(id="lab", mode=TargetMode.SSH, host="192.0.2.11", port=22, user="diag"),
        )
    )

    with pytest.raises(InitError, match="duplicate target"):
        service_instance.validate(duplicate)


def test_request_rejects_wildcard_capability_resource() -> None:
    with pytest.raises(ValidationError):
        CapabilityInit.model_validate(
            {"name": "files", "actions": ("replace",), "resources": ("/etc/*",)}
        )


def test_load_init_request_is_strict_json(tmp_path: Path) -> None:
    path = write_json(tmp_path / "request.json", {"model": None, "targets": []})

    request = load_init_request(path)

    assert request == InitRequest(model=None, targets=())


def test_load_init_request_rejects_duplicate_keys(tmp_path: Path) -> None:
    path = tmp_path / "request.json"
    path.write_text('{"model": null, "model": null}', encoding="utf-8")

    with pytest.raises(InitError, match="duplicate"):
        load_init_request(path)


def test_load_init_request_rejects_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "request.json"
    path.write_text("{not json", encoding="utf-8")

    with pytest.raises(InitError, match="invalid"):
        load_init_request(path)


def test_load_init_request_rejects_unknown_fields(tmp_path: Path) -> None:
    path = write_json(tmp_path / "request.json", {"targets": [], "surprise": 1})

    with pytest.raises(InitError, match="invalid"):
        load_init_request(path)


# ---------------------------------------------------------------------------
# Interactive request building
# ---------------------------------------------------------------------------


def answers(*values: str) -> Callable[[str], str]:
    iterator = iter(values)

    def prompt(_question: str) -> str:
        return next(iterator)

    return prompt


def test_interactive_without_enable_keeps_write_disabled() -> None:
    request = interactive_init_request(
        input_fn=answers(
            "no",  # configure model provider?
            "yes",  # add target?
            "lab",  # target id
            "local",  # mode
            "yes",  # add capability?
            "services",  # capability name
            "restart",  # actions
            "example.service",  # resources
            "no",  # add capability?
            "yes",  # enable writes?
            "no",  # type ENABLE ... -> not ENABLE
            "no",  # auto execute LOW?
            "no",  # add target?
            "no",  # add notification?
        )
    )

    assert len(request.targets) == 1
    assert request.targets[0].write_enabled is False


def test_interactive_literal_enable_allows_write() -> None:
    request = interactive_init_request(
        input_fn=answers(
            "no",
            "yes",
            "lab",
            "local",
            "no",  # add capability?
            "yes",  # enable writes?
            "ENABLE",  # literal confirmation
            "yes",  # auto execute LOW?
            "no",  # add target?
            "no",  # add notification?
        )
    )

    assert request.targets[0].write_enabled is True
    assert request.targets[0].auto_execute_low is True


def test_interactive_ssh_target() -> None:
    request = interactive_init_request(
        input_fn=answers(
            "yes",  # model
            "https://api.deepseek.com/v1",  # base_url
            "model:api-key",  # api_key_ref
            "deepseek-chat",  # model name
            "openai",  # style
            "30",  # timeout
            "yes",  # add target?
            "lab",  # id
            "ssh",  # mode
            "192.0.2.10",  # host
            "2222",  # port
            "diag",  # user
            "no",  # capability
            "no",  # write
            "no",  # LOW
            "no",  # target
            "no",  # notification
        )
    )

    assert request.model is not None
    assert request.model.base_url == "https://api.deepseek.com/v1"
    assert request.targets[0].mode is TargetMode.SSH
    assert request.targets[0].host == "192.0.2.10"


# ---------------------------------------------------------------------------
# No fixed environment literals
# ---------------------------------------------------------------------------


def test_no_fixed_environment_literals() -> None:
    sources = [
        Path("src/a4diag/init_config.py").read_text(encoding="utf-8"),
        Path("config/schemas/config-v3.json").read_text(encoding="utf-8"),
    ]
    combined = "\n".join(sources)
    assert "t_11" not in combined
    assert not re.search(r"(?<![0-9])(?:10|192\.168)(?:\.[0-9]{1,3}){3}(?![0-9])", combined)


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------


def run_cli(
    argv: list[str],
    monkeypatch: pytest.MonkeyPatch,
    service_instance: InitService | None = None,
) -> tuple[int, str, str]:
    import io

    effective = service_instance or InitService(
        transport=FakeTransport(), model=FakeModel()
    )
    monkeypatch.setattr("a4diag.cli._build_init_service", lambda: effective)
    stdout = io.StringIO()
    stderr = io.StringIO()
    monkeypatch.setattr("sys.stdout", stdout)
    monkeypatch.setattr("sys.stderr", stderr)
    code = cli_main(argv)
    return code, stdout.getvalue(), stderr.getvalue()


def test_cli_init_noninteractive_writes_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    request_path = write_json(
        tmp_path / "request.json",
        {"model": None, "targets": [{"id": "lab", "mode": "local"}]},
    )
    destination = tmp_path / "config.yaml"

    code, stdout, stderr = run_cli(
        ["init", "--input", str(request_path), "--output", str(destination)],
        monkeypatch,
    )

    assert code == 0, stderr
    assert "read_only" in stdout
    loaded = load_settings(destination)
    assert loaded.targets[0].id == "lab"


def test_cli_init_invalid_request_exits_65(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    request_path = tmp_path / "request.json"
    request_path.write_text('{"targets": [], "surprise": 1}', encoding="utf-8")

    code, _stdout, stderr = run_cli(
        ["init", "--input", str(request_path), "--output", str(tmp_path / "config.yaml")],
        monkeypatch,
    )

    assert code == 65
    assert "invalid" in stderr


def test_cli_init_probe_failure_exits_65(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    request_path = write_json(
        tmp_path / "request.json",
        {
            "model": None,
            "targets": [{"id": "lab", "mode": "ssh", "host": "192.0.2.10", "port": 22, "user": "diag"}],
        },
    )
    service_instance = InitService(
        transport=FakeTransport(), model=FakeModel()
    )
    service_instance.transport.probe_error = "host_key_mismatch"

    code, _stdout, stderr = run_cli(
        ["init", "--input", str(request_path), "--output", str(tmp_path / "config.yaml")],
        monkeypatch,
        service_instance=service_instance,
    )

    assert code == 65
    assert "host_key_mismatch" in stderr
