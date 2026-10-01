from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

from a4diag.init_config import InitService
from a4diag.setup_wizard import (
    MAX_WATCHED_SERVICES,
    MODEL_PRESETS,
    SetupAnswers,
    SetupEnvironment,
    SetupError,
    build_init_request,
    list_models,
    normalize_service,
    parse_service_list,
    parse_unit_listing,
    run_setup,
    target_install_document,
    write_secret,
)

POSIX = pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
FINGERPRINT = "sha256:" + "a" * 64


class FakeProbe:
    def probe(self, _value: object) -> str:
        return FINGERPRINT


def answers(services: tuple[str, ...] = ("nginx.service",)) -> SetupAnswers:
    return SetupAnswers(preset="deepseek", base_url="https://api.deepseek.com/v1",
                        api_style="openai", model="deepseek-chat", api_key="sk-test",
                        services=services)


def test_service_names_are_normalized_and_protected_units_refused() -> None:
    assert normalize_service("nginx") == "nginx.service"
    assert normalize_service(" redis-server.service ") == "redis-server.service"
    for protected in ("sshd", "ssh.service", "NetworkManager", "cron", "a4diag-core"):
        with pytest.raises(SetupError):
            normalize_service(protected)
    for invalid in ("", "-x", "bad name", "../etc/passwd", "foo.timer"):
        with pytest.raises(SetupError):
            normalize_service(invalid)


def test_service_list_deduplicates_and_is_bounded() -> None:
    assert parse_service_list("nginx, nginx.service mysql") == ("nginx.service", "mysql.service")
    assert parse_service_list("") == ()
    too_many = ",".join(f"app{index}" for index in range(MAX_WATCHED_SERVICES + 1))
    with pytest.raises(SetupError):
        parse_service_list(too_many)


def test_unit_listing_suggests_failed_and_common_services_only() -> None:
    listing = (
        "nginx.service loaded active running nginx\n"
        "myapp.service loaded failed failed My app\n"
        "ssh.service loaded failed failed OpenBSD Secure Shell\n"
        "random.service loaded active running something\n"
        "ghost.service not-found inactive dead ghost\n"
        "docker.socket loaded active running docker socket\n"
    )
    assert parse_unit_listing(listing) == (["myapp.service"], ["nginx.service"])


def test_init_request_is_read_only_and_accepted_by_the_real_validator() -> None:
    request = build_init_request(answers(("nginx.service", "mysql.service")),
                                 secret_ref="file:model-api-key")
    assert request.global_mode == "read_only"
    target = request.targets[0]
    assert (target.id, target.mode.value, target.write_enabled) == ("local", "local", False)
    assert [source.kind for source in target.evidence_sources] == [
        "service_state", "service_logs", "service_state", "service_logs"]
    assert {check.resource for check in target.recovery_checks} == {"nginx.service", "mysql.service"}
    result = InitService(transport=FakeProbe(), model=FakeProbe()).validate(request)
    assert result.settings.global_mode == "read_only"
    assert result.settings.model.api_key_ref == "file:model-api-key"
    assert b"sk-test" not in result.config_bytes


def test_maximum_watched_services_fit_the_evidence_budget() -> None:
    services = tuple(f"app{index}.service" for index in range(MAX_WATCHED_SERVICES))
    request = build_init_request(answers(services), secret_ref=None)
    InitService(transport=FakeProbe(), model=FakeProbe()).validate(request)


def test_target_document_enables_exactly_the_watched_services() -> None:
    bootstrap = {"target_id": "local", "managed_resources": [], "confirm_managed_resources": "DISABLED"}
    document = target_install_document(bootstrap, ("nginx.service",))
    assert document["managed_resources"] == [{"capability": "services", "resource": "nginx.service"}]
    assert document["confirm_managed_resources"] == "ENABLE"
    assert target_install_document(bootstrap, ())["confirm_managed_resources"] == "DISABLED"
    assert bootstrap["managed_resources"] == []


def test_model_listing_uses_provider_specific_endpoints() -> None:
    calls = []

    def http_get(url: str, headers: dict[str, str]) -> object:
        calls.append((url, headers))
        if url.endswith("/api/tags"):
            return {"models": [{"name": "qwen2.5:7b"}, {"name": "llama3"}]}
        return {"data": [{"id": "deepseek-chat"}, {"id": "deepseek-reasoner"}]}

    assert list_models(MODEL_PRESETS["deepseek"], "https://api.deepseek.com/v1/", "k", http_get) == [
        "deepseek-chat", "deepseek-reasoner"]
    assert calls[-1] == ("https://api.deepseek.com/v1/models", {"Authorization": "Bearer k"})
    assert list_models(MODEL_PRESETS["ollama"], "http://127.0.0.1:11434", None, http_get) == [
        "llama3", "qwen2.5:7b"]
    assert calls[-1] == ("http://127.0.0.1:11434/api/tags", {})


@POSIX
def test_secrets_are_written_private_and_reject_bad_values(tmp_path: Path) -> None:
    path = tmp_path / "secrets" / "model-api-key"
    write_secret(path, "  sk-abc  \n", None)
    assert path.read_text() == "sk-abc"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    for bad in ("", "a\nb", "x" * 5000):
        with pytest.raises(SetupError):
            write_secret(path, bad, None)
    assert path.read_text() == "sk-abc"


@POSIX
def test_setup_flow_installs_target_then_registers_read_only(tmp_path: Path) -> None:
    replies = iter(["1", "", ""])  # DeepSeek, default model, default services
    commands: list[list[str]] = []
    registered = []

    def run(command, **kwargs):
        commands.append(list(command))
        stdout = "nginx.service loaded active running nginx\n" if "list-units" in command else ""
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    release = tmp_path / "target-release"
    environment = SetupEnvironment(
        ask=lambda _prompt: next(replies),
        ask_secret=lambda _prompt: "sk-test",
        say=lambda _text: None,
        run=run,
        http_get=lambda _url, _headers: {"data": [{"id": "deepseek-chat"}]},
        init=registered.append,
        secret_root=tmp_path / "secrets",
        local_target_dir=tmp_path / "local-target",
        cache_root=tmp_path / "cache",
        dashboard_env=tmp_path / "dashboard.env",
        release_root=tmp_path / "controller",
    )
    assert run_setup(environment, target_release=release) == 0

    assert (tmp_path / "secrets" / "model-api-key").read_text() == "sk-test"
    document = json.loads((tmp_path / "local-target" / "target-install.json").read_text())
    assert document["allowed_source_cidrs"] == ["127.0.0.1/32"]
    assert document["managed_resources"] == [{"capability": "services", "resource": "nginx.service"}]
    assert (tmp_path / "secrets" / "targets" / "local" / "operation-ed25519.pem").is_file()
    install = next(command for command in commands if command[0] == "bash")
    assert install[1:] == [str(release / "tools" / "install_target_lib.sh"), "install", str(release),
                           str(tmp_path / "local-target" / "target-install.json")]
    request = registered[0]
    assert request.global_mode == "read_only"
    assert request.model.model == "deepseek-chat"
    assert request.model.api_key_ref == "file:model-api-key"
    assert not (tmp_path / "dashboard.env").exists()

    # Re-running keeps the existing key material and only rewrites the policy.
    replies = iter(["1", "", "mysql"])
    assert run_setup(environment, target_release=release) == 0
    document = json.loads((tmp_path / "local-target" / "target-install.json").read_text())
    assert document["managed_resources"] == [{"capability": "services", "resource": "mysql.service"}]
