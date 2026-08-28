"""Contract tests for the OpenAI-compatible model plugin.

Every provider interaction goes through an injected fake HTTP transport; no
live provider, network request, or real API key is ever used. The provider
response is always treated as untrusted: strict Pydantic schemas reject raw
command/script fields, unknown fields, truncation, and malformed JSON.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from a4diag.domain import Risk
from a4diag.plugin_api.manifest import PluginManifest, PluginType
from a4diag.plugin_api.protocol import MethodKind

from a4diag_builtin_plugins.model_openai import (
    HttpResult,
    ModelConfig,
    ModelCriticParams,
    ModelEvidenceParams,
    ModelPlugin,
    ModelProtocolError,
    build_model_bindings,
    build_chat_request,
)

MANIFEST_ROOT = (
    Path(__file__).resolve().parents[2]
    / "packages"
    / "a4diag-builtin-plugins"
    / "manifests"
)
SECRET_KEY = "super-secret-api-key-value"


class FakeSecrets:
    def resolve(self, ref: str) -> str:
        return SECRET_KEY


class FakeHttp:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self.status = 200
        self.error: Exception | None = None
        self.response: dict[str, Any] = {}

    def post(self, url: str, headers: dict[str, str], body: bytes, *, timeout_seconds: float) -> HttpResult:
        self.requests.append(
            {"url": url, "headers": headers, "body": body, "timeout": timeout_seconds}
        )
        if self.error is not None:
            raise self.error
        return HttpResult(status=self.status, body=json.dumps(self.response))


def provider_response(content: str, *, finish_reason: str = "stop") -> dict[str, Any]:
    return {"choices": [{"message": {"content": content}, "finish_reason": finish_reason}]}


def default_config(**updates: object) -> ModelConfig:
    values: dict[str, object] = {
        "base_url": "https://api.deepseek.com/v1",
        "api_key_ref": "model:api-key",
        "model": "deepseek-chat",
        "api_style": "openai",
        "timeout_seconds": 30.0,
    }
    values.update(updates)
    return ModelConfig.model_validate(values)


def model_plugin(
    http: FakeHttp | None = None,
    *,
    config: ModelConfig | None = None,
) -> ModelPlugin:
    return ModelPlugin(
        http=http or FakeHttp(),
        secrets=FakeSecrets(),
        config=config or default_config(),
    )


def valid_diagnosis() -> str:
    return json.dumps(
        {
            "cause": "example service stopped",
            "confidence": 0.9,
            "missing_evidence": ["journalctl"],
            "recommended_actions": ["services.start"],
        }
    )


def valid_plan() -> str:
    return json.dumps(
        {
            "reasoning": "restart the unit",
            "operations": [
                {
                    "capability": "services",
                    "action": "restart",
                    "resource": "example.service",
                    "parameters": {"unit": "example.service"},
                }
            ],
        }
    )


def valid_critic() -> str:
    return json.dumps(
        {
            "risk": "low",
            "complete": True,
            "issues": [],
            "verify_suggestions": ["ActiveState=active"],
            "undo_suggestions": ["services.stop"],
        }
    )


def evidence() -> dict[str, Any]:
    return {"target": "lab", "symptom": "service down", "os": {"id": "rocky", "version_id": "9"}}


def evidence_params(**updates: object) -> ModelEvidenceParams:
    values: dict[str, object] = {"evidence": evidence()}
    values.update(updates)
    return ModelEvidenceParams.model_validate(values)


def critic_params(plan: Any, **updates: object) -> ModelCriticParams:
    values: dict[str, object] = {"plan": plan.model_dump(mode="json"), "evidence": evidence()}
    values.update(updates)
    return ModelCriticParams.model_validate(values)


# ---------------------------------------------------------------------------
# Probe
# ---------------------------------------------------------------------------


def test_probe_failure_disables_write() -> None:
    http = FakeHttp()
    http.response = provider_response("not-json")
    plugin = model_plugin(http)

    result = plugin.capability_probe()

    assert result.write_capable is False
    assert result.reason == "structured_output_failed"
    assert len(http.requests) == 1


def test_probe_success_enables_write() -> None:
    http = FakeHttp()
    http.response = provider_response(json.dumps({"ok": True, "capabilities": ["structured"]}))
    plugin = model_plugin(http)

    result = plugin.capability_probe()

    assert result.write_capable is True
    assert result.reason is None


# ---------------------------------------------------------------------------
# Strict schemas reject raw execution fields
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("field", ["command", "shell", "script", "argv"])
def test_plan_rejects_raw_execution_fields(field: str) -> None:
    http = FakeHttp()
    http.response = provider_response(
        json.dumps({"reasoning": "x", "operations": [{"capability": "services", "action": "start", "resource": "u.service", "parameters": {}, field: "rm -rf /"}]})
    )
    plugin = model_plugin(http)

    with pytest.raises(ModelProtocolError, match="unknown field"):
        plugin.plan(evidence_params())


@pytest.mark.parametrize("field", ["command", "shell", "script", "argv", "cmd", "exec"])
def test_plan_rejects_execution_fields_nested_in_parameters(field: str) -> None:
    http = FakeHttp()
    http.response = provider_response(
        json.dumps({"reasoning": "x", "operations": [{"capability": "services", "action": "start", "resource": "u.service", "parameters": {field: "rm -rf /"}}]})
    )
    plugin = model_plugin(http)

    with pytest.raises(ModelProtocolError, match="unknown field"):
        plugin.plan(evidence_params())


def test_diagnose_rejects_unknown_fields() -> None:
    http = FakeHttp()
    http.response = provider_response(json.dumps({"cause": "x", "confidence": 0.5, "missing_evidence": [], "recommended_actions": [], "surprise": 1}))
    plugin = model_plugin(http)

    with pytest.raises(ModelProtocolError, match="unknown field"):
        plugin.diagnose(evidence_params())


# ---------------------------------------------------------------------------
# Separate calls
# ---------------------------------------------------------------------------


def test_diagnose_plan_critic_are_separate_calls() -> None:
    http = FakeHttp()
    plugin = model_plugin(http)
    http.response = provider_response(valid_diagnosis())
    plugin.diagnose(evidence_params())
    http.response = provider_response(valid_plan())
    plan = plugin.plan(evidence_params())
    http.response = provider_response(valid_critic())
    plugin.critic(critic_params(plan))

    assert len(http.requests) == 3
    payloads = [json.loads(request["body"]) for request in http.requests]
    # Each call sends a different user payload, never reusing another call's output.
    assert payloads[0]["messages"] != payloads[1]["messages"]
    assert payloads[1]["messages"] != payloads[2]["messages"]


def test_critic_reviews_plan_payload() -> None:
    http = FakeHttp()
    http.response = provider_response(valid_plan())
    plan = model_plugin(http).plan(evidence_params())
    http.response = provider_response(valid_critic())
    plugin = model_plugin(http)

    review = plugin.critic(critic_params(plan))

    assert review.risk is Risk.LOW
    assert review.complete is True
    body = json.loads(http.requests[1]["body"])
    user_content = body["messages"][1]["content"]
    assert '"capability": "services"' in user_content
    assert '"action": "restart"' in user_content
    assert "example.service" in user_content


# ---------------------------------------------------------------------------
# Provider request shapes
# ---------------------------------------------------------------------------


def test_deepseek_uses_openai_style_request() -> None:
    http = FakeHttp()
    http.response = provider_response(valid_diagnosis())
    plugin = model_plugin(http, config=default_config(base_url="https://api.deepseek.com/v1", model="deepseek-chat"))
    plugin.diagnose(evidence_params())

    request = http.requests[0]
    assert request["url"] == "https://api.deepseek.com/v1/chat/completions"
    assert request["headers"]["Authorization"] == f"Bearer {SECRET_KEY}"
    body = json.loads(request["body"])
    assert body["model"] == "deepseek-chat"
    assert body["response_format"] == {"type": "json_object"}


def test_openai_style_request() -> None:
    http = FakeHttp()
    http.response = provider_response(valid_diagnosis())
    plugin = model_plugin(http, config=default_config(base_url="https://api.openai.com/v1", model="gpt-4o"))
    plugin.diagnose(evidence_params())

    request = http.requests[0]
    assert request["url"] == "https://api.openai.com/v1/chat/completions"
    assert request["headers"]["Authorization"] == f"Bearer {SECRET_KEY}"


def test_azure_request_shape() -> None:
    config = default_config(
        base_url="https://example.azure.openai.com",
        api_style="azure",
        deployment="diag-deploy",
        api_version="2024-06-01",
        model="diag-model",
    )
    http = FakeHttp()
    http.response = provider_response(valid_plan())
    plugin = model_plugin(http, config=config)
    plugin.plan(evidence_params())

    request = http.requests[0]
    assert request["url"] == (
        "https://example.azure.openai.com/openai/deployments/diag-deploy/chat/completions"
        "?api-version=2024-06-01"
    )
    assert request["headers"]["api-key"] == SECRET_KEY
    assert "Authorization" not in request["headers"]
    assert json.loads(request["body"])["model"] == "diag-model"


def test_ollama_request_shape() -> None:
    http = FakeHttp()
    http.response = {"message": {"content": valid_diagnosis()}}
    plugin = model_plugin(
        http,
        config=default_config(base_url="http://127.0.0.1:11434", api_style="ollama", model="llama3", api_key_ref=None),
    )
    plugin.diagnose(evidence_params())

    request = http.requests[0]
    assert request["url"] == "http://127.0.0.1:11434/api/chat"
    assert "Authorization" not in request["headers"]
    body = json.loads(request["body"])
    assert body["model"] == "llama3"
    assert body["stream"] is False
    assert body["format"] == "json"


def test_vllm_request_shape() -> None:
    http = FakeHttp()
    http.response = provider_response(valid_diagnosis())
    plugin = model_plugin(
        http, config=default_config(base_url="https://vllm.example.local/v1", model="qwen2")
    )
    plugin.diagnose(evidence_params())

    assert http.requests[0]["url"] == "https://vllm.example.local/v1/chat/completions"


def test_build_chat_request_never_embeds_key_in_url() -> None:
    http = FakeHttp()
    http.response = provider_response(valid_diagnosis())
    plugin = model_plugin(http)
    plugin.diagnose(evidence_params())

    request = http.requests[0]
    assert SECRET_KEY not in request["url"]
    assert request["headers"]["Authorization"] == f"Bearer {SECRET_KEY}"


# ---------------------------------------------------------------------------
# Untrusted response handling
# ---------------------------------------------------------------------------


def test_invalid_json_from_provider_is_typed_failure() -> None:
    http = FakeHttp()
    http.response = provider_response("{not json")
    plugin = model_plugin(http)

    with pytest.raises(ModelProtocolError, match="invalid_json"):
        plugin.diagnose(evidence_params())


def test_truncated_response_is_typed_failure() -> None:
    http = FakeHttp()
    http.response = provider_response(valid_diagnosis(), finish_reason="length")
    plugin = model_plugin(http)

    with pytest.raises(ModelProtocolError, match="truncated"):
        plugin.diagnose(evidence_params())


def test_http_error_is_typed_failure() -> None:
    http = FakeHttp()
    http.status = 401
    http.response = {"error": {"message": "invalid key"}}
    plugin = model_plugin(http)

    with pytest.raises(ModelProtocolError, match="http_error"):
        plugin.diagnose(evidence_params())


def test_api_key_never_appears_in_errors_or_logs(caplog: pytest.LogCaptureFixture) -> None:
    http = FakeHttp()
    http.status = 500
    http.response = {}
    plugin = model_plugin(http)

    with pytest.raises(ModelProtocolError) as caught:
        plugin.diagnose(evidence_params())
    assert SECRET_KEY not in str(caught.value)

    with caplog.at_level(logging.DEBUG):
        with pytest.raises(ModelProtocolError):
            plugin.diagnose(evidence_params())
    assert SECRET_KEY not in caplog.text


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "base_url",
    ["http://api.example.com/v1", "https://user:pass@api.example.com/v1", "https://api.example.com/v1?x=1", "not-a-url"],
)
def test_config_rejects_insecure_or_credential_urls(base_url: str) -> None:
    with pytest.raises(ValidationError):
        default_config(base_url=base_url)


@pytest.mark.parametrize(
    "ref",
    ["", "Model:key", "model:", "model:../key", "model:key value"],
)
def test_config_rejects_unsafe_api_key_refs(ref: str) -> None:
    with pytest.raises(ValidationError):
        default_config(api_key_ref=ref)


# ---------------------------------------------------------------------------
# Host integration and manifest
# ---------------------------------------------------------------------------


def test_model_bindings_use_fixed_kinds() -> None:
    plugin = model_plugin()
    bindings = build_model_bindings(plugin)
    assert bindings["capability_probe"].kind is MethodKind.READ
    assert bindings["diagnose"].kind is MethodKind.MODEL
    assert bindings["plan"].kind is MethodKind.MODEL
    assert bindings["critic"].kind is MethodKind.MODEL
    assert all(binding.ticket_phase is None for binding in bindings.values())


def test_model_manifest_contract() -> None:
    manifest = PluginManifest.model_validate(
        json.loads((MANIFEST_ROOT / "model-openai-compatible.json").read_text(encoding="utf-8"))
    )
    assert manifest.plugin_type is PluginType.MODEL
    assert manifest.api_min == "1.0"
    assert manifest.api_max == "1.0"
    assert manifest.operations == ()
    assert manifest.network_access == ("model-provider",)
    assert manifest.secret_refs == ("model:api-key",)
    assert manifest.write_risk_floor is Risk.HIGH
    assert "linux:systemd" in manifest.target_compatibility
