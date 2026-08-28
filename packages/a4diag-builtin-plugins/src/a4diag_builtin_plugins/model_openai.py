"""OpenAI-compatible model plugin: diagnose, plan, and critic as typed calls.

The plugin supports OpenAI, DeepSeek, vLLM (all OpenAI-style), Azure OpenAI,
and Ollama chat APIs. Provider responses are always untrusted: every call
validates the returned JSON against a strict ``extra="forbid"`` schema, so raw
``command``/``shell``/``script``/``argv`` fields and any unknown field are
rejected. The API key is never hardcoded or logged: the config holds only a
secret reference, resolved per call through an injected resolver and sent
exclusively in the request header.
"""

from __future__ import annotations

import json
import re
import unicodedata
from typing import Any, Literal, Protocol
from urllib.parse import urlparse

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    ValidationError,
    field_validator,
    model_validator,
)

from a4diag.domain import Risk, canonical_json_bytes
from a4diag.plugin_api.protocol import EmptyParams, MethodBinding, MethodKind

from a4diag_builtin_plugins.transport_common import (
    CapabilityProbeResult,
    DescribeResult,
    HealthResult,
    PLUGIN_TYPE,
)

API_VERSION = "1.0"
MAX_RESPONSE_BYTES = 1_048_576
MAX_USER_PAYLOAD_BYTES = 262_144
_VERSION = "0.4.0"
_SAFE_REF = re.compile(r"^[a-z][a-z0-9_-]{0,31}:[a-z0-9][a-z0-9_.-]{0,63}$")
_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SAFE_HEADER_NAME = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_FORBIDDEN_EXECUTION_KEYS = frozenset({"command", "shell", "script", "argv", "cmd", "exec"})
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0:0:0:0:0:0:0:1"})

SYSTEM_PROMPT = (
    "You are the diagnostic core of A4Diag. Respond with a single JSON object "
    "matching the requested schema exactly. Never invent command lines, shell "
    "fragments, scripts, or argv arrays; express intent only as typed "
    "capability/action/resource fields."
)


class ModelProtocolError(RuntimeError):
    """Stable typed provider failure that never contains credentials."""

    def __init__(self, reason: str, detail: str | None = None) -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(reason)

    def __str__(self) -> str:
        if self.reason == "unknown_field" and self.detail:
            return f"unknown field: {self.detail}"
        if self.detail:
            return f"{self.reason}: {self.detail}"
        return self.reason


class ModelConfig(BaseModel):
    """Strict immutable provider configuration; never holds the key value."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    base_url: str
    api_key_ref: str | None = None
    model: str
    api_style: Literal["openai", "azure", "ollama"] = "openai"
    timeout_seconds: float = Field(default=30.0, ge=1.0, le=300.0)
    deployment: str | None = None
    api_version: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        if not isinstance(value, str) or not value or len(value) > 2048:
            raise ValueError("base_url must be a bounded URL")
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("base_url must not contain control characters")
        parsed = urlparse(value)
        if not parsed.scheme or not parsed.hostname:
            raise ValueError("base_url must be an absolute URL with a host")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("base_url must not contain credentials")
        if parsed.query or parsed.fragment or parsed.params:
            raise ValueError("base_url must not contain query, fragment, or params")
        return value

    @field_validator("api_key_ref")
    @classmethod
    def validate_api_key_ref(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or not _SAFE_REF.fullmatch(value):
            raise ValueError("api_key_ref must be a safe secret reference")
        return value

    @field_validator("model")
    @classmethod
    def validate_model(cls, value: str) -> str:
        if not isinstance(value, str) or not value or len(value) > 128:
            raise ValueError("model must be a bounded nonblank name")
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("model must not contain control characters")
        return unicodedata.normalize("NFC", value)

    @field_validator("deployment", "api_version")
    @classmethod
    def validate_optional_token(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or not _SAFE_TOKEN.fullmatch(value):
            raise ValueError("deployment/api_version must be safe tokens")
        return value

    @field_validator("headers")
    @classmethod
    def validate_headers(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > 8:
            raise ValueError("headers must not exceed 8 entries")
        for name, header_value in value.items():
            if not isinstance(name, str) or not _SAFE_HEADER_NAME.fullmatch(name):
                raise ValueError("header name is unsafe")
            if name.lower() in {"authorization", "api-key", "content-type"}:
                raise ValueError("authorization headers must come from the secret resolver")
            if not isinstance(header_value, str) or len(header_value) > 512:
                raise ValueError("header value is unsafe")
            if any(ord(character) < 32 or ord(character) == 127 for character in header_value):
                raise ValueError("header value must not contain control characters")
        return value

    @model_validator(mode="after")
    def validate_style_fields(self) -> ModelConfig:
        if self.api_style == "azure":
            if not self.deployment or not self.api_version:
                raise ValueError("azure style requires deployment and api_version")
        else:
            if self.deployment is not None or self.api_version is not None:
                raise ValueError("deployment/api_version are only valid for azure style")
        parsed = urlparse(self.base_url)
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" and not (
            parsed.scheme == "http"
            and self.api_style == "ollama"
            and host in _LOOPBACK_HOSTS
        ):
            raise ValueError(
                "base_url must use https (or loopback http for ollama)"
            )
        return self


class HttpResult:
    __slots__ = ("status", "body")

    def __init__(self, status: int, body: str) -> None:
        self.status = status
        self.body = body


class HttpTransport(Protocol):
    def post(
        self,
        url: str,
        headers: dict[str, str],
        body: bytes,
        *,
        timeout_seconds: float,
    ) -> HttpResult: ...


class SecretResolver(Protocol):
    def resolve(self, ref: str) -> str: ...


def _reject_execution_keys(value: object, path: str = "parameters") -> None:
    if type(value) is dict:
        for key, item in value.items():
            if key in _FORBIDDEN_EXECUTION_KEYS:
                raise ModelProtocolError("unknown_field", f"{path}.{key}")
            _reject_execution_keys(item, f"{path}.{key}")
    elif type(value) is list:
        for index, item in enumerate(value):
            _reject_execution_keys(item, f"{path}[{index}]")


def _auth_headers(config: ModelConfig, secrets: SecretResolver) -> dict[str, str]:
    if config.api_key_ref is None:
        return {}
    key = secrets.resolve(config.api_key_ref)
    if not key:
        return {}
    if config.api_style == "azure":
        return {"api-key": key}
    return {"Authorization": f"Bearer {key}"}


def build_chat_request(
    config: ModelConfig,
    *,
    messages: list[dict[str, str]],
    json_mode: bool,
    max_tokens: int | None = None,
) -> tuple[str, dict[str, str], bytes]:
    """Build the fixed request shape for the configured provider style."""
    if not isinstance(config, ModelConfig):
        raise TypeError("config must be ModelConfig")
    base = config.base_url.rstrip("/")
    if config.api_style == "azure":
        url = (
            f"{base}/openai/deployments/{config.deployment}/chat/completions"
            f"?api-version={config.api_version}"
        )
        payload: dict[str, Any] = {"model": config.model, "messages": messages}
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
    elif config.api_style == "ollama":
        url = f"{base}/api/chat"
        payload = {"model": config.model, "messages": messages, "stream": False}
        if json_mode:
            payload["format"] = "json"
    else:
        url = f"{base}/chat/completions"
        payload = {"model": config.model, "messages": messages}
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
    if max_tokens is not None:
        payload["max_tokens"] = max_tokens
    headers = {"Content-Type": "application/json"}
    headers.update(config.headers)
    body = canonical_json_bytes(payload)
    return url, headers, body


class ProbeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    ok: bool
    capabilities: list[str] = Field(default_factory=list)


class DiagnosisResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    cause: str
    confidence: float = Field(ge=0.0, le=1.0)
    missing_evidence: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)


class OperationProposal(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    capability: str
    action: str
    resource: str
    parameters: dict[str, JsonValue] = Field(default_factory=dict)
    model_risk: Risk = Risk.HIGH
    verify: dict[str, JsonValue] = Field(default_factory=dict)
    undo: dict[str, JsonValue] | None = None
    timeout_seconds: int = Field(default=20, ge=1, le=120)
    output_limit_bytes: int = Field(default=262_144, ge=1, le=262_144)

    @field_validator("parameters", "verify", "undo")
    @classmethod
    def validate_parameters(
        cls, value: dict[str, JsonValue] | None
    ) -> dict[str, JsonValue] | None:
        if value is None:
            return None
        _reject_execution_keys(value)
        return value


class PlanProposalResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    reasoning: str = ""
    operations: list[OperationProposal] = Field(default_factory=list, max_length=20)


class CriticReviewResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    risk: Risk
    complete: bool
    issues: list[str] = Field(default_factory=list)
    verify_suggestions: list[str] = Field(default_factory=list)
    undo_suggestions: list[str] = Field(default_factory=list)


class ModelEvidenceParams(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence: dict[str, JsonValue]
    max_tokens: int = Field(default=1024, ge=64, le=16384)

    @field_validator("evidence")
    @classmethod
    def validate_evidence(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        try:
            canonical_json_bytes(value, max_bytes=MAX_USER_PAYLOAD_BYTES)
        except (ValueError, TypeError) as error:
            raise ValueError(f"evidence is not a bounded canonical JSON object: {error}") from error
        return value


class ModelCriticParams(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    plan: dict[str, JsonValue]
    evidence: dict[str, JsonValue] = Field(default_factory=dict)
    max_tokens: int = Field(default=1024, ge=64, le=16384)

    @field_validator("plan", "evidence")
    @classmethod
    def validate_json_objects(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        try:
            canonical_json_bytes(value, max_bytes=MAX_USER_PAYLOAD_BYTES)
        except (ValueError, TypeError) as error:
            raise ValueError(f"plan/evidence is not a bounded canonical JSON object: {error}") from error
        return value


class ModelPlugin:
    """Unticketed model provider: probe, diagnose, plan, and critic."""

    def __init__(
        self,
        *,
        http: HttpTransport,
        secrets: SecretResolver,
        config: ModelConfig,
        name: str = "model-openai-compatible",
        version: str = _VERSION,
    ) -> None:
        if not isinstance(config, ModelConfig):
            raise TypeError("config must be ModelConfig")
        self._http = http
        self._secrets = secrets
        self._config = config
        self._name = name
        self._version = version

    def health(self, params: EmptyParams) -> HealthResult:
        return HealthResult(ok=True)

    def describe(self, params: EmptyParams) -> DescribeResult:
        return DescribeResult(
            name=self._name,
            plugin_type=PLUGIN_TYPE,
            version=self._version,
            api_version=API_VERSION,
        )

    def capability_probe(self, params: EmptyParams | None = None) -> CapabilityProbeResult:
        try:
            self._complete(
                payload={"probe": "structured-output"},
                result_model=ProbeResponse,
                content_failure_reason="structured_output_failed",
                schema_failure_reason="structured_output_failed",
            )
        except ModelProtocolError as error:
            return CapabilityProbeResult(
                read_capable=True,
                write_capable=False,
                read_risk_floor=Risk.LOW,
                write_risk_floor=Risk.HIGH,
                reason=error.reason,
            )
        return CapabilityProbeResult(
            read_capable=True,
            write_capable=True,
            read_risk_floor=Risk.LOW,
            write_risk_floor=Risk.HIGH,
            reason=None,
        )

    def diagnose(self, params: ModelEvidenceParams) -> DiagnosisResult:
        return self._complete(
            payload={"task": "diagnose", "evidence": params.evidence},
            result_model=DiagnosisResult,
            max_tokens=params.max_tokens,
        )

    def plan(self, params: ModelEvidenceParams) -> PlanProposalResult:
        return self._complete(
            payload={"task": "plan", "evidence": params.evidence},
            result_model=PlanProposalResult,
            max_tokens=params.max_tokens,
        )

    def critic(self, params: ModelCriticParams) -> CriticReviewResult:
        return self._complete(
            payload={"task": "critic", "plan": params.plan, "evidence": params.evidence},
            result_model=CriticReviewResult,
            max_tokens=params.max_tokens,
        )

    # ------------------------------------------------------------------

    def _complete(
        self,
        *,
        payload: dict[str, Any],
        result_model: type[BaseModel],
        content_failure_reason: str = "invalid_json",
        schema_failure_reason: str = "schema_error",
        max_tokens: int | None = None,
    ) -> Any:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(payload, ensure_ascii=False, sort_keys=True)},
        ]
        url, headers, body = build_chat_request(
            self._config,
            messages=messages,
            json_mode=True,
            max_tokens=max_tokens,
        )
        if self._config.api_key_ref is not None:
            headers.update(_auth_headers(self._config, self._secrets))
        try:
            result = self._http.post(
                url,
                headers,
                body,
                timeout_seconds=float(self._config.timeout_seconds),
            )
        except ModelProtocolError:
            raise
        except Exception as error:
            raise ModelProtocolError("http_error", type(error).__name__) from error
        if len(result.body) > MAX_RESPONSE_BYTES:
            raise ModelProtocolError("response_too_large")
        if result.status != 200:
            raise ModelProtocolError("http_error")
        content = self._extract_content(result.body, self._config.api_style)
        if content is None:
            raise ModelProtocolError(content_failure_reason)
        try:
            parsed = json.loads(
                content,
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
            )
        except (ValueError, TypeError):
            raise ModelProtocolError(content_failure_reason) from None
        if type(parsed) is not dict:
            raise ModelProtocolError(content_failure_reason)
        try:
            return result_model.model_validate(parsed)
        except ValidationError as error:
            field = _first_unknown_field(error)
            if field is not None:
                raise ModelProtocolError("unknown_field", field) from error
            raise ModelProtocolError(schema_failure_reason) from error

    def _extract_content(self, body: str, api_style: str) -> str | None:
        try:
            response = json.loads(
                body,
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
            )
        except (ValueError, TypeError):
            return None
        if type(response) is not dict:
            return None
        if api_style == "ollama":
            message = response.get("message")
            if type(message) is not dict:
                return None
            content = message.get("content")
            return content if type(content) is str else None
        choices = response.get("choices")
        if type(choices) is not list or not choices:
            return None
        first = choices[0]
        if type(first) is not dict:
            return None
        if first.get("finish_reason") == "length":
            raise ModelProtocolError("truncated")
        message = first.get("message")
        if type(message) is not dict:
            return None
        content = message.get("content")
        return content if type(content) is str else None


def _first_unknown_field(error: BaseException) -> str | None:
    errors = getattr(error, "errors", None)
    if not callable(errors):
        return None
    for item in errors():
        if type(item) is dict and item.get("type") == "extra_forbidden":
            location = item.get("loc")
            if isinstance(location, (list, tuple)) and location:
                return ".".join(str(part) for part in location)
    return None


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON value is forbidden: {value}")


def build_model_bindings(
    plugin: ModelPlugin,
) -> dict[str, MethodBinding[Any, Any]]:
    """Register the fixed unticketed model surface with the shared host."""
    return {
        "health": MethodBinding(
            "health", EmptyParams, HealthResult, plugin.health, kind=MethodKind.READ
        ),
        "describe": MethodBinding(
            "describe",
            EmptyParams,
            DescribeResult,
            plugin.describe,
            kind=MethodKind.READ,
        ),
        "capability_probe": MethodBinding(
            "capability_probe",
            EmptyParams,
            CapabilityProbeResult,
            plugin.capability_probe,
            kind=MethodKind.READ,
        ),
        "diagnose": MethodBinding(
            "diagnose",
            ModelEvidenceParams,
            DiagnosisResult,
            plugin.diagnose,
            kind=MethodKind.MODEL,
        ),
        "plan": MethodBinding(
            "plan",
            ModelEvidenceParams,
            PlanProposalResult,
            plugin.plan,
            kind=MethodKind.MODEL,
        ),
        "critic": MethodBinding(
            "critic",
            ModelCriticParams,
            CriticReviewResult,
            plugin.critic,
            kind=MethodKind.MODEL,
        ),
    }


def main() -> None:
    """Wired by the plugin manifest loader in the build task."""

    raise SystemExit(
        "model-openai-compatible is started by the plugin supervisor with its manifest"
    )


__all__ = [
    "API_VERSION",
    "CriticReviewResult",
    "DiagnosisResult",
    "HttpResult",
    "HttpTransport",
    "MAX_RESPONSE_BYTES",
    "ModelConfig",
    "ModelCriticParams",
    "ModelEvidenceParams",
    "ModelPlugin",
    "ModelProtocolError",
    "OperationProposal",
    "PlanProposalResult",
    "ProbeResponse",
    "SecretResolver",
    "build_chat_request",
    "build_model_bindings",
    "main",
]
