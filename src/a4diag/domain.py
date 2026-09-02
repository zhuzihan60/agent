from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from enum import StrEnum

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    ValidationError,
    field_validator,
    model_validator,
)


class Risk(StrEnum):
    LOW = "low"
    HIGH = "high"


class TargetMode(StrEnum):
    LOCAL = "local"
    SSH = "ssh"


_TARGET_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_ACTION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_JSON_MAX_DEPTH = 32
_JSON_VALUE_MAX_BYTES = 262_144
_CANONICAL_PLAN_MAX_BYTES = 1_048_576
CORE_HIGH_CAPABILITIES = frozenset(
    {"network", "firewall", "ssh", "virtualization", "script"}
)


class CanonicalPlanError(ValueError):
    """A plan cannot be represented by the bounded canonical JSON format."""


def _validate_text(value: str, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    value = unicodedata.normalize("NFC", value)
    if not value.strip():
        raise ValueError(f"{label} must not be blank")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"{label} must not contain control characters")
    return value


def _validate_action(value: str, label: str = "capability action") -> str:
    if not isinstance(value, str) or not _ACTION_PATTERN.fullmatch(value):
        raise ValueError(f"{label} must be a safe action name")
    return value


def _normalize_absolute_posix_path(value: str, label: str) -> str:
    if not value.startswith("/") or value.startswith("//"):
        raise ValueError(f"{label} must be an unambiguous absolute POSIX path")
    if value == "/" or value.endswith("/"):
        raise ValueError(f"{label} must not be a root-only or trailing-slash path")
    components = value.split("/")[1:]
    if any(component in {"", ".", ".."} for component in components):
        raise ValueError(f"{label} must not contain ambiguous path segments")
    return "/" + "/".join(components)


def normalize_resource(value: str, *, allow_descendant_pattern: bool) -> str:
    """Return an NFC resource after rejecting path ambiguity and unsafe globs."""

    value = _validate_text(value, "capability resource")
    if "\\" in value:
        raise ValueError("capability resource must not contain backslashes")

    descendant = value.endswith("/**")
    if descendant:
        if not allow_descendant_pattern:
            raise ValueError("operation resource must not contain wildcard patterns")
        base = value[:-3]
        if any(character in base for character in "*?["):
            raise ValueError("capability resource has an unsafe wildcard pattern")
        return f"{_normalize_absolute_posix_path(base, 'capability resource')}/**"

    if any(character in value for character in "*?["):
        raise ValueError("capability resource has an unsafe wildcard pattern")
    if value.startswith("/"):
        return _normalize_absolute_posix_path(value, "capability resource")

    components = value.split("/")
    if any(component in {"", ".", ".."} for component in components):
        raise ValueError("capability resource must not contain ambiguous path segments")
    return value


def _normalize_json_value(value: object, *, depth: int = 0) -> JsonValue:
    if depth > _JSON_MAX_DEPTH:
        raise ValueError(f"JSON nesting exceeds {_JSON_MAX_DEPTH} levels")
    if value is None or type(value) is bool or type(value) is int:
        return value
    if type(value) is str:
        return unicodedata.normalize("NFC", value)
    if type(value) is list:
        return [
            _normalize_json_value(item, depth=depth + 1)
            for item in value
        ]
    if type(value) is dict:
        normalized: dict[str, JsonValue] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise ValueError("JSON object keys must be strings")
            normalized_key = unicodedata.normalize("NFC", key)
            if normalized_key in normalized:
                raise ValueError("JSON object keys collide after NFC normalization")
            normalized[normalized_key] = _normalize_json_value(item, depth=depth + 1)
        return normalized
    raise ValueError(
        "JSON values must be null, boolean, integer, string, list, or object"
    )


def canonical_json_bytes(value: object, *, max_bytes: int = _JSON_VALUE_MAX_BYTES) -> bytes:
    try:
        normalized = _normalize_json_value(value)
        encoded = json.dumps(
            normalized,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise CanonicalPlanError(f"invalid canonical JSON: {error}") from error
    if len(encoded) > max_bytes:
        raise CanonicalPlanError(f"canonical JSON exceeds {max_bytes} bytes")
    return encoded


def _validate_json_object(value: object, label: str) -> dict[str, JsonValue]:
    if type(value) is not dict:
        raise ValueError(f"{label} must be a JSON object")
    normalized = _normalize_json_value(value)
    if not isinstance(normalized, dict):
        raise ValueError(f"{label} must be a JSON object")
    encoded = json.dumps(
        normalized,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(encoded) > _JSON_VALUE_MAX_BYTES:
        raise ValueError(f"{label} JSON exceeds {_JSON_VALUE_MAX_BYTES} bytes")
    return normalized


class CapabilityGrant(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    actions: tuple[str, ...] = ()
    resources: tuple[str, ...]

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return _validate_text(value, "capability name")

    @field_validator("actions")
    @classmethod
    def validate_actions(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(_validate_action(value) for value in values)
        if len(normalized) != len(set(normalized)):
            raise ValueError("duplicate capability action")
        return normalized

    @field_validator("resources")
    @classmethod
    def validate_resources(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(
            normalize_resource(value, allow_descendant_pattern=True) for value in values
        )
        if len(normalized) != len(set(normalized)):
            raise ValueError("duplicate capability resource")
        return normalized


class TargetConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    mode: TargetMode
    identity_ref: str
    identity_fingerprint: str | None = None
    transport: str | None = None
    host: str | None = None
    port: int | None = None
    user: str | None = None
    identity_file_ref: str | None = None
    known_hosts_ref: str | None = None
    operation_signing_key_ref: str | None = None
    host_key_sha256: str | None = None
    write_enabled: bool = False
    auto_execute_low: bool = False
    capabilities: tuple[CapabilityGrant, ...] = ()
    notification_required: bool = False

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if not _TARGET_ID_PATTERN.fullmatch(value):
            raise ValueError("id must match ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
        return value

    @field_validator("identity_fingerprint")
    @classmethod
    def validate_identity_fingerprint(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            raise ValueError("identity_fingerprint must be a sha256 fingerprint")
        return value

    @field_validator("host_key_sha256")
    @classmethod
    def validate_host_key_sha256(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("host_key_sha256 must be a lowercase SHA256 digest")
        return value

    @field_validator(
        "identity_file_ref", "known_hosts_ref", "operation_signing_key_ref"
    )
    @classmethod
    def validate_target_secret_ref(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(
            r"file:[A-Za-z0-9][A-Za-z0-9_./-]{0,255}", value
        ):
            raise ValueError("target secret reference must be a safe file reference")
        if value is not None and any(part in {"", ".", ".."} for part in value[5:].split("/")):
            raise ValueError("target secret reference contains an unsafe path")
        return value

    @model_validator(mode="after")
    def validate_target(self) -> TargetConfig:
        if self.identity_ref != f"target/{self.id}":
            raise ValueError("identity_ref must equal target/{id}")

        connection = (self.host, self.port, self.user)
        if self.mode is TargetMode.LOCAL and any(value is not None for value in connection):
            raise ValueError("local targets must not specify host, port, or user")
        if self.mode is TargetMode.SSH and any(value is not None for value in connection):
            if not all(value is not None for value in connection):
                raise ValueError("ssh connection requires host, port, and user")
        if self.port is not None and not 1 <= self.port <= 65535:
            raise ValueError("port must be between 1 and 65535")

        names = [capability.name for capability in self.capabilities]
        if len(names) != len(set(names)):
            raise ValueError("duplicate capability name")

        resources = [
            resource
            for capability in self.capabilities
            for resource in capability.resources
        ]
        if len(resources) != len(set(resources)):
            raise ValueError("duplicate capability resource")
        return self


class StepResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    ok: bool
    status: str
    data: dict[str, JsonValue] = Field(default_factory=dict)


class Operation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    capability: str
    action: str
    resource: str
    parameters: dict[str, JsonValue]
    model_risk: Risk
    verify: dict[str, JsonValue]
    undo: dict[str, JsonValue] | None
    timeout_seconds: int = Field(default=20, ge=1, le=120)
    output_limit_bytes: int = Field(default=262_144, ge=1, le=262_144)

    @field_validator("capability")
    @classmethod
    def validate_capability(cls, value: str) -> str:
        if not isinstance(value, str) or not _TARGET_ID_PATTERN.fullmatch(value):
            raise ValueError("capability must be a safe identifier")
        return value

    @field_validator("action")
    @classmethod
    def validate_action(cls, value: str) -> str:
        return _validate_action(value, "operation action")

    @field_validator("resource")
    @classmethod
    def validate_resource(cls, value: str) -> str:
        return normalize_resource(value, allow_descendant_pattern=False)

    @field_validator("parameters", "verify", mode="before")
    @classmethod
    def validate_required_json_objects(
        cls, value: object, info: object
    ) -> dict[str, JsonValue]:
        field_name = getattr(info, "field_name", "JSON field")
        return _validate_json_object(value, field_name)

    @field_validator("undo", mode="before")
    @classmethod
    def validate_optional_json_object(
        cls, value: object
    ) -> dict[str, JsonValue] | None:
        if value is None:
            return None
        return _validate_json_object(value, "undo")


class Plan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    target_id: str
    target_fingerprint: str
    operations: tuple[Operation, ...] = Field(max_length=20)

    @field_validator("target_id")
    @classmethod
    def validate_target_id(cls, value: str) -> str:
        if not isinstance(value, str) or not _TARGET_ID_PATTERN.fullmatch(value):
            raise ValueError("target_id must be a safe identifier")
        return value

    @field_validator("target_fingerprint")
    @classmethod
    def validate_target_fingerprint(cls, value: str) -> str:
        if not isinstance(value, str):
            raise ValueError("target_fingerprint must be a string")
        value = unicodedata.normalize("NFC", value)
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("target_fingerprint must not contain control characters")
        return value

    @model_validator(mode="after")
    def validate_operations(self) -> Plan:
        triples = [
            (operation.capability, operation.action, operation.resource)
            for operation in self.operations
        ]
        if len(triples) != len(set(triples)):
            raise ValueError("duplicate operation capability/action/resource triple")
        return self


def canonical_plan_bytes(plan: Plan) -> bytes:
    if not isinstance(plan, Plan):
        raise CanonicalPlanError("invalid plan: expected Plan")
    try:
        validated = Plan.model_validate(plan.model_dump(mode="python"))
        encoded = canonical_json_bytes(
            validated.model_dump(mode="json"),
            max_bytes=_CANONICAL_PLAN_MAX_BYTES,
        )
    except (ValidationError, CanonicalPlanError, ValueError, TypeError) as error:
        raise CanonicalPlanError(f"invalid plan: {error}") from error
    return encoded


def plan_digest(plan: Plan) -> str:
    return hashlib.sha256(canonical_plan_bytes(plan)).hexdigest()
