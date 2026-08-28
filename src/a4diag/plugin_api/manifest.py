from __future__ import annotations

import re
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated

from pydantic import (
    BaseModel,
    ConfigDict,
    JsonValue,
    StringConstraints,
    field_validator,
    model_validator,
)

from a4diag.domain import Risk


_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_SAFE_OPERATION_NAME = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}(?:\.[A-Za-z0-9][A-Za-z0-9_-]{0,63})?$"
)
_SAFE_ENTRYPOINT = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.:-]*$")
_SAFE_SCHEMA_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_API_VERSION = re.compile(r"^[0-9]+\.[0-9]+$")
_RISK_RANK = {Risk.LOW: 0, Risk.HIGH: 1}


class PluginType(StrEnum):
    MODEL = "model"
    TRANSPORT = "transport"
    CAPABILITY = "capability"
    NOTIFICATION = "notification"


class NetworkAccess(StrEnum):
    NONE = "none"
    TARGET_SSH = "target-ssh"
    MODEL_PROVIDER = "model-provider"
    NOTIFICATION_ENDPOINT = "notification-endpoint"
    SMTP_SERVER = "smtp-server"


PermissionDeclaration = Annotated[
    str,
    StringConstraints(
        pattern=r"^[a-z][a-z0-9_-]{0,31}:[a-z0-9][a-z0-9._/-]{0,127}$",
        max_length=160,
    ),
]
SecretReference = Annotated[
    str,
    StringConstraints(
        pattern=r"^[a-z][a-z0-9_-]{0,31}:[a-z0-9][a-z0-9_.-]{0,63}$",
        max_length=96,
    ),
]
TargetCompatibility = Annotated[
    str,
    StringConstraints(
        pattern=r"^[a-z][a-z0-9_-]{0,31}:[a-z0-9][a-z0-9._-]{0,31}$",
        max_length=64,
    ),
]


def parse_api_version(value: str) -> tuple[int, int]:
    if not isinstance(value, str) or not value.isascii() or not _API_VERSION.fullmatch(value):
        raise ValueError("API version must be an ASCII MAJOR.MINOR pair")
    major, minor = value.split(".")
    return int(major), int(minor)


def _contains_control_characters(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def _validate_name(value: str, label: str) -> str:
    if not isinstance(value, str) or not _SAFE_NAME.fullmatch(value):
        raise ValueError(f"{label} must be a safe plugin identifier")
    return value


class OperationContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    risk_floor: Risk
    reversible: bool
    supports_prepare: bool
    supports_verify: bool
    supports_reconcile: bool
    supports_undo: bool = False
    parameters_schema: dict[str, JsonValue]

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if not isinstance(value, str) or not _SAFE_OPERATION_NAME.fullmatch(value):
            raise ValueError("operation name must be a safe identifier or capability.action")
        return value


class PluginManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    plugin_type: PluginType
    version: str
    api_min: str
    api_max: str
    executable: str
    socket: str
    config_schema: str
    operations: tuple[OperationContract, ...]
    permissions: tuple[PermissionDeclaration, ...] = ()
    network_access: tuple[NetworkAccess, ...] = ()
    secret_refs: tuple[SecretReference, ...] = ()
    target_compatibility: tuple[TargetCompatibility, ...] = ()
    read_risk_floor: Risk = Risk.LOW
    write_risk_floor: Risk = Risk.HIGH

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return _validate_name(value, "plugin name")

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: str) -> str:
        if not isinstance(value, str) or not value or _contains_control_characters(value):
            raise ValueError("plugin version must be non-empty and contain no control characters")
        return value

    @field_validator("api_min", "api_max")
    @classmethod
    def validate_api_version(cls, value: str) -> str:
        parse_api_version(value)
        return value

    @field_validator("executable")
    @classmethod
    def validate_executable(cls, value: str) -> str:
        if (
            not isinstance(value, str)
            or not _SAFE_ENTRYPOINT.fullmatch(value)
            or ".." in value
            or _contains_control_characters(value)
        ):
            raise ValueError("executable must be a safe entrypoint string")
        return value

    @field_validator("socket")
    @classmethod
    def validate_socket(cls, value: str) -> str:
        if (
            not isinstance(value, str)
            or _contains_control_characters(value)
            or "\\" in value
            or not value.startswith("/")
        ):
            raise ValueError("socket must be an absolute Unix path")
        path = PurePosixPath(value)
        if len(path.parts) < 2 or any(part in {".", ".."} for part in path.parts):
            raise ValueError("socket must be an absolute Unix path without traversal")
        return value

    @field_validator("config_schema")
    @classmethod
    def validate_config_schema(cls, value: str) -> str:
        if (
            not isinstance(value, str)
            or not value
            or _contains_control_characters(value)
            or "\\" in value
            or ":" in value
            or value.startswith("/")
        ):
            raise ValueError("config_schema must be a safe relative path")
        raw_components = value.split("/")
        if any(not _SAFE_SCHEMA_COMPONENT.fullmatch(component) for component in raw_components):
            raise ValueError("config_schema must be a safe relative path")
        path = PurePosixPath(value)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise ValueError("config_schema must be a safe relative path")
        return value

    @field_validator(
        "permissions", "network_access", "secret_refs", "target_compatibility"
    )
    @classmethod
    def validate_security_declarations(
        cls, values: tuple[str, ...]
    ) -> tuple[str, ...]:
        for value in values:
            if (
                not isinstance(value, str)
                or not value.strip()
                or _contains_control_characters(value)
                or len(value) > 256
                or ".." in value
            ):
                raise ValueError(
                    "security declarations must be nonblank bounded text without control characters"
                )
        if len(values) != len(set(values)):
            raise ValueError("duplicate security declaration")
        return values

    @model_validator(mode="after")
    def validate_manifest(self) -> PluginManifest:
        if parse_api_version(self.api_min) > parse_api_version(self.api_max):
            raise ValueError("API version range is inverted")
        operation_names = [operation.name for operation in self.operations]
        if len(operation_names) != len(set(operation_names)):
            raise ValueError("duplicate operation name")
        if NetworkAccess.NONE in self.network_access and len(self.network_access) != 1:
            raise ValueError("network access none contradicts outbound declarations")
        if _RISK_RANK[self.write_risk_floor] < _RISK_RANK[self.read_risk_floor]:
            raise ValueError(
                "write risk floor must not be lower than the read risk floor"
            )
        return self
