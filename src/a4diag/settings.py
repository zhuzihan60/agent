from __future__ import annotations

from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from a4diag.domain import TargetConfig


def _validate_plugin_name(value: str) -> str:
    if not value.strip():
        raise ValueError("plugin name must not be blank")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("plugin name must not contain control characters")
    return value


class ModelSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    base_url: str
    model: str
    plugin: str = "model-openai-compatible"
    api_key_ref: str | None = None
    api_style: Literal["openai", "azure", "ollama"] = "openai"
    timeout_seconds: float = Field(default=30.0, ge=1.0, le=300.0)
    deployment: str | None = None
    api_version: str | None = None


class NotificationSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    channel: str
    config: dict[str, object] = Field(default_factory=dict)


class AlertmanagerSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    url: str
    poll_interval_seconds: int = Field(default=600, ge=1, le=3600)
    timeout_seconds: float = Field(default=5.0, ge=1.0, le=60.0)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("alertmanager url must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("alertmanager url must not contain credentials, query, or fragment")
        return value.rstrip("/")


class RetentionSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    normal_days: int = Field(default=1, ge=1, le=3650)
    abnormal_days: int = Field(default=14, ge=1, le=3650)


class AgentSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    global_mode: Literal["read_only", "read_write"] = "read_only"
    targets: tuple[TargetConfig, ...] = ()
    plugins: tuple[str, ...] = ()
    auto_execute_low: bool = False
    max_write_targets: int = Field(default=2, ge=1, le=32)
    model: ModelSettings | None = None
    notifications: tuple[NotificationSettings, ...] = ()
    alertmanager: AlertmanagerSettings | None = None
    retention: RetentionSettings = Field(default_factory=RetentionSettings)

    @field_validator("plugins")
    @classmethod
    def validate_plugins(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            _validate_plugin_name(value)
        if len(values) != len(set(values)):
            raise ValueError("duplicate plugin name")
        return values

    @model_validator(mode="after")
    def validate_targets(self) -> AgentSettings:
        ids = [target.id for target in self.targets]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate target id")
        return self


def load_settings(path: Path) -> AgentSettings:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as error:
        raise ValueError(f"invalid YAML settings: {error}") from error

    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ValueError("settings document must be a mapping")
    return AgentSettings.model_validate(data)
