"""Administrator-registered repair profiles shared by both trust boundaries."""

from __future__ import annotations

import hashlib
import hmac
import re
import unicodedata
from typing import TYPE_CHECKING, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    ValidationInfo,
    field_validator,
    model_validator,
)

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_SERVICE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@._-]{0,255}\.service$")
_PROTECTED_SERVICES = (
    "ssh",
    "sshd",
    "network",
    "networkmanager",
    "firewalld",
    "nftables",
    "libvirt",
    "cron",
    "crond",
    "a4diag-target",
)
_MAX_UTC_EPOCH = 253_402_300_799

if TYPE_CHECKING:
    from a4diag.domain import Operation, RepairBinding


class RepairAuthorizationError(ValueError):
    """Stable fail-closed profile authorization error."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _safe_id(value: str, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    normalized = unicodedata.normalize("NFC", value)
    if not _SAFE_ID.fullmatch(normalized):
        raise ValueError(f"{label} must be a safe identifier")
    return normalized


def _reject_normalized_key_collisions(value: object) -> object:
    if type(value) is not dict:
        return value
    keys: set[str] = set()
    for key in value:
        if type(key) is not str:
            raise ValueError("constraint keys must be strings")
        normalized = unicodedata.normalize("NFC", key)
        if normalized in keys:
            raise ValueError("constraint keys collide after NFC normalization")
        keys.add(normalized)
    return value


class ServicesConstraints(BaseModel):
    """Closed bounds understood by the currently registered systemd adapter."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    verification_window_seconds: int = Field(
        default=60, ge=60, le=600, strict=True
    )
    sample_interval_seconds: int = Field(default=5, ge=1, le=5, strict=True)


def validate_cache_root(value: str) -> str:
    if (not re.fullmatch(r'/(?:[A-Za-z0-9._+@:-]+/)*[A-Za-z0-9._+@:-]+', value)
            or len(value) > 1024 or len(value.split('/')) > 33
            or any(p in ('.', '..') for p in value.split('/'))
            or value in ('/var', '/var/cache', '/opt', '/srv', '/home', '/tmp')
            or value.split('/')[1] in ('etc','proc','sys','dev','usr','bin','sbin','boot','run')):
        raise ValueError('invalid_cache_root')
    protected=('/root','/var/lib/a4diag','/var/lib/a4diag-target','/var/lib/dpkg','/var/lib/systemd',
               '/opt/a4diag','/opt/a4diag-target')
    if any(value==p or value.startswith(p+'/') or p.startswith(value+'/') for p in protected):
        raise ValueError('protected_cache_root')
    return value


class DiskConstraints(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    writer_unit: str
    min_age_seconds: int = Field(ge=1, le=315360000, strict=True)
    max_files: int = Field(ge=1, le=1024, strict=True)
    max_bytes: int = Field(ge=1, le=1 << 40, strict=True)
    min_free_bytes: int = Field(ge=0, le=1 << 50, strict=True)
    min_free_inodes: int = Field(ge=0, le=1 << 40, strict=True)

    @field_validator('writer_unit')
    @classmethod
    def validate_writer(cls, value):
        if not _SERVICE.fullmatch(value) or value.casefold().startswith(_PROTECTED_SERVICES):
            raise ValueError('invalid_writer_unit')
        return value


class RepairProfile(BaseModel):
    """An exact, expiring grant selected by ID rather than created by a model."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    target_id: str
    capability: Literal["services", "disk"]
    resource: str
    actions: tuple[Literal["start", "restart", "stop", "cleanup"], ...] = Field(min_length=1)
    constraints: ServicesConstraints | DiskConstraints
    recovery_check_ids: tuple[str, ...] = Field(min_length=1, max_length=8)
    cooldown_seconds: int = Field(default=600, ge=1, strict=True)
    hourly_limit: int = Field(default=2, ge=1, strict=True)
    expires_at: int = Field(ge=0, le=_MAX_UTC_EPOCH, strict=True)
    standing_authorization: StrictBool = False

    @field_validator("id", "target_id")
    @classmethod
    def validate_ids(cls, value: str, info: ValidationInfo) -> str:
        return _safe_id(value, info.field_name)

    @field_validator("resource")
    @classmethod
    def validate_resource(cls, value: str, info: ValidationInfo) -> str:
        if not isinstance(value, str):
            raise ValueError("resource must be a string")
        normalized = unicodedata.normalize("NFC", value)
        if info.data.get('capability') == 'disk':
            return validate_cache_root(normalized)
        if not _SERVICE.fullmatch(normalized):
            raise ValueError("services resource must be an exact .service unit")
        if normalized.casefold().startswith(_PROTECTED_SERVICES):
            raise ValueError("protected service cannot be granted")
        return normalized

    @model_validator(mode='after')
    def check_capability_shape(self):
        if self.capability == 'disk':
            if self.actions != ('cleanup',) or not isinstance(self.constraints, DiskConstraints):
                raise ValueError('invalid_disk_profile')
        elif 'cleanup' in self.actions or not isinstance(self.constraints, ServicesConstraints):
            raise ValueError('invalid_service_profile')
        return self

    @field_validator("constraints", mode="before")
    @classmethod
    def validate_constraint_keys(cls, value: object) -> object:
        return _reject_normalized_key_collisions(value)

    @field_validator("actions")
    @classmethod
    def validate_actions(
        cls, values: tuple[Literal["start", "restart", "stop"], ...]
    ) -> tuple[Literal["start", "restart", "stop"], ...]:
        if len(values) != len(set(values)):
            raise ValueError("duplicate repair action")
        return values

    @field_validator("recovery_check_ids")
    @classmethod
    def validate_recovery_check_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(_safe_id(value, "recovery check id") for value in values)
        if len(normalized) != len(set(normalized)):
            raise ValueError("duplicate recovery check id")
        return normalized


def validate_repair_profiles(
    profiles: tuple[RepairProfile, ...],
    *,
    target_id: str,
    recovery_check_ids: set[str] | None,
) -> None:
    profile_ids = [profile.id for profile in profiles]
    if len(profile_ids) != len(set(profile_ids)):
        raise ValueError("duplicate repair profile id")
    for profile in profiles:
        if profile.target_id != target_id:
            raise ValueError("repair profile target_id must match target id")
        if recovery_check_ids is not None:
            missing = set(profile.recovery_check_ids) - recovery_check_ids
            if missing:
                raise ValueError("repair profile references an unknown recovery check")


def profile_digest(profile: RepairProfile) -> str:
    """Return the digest of the fully defaulted canonical profile document."""

    if not isinstance(profile, RepairProfile):
        raise TypeError("profile must be a RepairProfile")
    from a4diag.domain import canonical_json_bytes

    canonical = canonical_json_bytes(profile.model_dump(mode="json"))
    return hashlib.sha256(canonical).hexdigest()


def authorize_profile(
    profile: RepairProfile,
    operation: Operation,
    *,
    now: int,
    presented_digest: str,
) -> RepairBinding:
    """Bind one exact HIGH-risk operation to a current registered profile."""

    from a4diag.domain import Operation, RepairBinding, Risk

    if not isinstance(profile, RepairProfile):
        raise RepairAuthorizationError("invalid_profile")
    if not isinstance(operation, Operation):
        raise RepairAuthorizationError("invalid_operation")
    if type(now) is not int or now < 0:
        raise RepairAuthorizationError("invalid_clock")
    expected_digest = profile_digest(profile)
    if (
        not isinstance(presented_digest, str)
        or not hmac.compare_digest(expected_digest, presented_digest)
    ):
        raise RepairAuthorizationError("profile_digest_mismatch")
    if now >= profile.expires_at:
        raise RepairAuthorizationError("profile_expired")
    if operation.capability != profile.capability:
        raise RepairAuthorizationError("profile_capability_mismatch")
    if operation.resource != profile.resource:
        raise RepairAuthorizationError("profile_resource_mismatch")
    if operation.action not in profile.actions:
        raise RepairAuthorizationError("profile_action_not_allowed")
    if operation.model_risk is not Risk.HIGH:
        raise RepairAuthorizationError("risk_downgrade")
    if profile.capability == "services" and operation.parameters != {
        "unit": profile.resource
    }:
        raise RepairAuthorizationError("profile_parameters_mismatch")
    if profile.capability == 'disk' and operation.parameters != {}:
        raise RepairAuthorizationError('profile_parameters_mismatch')
    if operation.verify != {
        "recovery_check_ids": list(profile.recovery_check_ids)
    }:
        raise RepairAuthorizationError("recovery_checks_mismatch")
    return RepairBinding(
        profile_id=profile.id,
        profile_digest=expected_digest,
        preconditions_digest=None,
    )


__all__ = [
    "RepairAuthorizationError",
    "RepairProfile",
    "ServicesConstraints",
    "authorize_profile",
    "profile_digest",
    "validate_repair_profiles",
]
