"""Non-bypassable target-side resource policy."""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from a4diag.domain import Operation, normalize_resource

_SAFE_TARGET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+:-]{0,127}$")
_UNIT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@._-]{0,255}\.(service|socket|timer|target|mount|path)$")
_FINGERPRINT = re.compile(r"^sha256:[0-9a-f]{64}$")

_PROTECTED_PATHS = (
    "/etc/ssh", "/root/.ssh", "/etc/pam.d", "/etc/sudoers",
    "/etc/NetworkManager", "/etc/sysconfig/network-scripts", "/etc/resolv.conf",
    "/etc/hosts", "/etc/firewalld", "/etc/nftables.conf", "/usr/libexec/a4diag",
    "/etc/a4diag-target", "/var/lib/a4diag-target", "/etc/cron.d",
    "/var/spool/cron", "/proc/sys", "/etc/sysctl.conf", "/etc/selinux",
    "/etc/libvirt", "/var/lib/libvirt", "/usr/bin/qemu", "/usr/libexec/qemu",
)
_PROTECTED_UNITS = ("ssh", "sshd", "network", "networkmanager", "firewalld", "nftables", "libvirt", "cron", "crond", "a4diag-target")
_PROTECTED_PACKAGES = ("openssh", "sudo", "pam", "networkmanager", "firewalld", "nftables", "libvirt", "qemu", "selinux", "kernel", "a4diag")


class PolicyDenied(ValueError):
    pass


def _at_or_below(path: str, root: str) -> bool:
    return path == root or path.startswith(root + "/")


class PackageGrant(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    name: str
    versions: tuple[str, ...]
    repositories: tuple[str, ...]

    @field_validator("name")
    @classmethod
    def package_name(cls, value: str) -> str:
        if not _SAFE_TOKEN.fullmatch(value) or any(mark in value for mark in "*?[]"):
            raise ValueError("package name must be exact")
        if value.casefold().startswith(_PROTECTED_PACKAGES):
            raise ValueError("protected package cannot be granted")
        return value

    @field_validator("versions", "repositories")
    @classmethod
    def exact_values(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if not values or len(values) != len(set(values)):
            raise ValueError("package grant values must be nonempty and unique")
        if any(not _SAFE_TOKEN.fullmatch(value) or any(mark in value for mark in "*?[]") for value in values):
            raise ValueError("package grant values must be exact")
        return values


class TargetPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    target_id: str
    target_fingerprint: str
    controller_key_fingerprint: str
    managed_roots: tuple[str, ...] = ()
    allowed_units: tuple[str, ...] = ()
    allowed_packages: tuple[PackageGrant, ...] = ()

    @field_validator("target_id")
    @classmethod
    def target(cls, value: str) -> str:
        if not _SAFE_TARGET.fullmatch(value):
            raise ValueError("invalid target id")
        return value

    @field_validator("target_fingerprint", "controller_key_fingerprint")
    @classmethod
    def fingerprint(cls, value: str) -> str:
        if not _FINGERPRINT.fullmatch(value):
            raise ValueError("invalid fingerprint")
        return value

    @field_validator("managed_roots")
    @classmethod
    def roots(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(normalize_resource(value, allow_descendant_pattern=False) for value in values)
        if len(normalized) != len(set(normalized)):
            raise ValueError("duplicate managed root")
        return normalized

    @field_validator("allowed_units")
    @classmethod
    def units(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("duplicate unit")
        for value in values:
            if not _UNIT.fullmatch(value) or value.casefold().startswith(_PROTECTED_UNITS):
                raise ValueError("unit is not grantable")
        return values

    @model_validator(mode="after")
    def unique_packages(self) -> TargetPolicy:
        names = [grant.name for grant in self.allowed_packages]
        if len(names) != len(set(names)):
            raise ValueError("duplicate package grant")
        return self

    def authorize(self, operation: Operation) -> None:
        if operation.capability == "files":
            path = operation.resource
            if path.startswith("/home/") and "/.ssh" in path:
                raise PolicyDenied("protected_resource")
            if any(_at_or_below(path, protected) for protected in _PROTECTED_PATHS):
                raise PolicyDenied("protected_resource")
            if not any(_at_or_below(path, root) for root in self.managed_roots):
                raise PolicyDenied("resource_not_granted")
            return
        if operation.capability == "services":
            if operation.resource not in self.allowed_units:
                raise PolicyDenied("unit_not_granted")
            return
        if operation.capability == "packages":
            grant = next((item for item in self.allowed_packages if item.name == operation.resource), None)
            if grant is None:
                raise PolicyDenied("package_not_granted")
            parameters = operation.parameters
            if parameters.get("name") != grant.name:
                raise PolicyDenied("package_name_mismatch")
            if parameters.get("version") not in grant.versions:
                raise PolicyDenied("package_version_not_granted")
            if parameters.get("repository") not in grant.repositories:
                raise PolicyDenied("package_repository_not_granted")
            return
        raise PolicyDenied("capability_not_granted")


__all__ = ["PackageGrant", "PolicyDenied", "TargetPolicy"]
