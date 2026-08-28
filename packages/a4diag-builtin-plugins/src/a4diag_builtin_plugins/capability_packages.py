"""Packages capability plugin: exact install and remove operations.

Both operations are HIGH by default. The plugin requires exact package name
and version (wildcards and blank versions are rejected), selects dnf or
apt-get from the verified OS identity, and only ever builds fixed
noninteractive argv templates. Undo restores the recorded prior version only
when that exact artifact is still available; otherwise it fails closed and
never claims rollback success.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator

from a4diag_builtin_plugins.capability_common import (
    BaseCapabilityPlugin,
    CapabilityApplyParams,
    CapabilityPrepareParams,
    CapabilityReconcileParams,
    CapabilityUndoParams,
    CapabilityVerifyParams,
    CapabilityError,
    CommandOutcome,
    EffectResult,
    PrepareResult,
    ReconcileResult,
    ReconcileState,
    TransportAdapter,
    VerifyResult,
    marker_from,
)

_VERSION = "0.4.0"
_PACKAGE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._-]{0,127}$")
_PACKAGE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+~:_-]{0,127}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_WILDCARD_CHARACTERS = frozenset("*?[")
_DNF_FAMILY = frozenset({"rocky", "almalinux", "rhel", "fedora"})
_APT_FAMILY = frozenset({"ubuntu", "debian"})
_ACTIONS = frozenset({"install_exact", "remove_exact"})


class PackageMarker(BaseModel):
    """Bounded typed pre-state for one exact package operation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: Literal["install_exact", "remove_exact"]
    package_manager: Literal["dnf", "apt"]
    name: str
    version: str
    prior_installed: bool
    prior_version: str | None
    repository: str | None = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if not isinstance(value, str) or not _PACKAGE_NAME.fullmatch(value):
            raise CapabilityError("package_name_invalid")
        return value

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: str) -> str:
        if not isinstance(value, str) or not _PACKAGE_VERSION.fullmatch(value):
            raise CapabilityError("package_version_invalid")
        return value

    @field_validator("repository")
    @classmethod
    def validate_repository(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or not _REPOSITORY.fullmatch(value):
            raise CapabilityError("repository_invalid")
        return value


def rpm_query_argv(name: str) -> list[str]:
    return ["/usr/bin/rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", name]


def dpkg_query_argv(name: str) -> list[str]:
    return ["/usr/bin/dpkg-query", "-W", "-f=${Version}", name]


def dnf_install_argv(name: str, version: str, repository: str | None) -> list[str]:
    argv = ["/usr/bin/dnf", "-y", "install", f"{name}-{version}"]
    if repository is not None:
        argv.extend(["--disablerepo=*", f"--enablerepo={repository}"])
    return argv


def dnf_remove_argv(name: str) -> list[str]:
    return ["/usr/bin/dnf", "-y", "remove", name]


def apt_install_argv(name: str, version: str, repository: str | None) -> list[str]:
    argv = [
        "/usr/bin/apt-get",
        "install",
        "-y",
        "--no-install-recommends",
        f"{name}={version}",
    ]
    if repository is not None:
        argv.extend(["-o", f"Dir::Etc::sourcelist=sources.list.d/a4diag-{repository}.list"])
    return argv


def apt_remove_argv(name: str) -> list[str]:
    return ["/usr/bin/apt-get", "remove", "-y", name]


def dnf_available_argv(name: str, version: str) -> list[str]:
    return ["/usr/bin/dnf", "repoquery", "--available", "--quiet", f"{name}-{version}"]


def apt_policy_argv(name: str) -> list[str]:
    return ["/usr/bin/apt-cache", "policy", name]


class PackagesPlugin(BaseCapabilityPlugin):
    def __init__(self, *, transport: TransportAdapter) -> None:
        super().__init__(transport=transport, name="capability-packages", version=_VERSION, actions=_ACTIONS)

    async def prepare(
        self, params: CapabilityPrepareParams, invocation: object | None = None
    ) -> PrepareResult:
        action = params.operation.action
        self._require_action(action)
        name, version, repository = self._exact_package(params)
        manager = await self._package_manager()
        installed = await self._installed_version(name, manager, params)
        prior_installed = installed is not None
        if action == "remove_exact" and not prior_installed:
            raise CapabilityError("package_not_installed")
        marker = PackageMarker(
            action=action,
            package_manager=manager,
            name=name,
            version=version if action == "install_exact" else (installed or ""),
            prior_installed=prior_installed,
            prior_version=installed,
            repository=repository,
        )
        return PrepareResult(marker=marker.model_dump(mode="json"))

    async def apply(
        self, params: CapabilityApplyParams, invocation: object | None = None
    ) -> EffectResult:
        marker = self._marker(params)
        self._require_action(marker.action)
        if marker.action != params.operation.action:
            raise CapabilityError("marker_action_mismatch")
        argv = self._action_argv(marker)
        outcome = await self._run(argv, params)
        if outcome.returncode != 0:
            return EffectResult(ok=False, changed=False, reason="command_failed")
        return EffectResult(ok=True, changed=True)

    async def undo(
        self, params: CapabilityUndoParams, invocation: object | None = None
    ) -> EffectResult:
        marker = self._marker(params)
        self._require_action(marker.action)
        if marker.action != params.operation.action:
            raise CapabilityError("marker_action_mismatch")
        if marker.action == "install_exact":
            if marker.prior_installed:
                assert marker.prior_version is not None
                if not await self._artifact_available(marker.name, marker.prior_version, marker.package_manager, params):
                    raise CapabilityError("prior_artifact_unavailable")
                argv = self._install_argv(marker.name, marker.prior_version, marker.repository, marker.package_manager)
            else:
                argv = self._remove_argv(marker.name, marker.package_manager)
        else:
            if not await self._artifact_available(marker.name, marker.version, marker.package_manager, params):
                raise CapabilityError("prior_artifact_unavailable")
            argv = self._install_argv(marker.name, marker.version, marker.repository, marker.package_manager)
        outcome = await self._run(argv, params)
        if outcome.returncode != 0:
            return EffectResult(ok=False, changed=False, reason="undo_failed")
        return EffectResult(ok=True, changed=True)

    async def verify(self, params: CapabilityVerifyParams) -> VerifyResult:
        marker = self._marker(params)
        self._require_action(marker.action)
        installed = await self._installed_version_or_none(marker.name, params)
        if marker.action == "install_exact":
            if installed != marker.version:
                return VerifyResult(ok=False, reason="version_mismatch")
        elif installed is not None:
            return VerifyResult(ok=False, reason="still_installed")
        return VerifyResult(ok=True)

    async def reconcile(self, params: CapabilityReconcileParams) -> ReconcileResult:
        marker = self._marker(params)
        self._require_action(marker.action)
        installed = await self._installed_version_or_none(marker.name, params)
        if marker.action == "install_exact":
            if installed is None:
                if not marker.prior_installed:
                    return ReconcileResult(state=ReconcileState.NOT_APPLIED)
                return ReconcileResult(state=ReconcileState.PARTIAL)
            if installed == marker.version:
                return ReconcileResult(state=ReconcileState.APPLIED)
            if installed == marker.prior_version:
                return ReconcileResult(state=ReconcileState.NOT_APPLIED)
            return ReconcileResult(state=ReconcileState.PARTIAL)
        if installed is None:
            return ReconcileResult(state=ReconcileState.APPLIED)
        if installed == marker.version:
            return ReconcileResult(state=ReconcileState.NOT_APPLIED)
        return ReconcileResult(state=ReconcileState.PARTIAL)

    # ------------------------------------------------------------------

    def _marker(self, params: object) -> PackageMarker:
        marker = getattr(params, "marker", None)
        if not isinstance(marker, dict):
            raise CapabilityError("invalid_marker")
        parsed = marker_from(PackageMarker, marker)  # type: ignore[arg-type]
        assert isinstance(parsed, PackageMarker)
        return parsed

    def _exact_package(self, params: CapabilityPrepareParams) -> tuple[str, str, str | None]:
        parameters = params.operation.parameters
        name = parameters.get("name")
        version = parameters.get("version")
        repository = parameters.get("repository")
        if any(key not in {"name", "version", "repository"} for key in parameters):
            raise CapabilityError("invalid_parameters")
        if (
            type(name) is not str
            or type(version) is not str
            or not version
            or _WILDCARD_CHARACTERS.intersection(name)
            or _WILDCARD_CHARACTERS.intersection(version)
        ):
            raise CapabilityError("exact_package_required")
        if not _PACKAGE_NAME.fullmatch(name):
            raise CapabilityError("package_name_invalid")
        if not _PACKAGE_VERSION.fullmatch(version):
            raise CapabilityError("package_version_invalid")
        if repository is not None and (type(repository) is not str or not _REPOSITORY.fullmatch(repository)):
            raise CapabilityError("repository_invalid")
        if params.operation.resource != name:
            raise CapabilityError("resource_mismatch")
        return name, version, repository

    async def _package_manager(self) -> str:
        os_id, _version = await self._transport.os_release()
        if os_id in _DNF_FAMILY:
            return "dnf"
        if os_id in _APT_FAMILY:
            return "apt"
        raise CapabilityError("unsupported_package_manager")

    async def _installed_version(self, name: str, manager: str, params: object) -> str | None:
        outcome = await self._run(self._query_argv(name, manager), params)
        if outcome.returncode == 0 and outcome.stdout.strip():
            return outcome.stdout.strip().splitlines()[-1].strip()
        return None

    async def _installed_version_or_none(self, name: str, params: object) -> str | None:
        try:
            return await self._installed_version(name, await self._package_manager(), params)
        except CapabilityError:
            return None

    def _query_argv(self, name: str, manager: str) -> list[str]:
        return rpm_query_argv(name) if manager == "dnf" else dpkg_query_argv(name)

    def _action_argv(self, marker: PackageMarker) -> list[str]:
        if marker.action == "install_exact":
            return self._install_argv(marker.name, marker.version, marker.repository, marker.package_manager)
        return self._remove_argv(marker.name, marker.package_manager)

    def _install_argv(self, name: str, version: str, repository: str | None, manager: str) -> list[str]:
        return dnf_install_argv(name, version, repository) if manager == "dnf" else apt_install_argv(name, version, repository)

    def _remove_argv(self, name: str, manager: str) -> list[str]:
        return dnf_remove_argv(name) if manager == "dnf" else apt_remove_argv(name)

    async def _artifact_available(self, name: str, version: str, manager: str, params: object) -> bool:
        if manager == "dnf":
            outcome = await self._run(dnf_available_argv(name, version), params)
            return outcome.returncode == 0 and bool(outcome.stdout.strip())
        outcome = await self._run(apt_policy_argv(name), params)
        if outcome.returncode != 0:
            return False
        return f"Candidate: {version}" in outcome.stdout

    async def _run(self, argv: list[str], params: object) -> CommandOutcome:
        return await self._transport.run_command(
            argv,
            timeout_seconds=self._timeout(params),
            output_limit_bytes=self._output_limit(params),
        )


def main() -> None:
    """Wired by the plugin manifest loader in the build task."""

    raise SystemExit(
        "capability-packages is started by the plugin supervisor with its manifest"
    )


__all__ = [
    "PackageMarker",
    "PackagesPlugin",
    "apt_install_argv",
    "apt_policy_argv",
    "apt_remove_argv",
    "dnf_available_argv",
    "dnf_install_argv",
    "dnf_remove_argv",
    "dpkg_query_argv",
    "main",
    "rpm_query_argv",
]
