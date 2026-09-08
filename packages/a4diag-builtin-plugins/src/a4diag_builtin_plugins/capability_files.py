"""Files capability plugin: replace managed files and set their mode.

Operations run through the narrow typed transport adapter only. Every path is
walked component by component with lstat, refusing symlinks and device files,
so a managed path can never escape into an attacker-chosen target. The marker
carries the exact prior bytes/mode/uid/gid plus SHA256, enabling precise undo
and honest reconciliation.
"""

from __future__ import annotations

import base64
import hashlib
import stat
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
    EffectResult,
    PrepareResult,
    ReconcileResult,
    ReconcileState,
    TransportAdapter,
    VerifyResult,
    marker_from,
    validate_sha256,
)
from a4diag_builtin_plugins.transport_common import validate_absolute_path

_VERSION = "0.4.2"
MAX_MANAGED_FILE_BYTES = 256 * 1024
_ACTIONS = frozenset({"replace_managed_file", "set_mode"})


class FileMarker(BaseModel):
    """Bounded typed pre-state for a managed file operation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: Literal["replace_managed_file", "set_mode"]
    path: str
    prior_content_b64: str = ""
    prior_content_sha256: str
    prior_mode: int
    prior_uid: int
    prior_gid: int
    new_content_sha256: str | None = None
    new_mode: int | None = None

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return validate_absolute_path(value, "managed path")

    @field_validator("prior_content_b64")
    @classmethod
    def validate_prior_content(cls, value: str) -> str:
        if len(value) > (MAX_MANAGED_FILE_BYTES * 4) // 3 + 8:
            raise ValueError("prior content exceeds the managed file bound")
        return value

    @field_validator("prior_content_sha256", "new_content_sha256")
    @classmethod
    def validate_digests(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return validate_sha256(value)

    @field_validator("prior_mode", "new_mode", "prior_uid", "prior_gid")
    @classmethod
    def validate_non_negative(cls, value: int | None) -> int | None:
        if value is None:
            return None
        if type(value) is not int or value < 0:
            raise ValueError("mode/uid/gid must be non-negative integers")
        return value


class FilesPlugin(BaseCapabilityPlugin):
    def __init__(self, *, transport: TransportAdapter) -> None:
        super().__init__(transport=transport, name="capability-files", version=_VERSION, actions=_ACTIONS)

    async def prepare(
        self, params: CapabilityPrepareParams, invocation: object | None = None
    ) -> PrepareResult:
        action = params.operation.action
        self._require_action(action)
        path = self._managed_path(params)
        new_content, new_mode = self._parameters(action, params)
        await self._reject_symlink_or_device(path)
        prior = await self._transport.lstat(path)
        if not stat.S_ISREG(prior.mode):
            raise CapabilityError("not_regular_file")
        try:
            prior_content = await self._transport.read_file(path, MAX_MANAGED_FILE_BYTES)
        except CapabilityError as exc:
            if exc.code == "read_limit_exceeded":
                raise CapabilityError("managed_file_too_large") from None
            raise
        if len(prior_content) > MAX_MANAGED_FILE_BYTES:
            raise CapabilityError("managed_file_too_large")
        marker = FileMarker(
            action=action,
            path=path,
            prior_content_b64=base64.b64encode(prior_content).decode("ascii"),
            prior_content_sha256=sha256(prior_content),
            prior_mode=prior.mode,
            prior_uid=prior.uid,
            prior_gid=prior.gid,
            new_content_sha256=sha256(new_content) if new_content is not None else None,
            new_mode=new_mode,
        )
        return PrepareResult(marker=marker.model_dump(mode="json"))

    async def apply(
        self, params: CapabilityApplyParams, invocation: object | None = None
    ) -> EffectResult:
        marker = self._marker(params)
        self._require_action(marker.action)
        if marker.action != params.operation.action:
            raise CapabilityError("marker_action_mismatch")
        if marker.action == "replace_managed_file":
            content = self._new_content(params.operation.parameters)
            await self._write_file(marker, content)
        else:
            assert marker.new_mode is not None
            await self._transport.set_mode(marker.path, marker.new_mode)
        return EffectResult(ok=True, changed=True)

    async def undo(
        self, params: CapabilityUndoParams, invocation: object | None = None
    ) -> EffectResult:
        marker = self._marker(params)
        self._require_action(marker.action)
        if marker.action != params.operation.action:
            raise CapabilityError("marker_action_mismatch")
        await self._write_file(
            marker, base64.b64decode(marker.prior_content_b64), undo=True
        )
        verified = await self._verify_restored(marker)
        if not verified.ok:
            return EffectResult(ok=False, changed=False, reason="undo_verification_failed")
        return EffectResult(ok=True, changed=True, reason=None)

    async def verify(self, params: CapabilityVerifyParams) -> VerifyResult:
        marker = self._marker(params)
        self._require_action(marker.action)
        try:
            current = await self._transport.read_file(marker.path, MAX_MANAGED_FILE_BYTES)
            info = await self._transport.lstat(marker.path)
        except CapabilityError:
            return VerifyResult(ok=False, reason="state_unavailable")
        if marker.action == "replace_managed_file":
            if sha256(current) != marker.new_content_sha256:
                return VerifyResult(ok=False, reason="content_mismatch")
        expected_mode = marker.new_mode if marker.new_mode is not None else marker.prior_mode
        if stat.S_IMODE(info.mode) != stat.S_IMODE(expected_mode):
            return VerifyResult(ok=False, reason="mode_mismatch")
        if info.uid != marker.prior_uid or info.gid != marker.prior_gid:
            return VerifyResult(ok=False, reason="ownership_mismatch")
        return VerifyResult(ok=True)

    async def verify_restored(self, params: CapabilityVerifyParams) -> VerifyResult:
        marker = self._marker(params)
        self._require_action(marker.action)
        return await self._verify_restored(marker)

    async def reconcile(self, params: CapabilityReconcileParams) -> ReconcileResult:
        marker = self._marker(params)
        self._require_action(marker.action)
        try:
            current = await self._transport.read_file(marker.path, MAX_MANAGED_FILE_BYTES)
            info = await self._transport.lstat(marker.path)
        except CapabilityError:
            return ReconcileResult(state=ReconcileState.UNKNOWN, reason="state_unavailable")
        prior_state = (
            marker.prior_content_sha256,
            stat.S_IMODE(marker.prior_mode),
            marker.prior_uid,
            marker.prior_gid,
        )
        expected_state = (
            marker.new_content_sha256
            if marker.action == "replace_managed_file"
            else marker.prior_content_sha256,
            stat.S_IMODE(
                marker.new_mode if marker.new_mode is not None else marker.prior_mode
            ),
            marker.prior_uid,
            marker.prior_gid,
        )
        current_state = (
            sha256(current),
            stat.S_IMODE(info.mode),
            info.uid,
            info.gid,
        )
        if current_state == expected_state:
            return ReconcileResult(state=ReconcileState.APPLIED)
        if current_state == prior_state:
            return ReconcileResult(state=ReconcileState.NOT_APPLIED)
        return ReconcileResult(state=ReconcileState.PARTIAL)

    # ------------------------------------------------------------------

    def _marker(self, params: object) -> FileMarker:
        marker = getattr(params, "marker", None)
        if not isinstance(marker, dict):
            raise CapabilityError("invalid_marker")
        return marker_from(FileMarker, marker)  # type: ignore[arg-type]

    def _managed_path(self, params: CapabilityPrepareParams) -> str:
        path = params.operation.resource
        try:
            return validate_absolute_path(path, "managed path")
        except ValueError:
            raise CapabilityError("invalid_path") from None

    def _parameters(
        self, action: str, params: CapabilityPrepareParams
    ) -> tuple[bytes | None, int | None]:
        parameters = params.operation.parameters
        if action == "replace_managed_file":
            content_value = parameters.get("content")
            if type(content_value) is not str or not content_value:
                raise CapabilityError("content_required")
            mode_value = parameters.get("mode")
            if mode_value is not None and type(mode_value) is not int:
                raise CapabilityError("invalid_mode")
            if any(key not in {"content", "mode"} for key in parameters):
                raise CapabilityError("invalid_parameters")
            try:
                content = base64.b64decode(content_value, validate=True)
            except (ValueError, TypeError):
                raise CapabilityError("invalid_content") from None
            if len(content) > MAX_MANAGED_FILE_BYTES:
                raise CapabilityError("managed_file_too_large")
            return content, mode_value
        mode_value = parameters.get("mode")
        if type(mode_value) is not int or mode_value < 0:
            raise CapabilityError("mode_required")
        if any(key != "mode" for key in parameters):
            raise CapabilityError("invalid_parameters")
        return None, mode_value

    def _new_content(self, parameters: dict) -> bytes:
        content_value = parameters.get("content")
        if type(content_value) is not str:
            raise CapabilityError("content_required")
        try:
            content = base64.b64decode(content_value, validate=True)
        except (ValueError, TypeError):
            raise CapabilityError("invalid_content") from None
        return content

    async def _reject_symlink_or_device(self, path: str) -> None:
        components = path.split("/")[1:]
        for index in range(1, len(components) + 1):
            prefix = "/" + "/".join(components[:index])
            info = await self._transport.lstat(prefix)
            if stat.S_ISLNK(info.mode):
                raise CapabilityError("symlink_escape")
            if stat.S_ISCHR(info.mode) or stat.S_ISBLK(info.mode):
                raise CapabilityError("device_file")
            if index < len(components) and not stat.S_ISDIR(info.mode):
                raise CapabilityError("not_a_directory")

    async def _write_file(
        self, marker: FileMarker, content: bytes, *, undo: bool = False
    ) -> None:
        mode = marker.prior_mode if undo or marker.new_mode is None else marker.new_mode
        metadata_writer = getattr(self._transport, "write_file_with_metadata", None)
        if callable(metadata_writer):
            await metadata_writer(
                marker.path,
                content,
                mode,
                marker.prior_uid,
                marker.prior_gid,
            )
            return
        await self._transport.write_file(marker.path, content, mode)
        await self._transport.chown(marker.path, marker.prior_uid, marker.prior_gid)

    async def _verify_restored(self, marker: FileMarker) -> VerifyResult:
        try:
            content = await self._transport.read_file(marker.path, MAX_MANAGED_FILE_BYTES)
            info = await self._transport.lstat(marker.path)
        except CapabilityError:
            return VerifyResult(ok=False, reason="state_unavailable")
        if sha256(content) != marker.prior_content_sha256:
            return VerifyResult(ok=False, reason="restored_state_mismatch")
        if stat.S_IMODE(info.mode) != stat.S_IMODE(marker.prior_mode):
            return VerifyResult(ok=False, reason="restored_state_mismatch")
        if info.uid != marker.prior_uid or info.gid != marker.prior_gid:
            return VerifyResult(ok=False, reason="restored_state_mismatch")
        return VerifyResult(ok=True)


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def main() -> None:
    """Wired by the plugin manifest loader in the build task."""

    raise SystemExit(
        "capability-files is started by the plugin supervisor with its manifest"
    )


__all__ = [
    "FileMarker",
    "FilesPlugin",
    "MAX_MANAGED_FILE_BYTES",
    "main",
    "sha256",
]
