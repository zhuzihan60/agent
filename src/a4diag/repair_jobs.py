"""Bounded protocol 1.1 job snapshots shared by controller and target."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, StrictBool, model_validator
from a4diag.domain import canonical_json_bytes

TERMINAL_JOB_STATES = frozenset({'succeeded', 'failed', 'partial'})
MAX_JOB_RESULT_BYTES = 196608


class RepairJob(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    id: str = Field(pattern=r'^[A-Za-z0-9_.-]{1,128}$')
    transaction_id: str = Field(pattern=r'^[A-Za-z0-9_.:-]{1,128}$')
    step_id: str = Field(pattern=r'^[A-Za-z0-9_.-]{1,128}$')
    profile_digest: str = Field(pattern=r'^[0-9a-f]{64}$')
    operation_digest: str = Field(pattern=r'^[0-9a-f]{64}$')
    state: Literal['prepared', 'running', 'succeeded', 'failed', 'partial', 'unknown']
    changed: StrictBool | None = None
    result: dict[str, JsonValue] = Field(default_factory=dict)
    started_at: int | None = Field(default=None, ge=0, strict=True)
    finished_at: int | None = Field(default=None, ge=0, strict=True)

    @model_validator(mode='after')
    def bounded_result(self):
        canonical_json_bytes(self.result, max_bytes=MAX_JOB_RESULT_BYTES)
        if self.state in TERMINAL_JOB_STATES and (self.finished_at is None or self.started_at is None):
            raise ValueError('terminal job requires execution timestamps')
        if self.finished_at is not None and self.started_at is not None and self.finished_at < self.started_at:
            raise ValueError('job clock rollback')
        return self


class RepairJobResponse(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    protocol_version: Literal['1.1'] = '1.1'
    job: RepairJob
