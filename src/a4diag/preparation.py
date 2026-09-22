"""Frozen core-only identity for the compiled stop -> cleanup dependency."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_serializer, model_validator

ID = r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$'
DIGEST = r'^[0-9a-f]{64}$'


class PreparationDependency(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    stop_step_id: str = Field(pattern=ID)
    stop_profile_id: str = Field(pattern=ID)
    stop_profile_digest: str = Field(pattern=DIGEST)
    stop_operation_digest: str = Field(pattern=DIGEST)
    dependent_step_id: str = Field(pattern=ID)
    dependent_profile_id: str = Field(pattern=ID)
    dependent_profile_digest: str = Field(pattern=DIGEST)
    dependent_operation_digest: str = Field(pattern=DIGEST)
    stop_job_id: str | None = Field(default=None, pattern=ID)

    @model_validator(mode='after')
    def distinct_steps(self):
        if self.stop_step_id == self.dependent_step_id:
            raise ValueError('preparation_dependency_steps_equal')
        return self

    def identity(self):
        return self.model_dump(mode='json', exclude={'stop_job_id'})


class PreparationContext(BaseModel):
    """Mixin preserving historical canonical bytes when no dependency exists."""
    preparation_dependency: PreparationDependency | None = None

    @model_serializer(mode='wrap')
    def serialize_context(self, handler):
        value = handler(self)
        if self.preparation_dependency is None:
            value.pop('preparation_dependency', None)
        return value

    @model_validator(mode='after')
    def validate_dependency(self):
        dep = self.preparation_dependency
        if dep is None:
            return self
        from a4diag.policy_engine import canonical_operation_digest
        operation = getattr(self, 'operation', None)
        capability = operation.capability if operation is not None else self.capability
        action = operation.action if operation is not None else self.action
        digest = canonical_operation_digest(operation) if operation is not None else self.operation_digest
        phase = getattr(self, 'lifecycle', getattr(self, 'phase', 'apply'))
        stop = self.step_id == dep.stop_step_id
        prefix = 'stop' if stop else 'dependent'
        if (self.step_id != getattr(dep, prefix+'_step_id')
                or self.binding.profile_id != getattr(dep, prefix+'_profile_id')
                or self.binding.profile_digest != getattr(dep, prefix+'_profile_digest')
                or digest != getattr(dep, prefix+'_operation_digest')
                or (capability, action) != (('services', 'stop') if stop else ('disk', 'cleanup'))
                or (dep.stop_job_id is None and not (stop and phase in ('prepare', 'apply')))
                or (stop and phase in ('prepare', 'apply') and dep.stop_job_id is not None)):
            raise ValueError('preparation_dependency_binding_mismatch')
        return self
