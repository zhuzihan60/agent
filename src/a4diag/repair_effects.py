"""Manifest-owned effect semantics; compensation is not full restoration."""
from collections.abc import Sequence
from typing import Literal

from pydantic import BaseModel, ConfigDict, StrictBool

EffectKind = Literal['restorable', 'compensatable', 'irreversible']


class RepairEffect(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    kind: EffectKind
    changed: StrictBool | None
    restoration_verified: StrictBool


def rollback_outcome(effects: Sequence[RepairEffect]) -> str:
    if any(effect.changed is None for effect in effects):
        return 'rollback_unknown'
    if any(effect.changed and (effect.kind != 'restorable' or
                              not effect.restoration_verified) for effect in effects):
        return 'rollback_partial'
    return 'rollback_succeeded'
