"""Container contract discovery and read evidence; effects require target helpers."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, StrictBool
from a4diag_builtin_plugins.capability_common import BaseCapabilityPlugin, CapabilityError
from a4diag_builtin_plugins.transport_common import CapabilityProbeResult


class ContainerIdentity(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    runtime: Literal['docker', 'podman']
    container_id: str = Field(pattern=r'^[0-9a-f]{64}$')
    image_digest: str = Field(pattern=r'^sha256:[0-9a-f]{64}$')
    owner_uid: int = Field(ge=0, strict=True)


class ContainerSnapshot(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    identity: ContainerIdentity
    running: StrictBool
    health: Literal['healthy', 'unhealthy', 'starting', 'unknown']
    exit_code: int = Field(strict=True)
    oom_killed: StrictBool
    restart_count: int = Field(ge=0, strict=True)
    started_at: str = Field(min_length=1, max_length=128)


class ContainersPlugin(BaseCapabilityPlugin):
    def __init__(self):
        super().__init__(transport=None, name='capability-containers', version='1.1.0', actions=frozenset({'start','restart'}))

    async def prepare(self, *args, **kwargs):
        raise CapabilityError('container_helper_required')

    async def capability_probe(self, params):
        return CapabilityProbeResult(read_capable=False,write_capable=False,
            read_risk_floor='low',write_risk_floor='high',reason='exact_target_container_helper_required')

    apply = prepare
    undo = prepare
    verify = prepare
    reconcile = prepare


def main():
    raise SystemExit('capability-containers is started by the plugin supervisor with its manifest')
