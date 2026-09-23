"""Closed Deployment identity and sanitized observation contract."""
from pydantic import BaseModel, ConfigDict, Field, StrictBool
from a4diag_builtin_plugins.capability_common import BaseCapabilityPlugin, CapabilityError
from a4diag_builtin_plugins.transport_common import CapabilityProbeResult


class DeploymentIdentity(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    cluster_id: str
    namespace: str
    name: str
    uid: str


class DeploymentSnapshot(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    identity: DeploymentIdentity
    generation: int = Field(ge=1, strict=True)
    observed_generation: int = Field(ge=0, strict=True)
    replicas: int = Field(ge=0, strict=True)
    updated: int = Field(ge=0, strict=True)
    available: int = Field(ge=0, strict=True)
    complete: StrictBool
    pod_uids: tuple[str, ...]
    restart_count: int = Field(ge=0, strict=True)
    image: str
    reasons: tuple[str, ...] = ()


class KubernetesCapability(BaseCapabilityPlugin):
    def __init__(self):
        super().__init__(transport=None,name='capability-kubernetes',version='1.0.0',actions=frozenset({'restart','restore-image'}))

    async def prepare(self,*args,**kwargs):
        raise CapabilityError('kubernetes_helper_required')

    apply=prepare
    undo=prepare
    verify=prepare
    reconcile=prepare

    async def capability_probe(self,params):
        return CapabilityProbeResult(read_capable=False,write_capable=False,read_risk_floor='low',
            write_risk_floor='high',reason='exact_target_kubernetes_helper_required')


def main():
    raise SystemExit('capability-kubernetes requires the plugin supervisor')
