"""Disk contract discovery. Effects require the exact installed target helper."""
from a4diag_builtin_plugins.capability_common import BaseCapabilityPlugin, CapabilityError
from a4diag_builtin_plugins.transport_common import CapabilityProbeResult


class DiskPlugin(BaseCapabilityPlugin):
    def __init__(self):
        super().__init__(transport=None, name='capability-disk', version='1.1.0', actions=frozenset({'cleanup'}))

    async def prepare(self, *args, **kwargs):
        raise CapabilityError('disk_helper_required')

    async def capability_probe(self, params):
        return CapabilityProbeResult(read_capable=False,write_capable=False,
            read_risk_floor='low',write_risk_floor='high',reason='exact_target_disk_helper_required')

    apply = prepare
    undo = prepare
    verify = prepare
    reconcile = prepare


def main():
    raise SystemExit('capability-disk is started by the plugin supervisor with its manifest')
