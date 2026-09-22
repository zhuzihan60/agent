"""Trusted compiled-adapter rejection before any effect invocation."""


class EffectAdmissionRejected(ValueError):
    """Only a closed adapter's admission hook can produce no-change evidence."""


def admit_effect(plugin, request):
    hook = getattr(plugin, 'admit_effect', None)
    if hook is not None:
        # This plugin comes from the compiled target registry, never the wire.
        hook(request)
