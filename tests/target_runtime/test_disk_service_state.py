def test_stopped_service_empty_invocation_id_is_real_state():
    from a4diag_builtin_plugins.capability_services import parse_service_state
    state=parse_service_state('ActiveState=inactive\nSubState=dead\nUnitFileState=disabled\nInvocationID=\n')
    assert state.invocation_id=='' and state.active_state=='inactive'
