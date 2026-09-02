from __future__ import annotations

import inspect
import io
import json

import pytest

from a4diag_target import helper


def test_helper_relays_one_bounded_json_object_to_fixed_socket() -> None:
    seen: list[tuple[str, bytes, int]] = []

    def connector(socket_path: str, request: bytes, limit: int) -> bytes:
        seen.append((socket_path, request, limit))
        return b'{"ok":true}'

    stdin = io.BytesIO(b'{"payload":"{}","signature":"AA","key_fingerprint":"sha256:x"}\n')
    stdout = io.BytesIO()
    assert helper.run_helper(stdin, stdout, env={}, connector=connector) == 0
    assert seen[0][0] == "/run/a4diag-target/executor.sock"
    assert json.loads(seen[0][1]) == json.loads(stdin.getvalue())
    assert stdout.getvalue() == b'{"ok":true}\n'


@pytest.mark.parametrize(
    ("body", "environment"),
    (
        (b"{}\n{}\n", {}),
        (b"x" * (1_048_576 + 1), {}),
        (b"{}\n", {"SSH_ORIGINAL_COMMAND": "uname -a"}),
        (b'{"x":1,"x":2}\n', {}),
    ),
)
def test_helper_rejects_ambiguous_oversized_or_command_input(
    body: bytes, environment: dict[str, str]
) -> None:
    calls: list[bytes] = []

    def connector(_socket: str, request: bytes, _limit: int) -> bytes:
        calls.append(request)
        return b"{}"

    with pytest.raises(helper.HelperError):
        helper.run_helper(io.BytesIO(body), io.BytesIO(), env=environment, connector=connector)
    assert calls == []


def test_helper_has_no_process_or_shell_surface() -> None:
    source = inspect.getsource(helper)
    for forbidden in ("subprocess", "os.system", "shell=True", "pty", "shlex"):
        assert forbidden not in source
