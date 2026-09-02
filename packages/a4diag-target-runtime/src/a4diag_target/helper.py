"""Bounded forced-command relay to the fixed target executor socket."""

from __future__ import annotations

import json
import os
import socket
import struct
import sys
from collections.abc import Callable, Mapping
from typing import BinaryIO

MAX_FRAME_BYTES = 1_048_576
EXECUTOR_SOCKET = "/run/a4diag-target/executor.sock"
FIXED_COMMAND = "/usr/libexec/a4diag/a4diag-transport-helper"


class HelperError(ValueError):
    pass


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise HelperError("duplicate_key")
        result[key] = value
    return result


def _socket_connector(path: str, request: bytes, limit: int) -> bytes:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(path)
        client.sendall(struct.pack("!I", len(request)) + request)
        header = client.recv(4)
        if len(header) != 4:
            raise HelperError("response_header_invalid")
        length = struct.unpack("!I", header)[0]
        if length > limit:
            raise HelperError("response_too_large")
        chunks = bytearray()
        while len(chunks) < length:
            chunk = client.recv(length - len(chunks))
            if not chunk:
                raise HelperError("response_truncated")
            chunks.extend(chunk)
        return bytes(chunks)


def run_helper(stdin: BinaryIO, stdout: BinaryIO, *, env: Mapping[str, str], connector: Callable[[str, bytes, int], bytes] = _socket_connector) -> int:
    original = env.get("SSH_ORIGINAL_COMMAND")
    if original not in (None, "", FIXED_COMMAND):
        raise HelperError("original_command_rejected")
    body = stdin.read(MAX_FRAME_BYTES + 1)
    if len(body) > MAX_FRAME_BYTES:
        raise HelperError("request_too_large")
    try:
        decoded = json.loads(body, object_pairs_hook=_unique)
    except HelperError:
        raise
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HelperError("request_invalid") from exc
    if not isinstance(decoded, dict):
        raise HelperError("request_invalid")
    request = json.dumps(decoded, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    limit = MAX_FRAME_BYTES
    try:
        signed_payload = json.loads(str(decoded.get("payload", "")))
        requested_limit = signed_payload["operation"]["output_limit_bytes"]
        if type(requested_limit) is int and 1 <= requested_limit <= MAX_FRAME_BYTES:
            limit = requested_limit
    except (KeyError, TypeError, json.JSONDecodeError):
        pass
    response = connector(EXECUTOR_SOCKET, request, limit)
    if len(response) > limit:
        raise HelperError("response_too_large")
    parsed = json.loads(response, object_pairs_hook=_unique)
    encoded = json.dumps(parsed, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    stdout.write(encoded + b"\n")
    return 0


def main() -> int:
    try:
        return run_helper(sys.stdin.buffer, sys.stdout.buffer, env=os.environ)
    except (HelperError, OSError) as exc:
        print(f"a4diag-transport-helper: {exc}", file=sys.stderr)
        return 69


__all__ = ["EXECUTOR_SOCKET", "FIXED_COMMAND", "HelperError", "main", "run_helper"]
