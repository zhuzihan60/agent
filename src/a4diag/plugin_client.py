from __future__ import annotations

import asyncio
import json
import os
import uuid
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from a4diag.plugin_api.protocol import (
    API_VERSION,
    DEFAULT_EFFECT_CANCELLATION_GRACE_SECONDS,
    DEFAULT_RPC_TIMEOUT_SECONDS,
    EFFECT_METHOD_NAMES,
    EFFECT_RESPONSE_TRANSPORT_GRACE_SECONDS,
    MAX_RPC_BYTES,
    RpcClientError,
    RpcRequest,
    decode_response_frame,
    read_bounded_frame,
)


_QUARANTINE_BLOCKED_METHODS = EFFECT_METHOD_NAMES | frozenset({"reconcile"})


class PluginClient:
    """One-call-per-connection client for the bounded plugin RPC protocol."""

    def __init__(
        self,
        socket_path: str | os.PathLike[str],
        *,
        timeout_seconds: float = DEFAULT_RPC_TIMEOUT_SECONDS,
        request_id_factory: Callable[[], str] | None = None,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._socket_path = Path(socket_path)
        self._timeout = float(timeout_seconds)
        self._request_id_factory = request_id_factory or (lambda: uuid.uuid4().hex)
        self._quarantine_required = False

    @property
    def quarantine_required(self) -> bool:
        """Whether this client must stop using the current plugin instance."""

        return self._quarantine_required

    def _quarantine_error(self, underlying_reason: str) -> RpcClientError:
        self._quarantine_required = True
        return RpcClientError(
            "quarantine_required",
            data={"underlying_reason": underlying_reason},
        )

    async def call(
        self,
        method: str,
        params: Mapping[str, Any],
        ticket: str | None = None,
    ) -> Any:
        if self._quarantine_required and method in _QUARANTINE_BLOCKED_METHODS:
            raise self._quarantine_error("client_quarantined")
        request_id = self._request_id_factory()
        try:
            request = RpcRequest(
                jsonrpc="2.0",
                api_version=API_VERSION,
                id=request_id,
                method=method,
                params=dict(params),
                ticket=ticket,
            )
            frame = json.dumps(
                request.model_dump(mode="json", exclude_none=True),
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8") + b"\n"
        except Exception as error:
            raise RpcClientError("invalid_request") from error
        if len(frame) > MAX_RPC_BYTES + 1:
            raise RpcClientError("payload_too_large")

        effect_dispatch = method in EFFECT_METHOD_NAMES
        response_timeout = self._timeout
        if effect_dispatch:
            # The host owns the effect deadline and needs time to cancel and
            # quiesce the handler before it can return an outcome.  Extend only
            # the response wait; connection setup and request writes retain the
            # caller's transport deadline.
            operation_value = params.get("operation")
            if isinstance(operation_value, Mapping):
                operation_timeout = operation_value.get("timeout_seconds", 20)
                if type(operation_timeout) is int and 1 <= operation_timeout <= 120:
                    response_timeout = max(
                        response_timeout,
                        float(operation_timeout)
                        + DEFAULT_EFFECT_CANCELLATION_GRACE_SECONDS
                        + EFFECT_RESPONSE_TRANSPORT_GRACE_SECONDS,
                    )

        writer: asyncio.StreamWriter | None = None
        dispatch_started = False
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_unix_connection(str(self._socket_path)),
                timeout=self._timeout,
            )
            writer.write(frame)
            dispatch_started = True
            await asyncio.wait_for(writer.drain(), timeout=self._timeout)
            if writer.can_write_eof():
                writer.write_eof()
            response_frame = await asyncio.wait_for(
                read_bounded_frame(reader, eof_reason="premature_eof"),
                timeout=response_timeout,
            )
        except asyncio.TimeoutError as error:
            if effect_dispatch and dispatch_started:
                raise self._quarantine_error("timeout") from error
            raise RpcClientError("timeout") from error
        except RpcClientError as error:
            underlying_reason = (
                "response_too_large"
                if error.reason == "payload_too_large"
                else error.reason
            )
            if effect_dispatch and dispatch_started:
                raise self._quarantine_error(underlying_reason) from error
            if error.reason == "payload_too_large":
                raise RpcClientError("response_too_large") from error
            raise
        except (ConnectionError, OSError) as error:
            if effect_dispatch and dispatch_started:
                raise self._quarantine_error("connection_failed") from error
            raise RpcClientError("connection_failed") from error
        except Exception as error:
            if effect_dispatch and dispatch_started:
                raise self._quarantine_error("transport_failed") from error
            raise RpcClientError("connection_failed") from error
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

        try:
            response = decode_response_frame(response_frame)
            if response.id != request_id:
                raise RpcClientError("response_id_mismatch")
        except RpcClientError as error:
            if effect_dispatch and dispatch_started:
                underlying_reason = (
                    "response_too_large"
                    if error.reason == "payload_too_large"
                    else error.reason
                )
                raise self._quarantine_error(underlying_reason) from error
            raise
        except Exception as error:
            if effect_dispatch and dispatch_started:
                raise self._quarantine_error("response_decode_failed") from error
            raise RpcClientError("response_decode_failed") from error
        if response.error is not None:
            data = response.error.data.model_dump(mode="json")
            if response.error.data.reason == "quarantine_required":
                self._quarantine_required = True
            raise RpcClientError(
                response.error.data.reason,
                code=response.error.code,
                data=data,
            )
        return response.result


__all__ = ["PluginClient", "RpcClientError"]
