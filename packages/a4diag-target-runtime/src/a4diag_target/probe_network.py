"""Disposable resolver process; parent enforces a deadline and kills its group."""
from __future__ import annotations

import ipaddress
import json
import socket
import sys
from urllib.parse import urlsplit

from a4diag.linux_probes import LinuxProbe


def main(argv=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2 or args[0] not in {"tcp", "dns"}:
        return 2
    try:
        probe = LinuxProbe(id="network", kind=args[0], resource=args[1])
    except ValueError:
        return 2
    if probe.kind == "tcp":
        target = urlsplit(probe.resource)
        try:
            with socket.create_connection((target.hostname, target.port), timeout=3.0):
                result = {"reachable": True}
        except OSError:
            result = {"reachable": False}
    else:
        try:
            rows = socket.getaddrinfo(probe.resource, None, type=socket.SOCK_STREAM)
            addresses = sorted({str(ipaddress.ip_address(row[4][0])) for row in rows if "%" not in row[4][0]})[:16]
        except socket.gaierror as exc:
            if exc.errno not in {socket.EAI_NONAME, getattr(socket, "EAI_NODATA", socket.EAI_NONAME)}:
                return 1
            addresses = []
        result = {"resolved": bool(addresses), "addresses": addresses}
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
