"""Administrator-defined Linux diagnostics and strict recovery predicates."""
from __future__ import annotations

import ipaddress
import hashlib
import json
import re
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr, model_validator


def validate_probe_id(value: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", value) is None:
        raise ValueError("invalid probe id")
    return value


def _host(value: str) -> None:
    try:
        ipaddress.ip_address(value)
        if "%" in value:
            raise ValueError("scoped address unsupported")
        return
    except ValueError:
        pass
    if len(value) > 253 or not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", p) for p in value.split(".")):
        raise ValueError("invalid hostname")


class LinuxProbe(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str
    kind: Literal["filesystem", "memory", "load", "file", "package", "tcp", "dns"]
    resource: str = Field(min_length=1, max_length=1024)
    max_bytes: int = Field(default=1048576, ge=1, le=1048576, strict=True)

    @model_validator(mode="after")
    def validate_definition(self) -> LinuxProbe:
        validate_probe_id(self.id)
        value = self.resource
        if self.kind in {"filesystem", "file"}:
            if value == "/" and self.kind == "filesystem":
                return self
            if (not value.startswith("/") or any(p in {"", ".", ".."} for p in value[1:].split("/"))
                or any(ord(c) < 32 or ord(c) == 127 or c in "\\*?[]" for c in value)):
                raise ValueError("probe requires canonical absolute path")
        elif self.kind in {"memory", "load"}:
            if value != "host":
                raise ValueError("host probe resource must be host")
        elif self.kind == "package":
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+_.-]{0,127}", value) is None:
                raise ValueError("invalid exact package name")
        elif self.kind == "dns":
            _host(value)
        elif self.kind == "tcp":
            url = urlsplit(value)
            if (url.scheme != "tcp" or not url.hostname or url.username is not None or url.password is not None
                or url.path or "?" in value or "#" in value or not url.port or any(ord(c) <= 32 for c in value)):
                raise ValueError("TCP probe requires tcp://host:port")
            _host(url.hostname)
        return self


PROBE_OUTPUTS = {
    "filesystem": dict.fromkeys(("total_bytes", "available_bytes", "used_percent", "free_inodes"), "int"),
    "memory": dict.fromkeys(("total_bytes", "available_bytes", "used_percent", "swap_total_bytes", "swap_free_bytes"), "int"),
    "load": dict.fromkeys(("load_1_milli", "load_5_milli", "load_15_milli", "cpu_count"), "int"),
    "file": {"exists": "bool", "mode": "int", "size_bytes": "int", "sha256": "str"},
    "package": {"installed": "bool", "version": "str"},
    "tcp": {"reachable": "bool"},
    "dns": {"resolved": "bool", "addresses": "addresses"},
}


class ProbeCondition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    field: str = Field(min_length=1, max_length=64)
    operator: Literal["eq", "ge", "le", "contains"]
    value: StrictBool | StrictInt | StrictStr


def validate_probe_checks(probes, sources, checks) -> None:
    catalog = {p.id: p for p in probes}
    if len(probes) > 8 or len(catalog) != len(probes):
        raise ValueError("duplicate or excessive probes")
    for entry in (*sources, *checks):
        if entry.kind != "probe":
            continue
        if entry.resource not in catalog:
            raise ValueError("unknown probe id")
        probe = catalog[entry.resource]
        conditions = getattr(entry, "conditions", ())
        for condition in conditions:
            field_type = PROBE_OUTPUTS[probe.kind].get(condition.field)
            expected = {"int": int, "str": str, "bool": bool, "addresses": str}.get(field_type)
            allowed = {"int": {"eq", "ge", "le"}, "str": {"eq"}, "bool": {"eq"}, "addresses": {"contains"}}.get(field_type, set())
            if type(condition.value) is not expected or condition.operator not in allowed:
                raise ValueError("invalid probe condition type or operator")
            if field_type == "int" and (condition.value < 0 or condition.value > 2**63 - 1):
                raise ValueError("invalid numeric probe condition")
            if condition.field == "sha256" and re.fullmatch(r"[0-9a-f]{64}", condition.value) is None:
                raise ValueError("expected sha256 must be a digest")
            if condition.field == "version" and not condition.value:
                raise ValueError("expected version must not be empty")
            if field_type == "addresses" and str(ipaddress.ip_address(condition.value)) != condition.value:
                raise ValueError("expected address must be canonical")
        required = "exists" if probe.kind == "file" else "installed" if probe.kind == "package" else None
        if required and any(c.field != required for c in conditions):
            if not any(c.field == required and c.operator == "eq" and c.value is True for c in conditions):
                raise ValueError("attribute condition requires positive presence check")


def validate_probe_output(probe: LinuxProbe, data: object) -> dict:
    fields = PROBE_OUTPUTS[probe.kind]
    if not isinstance(data, dict) or data.keys() != fields.keys():
        raise ValueError("invalid probe output fields")
    for key, kind in fields.items():
        value = data[key]
        expected = {"int": int, "bool": bool, "str": str, "addresses": list}[kind]
        if type(value) is not expected:
            raise ValueError("invalid probe output type")
        if kind == "int" and not 0 <= value <= 2**63 - 1:
            raise ValueError("invalid probe output number")
        if kind == "str" and (len(value) > 1024 or any(ord(c) < 32 for c in value)):
            raise ValueError("invalid probe output text")
        if kind == "addresses":
            if len(value) > 16 or any(not isinstance(v, str) or str(ipaddress.ip_address(v)) != v for v in value):
                raise ValueError("invalid probe addresses")
    if "used_percent" in data and data["used_percent"] > 100:
        raise ValueError("invalid percentage")
    if probe.kind == "file" and (data["mode"] > 4095 or (data["sha256"] and re.fullmatch(r"[0-9a-f]{64}", data["sha256"]) is None)):
        raise ValueError("invalid file attributes")
    if probe.kind == "file" and not data["exists"] and any(data[k] for k in ("mode", "size_bytes", "sha256")):
        raise ValueError("absent file has attributes")
    if probe.kind == "package" and data["installed"] != bool(data["version"]):
        raise ValueError("inconsistent package presence")
    if probe.kind == "dns" and (data["resolved"] != bool(data["addresses"]) or len(set(data["addresses"])) != len(data["addresses"]) or any("%" in a for a in data["addresses"])):
        raise ValueError("inconsistent DNS output")
    if probe.kind in {"memory", "filesystem"} and (data["total_bytes"] <= 0 or data["available_bytes"] > data["total_bytes"]):
        raise ValueError("inconsistent capacity output")
    if probe.kind in {"memory", "filesystem"} and data["used_percent"] != (data["total_bytes"] - data["available_bytes"]) * 100 // data["total_bytes"]:
        raise ValueError("inconsistent capacity percentage")
    if probe.kind == "memory" and data["swap_free_bytes"] > data["swap_total_bytes"]:
        raise ValueError("inconsistent swap output")
    if probe.kind == "load" and data["cpu_count"] == 0:
        raise ValueError("invalid CPU count")
    return data


def probe_definition_digest(probe: LinuxProbe) -> str:
    """Bind observations to the complete administrator definition, including defaults."""
    canonical = json.dumps(probe.model_dump(mode="json"), sort_keys=True,
                           separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _parse_probe_json(text: str) -> object:
    if len(text.encode("utf-8")) > 16384:
        raise ValueError("probe output too large")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate probe field")
            result[key] = value
        return result
    try:
        return json.loads(text, object_pairs_hook=unique)
    except RecursionError as error:
        raise ValueError("probe output nesting too deep") from error


def parse_probe_output(probe: LinuxProbe, text: str) -> dict:
    return validate_probe_output(probe, _parse_probe_json(text))


def parse_bound_probe_output(probe: LinuxProbe, text: str) -> dict:
    envelope = _parse_probe_json(text)
    if (not isinstance(envelope, dict) or set(envelope) != {"probe_digest", "result"}
        or envelope["probe_digest"] != probe_definition_digest(probe)):
        raise ValueError("probe definition mismatch")
    return validate_probe_output(probe, envelope["result"])


def evaluate_probe_conditions(data: dict, conditions) -> bool:
    return all({"eq": lambda: data[c.field] == c.value,
                "ge": lambda: data[c.field] >= c.value,
                "le": lambda: data[c.field] <= c.value,
                "contains": lambda: c.value in data[c.field]}[c.operator]() for c in conditions)
