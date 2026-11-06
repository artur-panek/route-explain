from __future__ import annotations

import ipaddress
import json
import platform
from dataclasses import asdict, fields
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .analyze import build_report
from .collect import (
    CollectionError,
    collect_links,
    collect_route_get,
    collect_routes,
    collect_rules,
)
from .context import ExecutionContext
from .model import Evidence, Flow, Report
from .overlay import collect_tailscale, collect_wireguard, overlay_evidence

SNAPSHOT_SCHEMA_VERSION = 1


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate snapshot key {key!r}")
        result[key] = value
    return result


def capture_snapshot(flow: Flow, context: ExecutionContext) -> dict[str, Any]:
    route_get = collect_route_get(flow, context=context)
    try:
        fibmatch = collect_route_get(flow, fibmatch=True, context=context)
    except CollectionError:
        fibmatch = None

    rules = collect_rules(flow, context=context)
    routes = collect_routes(flow, context=context)
    links = collect_links(context=context)
    wireguard = collect_wireguard(context)
    tailscale = collect_tailscale(context)

    return {
        "snapshot_schema_version": SNAPSHOT_SCHEMA_VERSION,
        "captured_at": datetime.now(UTC).isoformat(),
        "context": {
            "kind": context.kind,
            "value": context.value,
            "label": context.label,
        },
        "host": {
            "node": platform.node(),
            "kernel": platform.release(),
        },
        "flow": asdict(flow),
        "evidence": {
            "route_get": route_get,
            "fibmatch": fibmatch,
            "rules": rules,
            "routes": routes,
            "links": links,
            "wireguard": wireguard,
            "tailscale": tailscale,
        },
    }


def load_snapshot(path: str | Path) -> dict[str, Any]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
        validate_snapshot(data)
    except ValueError as exc:
        raise ValueError(f"{path}: {exc}") from exc
    return data


def validate_snapshot(data: object) -> None:
    if not isinstance(data, dict) or type(data.get("snapshot_schema_version")) is not int or data["snapshot_schema_version"] != SNAPSHOT_SCHEMA_VERSION:
        raise ValueError("unsupported or invalid route-explain snapshot")
    flow = data.get("flow")
    if not isinstance(flow, dict) or "destination" not in flow or set(flow) - {field.name for field in fields(Flow)}:
        raise ValueError("snapshot.flow requires destination and supported flow fields")
    for name in ("destination", "source"):
        value = flow.get(name)
        if value is None and name == "source":
            continue
        if not isinstance(value, str):
            raise ValueError(f"snapshot.flow.{name} must be an IP address")
        ipaddress.ip_address(value)
    if flow.get("source") and ipaddress.ip_address(flow["source"]).version != ipaddress.ip_address(flow["destination"]).version:
        raise ValueError("snapshot.flow source and destination address families differ")
    for name, maximum in (("destination_port", 65535), ("source_port", 65535), ("mark", 0xffffffff), ("tos", 255)):
        value = flow.get(name)
        if value is not None and (type(value) is not int or not 0 <= value <= maximum):
            raise ValueError(f"snapshot.flow.{name} must be an integer in 0..{maximum}")
    for name in ("protocol", "iif", "oif", "vrf"):
        if flow.get(name) is not None and not isinstance(flow[name], str):
            raise ValueError(f"snapshot.flow.{name} must be a string")
    evidence = data.get("evidence")
    if not isinstance(evidence, dict):
        raise ValueError("snapshot.evidence must be an object")
    for name in ("route_get", "rules", "routes", "links", "fibmatch", "wireguard"):
        value = evidence.get(name)
        if value is None and name in {"fibmatch", "wireguard"}:
            continue
        if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
            raise ValueError(f"snapshot.evidence.{name} must be a list of objects")
        if name == "route_get" and not value:
            raise ValueError("snapshot.evidence.route_get must not be empty")
        for item in value:
            if "priority" in item and type(item["priority"]) is not int:
                raise ValueError(f"snapshot.evidence.{name}.priority must be an integer")
            if "metric" in item and type(item["metric"]) is not int:
                raise ValueError(f"snapshot.evidence.{name}.metric must be an integer")
            if item.get("linkinfo") is not None and not isinstance(item["linkinfo"], dict):
                raise ValueError(f"snapshot.evidence.{name}.linkinfo must be an object")
            if "nexthops" in item and (not isinstance(item["nexthops"], list) or any(not isinstance(hop, dict) for hop in item["nexthops"])):
                raise ValueError(f"snapshot.evidence.{name}.nexthops must be a list of objects")
    for name in ("context", "host"):
        if data.get(name) is not None and not isinstance(data[name], dict):
            raise ValueError(f"snapshot.{name} must be an object")
    if evidence.get("tailscale") is not None and not isinstance(evidence["tailscale"], dict):
        raise ValueError("snapshot.evidence.tailscale must be an object")
    for interface in evidence.get("wireguard") or []:
        peers = interface.get("peers", [])
        if not isinstance(peers, list) or any(not isinstance(peer, dict) for peer in peers):
            raise ValueError("snapshot.evidence.wireguard.peers must be a list of objects")
        for peer in peers:
            ips = peer.get("allowed_ips", [])
            if not isinstance(ips, list) or any(not isinstance(ip, str) for ip in ips):
                raise ValueError("snapshot.evidence.wireguard.peers.allowed_ips must be a list of strings")
    tailscale = evidence.get("tailscale") or {}
    if tailscale.get("Self") is not None and not isinstance(tailscale["Self"], dict):
        raise ValueError("snapshot.evidence.tailscale.Self must be an object")
    if tailscale.get("Peer") is not None and not isinstance(tailscale["Peer"], dict):
        raise ValueError("snapshot.evidence.tailscale.Peer must be an object")
    for peer in (tailscale.get("Peer") or {}).values():
        if not isinstance(peer, dict):
            raise ValueError("snapshot.evidence.tailscale.Peer entries must be objects")
        for key in ("TailscaleIPs", "PrimaryRoutes", "AllowedIPs"):
            if peer.get(key) is not None and (not isinstance(peer[key], list) or any(not isinstance(ip, str) for ip in peer[key])):
                raise ValueError(f"snapshot.evidence.tailscale.Peer.{key} must be a list of strings")


def save_snapshot(
    snapshot: dict[str, Any],
    path: str | Path | None = None,
) -> str:
    text = json.dumps(snapshot, indent=2, sort_keys=True)
    if path is not None:
        Path(path).write_text(text + "\n", encoding="utf-8")
    return text


def report_from_snapshot(snapshot: dict[str, Any]) -> Report:
    validate_snapshot(snapshot)
    flow = Flow(**snapshot["flow"])
    evidence = snapshot["evidence"]
    report = build_report(
        flow,
        route_get=evidence["route_get"],
        fibmatch=evidence.get("fibmatch"),
        rules=evidence["rules"],
        routes=evidence["routes"],
        links=evidence["links"],
    )

    messages = overlay_evidence(
        flow.destination,
        evidence.get("wireguard") or [],
        evidence.get("tailscale"),
    )
    for message in messages:
        report.evidence.insert(-1, Evidence("derived", message))

    return report
