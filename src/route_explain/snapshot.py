from __future__ import annotations

import ipaddress
import json
import platform
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .analyze import parse_decision
from .collect import (
    CollectionError,
    collect_links,
    collect_overlay_state,
    collect_route_get,
    collect_routes_family,
    collect_rules_family,
)
from .model import Flow, NamespaceTarget

SNAPSHOT_SCHEMA_VERSION = 1


def capture_snapshot(
    *,
    target: NamespaceTarget | None = None,
    probe_flows: list[Flow] | None = None,
) -> dict[str, Any]:
    state = {
        "rules_v4": collect_rules_family(4, target=target),
        "rules_v6": collect_rules_family(6, target=target),
        "routes_v4": collect_routes_family(4, target=target),
        "routes_v6": collect_routes_family(6, target=target),
        "links": collect_links(target=target),
        "overlays": collect_overlay_state(target=target),
    }
    probes: list[dict[str, Any]] = []
    for flow in probe_flows or []:
        entry: dict[str, Any] = {"flow": asdict(flow), "route_get": [], "fibmatch": None}
        try:
            entry["route_get"] = collect_route_get(flow, target=target)
            try:
                entry["fibmatch"] = collect_route_get(flow, fibmatch=True, target=target)
            except CollectionError as exc:
                entry["fibmatch_error"] = str(exc)
        except CollectionError as exc:
            entry["error"] = str(exc)
        probes.append(entry)

    return {
        "snapshot_schema_version": SNAPSHOT_SCHEMA_VERSION,
        "route_explain_version": __version__,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "namespace": asdict(target) if target else None,
        "system": {
            "kernel_release": platform.release(),
            "machine": platform.machine(),
        },
        "state": state,
        "probes": probes,
    }


def dump_snapshot(snapshot: dict[str, Any]) -> str:
    return json.dumps(snapshot, indent=2, sort_keys=True)


def load_snapshot(path: str) -> dict[str, Any]:
    text = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid snapshot JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("snapshot must be a JSON object")
    version = payload.get("snapshot_schema_version")
    if version != SNAPSHOT_SCHEMA_VERSION:
        raise ValueError(
            f"unsupported snapshot schema {version!r}; expected {SNAPSHOT_SCHEMA_VERSION}"
        )
    if not isinstance(payload.get("state"), dict):
        raise ValueError("snapshot is missing state")
    return payload


def flow_from_dict(payload: dict[str, Any]) -> Flow:
    allowed = {
        "destination",
        "source",
        "protocol",
        "destination_port",
        "source_port",
        "mark",
        "tos",
        "iif",
        "oif",
        "vrf",
    }
    return Flow(**{key: value for key, value in payload.items() if key in allowed})


def _flow_key(flow: Flow) -> str:
    return json.dumps(asdict(flow), sort_keys=True, separators=(",", ":"))


def find_probe(snapshot: dict[str, Any], flow: Flow) -> dict[str, Any] | None:
    wanted = _flow_key(flow)
    probes = snapshot.get("probes")
    if not isinstance(probes, list):
        return None
    for probe in probes:
        if not isinstance(probe, dict) or not isinstance(probe.get("flow"), dict):
            continue
        try:
            candidate = flow_from_dict(probe["flow"])
        except (TypeError, ValueError):
            continue
        if _flow_key(candidate) == wanted:
            return probe
    return None


def state_for_flow(snapshot: dict[str, Any], flow: Flow) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    state = snapshot["state"]
    version = ipaddress.ip_address(flow.destination).version
    rules = state.get("rules_v6" if version == 6 else "rules_v4") or []
    routes = state.get("routes_v6" if version == 6 else "routes_v4") or []
    if not isinstance(rules, list) or not isinstance(routes, list):
        raise ValueError("snapshot route/rule state has an invalid shape")
    return rules, routes


def snapshot_namespace_label(snapshot: dict[str, Any]) -> str | None:
    namespace = snapshot.get("namespace")
    if not isinstance(namespace, dict):
        return None
    kind = namespace.get("kind")
    value = namespace.get("value")
    return f"{kind}:{value}" if kind and value else None


def _canonical(item: Any) -> str:
    return json.dumps(item, sort_keys=True, separators=(",", ":"), default=str)


def _route_summary(item: dict[str, Any]) -> str:
    dst = str(item.get("dst", "default"))
    table = str(item.get("table", "main"))
    dev = f" dev {item['dev']}" if item.get("dev") else ""
    gateway = f" via {item['gateway']}" if item.get("gateway") else ""
    metric = f" metric {item['metric']}" if item.get("metric") is not None else ""
    route_type = str(item.get("type", "unicast"))
    type_text = "" if route_type == "unicast" else f" type {route_type}"
    return f"{dst}{gateway}{dev} table {table}{metric}{type_text}"


def _rule_summary(item: dict[str, Any]) -> str:
    priority = item.get("priority", 0)
    src = item.get("src", "all")
    dst = item.get("dst", "all")
    table = item.get("table")
    action = f"lookup {table}" if table is not None else str(item.get("action", "unspecified"))
    extras = []
    for key in ("fwmark", "fwmask", "iif", "oif", "tos", "ipproto", "sport", "dport", "l3mdev"):
        if key in item:
            extras.append(f"{key}={item[key]}")
    suffix = f" [{', '.join(extras)}]" if extras else ""
    return f"{priority}: from {src} to {dst} {action}{suffix}"


def _link_summary(item: dict[str, Any]) -> str:
    name = str(item.get("ifname", "?"))
    kind = str((item.get("linkinfo") or {}).get("info_kind", ""))
    master = item.get("master")
    extra = f" kind {kind}" if kind else ""
    extra += f" master {master}" if master else ""
    return name + extra


def _diff_items(
    before: list[dict[str, Any]],
    after: list[dict[str, Any]],
    summarizer: Any,
) -> tuple[list[str], list[str]]:
    before_map = {_canonical(item): item for item in before}
    after_map = {_canonical(item): item for item in after}
    added = [summarizer(after_map[key]) for key in sorted(after_map.keys() - before_map.keys())]
    removed = [summarizer(before_map[key]) for key in sorted(before_map.keys() - after_map.keys())]
    return added, removed


def _destination_matches_route(destination: str, route: dict[str, Any]) -> bool:
    address = ipaddress.ip_address(destination)
    raw = str(route.get("dst", "default"))
    try:
        network = ipaddress.ip_network(
            ("0.0.0.0/0" if address.version == 4 else "::/0") if raw == "default" else raw,
            strict=False,
        )
    except ValueError:
        return False
    return network.version == address.version and address in network


def _probe_decision(probe: dict[str, Any]) -> dict[str, Any] | None:
    if probe.get("error") or not probe.get("route_get") or not isinstance(probe.get("flow"), dict):
        return None
    flow = flow_from_dict(probe["flow"])
    try:
        decision = parse_decision(flow, probe["route_get"], probe.get("fibmatch"))
    except (TypeError, ValueError):
        return None
    return {
        "table": decision.table,
        "dev": decision.dev,
        "gateway": decision.gateway,
        "source": decision.source,
        "matched_prefix": decision.matched_prefix,
        "route_type": decision.route_type,
    }


def diff_snapshots(
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    destination: str | None = None,
) -> dict[str, Any]:
    bstate = before["state"]
    astate = after["state"]
    route_key = "routes_v6" if destination and ":" in destination else "routes_v4"
    route_versions = [route_key] if destination else ["routes_v4", "routes_v6"]

    added_routes: list[str] = []
    removed_routes: list[str] = []
    for key in route_versions:
        b_routes = list(bstate.get(key) or [])
        a_routes = list(astate.get(key) or [])
        if destination:
            b_routes = [item for item in b_routes if _destination_matches_route(destination, item)]
            a_routes = [item for item in a_routes if _destination_matches_route(destination, item)]
        added, removed = _diff_items(b_routes, a_routes, _route_summary)
        added_routes.extend(added)
        removed_routes.extend(removed)

    added_rules: list[str] = []
    removed_rules: list[str] = []
    rule_versions = ["rules_v6" if destination and ":" in destination else "rules_v4"] if destination else ["rules_v4", "rules_v6"]
    for key in rule_versions:
        added, removed = _diff_items(
            list(bstate.get(key) or []),
            list(astate.get(key) or []),
            _rule_summary,
        )
        added_rules.extend(added)
        removed_rules.extend(removed)

    added_links, removed_links = _diff_items(
        list(bstate.get("links") or []),
        list(astate.get("links") or []),
        _link_summary,
    )

    before_overlays = ((bstate.get("overlays") or {}).get("wireguard") or {}).get("routes", []) + ((bstate.get("overlays") or {}).get("tailscale") or {}).get("routes", [])
    after_overlays = ((astate.get("overlays") or {}).get("wireguard") or {}).get("routes", []) + ((astate.get("overlays") or {}).get("tailscale") or {}).get("routes", [])
    added_overlay, removed_overlay = _diff_items(
        before_overlays,
        after_overlays,
        lambda item: f"{item.get('kind')} {item.get('prefix')} via {item.get('interface')}",
    )

    before_probes = {
        _flow_key(flow_from_dict(item["flow"])): item
        for item in before.get("probes", [])
        if isinstance(item, dict) and isinstance(item.get("flow"), dict)
    }
    after_probes = {
        _flow_key(flow_from_dict(item["flow"])): item
        for item in after.get("probes", [])
        if isinstance(item, dict) and isinstance(item.get("flow"), dict)
    }
    decision_changes: list[dict[str, Any]] = []
    for key in sorted(before_probes.keys() & after_probes.keys()):
        flow = flow_from_dict(before_probes[key]["flow"])
        if destination and flow.destination != destination:
            continue
        bdecision = _probe_decision(before_probes[key])
        adecision = _probe_decision(after_probes[key])
        if bdecision != adecision:
            decision_changes.append(
                {
                    "flow": asdict(flow),
                    "before": bdecision,
                    "after": adecision,
                }
            )

    return {
        "diff_schema_version": 1,
        "destination": destination,
        "before_created_at": before.get("created_at"),
        "after_created_at": after.get("created_at"),
        "added_routes": added_routes,
        "removed_routes": removed_routes,
        "added_rules": added_rules,
        "removed_rules": removed_rules,
        "added_links": added_links,
        "removed_links": removed_links,
        "added_overlay_routes": added_overlay,
        "removed_overlay_routes": removed_overlay,
        "decision_changes": decision_changes,
    }
