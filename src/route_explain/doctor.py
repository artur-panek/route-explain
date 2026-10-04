from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from .collect import CollectionError, collect_links, collect_routes, collect_rules
from .context import ExecutionContext
from .model import Flow


def _default_routes(routes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        route
        for route in routes
        if str(route.get("dst", "default")) == "default"
    ]


def doctor(context: ExecutionContext) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    links = collect_links(context=context)
    all_routes: list[dict[str, Any]] = []
    all_rules: list[dict[str, Any]] = []
    routes_by_family: dict[str, list[dict[str, Any]]] = {}

    for family, destination in (
        ("ipv4", "192.0.2.1"),
        ("ipv6", "2001:db8::1"),
    ):
        flow = Flow(destination=destination)
        try:
            family_routes = collect_routes(flow, context=context)
            family_rules = collect_rules(flow, context=context)
        except CollectionError as exc:
            findings.append(
                {
                    "level": "CHECK",
                    "message": f"could not inspect {family}: {exc}",
                }
            )
            continue
        routes_by_family[family] = family_routes
        all_routes.extend(family_routes)
        all_rules.extend(family_rules)

    tables: dict[str, int] = defaultdict(int)
    for route in all_routes:
        tables[str(route.get("table", "main"))] += 1

    referenced = {
        str(rule.get("table"))
        for rule in all_rules
        if rule.get("table") is not None
    }
    standard_tables = {"local", "main", "default", "255", "254", "253"}
    for table, count in sorted(tables.items()):
        if table not in standard_tables and table not in referenced:
            findings.append(
                {
                    "level": "CHECK",
                    "message": (
                        f"table {table} has {count} route(s) but no direct RPDB lookup rule"
                    ),
                }
            )

    for family, family_routes in routes_by_family.items():
        distinct_defaults = {
            (
                str(route.get("table", "main")),
                str(route.get("dev", "-")),
                str(route.get("gateway", "-")),
            )
            for route in _default_routes(family_routes)
        }
        if len(distinct_defaults) > 1:
            findings.append(
                {
                    "level": "INFO",
                    "message": (
                        f"{family} has {len(distinct_defaults)} distinct default-route paths"
                    ),
                }
            )

    advanced_keys = {
        "fwmark",
        "iif",
        "oif",
        "uidrange",
        "l3mdev",
        "suppress_prefixlen",
        "suppress_prefixlength",
    }
    advanced = [
        rule for rule in all_rules if any(key in rule for key in advanced_keys)
    ]
    if advanced:
        findings.append(
            {
                "level": "INFO",
                "message": (
                    f"{len(advanced)} policy rule(s) use advanced selectors/modifiers"
                ),
            }
        )

    overlay_names: list[str] = []
    bridge_names: list[str] = []
    for link in links:
        name = str(link.get("ifname", ""))
        kind = str((link.get("linkinfo") or {}).get("info_kind", ""))
        if name.startswith(("wg", "tailscale", "tun", "zt", "nebula")):
            overlay_names.append(name)
        if kind in {"bridge", "veth"} or name.startswith(
            ("docker", "br-", "podman", "cni", "veth")
        ):
            bridge_names.append(name)

    if overlay_names:
        findings.append(
            {
                "level": "INFO",
                "message": (
                    "overlay-like interfaces present: "
                    + ", ".join(sorted(set(overlay_names)))
                ),
            }
        )
    if bridge_names:
        findings.append(
            {
                "level": "INFO",
                "message": (
                    "container/bridge interfaces present: "
                    + ", ".join(sorted(set(bridge_names)))
                ),
            }
        )

    if not findings:
        findings.append(
            {
                "level": "OK",
                "message": (
                    "no obvious route-table/RPDB anomalies detected by current checks"
                ),
            }
        )

    return {
        "context": context.label,
        "findings": findings,
        "route_count": len(all_routes),
        "rule_count": len(all_rules),
    }


def render_doctor(result: dict[str, Any]) -> str:
    lines = ["ROUTE-EXPLAIN DOCTOR", f"context: {result['context']}", ""]
    lines.extend(
        f"{item['level']:<5} {item['message']}" for item in result["findings"]
    )
    return "\n".join(lines)


def render_doctor_json(result: dict[str, Any]) -> str:
    return json.dumps({"schema_version": 1, **result}, indent=2, sort_keys=True)
