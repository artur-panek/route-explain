from __future__ import annotations

import ipaddress
from typing import Any

from .model import Flow, PolicyRule, Report, Route, RouteDecision

TABLE_NAMES = {
    253: "default",
    254: "main",
    255: "local",
}
OVERLAY_PREFIXES = ("tailscale", "wg", "wireguard", "tun", "nebula", "zt")


def table_name(value: Any, *, default: str = "main") -> str:
    if value is None:
        return default
    if isinstance(value, int):
        return TABLE_NAMES.get(value, str(value))
    text = str(value)
    if text.isdigit():
        return TABLE_NAMES.get(int(text), text)
    return text


def _network(value: str, version: int) -> ipaddress._BaseNetwork:
    if value in {"all", "default"}:
        return ipaddress.ip_network("0.0.0.0/0" if version == 4 else "::/0")
    return ipaddress.ip_network(value, strict=False)


def _address_matches(selector: str, address: str | None, version: int) -> bool:
    if selector in {"all", "default"}:
        return True
    if address is None:
        return False
    try:
        return ipaddress.ip_address(address) in _network(selector, version)
    except ValueError:
        return False


def parse_decision(flow: Flow, route_get: list[dict[str, Any]]) -> RouteDecision:
    if not route_get:
        raise ValueError("kernel returned no route for the destination")
    item = route_get[0]
    return RouteDecision(
        destination=str(item.get("dst", flow.destination)),
        gateway=item.get("gateway"),
        dev=item.get("dev"),
        source=item.get("prefsrc") or item.get("src") or flow.source,
        table=table_name(item.get("table")),
        raw=item,
    )


def parse_rules(flow: Flow, rules: list[dict[str, Any]]) -> list[PolicyRule]:
    version = ipaddress.ip_address(flow.destination).version
    candidates: list[PolicyRule] = []

    for item in rules:
        source = str(item.get("src", "all"))
        destination = str(item.get("dst", "all"))
        if not _address_matches(source, flow.source, version):
            continue
        if not _address_matches(destination, flow.destination, version):
            continue

        known = {"priority", "src", "dst", "table", "action", "protocol"}
        selectors = {key: value for key, value in item.items() if key not in known}
        candidates.append(
            PolicyRule(
                priority=int(item.get("priority", 0)),
                source=source,
                destination=destination,
                table=table_name(item.get("table"), default="unspecified"),
                selectors=selectors,
            )
        )

    return sorted(candidates, key=lambda rule: rule.priority)


def parse_matching_routes(flow: Flow, routes: list[dict[str, Any]]) -> list[Route]:
    destination = ipaddress.ip_address(flow.destination)
    matches: list[tuple[int, Route]] = []

    for item in routes:
        raw_dst = str(item.get("dst", "default"))
        try:
            network = _network(raw_dst, destination.version)
        except ValueError:
            continue
        if destination not in network:
            continue

        route = Route(
            destination=raw_dst,
            gateway=item.get("gateway"),
            dev=item.get("dev"),
            table=table_name(item.get("table")),
            metric=item.get("metric"),
            raw=item,
        )
        matches.append((network.prefixlen, route))

    matches.sort(key=lambda pair: (-pair[0], pair[1].table, pair[1].metric or 0))
    return [route for _, route in matches]


def detect_overlays(links: list[dict[str, Any]]) -> list[str]:
    names: list[str] = []
    for item in links:
        name = str(item.get("ifname", ""))
        lowered = name.casefold()
        if any(lowered.startswith(prefix) for prefix in OVERLAY_PREFIXES):
            names.append(name)
    return sorted(set(names))


def _same_route(decision: RouteDecision, route: Route) -> bool:
    if route.table != decision.table:
        return False
    if decision.dev and route.dev != decision.dev:
        return False
    if decision.gateway and route.gateway != decision.gateway:
        return False
    return True


def build_report(
    flow: Flow,
    *,
    route_get: list[dict[str, Any]],
    rules: list[dict[str, Any]],
    routes: list[dict[str, Any]],
    links: list[dict[str, Any]],
) -> Report:
    decision = parse_decision(flow, route_get)
    candidate_rules = parse_rules(flow, rules)
    matching_routes = parse_matching_routes(flow, routes)
    overlays = detect_overlays(links)
    notes: list[str] = []

    unused_overlays = [name for name in overlays if name != decision.dev]
    if unused_overlays:
        notes.append(f"overlay interface(s) present but not selected: {', '.join(unused_overlays)}")

    other_tables = sorted(
        {
            route.table
            for route in matching_routes
            if route.table != decision.table and not _same_route(decision, route)
        }
    )
    if other_tables:
        notes.append(f"matching routes also exist in other table(s): {', '.join(other_tables)}")

    advanced_rules = [
        rule for rule in candidate_rules if rule.selectors
    ]
    if advanced_rules:
        notes.append(
            "some candidate policy rules contain advanced selectors that v0.1 does not fully evaluate"
        )

    notes.append("firewall/NAT policy is not evaluated in v0.1; no verdict is fabricated")

    return Report(
        flow=flow,
        decision=decision,
        candidate_rules=candidate_rules,
        matching_routes=matching_routes,
        overlays=overlays,
        notes=notes,
    )
