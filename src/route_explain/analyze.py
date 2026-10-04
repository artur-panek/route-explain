from __future__ import annotations

import ipaddress
from contextlib import suppress
from typing import Any

from .model import Evidence, Flow, PolicyRule, Report, Route, RouteDecision

TABLE_NAMES = {
    253: "default",
    254: "main",
    255: "local",
}
OVERLAY_PREFIXES = ("tailscale", "wg", "wireguard", "tun", "nebula", "zt", "headscale")
PROTOCOL_NUMBERS = {
    "icmp": 1,
    "tcp": 6,
    "udp": 17,
    "icmpv6": 58,
}
SELECTOR_KEYS = {
    "tos",
    "fwmark",
    "fwmask",
    "iif",
    "oif",
    "uidrange",
    "ipproto",
    "sport",
    "dport",
    "tun_id",
    "l3mdev",
    "not",
}
MODIFIER_KEYS = {"suppress_prefixlen", "suppress_prefixlength", "suppress_ifgroup", "goto", "nat", "realms", "nop"}


def table_name(value: Any, *, default: str = "main") -> str:
    if value is None:
        return default
    if isinstance(value, int):
        return TABLE_NAMES.get(value, str(value))
    text = str(value)
    if text.isdigit():
        return TABLE_NAMES.get(int(text), text)
    return text


def _network(value: str, version: int) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
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


def _rule_prefix(item: dict[str, Any], key: str, version: int) -> str:
    raw = str(item.get(key, "all"))
    if raw in {"all", "default"} or "/" in raw:
        return raw
    length = item.get(f"{key}len")
    if length is None:
        return raw
    try:
        prefixlen = int(length)
        return str(ipaddress.ip_network(f"{raw}/{prefixlen}", strict=False))
    except (TypeError, ValueError):
        return raw


def _as_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    text = str(value).strip()
    try:
        return int(text, 0)
    except ValueError:
        try:
            return int(text)
        except ValueError:
            return None


def _protocol_number(value: Any) -> int | None:
    if value is None:
        return None
    number = _as_int(value)
    if number is not None:
        return number
    return PROTOCOL_NUMBERS.get(str(value).casefold())


def _range_matches(selector: Any, value: int | None) -> bool | None:
    if value is None:
        return None
    if isinstance(selector, int):
        return value == selector
    text = str(selector).strip()
    if "-" not in text:
        parsed = _as_int(text)
        return None if parsed is None else value == parsed
    start_text, end_text = text.split("-", 1)
    start = _as_int(start_text)
    end = _as_int(end_text)
    if start is None or end is None:
        return None
    return start <= value <= end


def _selector_result(item: dict[str, Any], flow: Flow) -> tuple[bool | None, tuple[str, ...]]:
    """Return selector truth and selectors that could not be evaluated.

    True means every known selector matches. False means at least one known selector
    definitely does not match. None means no known selector mismatched, but one or more
    selectors could not be evaluated from the provided flow metadata.
    """

    version = ipaddress.ip_address(flow.destination).version
    unknown: list[str] = []
    results: list[bool] = [
        _address_matches(_rule_prefix(item, "src", version), flow.source, version),
        _address_matches(_rule_prefix(item, "dst", version), flow.destination, version),
    ]

    if "iif" in item:
        if flow.iif is None:
            unknown.append("iif")
        else:
            results.append(str(item["iif"]) == flow.iif)

    if "oif" in item:
        if flow.oif is None:
            unknown.append("oif")
        else:
            results.append(str(item["oif"]) == flow.oif)

    if "fwmark" in item:
        rule_mark = _as_int(item.get("fwmark"))
        mask = _as_int(item.get("fwmask"))
        if mask is None:
            mask = 0xFFFFFFFF
        if flow.mark is None or rule_mark is None:
            unknown.append("fwmark")
        else:
            results.append((flow.mark & mask) == (rule_mark & mask))

    if "tos" in item:
        rule_tos = _as_int(item.get("tos"))
        if flow.tos is None or rule_tos is None:
            unknown.append("tos")
        else:
            results.append(flow.tos == rule_tos)

    if "ipproto" in item:
        rule_proto = _protocol_number(item.get("ipproto"))
        flow_proto = _protocol_number(flow.protocol)
        if rule_proto is None or flow_proto is None:
            unknown.append("ipproto")
        else:
            results.append(rule_proto == flow_proto)

    for key, value in (("sport", flow.source_port), ("dport", flow.destination_port)):
        if key in item:
            result = _range_matches(item[key], value)
            if result is None:
                unknown.append(key)
            else:
                results.append(result)

    # These selectors need state we intentionally do not synthesize yet.
    for key in ("uidrange", "tun_id", "l3mdev"):
        if key in item:
            unknown.append(key)

    if any(result is False for result in results):
        base: bool | None = False
    elif unknown:
        base = None
    else:
        base = True

    # iproute2 JSON represents `not` as a key with a null value, so presence matters.
    if "not" in item and base is not None:
        base = not base

    unresolved = tuple(sorted(set(unknown))) if base is None else ()
    return base, unresolved


def parse_decision(
    flow: Flow,
    route_get: list[dict[str, Any]],
    fibmatch: list[dict[str, Any]] | None = None,
) -> RouteDecision:
    if not route_get:
        raise ValueError("kernel returned no route for the destination")

    item = route_get[0]
    fib = fibmatch[0] if fibmatch else {}
    route_type = str(fib.get("type") or item.get("type") or "unicast")
    return RouteDecision(
        destination=str(item.get("dst", flow.destination)),
        gateway=item.get("gateway"),
        dev=item.get("dev"),
        source=item.get("prefsrc") or item.get("src") or flow.source,
        table=table_name(item.get("table") if "table" in item else fib.get("table")),
        matched_prefix=str(fib["dst"]) if fib.get("dst") is not None else None,
        route_type=route_type,
        metric=fib.get("metric") if fib.get("metric") is not None else item.get("metric"),
        raw=item,
        fibmatch_raw=fib,
    )


def parse_rules(flow: Flow, rules: list[dict[str, Any]]) -> list[PolicyRule]:
    version = ipaddress.ip_address(flow.destination).version
    candidates: list[PolicyRule] = []

    for item in rules:
        source = _rule_prefix(item, "src", version)
        destination = _rule_prefix(item, "dst", version)
        selector_result, unknown = _selector_result(item, flow)
        if selector_result is False:
            continue

        selectors = {key: item[key] for key in SELECTOR_KEYS if key in item and key != "not"}
        modifiers = {key: item[key] for key in MODIFIER_KEYS if key in item}
        if item.get("table") is not None:
            action = "lookup"
        elif "goto" in item:
            action = f"goto {item['goto']}"
        elif "nop" in item:
            action = "nop"
        else:
            action = str(item.get("action") or "unspecified")

        candidates.append(
            PolicyRule(
                priority=int(item.get("priority", 0)),
                source=source,
                destination=destination,
                table=table_name(item.get("table"), default="unspecified"),
                action=action,
                certainty="match" if selector_result is True else "indeterminate",
                inverted="not" in item,
                selectors=selectors,
                unknown_selectors=unknown,
                modifiers=modifiers,
                raw=item,
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
            route_type=str(item.get("type", "unicast")),
            protocol=str(item["protocol"]) if item.get("protocol") is not None else None,
            scope=str(item["scope"]) if item.get("scope") is not None else None,
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
        link_kind = str((item.get("linkinfo") or {}).get("info_kind", "")).casefold()
        if any(lowered.startswith(prefix) for prefix in OVERLAY_PREFIXES) or link_kind in {
            "wireguard",
            "tun",
        }:
            names.append(name)
    return sorted({name for name in names if name})


def _route_prefixlen(route: Route, version: int) -> int:
    try:
        return _network(route.destination, version).prefixlen
    except ValueError:
        return -1


def _build_evidence(
    flow: Flow,
    decision: RouteDecision,
    candidate_rules: list[PolicyRule],
    matching_routes: list[Route],
    overlays: list[str],
) -> list[Evidence]:
    evidence = [
        Evidence(
            "kernel",
            f"kernel resolved the flow through table {decision.table}"
            + (f" on {decision.dev}" if decision.dev else ""),
        )
    ]

    if decision.matched_prefix:
        evidence.append(
            Evidence(
                "kernel",
                f"fibmatch selected prefix {decision.matched_prefix} in table {decision.table}",
            )
        )

    selected_table_rules = [
        rule for rule in candidate_rules if rule.table == decision.table and rule.action == "lookup"
    ]
    certain = [rule for rule in selected_table_rules if rule.certainty == "match"]
    uncertain = [rule for rule in selected_table_rules if rule.certainty == "indeterminate"]
    if certain:
        priorities = ", ".join(str(rule.priority) for rule in certain)
        evidence.append(
            Evidence(
                "derived",
                f"policy rule selector(s) at priority {priorities} match and reference the selected table",
            )
        )
    elif uncertain:
        priorities = ", ".join(str(rule.priority) for rule in uncertain)
        evidence.append(
            Evidence(
                "caution",
                f"rule(s) at priority {priorities} reference the selected table but need missing selector context",
            )
        )

    version = ipaddress.ip_address(flow.destination).version
    selected_prefixlen = -1
    if decision.matched_prefix:
        with suppress(ValueError):
            selected_prefixlen = _network(decision.matched_prefix, version).prefixlen

    competitors = [
        route
        for route in matching_routes
        if route.table != decision.table and _route_prefixlen(route, version) > selected_prefixlen
    ]
    if competitors:
        best = max(competitors, key=lambda route: _route_prefixlen(route, version))
        evidence.append(
            Evidence(
                "caution",
                f"a more-specific route exists in table {best.table}: {best.destination}"
                + (f" via {best.dev}" if best.dev else "")
                + "; policy routing kept it out of the selected path",
            )
        )
    else:
        other_tables = sorted({route.table for route in matching_routes if route.table != decision.table})
        if other_tables:
            evidence.append(
                Evidence(
                    "derived",
                    f"matching route context also exists in table(s): {', '.join(other_tables)}",
                )
            )

    unused_overlays = [name for name in overlays if name != decision.dev]
    if unused_overlays:
        evidence.append(
            Evidence(
                "derived",
                f"overlay interface(s) are present but not selected: {', '.join(unused_overlays)}",
            )
        )

    indeterminate = [rule for rule in candidate_rules if rule.certainty == "indeterminate"]
    if indeterminate:
        details = sorted({selector for rule in indeterminate for selector in rule.unknown_selectors})
        evidence.append(
            Evidence(
                "caution",
                "some policy-rule candidates remain indeterminate because the flow lacks: "
                + ", ".join(details),
            )
        )

    evidence.append(
        Evidence(
            "caution",
            "firewall, NAT, conntrack, and packet-mark mutation are not traced; routing evidence stops at the FIB/RPDB boundary",
        )
    )
    return evidence


def build_report(
    flow: Flow,
    *,
    route_get: list[dict[str, Any]],
    fibmatch: list[dict[str, Any]] | None = None,
    rules: list[dict[str, Any]],
    routes: list[dict[str, Any]],
    links: list[dict[str, Any]],
) -> Report:
    decision = parse_decision(flow, route_get, fibmatch)
    candidate_rules = parse_rules(flow, rules)
    matching_routes = parse_matching_routes(flow, routes)
    overlays = detect_overlays(links)
    evidence = _build_evidence(flow, decision, candidate_rules, matching_routes, overlays)

    notes: list[str] = []
    if not fibmatch:
        notes.append("fibmatch evidence was unavailable; exact selected route prefix is unknown")
    if any(rule.modifiers for rule in candidate_rules):
        notes.append("one or more matching rules use RPDB action modifiers; read them as context, not a simulated rule trace")

    return Report(
        flow=flow,
        decision=decision,
        candidate_rules=candidate_rules,
        matching_routes=matching_routes,
        overlays=overlays,
        evidence=evidence,
        notes=notes,
    )
