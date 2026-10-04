from __future__ import annotations

from typing import Any

from .analyze import table_name
from .model import DoctorFinding

BUILTIN_TABLES = {"local", "main", "default", "unspecified"}


def _route_table(item: dict[str, Any]) -> str:
    return table_name(item.get("table"))


def _rule_table(item: dict[str, Any]) -> str | None:
    if item.get("table") is None:
        return None
    return table_name(item.get("table"))


def _default_routes(routes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [item for item in routes if str(item.get("dst", "default")) == "default"]


def _route_label(item: dict[str, Any]) -> str:
    table = _route_table(item)
    dev = f" dev {item['dev']}" if item.get("dev") else ""
    gateway = f" via {item['gateway']}" if item.get("gateway") else ""
    return f"{item.get('dst', 'default')}{gateway}{dev} table {table}"


def _links_by_kind(links: list[dict[str, Any]], kind: str) -> list[str]:
    result = []
    for item in links:
        info_kind = str((item.get("linkinfo") or {}).get("info_kind", ""))
        if info_kind == kind and item.get("ifname"):
            result.append(str(item["ifname"]))
    return result


def diagnose_snapshot(snapshot: dict[str, Any]) -> list[DoctorFinding]:
    state = snapshot.get("state") or {}
    findings: list[DoctorFinding] = []

    for version, rules_key, routes_key in (
        (4, "rules_v4", "routes_v4"),
        (6, "rules_v6", "routes_v6"),
    ):
        rules = list(state.get(rules_key) or [])
        routes = list(state.get(routes_key) or [])
        rule_tables = {_rule_table(item) for item in rules if _rule_table(item)}
        route_tables = {_route_table(item) for item in routes}
        orphan_tables = sorted(
            table for table in route_tables - rule_tables if table not in BUILTIN_TABLES
        )
        for table in orphan_tables:
            findings.append(
                DoctorFinding(
                    "check",
                    f"ipv{version}.table-without-rule",
                    f"table {table} contains IPv{version} routes but no RPDB rule explicitly references it",
                )
            )

        defaults = _default_routes(routes)
        default_tables = sorted({_route_table(item) for item in defaults})
        if len(default_tables) > 1:
            findings.append(
                DoctorFinding(
                    "info",
                    f"ipv{version}.multiple-default-tables",
                    f"default routes exist in multiple tables: {', '.join(default_tables)}",
                )
            )

        mark_rules = [item for item in rules if "fwmark" in item]
        if mark_rules:
            priorities = ", ".join(str(item.get("priority", 0)) for item in mark_rules[:8])
            findings.append(
                DoctorFinding(
                    "info",
                    f"ipv{version}.fwmark-routing",
                    f"fwmark-based policy routing is active at priority {priorities}; nft trace can reveal where packet marks change",
                )
            )

        modifier_rules = [
            item
            for item in rules
            if any(
                key in item
                for key in (
                    "suppress_prefixlen",
                    "suppress_prefixlength",
                    "suppress_ifgroup",
                    "goto",
                    "l3mdev",
                )
            )
        ]
        if modifier_rules:
            findings.append(
                DoctorFinding(
                    "info",
                    f"ipv{version}.advanced-rpdb",
                    f"{len(modifier_rules)} RPDB rule(s) use suppress/goto/l3mdev semantics; selector output is context, not a full RPDB execution trace",
                )
            )

        blackholes = [
            item
            for item in routes
            if str(item.get("type", "unicast")) in {"blackhole", "unreachable", "prohibit", "throw"}
        ]
        for item in blackholes[:8]:
            findings.append(
                DoctorFinding(
                    "info",
                    f"ipv{version}.special-route",
                    f"special route present: {_route_label(item)} type {item.get('type')}",
                )
            )

    links = list(state.get("links") or [])
    vrfs = _links_by_kind(links, "vrf")

    bridges = _links_by_kind(links, "bridge")
    veths = _links_by_kind(links, "veth")
    if bridges:
        findings.append(
            DoctorFinding(
                "info",
                "links.bridge",
                f"bridge device(s) present: {', '.join(sorted(bridges))}; use --netns/--pid when the interesting route lives behind a container namespace",
            )
        )
    if veths:
        findings.append(
            DoctorFinding(
                "info",
                "links.veth",
                f"{len(veths)} veth interface(s) detected, suggesting container or namespace networking context",
            )
        )
    if vrfs:
        findings.append(
            DoctorFinding(
                "info",
                "links.vrf",
                f"VRF device(s) present: {', '.join(sorted(vrfs))}",
            )
        )

    overlays = state.get("overlays") or {}
    all_routes = list(state.get("routes_v4") or []) + list(state.get("routes_v6") or [])
    for kind in ("wireguard", "tailscale"):
        section = overlays.get(kind) or {}
        if not section.get("available"):
            reason = section.get("reason")
            if reason:
                findings.append(
                    DoctorFinding(
                        "info",
                        f"overlay.{kind}.unavailable",
                        f"{kind} context unavailable: {reason}",
                    )
                )
            continue
        overlay_routes = section.get("routes") or []
        if overlay_routes:
            findings.append(
                DoctorFinding(
                    "info",
                    f"overlay.{kind}.routes",
                    f"{kind} reports {len(overlay_routes)} prefix assignment(s)",
                )
            )
        for overlay in overlay_routes[:32]:
            prefix = str(overlay.get("prefix", ""))
            interface = str(overlay.get("interface", ""))
            if not prefix or not interface:
                continue
            matching_kernel = [
                route
                for route in all_routes
                if str(route.get("dst", "default")) == prefix and route.get("dev") == interface
            ]
            if not matching_kernel:
                findings.append(
                    DoctorFinding(
                        "check",
                        f"overlay.{kind}.prefix-without-route",
                        f"{kind} metadata covers {prefix} on {interface}, but no identical kernel route was found on that interface",
                    )
                )

    tailscale = overlays.get("tailscale") or {}
    backend_state = tailscale.get("backend_state")
    if tailscale.get("available") and backend_state not in {None, "Running"}:
        findings.append(
            DoctorFinding(
                "check",
                "overlay.tailscale.backend",
                f"Tailscale backend state is {backend_state!r}, not Running",
            )
        )

    if not snapshot.get("probes"):
        findings.append(
            DoctorFinding(
                "info",
                "snapshot.no-probes",
                "snapshot contains topology/state only; add --probe DEST to capture replayable kernel decisions",
            )
        )

    if not any(item.level == "check" for item in findings):
        findings.append(
            DoctorFinding(
                "ok",
                "summary.no-obvious-conflicts",
                "no obvious route-table/RPDB conflicts were detected by the current doctor checks",
            )
        )
    return findings
