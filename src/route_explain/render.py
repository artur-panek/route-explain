from __future__ import annotations

import json
from dataclasses import asdict

from .model import PolicyRule, Report, Route

SCHEMA_VERSION = 2


def _flow_label(report: Report) -> str:
    flow = report.flow
    target = flow.destination
    if flow.destination_port is not None:
        target = f"{target}:{flow.destination_port}"
    source = f" from {flow.source}" if flow.source else ""
    if flow.source_port is not None:
        source += f":{flow.source_port}"
    return f"{flow.protocol} {target}{source}"


def _flow_context(report: Report) -> list[str]:
    flow = report.flow
    parts: list[str] = []
    if flow.mark is not None:
        parts.append(f"mark={hex(flow.mark)}")
    if flow.tos is not None:
        parts.append(f"tos={hex(flow.tos)}")
    if flow.iif:
        parts.append(f"iif={flow.iif}")
    if flow.oif:
        parts.append(f"oif={flow.oif}")
    if flow.vrf:
        parts.append(f"vrf={flow.vrf}")
    return parts


def _route_is_selected(report: Report, route: Route) -> bool:
    decision = report.decision
    if route.table != decision.table:
        return False
    if decision.matched_prefix is not None and route.destination != decision.matched_prefix:
        return False
    if decision.dev and route.dev != decision.dev:
        return False
    return not decision.gateway or route.gateway == decision.gateway


def _rule_line(rule: PolicyRule, selected_table: str) -> str:
    status = "MATCH" if rule.certainty == "match" else "MAYBE"
    action = f"lookup {rule.table}" if rule.action == "lookup" else rule.action
    prefix = "not " if rule.inverted else ""
    suffix: list[str] = []
    if rule.selectors:
        selector_text = ", ".join(f"{key}={value}" for key, value in sorted(rule.selectors.items()))
        suffix.append(selector_text)
    if rule.unknown_selectors:
        suffix.append("needs " + ", ".join(rule.unknown_selectors))
    if rule.modifiers:
        modifier_text = ", ".join(f"{key}={value}" for key, value in sorted(rule.modifiers.items()))
        suffix.append(modifier_text)
    if rule.table == selected_table:
        suffix.append("selected table")
    detail = f" [{'; '.join(suffix)}]" if suffix else ""
    return (
        f"  {status:<5} {rule.priority}: {prefix}from {rule.source} to {rule.destination} "
        f"{action}{detail}"
    )


def render_text(report: Report) -> str:
    decision = report.decision
    lines = [
        "ROUTE-EXPLAIN",
        f"flow:  {_flow_label(report)}",
    ]
    context = _flow_context(report)
    if context:
        lines.append("meta:  " + "  ".join(context))

    lines.extend(
        [
            "",
            "Kernel decision",
            f"  destination:    {decision.destination}",
            f"  matched prefix: {decision.matched_prefix or '?'}",
            f"  route type:     {decision.route_type}",
            f"  via:            {decision.gateway or '-'}",
            f"  dev:            {decision.dev or '-'}",
            f"  source:         {decision.source or '-'}",
            f"  table:          {decision.table}",
        ]
    )
    if decision.metric is not None:
        lines.append(f"  metric:         {decision.metric}")

    lines.extend(["", "Why this path"])
    icons = {"kernel": "KERNEL", "derived": "INFO", "caution": "CHECK"}
    for item in report.evidence:
        lines.append(f"  {icons[item.level]:<6} {item.message}")

    lines.extend(["", "Policy-rule candidates"])
    if report.candidate_rules:
        for rule in report.candidate_rules:
            lines.append(_rule_line(rule, decision.table))
    else:
        lines.append("  none found")
    lines.append("  note: MATCH means the selector matches, not that the rule necessarily terminated the RPDB walk")

    lines.extend(["", "Matching routes across all tables"])
    if report.matching_routes:
        for route in report.matching_routes:
            marker = "*" if _route_is_selected(report, route) else " "
            via = f" via {route.gateway}" if route.gateway else ""
            dev = f" dev {route.dev}" if route.dev else ""
            metric = f" metric {route.metric}" if route.metric is not None else ""
            rtype = "" if route.route_type == "unicast" else f" type {route.route_type}"
            lines.append(
                f" {marker} {route.destination}{via}{dev} table {route.table}{metric}{rtype}"
            )
    else:
        lines.append("  none found")

    if report.notes:
        lines.extend(["", "Notes"])
        for note in report.notes:
            lines.append(f"  - {note}")

    return "\n".join(lines)


def render_json(report: Report) -> str:
    return json.dumps(
        {"schema_version": SCHEMA_VERSION, **asdict(report)},
        indent=2,
        sort_keys=True,
    )
