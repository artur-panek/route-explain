from __future__ import annotations

import json
from dataclasses import asdict

from .model import Report, Route


def _flow_label(report: Report) -> str:
    flow = report.flow
    target = flow.destination
    if flow.port is not None:
        target = f"{target}:{flow.port}"
    source = f" from {flow.source}" if flow.source else ""
    return f"{flow.protocol} {target}{source}"


def _route_is_selected(report: Report, route: Route) -> bool:
    decision = report.decision
    return (
        route.table == decision.table
        and (not decision.dev or route.dev == decision.dev)
        and (not decision.gateway or route.gateway == decision.gateway)
    )


def render_text(report: Report) -> str:
    decision = report.decision
    lines = [
        "ROUTE-EXPLAIN",
        f"flow:  {_flow_label(report)}",
        "",
        "Kernel routing decision",
        f"  destination: {decision.destination}",
        f"  via:         {decision.gateway or '-'}",
        f"  dev:         {decision.dev or '-'}",
        f"  source:      {decision.source or '-'}",
        f"  table:       {decision.table}",
        "",
        "Candidate policy rule(s)",
    ]

    if report.candidate_rules:
        for rule in report.candidate_rules:
            suffix = ""
            if rule.selectors:
                selector_text = ", ".join(
                    f"{key}={value}" for key, value in sorted(rule.selectors.items())
                )
                suffix = f" [{selector_text}]"
            lines.append(
                f"  {rule.priority}: from {rule.source} to {rule.destination} "
                f"lookup {rule.table}{suffix}"
            )
    else:
        lines.append("  none found")

    lines.extend(["", "Matching routes across all tables"])
    if report.matching_routes:
        for route in report.matching_routes:
            marker = "*" if _route_is_selected(report, route) else " "
            via = f" via {route.gateway}" if route.gateway else ""
            dev = f" dev {route.dev}" if route.dev else ""
            metric = f" metric {route.metric}" if route.metric is not None else ""
            lines.append(
                f" {marker} {route.destination}{via}{dev} table {route.table}{metric}"
            )
    else:
        lines.append("  none found")

    lines.extend(["", "Notes"])
    for note in report.notes:
        lines.append(f"  - {note}")

    return "\n".join(lines)


def render_json(report: Report) -> str:
    return json.dumps(asdict(report), indent=2, sort_keys=True)
