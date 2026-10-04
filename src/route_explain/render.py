from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from typing import Any

from .model import (
    ContextReport,
    DoctorFinding,
    PolicyRule,
    Report,
    Route,
    TraceReport,
    WhyNotResult,
)

SCHEMA_VERSION = 3


def _json_default(value: Any) -> Any:
    if is_dataclass(value):
        return asdict(value)
    raise TypeError(f"cannot serialize {type(value)!r}")


def render_json(value: Any, *, schema_name: str = "report") -> str:
    if is_dataclass(value):
        payload = asdict(value)
    else:
        payload = value
    if isinstance(payload, dict):
        payload = {"schema_version": SCHEMA_VERSION, "schema": schema_name, **payload}
    return json.dumps(payload, indent=2, sort_keys=True, default=_json_default)


def _flow_label(report: Report | ContextReport) -> str:
    flow = report.flow
    target = flow.destination
    if flow.destination_port is not None:
        target = f"{target}:{flow.destination_port}"
    source = f" from {flow.source}" if flow.source else ""
    if flow.source_port is not None:
        source += f":{flow.source_port}"
    return f"{flow.protocol} {target}{source}"


def _flow_context(report: Report | ContextReport) -> list[str]:
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
    if report.namespace:
        parts.append(f"namespace={report.namespace}")
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


def _rule_line(rule: PolicyRule, selected_table: str | None) -> str:
    status = "MATCH" if rule.certainty == "match" else "MAYBE"
    action = f"lookup {rule.table}" if rule.action == "lookup" else rule.action
    prefix = "not " if rule.inverted else ""
    suffix: list[str] = []
    if rule.selectors:
        suffix.append(", ".join(f"{key}={value}" for key, value in sorted(rule.selectors.items())))
    if rule.unknown_selectors:
        suffix.append("needs " + ", ".join(rule.unknown_selectors))
    if rule.modifiers:
        suffix.append(", ".join(f"{key}={value}" for key, value in sorted(rule.modifiers.items())))
    if selected_table and rule.table == selected_table:
        suffix.append("selected table")
    detail = f" [{'; '.join(suffix)}]" if suffix else ""
    return (
        f"  {status:<5} {rule.priority}: {prefix}from {rule.source} to {rule.destination} "
        f"{action}{detail}"
    )


def _render_routes(report: Report | ContextReport) -> list[str]:
    lines = ["", "Matching routes across all tables"]
    if not report.matching_routes:
        return [*lines, "  none found"]
    for route in report.matching_routes:
        marker = "*" if isinstance(report, Report) and _route_is_selected(report, route) else " "
        via = f" via {route.gateway}" if route.gateway else ""
        dev = f" dev {route.dev}" if route.dev else ""
        metric = f" metric {route.metric}" if route.metric is not None else ""
        rtype = "" if route.route_type == "unicast" else f" type {route.route_type}"
        lines.append(f" {marker} {route.destination}{via}{dev} table {route.table}{metric}{rtype}")
    return lines


def render_text(report: Report | ContextReport) -> str:
    lines = ["ROUTE-EXPLAIN", f"flow:  {_flow_label(report)}"]
    context = _flow_context(report)
    if context:
        lines.append("meta:  " + "  ".join(context))

    selected_table: str | None = None
    if isinstance(report, Report):
        decision = report.decision
        selected_table = decision.table
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
    else:
        lines.extend(["", "Kernel decision", "  not recorded for this exact snapshot flow"])

    lines.extend(["", "Why this path" if isinstance(report, Report) else "Snapshot context"])
    labels = {"kernel": "KERNEL", "derived": "INFO", "caution": "CHECK"}
    for item in report.evidence:
        lines.append(f"  {labels[item.level]:<6} {item.message}")

    lines.extend(["", "Policy-rule candidates"])
    if report.candidate_rules:
        for rule in report.candidate_rules:
            lines.append(_rule_line(rule, selected_table))
    else:
        lines.append("  none found")
    lines.append(
        "  note: MATCH means the selector matches, not that the rule necessarily terminated the RPDB walk"
    )
    lines.extend(_render_routes(report))

    if report.notes:
        lines.extend(["", "Notes"])
        lines.extend(f"  - {note}" for note in report.notes)
    return "\n".join(lines)


def render_why_not(result: WhyNotResult) -> str:
    labels = {"kernel": "KERNEL", "derived": "INFO", "caution": "CHECK"}
    lines = [f"WHY NOT {result.target}?", f"status: {result.status}", ""]
    lines.extend(f"  {labels[item.level]:<6} {item.message}" for item in result.evidence)
    return "\n".join(lines)


def render_doctor(findings: list[DoctorFinding], *, namespace: str | None = None) -> str:
    lines = ["ROUTE-EXPLAIN DOCTOR"]
    if namespace:
        lines.append(f"namespace: {namespace}")
    lines.append("")
    labels = {"ok": "OK", "info": "INFO", "check": "CHECK"}
    for finding in findings:
        lines.append(f"  {labels[finding.level]:<5} {finding.message}  [{finding.code}]")
    return "\n".join(lines)


def _render_diff_list(lines: list[str], title: str, added: list[str], removed: list[str]) -> None:
    if not added and not removed:
        return
    lines.extend(["", title])
    lines.extend(f"  + {item}" for item in added)
    lines.extend(f"  - {item}" for item in removed)


def render_diff(diff: dict[str, Any]) -> str:
    lines = ["ROUTE-EXPLAIN DIFF"]
    if diff.get("destination"):
        lines.append(f"destination: {diff['destination']}")
    changes = diff.get("decision_changes") or []
    if changes:
        lines.extend(["", "Kernel decision changes"])
        for change in changes:
            flow = change.get("flow") or {}
            before = change.get("before")
            after = change.get("after")
            lines.append(f"  flow: {flow.get('destination')}")
            lines.append(f"    before: {before}")
            lines.append(f"    after:  {after}")

    _render_diff_list(lines, "Routes", diff.get("added_routes") or [], diff.get("removed_routes") or [])
    _render_diff_list(lines, "Policy rules", diff.get("added_rules") or [], diff.get("removed_rules") or [])
    _render_diff_list(lines, "Links", diff.get("added_links") or [], diff.get("removed_links") or [])
    _render_diff_list(
        lines,
        "Overlay metadata",
        diff.get("added_overlay_routes") or [],
        diff.get("removed_overlay_routes") or [],
    )
    if len(lines) <= 2:
        lines.extend(["", "  no relevant changes"])
    return "\n".join(lines)


def _mark_values(value: Any) -> list[str]:
    result: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if "mark" in str(key).casefold() and isinstance(child, (str, int)):
                result.append(f"{key}={child}")
            result.extend(_mark_values(child))
    elif isinstance(value, list):
        for child in value:
            result.extend(_mark_values(child))
    return result


def render_trace(report: TraceReport) -> str:
    lines = ["ROUTE-EXPLAIN NFT TRACE"]
    if report.namespace:
        lines.append(f"namespace: {report.namespace}")
    lines.append(f"events: {len(report.events)}")
    if report.command_exit_code is not None:
        lines.append(f"probe command exit: {report.command_exit_code}")
    lines.append("")
    for event in report.events:
        location = "/".join(part for part in (event.family, event.table, event.chain) if part)
        bits = [event.event or "trace"]
        if event.verdict:
            bits.append(f"verdict={event.verdict}")
        marks = sorted(set(_mark_values(event.raw)))
        if marks:
            bits.append("marks=" + ",".join(marks[:4]))
        trace_id = f"id={event.trace_id} " if event.trace_id else ""
        lines.append(f"  {trace_id}{location or '-'}  {' '.join(bits)}")
    if report.notes:
        lines.extend(["", "Notes"])
        lines.extend(f"  - {note}" for note in report.notes)
    return "\n".join(lines)
