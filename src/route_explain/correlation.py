from __future__ import annotations

import json
from dataclasses import asdict, replace
from typing import Any

from .analyze import build_report
from .collect import CollectionError, collect_route_get
from .context import ExecutionContext
from .model import Flow, RouteDecision
from .snapshot import capture_snapshot, report_from_snapshot

CORRELATION_NOTE = (
    "A correlated kernel lookup proves the routing result for the observed selectors; "
    "it does not by itself prove that the kernel performed a reroute at that nftables hook."
)


def extract_observations(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    state_by_trace: dict[str, dict[str, Any]] = {}
    last_emitted: dict[str, tuple[int | None, str | None, str | None]] = {}

    for event in events:
        trace_id = str(event.get("trace_id", ""))
        state = state_by_trace.setdefault(
            trace_id,
            {"mark": None, "iif": None, "oif": None},
        )

        packet = event.get("packet")
        if isinstance(packet, dict):
            if packet.get("iif"):
                state["iif"] = packet["iif"]
            if packet.get("oif"):
                state["oif"] = packet["oif"]

        if isinstance(event.get("mark"), int):
            state["mark"] = event["mark"]

        selectors = (state["mark"], state["iif"], state["oif"])
        if state["mark"] is None and state["iif"] is None:
            continue
        if last_emitted.get(trace_id) == selectors:
            continue

        observations.append(
            {
                "trace_id": trace_id,
                "mark": state["mark"],
                "iif": state["iif"],
                "oif": state["oif"],
                "family": event.get("family"),
                "table": event.get("table"),
                "chain": event.get("chain"),
                "type": event.get("type"),
                "rule": event.get("rule"),
                "verdict": event.get("verdict"),
                "raw": event.get("raw"),
            }
        )
        last_emitted[trace_id] = selectors

    return observations


def _decision_changed(before: RouteDecision, after: RouteDecision) -> bool:
    return any(
        (
            before.table != after.table,
            before.matched_prefix != after.matched_prefix,
            before.dev != after.dev,
            before.gateway != after.gateway,
            before.source != after.source,
            before.route_type != after.route_type,
        )
    )


def _probe(
    flow: Flow,
    context: ExecutionContext,
    baseline_snapshot: dict[str, Any],
) -> RouteDecision:
    route_get = collect_route_get(flow, context=context)
    try:
        fibmatch = collect_route_get(flow, fibmatch=True, context=context)
    except CollectionError:
        fibmatch = None
    evidence = baseline_snapshot["evidence"]
    return build_report(
        flow,
        route_get=route_get,
        fibmatch=fibmatch,
        rules=evidence["rules"],
        routes=evidence["routes"],
        links=evidence["links"],
    ).decision


def correlate_trace(
    flow: Flow,
    events: list[dict[str, Any]],
    context: ExecutionContext,
    *,
    baseline_snapshot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    snapshot = baseline_snapshot if baseline_snapshot is not None else capture_snapshot(flow, context)
    baseline = report_from_snapshot(snapshot).decision
    lookups: list[dict[str, Any]] = []

    for observation in extract_observations(events):
        lookup_flow = replace(
            flow,
            mark=observation["mark"] if observation["mark"] is not None else flow.mark,
            iif=observation["iif"] or flow.iif,
        )
        item: dict[str, Any] = {
            "observation": observation,
            "lookup_flow": asdict(lookup_flow),
        }
        try:
            decision = _probe(lookup_flow, context, snapshot)
        except (CollectionError, ValueError) as exc:
            item.update({"decision": None, "decision_changed": None, "error": str(exc)})
        else:
            item.update(
                {
                    "decision": asdict(decision),
                    "decision_changed": _decision_changed(baseline, decision),
                    "error": None,
                }
            )
        lookups.append(item)

    return {
        "schema_version": 2,
        "baseline": asdict(baseline),
        "lookups": lookups,
        "note": CORRELATION_NOTE,
    }


def _decision_label(decision: dict[str, Any]) -> str:
    parts = [f"table {decision['table']}"]
    if decision.get("matched_prefix"):
        parts.append(f"prefix {decision['matched_prefix']}")
    if decision.get("dev"):
        parts.append(f"dev {decision['dev']}")
    if decision.get("gateway"):
        parts.append(f"via {decision['gateway']}")
    return " · ".join(parts)


def render_correlation(correlation: dict[str, Any]) -> str:
    lines = [
        "ROUTE-EXPLAIN TRACE CORRELATION",
        "",
        f"Baseline kernel lookup: {_decision_label(correlation['baseline'])}",
    ]
    if not correlation["lookups"]:
        lines.extend(
            [
                "",
                "CHECK no route-relevant mark or input-interface state was observed",
                f"NOTE  {correlation['note']}",
            ]
        )
        return "\n".join(lines)

    for index, item in enumerate(correlation["lookups"], start=1):
        obs = item["observation"]
        trace_context = "/".join(
            str(value)
            for value in (obs.get("family"), obs.get("table"), obs.get("chain"))
            if value
        ) or "unknown trace context"
        lines.extend(["", f"Observation {index}", f"  TRACE {trace_context}"])
        if obs.get("rule"):
            lines.append(f"  TRACE rule={obs['rule']}")
        if obs.get("mark") is not None:
            lines.append(f"  TRACE observed mark={hex(obs['mark'])}")
        if obs.get("iif"):
            lines.append(f"  TRACE observed iif={obs['iif']}")
        if obs.get("oif"):
            lines.append(f"  INFO  observed oif={obs['oif']} (not forced into the re-lookup)")

        lookup = item["lookup_flow"]
        selectors = []
        if lookup.get("mark") is not None:
            selectors.append(f"mark={hex(lookup['mark'])}")
        if lookup.get("iif"):
            selectors.append(f"iif={lookup['iif']}")
        lines.append(
            "  PROBE kernel re-lookup with "
            + (", ".join(selectors) if selectors else "the original flow selectors")
        )

        if item.get("error"):
            lines.append(f"  CHECK re-lookup failed: {item['error']}")
        elif item.get("decision"):
            lines.append(f"  KERNEL {_decision_label(item['decision'])}")
            if item["decision_changed"]:
                lines.append("  CHANGE observed selectors produce a different kernel routing decision")
            else:
                lines.append("  INFO  observed selectors do not change the kernel routing decision")

    lines.extend(["", f"NOTE  {correlation['note']}"])
    return "\n".join(lines)


def render_correlation_json(correlation: dict[str, Any]) -> str:
    return json.dumps(correlation, indent=2, sort_keys=True)
