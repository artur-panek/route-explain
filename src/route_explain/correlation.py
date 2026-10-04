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


def _as_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip(), 0)
    except ValueError:
        return None


def _trace_objects(event: dict[str, Any]) -> list[dict[str, Any]]:
    objects = event.get("nftables")
    if not isinstance(objects, list):
        return []
    return [
        item["trace"]
        for item in objects
        if isinstance(item, dict) and isinstance(item.get("trace"), dict)
    ]


def _meta(trace: dict[str, Any]) -> dict[str, Any]:
    packet = trace.get("packet")
    if not isinstance(packet, dict):
        return {}
    meta = packet.get("meta")
    return meta if isinstance(meta, dict) else {}


def _interface(meta: dict[str, Any], name_key: str, index_key: str) -> str | None:
    value = meta.get(name_key)
    if isinstance(value, str) and value:
        return value
    value = meta.get(index_key)
    if isinstance(value, str) and value and not value.isdigit():
        return value
    return None


def extract_observations(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    last: tuple[int | None, str | None, str | None] | None = None

    for event in events:
        for trace in _trace_objects(event):
            meta = _meta(trace)
            observation = {
                "mark": _as_int(meta.get("mark")),
                "iif": _interface(meta, "iifname", "iif"),
                "oif": _interface(meta, "oifname", "oif"),
                "family": trace.get("family"),
                "table": trace.get("table"),
                "chain": trace.get("chain"),
                "hook": trace.get("hook"),
                "type": trace.get("type"),
                "rule": trace.get("rule"),
            }
            if observation["mark"] is None and observation["iif"] is None:
                continue
            selectors = (
                observation["mark"],
                observation["iif"],
                observation["oif"],
            )
            if selectors == last:
                continue
            observations.append(observation)
            last = selectors

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
    snapshot = baseline_snapshot or capture_snapshot(flow, context)
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
        "schema_version": 1,
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
        if obs.get("hook"):
            lines.append(f"  TRACE hook={obs['hook']}")
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
