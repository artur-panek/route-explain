from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from .snapshot import report_from_snapshot

_ROUTE_KEYS = ("dst", "gateway", "dev", "table", "metric", "type")
_RULE_KEYS = (
    "priority",
    "src",
    "dst",
    "table",
    "fwmark",
    "fwmask",
    "iif",
    "oif",
    "ipproto",
    "sport",
    "dport",
)


def _decision_dict(snapshot: dict[str, Any]) -> dict[str, Any]:
    decision = asdict(report_from_snapshot(snapshot).decision)
    return {
        key: decision[key]
        for key in (
            "table",
            "matched_prefix",
            "dev",
            "gateway",
            "source",
            "route_type",
            "metric",
        )
    }


def _index(
    items: list[dict[str, Any]],
    keys: tuple[str, ...],
) -> dict[tuple[Any, ...], dict[str, Any]]:
    indexed: dict[tuple[Any, ...], dict[str, Any]] = {}
    for item in items:
        fingerprint = tuple(item.get(key) for key in keys)
        indexed[fingerprint] = {
            key: item.get(key)
            for key in keys
            if item.get(key) is not None
        }
    return indexed


def _changes(
    before: dict[tuple[Any, ...], dict[str, Any]],
    after: dict[tuple[Any, ...], dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    added = [after[key] for key in sorted(after.keys() - before.keys(), key=str)]
    removed = [before[key] for key in sorted(before.keys() - after.keys(), key=str)]
    return added, removed


def diff_snapshots(
    before: dict[str, Any],
    after: dict[str, Any],
) -> dict[str, Any]:
    before_decision = _decision_dict(before)
    after_decision = _decision_dict(after)
    before_evidence = before["evidence"]
    after_evidence = after["evidence"]

    before_routes = _index(before_evidence["routes"], _ROUTE_KEYS)
    after_routes = _index(after_evidence["routes"], _ROUTE_KEYS)
    before_rules = _index(before_evidence["rules"], _RULE_KEYS)
    after_rules = _index(after_evidence["rules"], _RULE_KEYS)

    routes_added, routes_removed = _changes(before_routes, after_routes)
    rules_added, rules_removed = _changes(before_rules, after_rules)

    return {
        "flow_changed": before.get("flow") != after.get("flow"),
        "decision_changed": before_decision != after_decision,
        "before": before_decision,
        "after": after_decision,
        "routes_added": routes_added,
        "routes_removed": routes_removed,
        "rules_added": rules_added,
        "rules_removed": rules_removed,
    }


def _route_change(item: dict[str, Any]) -> str:
    parts = [str(item.get("dst", "default"))]
    if item.get("gateway"):
        parts.append(f"via {item['gateway']}")
    if item.get("dev"):
        parts.append(f"dev {item['dev']}")
    parts.append(f"table {item.get('table', 'main')}")
    if item.get("metric") is not None:
        parts.append(f"metric {item['metric']}")
    if item.get("type") not in {None, "unicast"}:
        parts.append(f"type {item['type']}")
    return " ".join(parts)


def _rule_change(item: dict[str, Any]) -> str:
    priority = item.get("priority", "?")
    source = item.get("src", "all")
    destination = item.get("dst", "all")
    table = item.get("table", "unspecified")
    selectors = []
    for key in ("fwmark", "fwmask", "iif", "oif", "ipproto", "sport", "dport"):
        if item.get(key) is not None:
            selectors.append(f"{key}={item[key]}")
    suffix = f" [{', '.join(selectors)}]" if selectors else ""
    return (
        f"{priority}: from {source} to {destination} lookup {table}{suffix}"
    )


def render_diff(diff: dict[str, Any]) -> str:
    lines = ["ROUTE-EXPLAIN DIFF", ""]
    if diff["flow_changed"]:
        lines.append("CHECK snapshots describe different flows")

    lines.append(
        "ROUTING DECISION "
        + ("CHANGED" if diff["decision_changed"] else "UNCHANGED")
    )
    for label in ("before", "after"):
        decision = diff[label]
        lines.extend(
            [
                f"  {label}:",
                f"    table:  {decision['table']}",
                f"    prefix: {decision['matched_prefix'] or '?'}",
                f"    dev:    {decision['dev'] or '-'}",
                f"    via:    {decision['gateway'] or '-'}",
            ]
        )

    lines.extend(["", "WHY"])
    emitted = False
    for prefix, key, renderer in (
        ("+", "routes_added", _route_change),
        ("-", "routes_removed", _route_change),
        ("+", "rules_added", _rule_change),
        ("-", "rules_removed", _rule_change),
    ):
        for item in diff[key][:12]:
            kind = "route" if "routes_" in key else "rule"
            lines.append(f"  {prefix} {kind}: {renderer(item)}")
            emitted = True

    if not emitted:
        lines.append("  no route/rule set changes detected")

    return "\n".join(lines)


def render_diff_json(diff: dict[str, Any]) -> str:
    return json.dumps({"schema_version": 1, **diff}, indent=2, sort_keys=True)
