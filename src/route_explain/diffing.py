from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from .snapshot import report_from_snapshot

_ROUTE_KEYS = ("dst", "gateway", "dev", "table", "metric", "type")
_RULE_KEYS = (
    "priority",
    "not",
    "src",
    "srclen",
    "dst",
    "dstlen",
    "table",
    "action",
    "goto",
    "nop",
    "suppress_prefixlen",
    "suppress_ifgroup",
    "fwmark",
    "fwmask",
    "iif",
    "oif",
    "ipproto",
    "sport",
    "sport_start",
    "sport_end",
    "dport",
    "dport_start",
    "dport_end",
    "uidrange",
    "uid_start",
    "uid_end",
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
        # iproute2 encodes these flags as null; presence carries their meaning.
        fingerprint = tuple(key in item if key in {"not", "nop"} else item.get(key) for key in keys)
        indexed[fingerprint] = {
            key: item.get(key)
            for key in keys
            if item.get(key) is not None or (key in {"not", "nop"} and key in item)
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
        "context_changed": before.get("context") != after.get("context"),
        "host_changed": (before.get("host") or {}).get("node")
        != (after.get("host") or {}).get("node"),
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


def _rule_address(item: dict[str, Any], key: str) -> str:
    address = str(item.get(key, "all"))
    length = item.get(f"{key}len")
    if length is not None and "/" not in address:
        return f"{address}/{length}"
    return address


def _rule_change(item: dict[str, Any]) -> str:
    priority = item.get("priority", "?")
    inversion = "not " if "not" in item else ""
    source = _rule_address(item, "src")
    destination = _rule_address(item, "dst")
    actions = []
    if item.get("table") is not None:
        actions.append(f"lookup {item['table']}")
    if item.get("goto") is not None:
        actions.append(f"goto {item['goto']}")
    elif "nop" in item:
        actions.append("nop")
    elif item.get("action") is not None:
        actions.append(str(item["action"]))
    action = " ".join(actions) or "lookup unspecified"
    selectors = []
    for key in ("fwmark", "fwmask", "iif", "oif", "ipproto", "suppress_prefixlen", "suppress_ifgroup"):
        if item.get(key) is not None:
            selectors.append(f"{key}={item[key]}")
    for key, prefix in (("sport", "sport"), ("dport", "dport"), ("uidrange", "uid")):
        start_key = f"{prefix}_start"
        end_key = f"{prefix}_end"
        if start_key in item or end_key in item:
            selectors.append(f"{key}={item.get(start_key, '?')}-{item.get(end_key, '?')}")
        elif item.get(key) is not None:
            selectors.append(f"{key}={item[key]}")
    suffix = f" [{', '.join(selectors)}]" if selectors else ""
    return (
        f"{priority}: {inversion}from {source} to {destination} {action}{suffix}"
    )


def render_diff(diff: dict[str, Any]) -> str:
    lines = ["ROUTE-EXPLAIN DIFF", ""]
    if diff["flow_changed"]:
        lines.append("CHECK snapshots describe different flows")
    if diff["context_changed"]:
        lines.append("CHECK snapshots use different execution contexts")
    if diff["host_changed"]:
        lines.append("CHECK snapshots report different host names")

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
