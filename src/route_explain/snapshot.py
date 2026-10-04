from __future__ import annotations

import json
import platform
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .analyze import build_report
from .collect import (
    CollectionError,
    collect_links,
    collect_route_get,
    collect_routes,
    collect_rules,
)
from .context import ExecutionContext
from .model import Evidence, Flow, Report
from .overlay import collect_tailscale, collect_wireguard, overlay_evidence

SNAPSHOT_SCHEMA_VERSION = 1


def capture_snapshot(flow: Flow, context: ExecutionContext) -> dict[str, Any]:
    route_get = collect_route_get(flow, context=context)
    try:
        fibmatch = collect_route_get(flow, fibmatch=True, context=context)
    except CollectionError:
        fibmatch = None

    rules = collect_rules(flow, context=context)
    routes = collect_routes(flow, context=context)
    links = collect_links(context=context)
    wireguard = collect_wireguard(context)
    tailscale = collect_tailscale(context)

    return {
        "snapshot_schema_version": SNAPSHOT_SCHEMA_VERSION,
        "captured_at": datetime.now(UTC).isoformat(),
        "context": {
            "kind": context.kind,
            "value": context.value,
            "label": context.label,
        },
        "host": {
            "node": platform.node(),
            "kernel": platform.release(),
        },
        "flow": asdict(flow),
        "evidence": {
            "route_get": route_get,
            "fibmatch": fibmatch,
            "rules": rules,
            "routes": routes,
            "links": links,
            "wireguard": wireguard,
            "tailscale": tailscale,
        },
    }


def load_snapshot(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if (
        not isinstance(data, dict)
        or data.get("snapshot_schema_version") != SNAPSHOT_SCHEMA_VERSION
    ):
        raise ValueError("unsupported or invalid route-explain snapshot")
    return data


def save_snapshot(
    snapshot: dict[str, Any],
    path: str | Path | None = None,
) -> str:
    text = json.dumps(snapshot, indent=2, sort_keys=True)
    if path is not None:
        Path(path).write_text(text + "\n", encoding="utf-8")
    return text


def report_from_snapshot(snapshot: dict[str, Any]) -> Report:
    flow = Flow(**snapshot["flow"])
    evidence = snapshot["evidence"]
    report = build_report(
        flow,
        route_get=evidence["route_get"],
        fibmatch=evidence.get("fibmatch"),
        rules=evidence["rules"],
        routes=evidence["routes"],
        links=evidence["links"],
    )

    messages = overlay_evidence(
        flow.destination,
        evidence.get("wireguard") or [],
        evidence.get("tailscale"),
    )
    for message in messages:
        report.evidence.insert(-1, Evidence("derived", message))

    return report
