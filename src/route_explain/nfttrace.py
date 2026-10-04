from __future__ import annotations

import json
import selectors
import shutil
import subprocess
import time
from typing import Any

from .context import ExecutionContext
from .model import Flow


class TraceError(RuntimeError):
    pass


def _event_matches_flow(event: dict[str, Any], flow: Flow) -> bool:
    text = json.dumps(event, sort_keys=True)
    if flow.destination not in text:
        return False
    return not flow.source or flow.source in text


def _trace_objects(event: dict[str, Any]) -> list[dict[str, Any]]:
    objects = event.get("nftables")
    if not isinstance(objects, list):
        return []
    traces: list[dict[str, Any]] = []
    for item in objects:
        if isinstance(item, dict) and isinstance(item.get("trace"), dict):
            traces.append(item["trace"])
    return traces


def collect_nft_trace(
    flow: Flow,
    context: ExecutionContext,
    seconds: float = 3.0,
) -> list[dict[str, Any]]:
    if shutil.which("nft") is None:
        raise TraceError("nft command not found")
    argv = [*context.prefix(), "nft", "-j", "monitor", "trace"]
    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as exc:
        raise TraceError(str(exc)) from exc

    deadline = time.monotonic() + seconds
    events: list[dict[str, Any]] = []
    selector = selectors.DefaultSelector()
    if proc.stdout:
        selector.register(proc.stdout, selectors.EVENT_READ)

    try:
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                break
            remaining = max(0.0, deadline - time.monotonic())
            ready = selector.select(timeout=min(0.2, remaining))
            if not ready:
                continue
            line = proc.stdout.readline() if proc.stdout else ""
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict) and _event_matches_flow(payload, flow):
                events.append(payload)
    finally:
        selector.close()
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=1)

    if proc.returncode not in {0, -15} and not events:
        stderr = proc.stderr.read().strip() if proc.stderr else ""
        if stderr:
            raise TraceError(f"nft monitor trace failed: {stderr}")

    return events


def _packet_mark(trace: dict[str, Any]) -> object | None:
    packet = trace.get("packet")
    if not isinstance(packet, dict):
        return None
    meta = packet.get("meta")
    if not isinstance(meta, dict):
        return None
    return meta.get("mark")


def render_trace(events: list[dict[str, Any]]) -> str:
    lines = ["ROUTE-EXPLAIN NFT TRACE", ""]
    if not events:
        lines.extend(
            [
                "No matching nftables trace events were observed.",
                (
                    "CHECK nft monitor trace only sees packets already marked for "
                    "tracing (meta nftrace set 1)."
                ),
                (
                    "CHECK route-explain does not mutate your ruleset to enable "
                    "tracing automatically."
                ),
            ]
        )
        return "\n".join(lines)

    last_mark: object | None = None
    for event in events:
        traces = _trace_objects(event)
        if not traces:
            lines.append(json.dumps(event, sort_keys=True))
            continue
        for trace in traces:
            parts = [
                str(trace.get("type") or "trace"),
                f"{trace.get('family', '?')} {trace.get('table', '?')} "
                f"{trace.get('chain', '?')}",
            ]
            if trace.get("rule"):
                parts.append(f"rule={trace['rule']}")
            if trace.get("verdict"):
                parts.append(f"verdict={trace['verdict']}")
            lines.append("  " + " | ".join(parts))

            mark = _packet_mark(trace)
            if mark is not None:
                lines.append(f"    packet mark: {mark}")
                if last_mark is not None and mark != last_mark:
                    lines.append(f"    MARK changed: {last_mark} -> {mark}")
                last_mark = mark

    return "\n".join(lines)
