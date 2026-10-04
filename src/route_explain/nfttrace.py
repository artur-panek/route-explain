from __future__ import annotations

import re
import selectors
import shutil
import subprocess
import time
from typing import Any

from .context import ExecutionContext
from .model import Flow

TRACE_SCHEMA_VERSION = 2
_TRACE_HEADER = re.compile(
    r"^trace id (?P<trace_id>[0-9a-fA-F]+) "
    r"(?P<family>\S+) (?P<table>\S+) (?P<chain>\S+) (?P<body>.*)$"
)
_QUOTED_IFACE = {
    "iif": re.compile(r'\biif "([^"]+)"'),
    "oif": re.compile(r'\boif "([^"]+)"'),
}
_IPV4 = {
    "source": re.compile(r"\bip saddr (\S+)"),
    "destination": re.compile(r"\bip daddr (\S+)"),
}
_IPV6_ = {
    "source": re.compile(r"\bip6 saddr (\S+)"),
    "destination": re.compile(r"\bip6 daddr (\S+)"),
}
_PROTOCOL_PATTERNS = (
    re.compile(r"\bip protocol (\S+)"),
    re.compile(r"\bip6 nexthdr (\S+)"),
)
_PORT_PATTERN = {
    "sport": re.compile(r"\b(?:tcp|udp|sctp) sport (\d+)"),
    "dport": re.compile(r"\b(?:tcp|udp|sctp) dport (\d+)"),
}
_VERDICT_SUFFIX = re.compile(r"\s+\(verdict ([^)]+)\)$")
_MARK_VALUE = re.compile(r"\bmark (0x[0-9a-fA-F]+|\d+)\b")


class TraceError(RuntimeError):
    pass


def _match(pattern: re.Pattern[str], text: str) -> str | None:
    found = pattern.search(text)
    return found.group(1) if found else None


def _as_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value, 0)
    except ValueError:
        return None


def _packet_fields(body: str) -> dict[str, Any]:
    packet_text = body.removeprefix("packet:").strip()
    source = _match(_IPV4["source"], packet_text) or _match(
        _IPV6_["source"], packet_text
    )
    destination = _match(_IPV4["destination"], packet_text) or _match(
        _IPV6_["destination"], packet_text
    )

    protocol = None
    for pattern in _PROTOCOL_PATTERNS:
        protocol = _match(pattern, packet_text)
        if protocol:
            break
    if protocol is None:
        for candidate in ("tcp", "udp", "sctp", "icmp", "icmpv6"):
            if re.search(rf"\b{candidate}\b", packet_text):
                protocol = candidate
                break

    return {
        "source": source,
        "destination": destination,
        "protocol": protocol,
        "sport": _as_int(_match(_PORT_PATTERN["sport"], packet_text)),
        "dport": _as_int(_match(_PORT_PATTERN["dport"], packet_text)),
        "iif": _match(_QUOTED_IFACE["iif"], packet_text),
        "oif": _match(_QUOTED_IFACE["oif"], packet_text),
    }


def parse_native_trace_line(line: str) -> dict[str, Any] | None:
    raw = line.strip()
    match = _TRACE_HEADER.match(raw)
    if not match:
        return None

    body = match.group("body")
    event_type = "trace"
    packet: dict[str, Any] | None = None
    rule: str | None = None
    verdict: str | None = None
    mark: int | None = None

    if body.startswith("packet:"):
        event_type = "packet"
        packet = _packet_fields(body)
    elif body.startswith("rule "):
        event_type = "rule"
        rule_text = body.removeprefix("rule ").strip()
        suffix = _VERDICT_SUFFIX.search(rule_text)
        if suffix:
            verdict = suffix.group(1)
            rule_text = rule_text[: suffix.start()].rstrip()
        rule = rule_text
    elif body.startswith("policy "):
        event_type = "policy"
        verdict = body.split(maxsplit=2)[1]
        mark = _as_int(_match(_MARK_VALUE, body))
    elif body.startswith("verdict "):
        event_type = "verdict"
        verdict = body.split(maxsplit=2)[1]
        mark = _as_int(_match(_MARK_VALUE, body))
    elif body.startswith("mark "):
        event_type = "mark"
        mark = _as_int(_match(_MARK_VALUE, body))

    return {
        "trace_id": match.group("trace_id").lower(),
        "family": match.group("family"),
        "table": match.group("table"),
        "chain": match.group("chain"),
        "type": event_type,
        "packet": packet,
        "mark": mark,
        "rule": rule,
        "verdict": verdict,
        "raw": raw,
    }


def _packet_matches_flow(event: dict[str, Any], flow: Flow) -> bool:
    packet = event.get("packet")
    if not isinstance(packet, dict):
        return False
    if packet.get("destination") != flow.destination:
        return False
    if flow.source and packet.get("source") != flow.source:
        return False
    if flow.protocol and packet.get("protocol") and packet["protocol"] != flow.protocol:
        return False
    if (
        flow.source_port is not None
        and packet.get("sport") is not None
        and packet["sport"] != flow.source_port
    ):
        return False
    return not (
        flow.destination_port is not None
        and packet.get("dport") is not None
        and packet["dport"] != flow.destination_port
    )


def filter_flow_trace(
    events: list[dict[str, Any]], flow: Flow
) -> list[dict[str, Any]]:
    matching_ids = {
        str(event["trace_id"])
        for event in events
        if _packet_matches_flow(event, flow)
    }
    return [
        event
        for event in events
        if str(event.get("trace_id")) in matching_ids
    ]


def collect_nft_trace(
    flow: Flow,
    context: ExecutionContext,
    seconds: float = 3.0,
) -> list[dict[str, Any]]:
    if shutil.which("nft") is None:
        raise TraceError("nft command not found")

    # nft trace notifications use the native "trace id ..." representation.
    # Parse that representation into route-explain's own stable JSON schema.
    argv = [*context.prefix(), "nft", "monitor", "trace"]
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
    captured: list[dict[str, Any]] = []
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
            event = parse_native_trace_line(line)
            if event is not None:
                captured.append(event)
    finally:
        selector.close()
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=1)

    events = filter_flow_trace(captured, flow)
    if proc.returncode not in {0, -15} and not events:
        stderr = proc.stderr.read().strip() if proc.stderr else ""
        if stderr:
            raise TraceError(f"nft monitor trace failed: {stderr}")

    return events


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

    last_mark_by_trace: dict[str, int] = {}
    for event in events:
        lines.append("  " + str(event.get("raw", "")))
        mark = event.get("mark")
        trace_id = str(event.get("trace_id", ""))
        if isinstance(mark, int):
            previous = last_mark_by_trace.get(trace_id)
            if previous is not None and previous != mark:
                lines.append(f"    MARK changed: {hex(previous)} -> {hex(mark)}")
            last_mark_by_trace[trace_id] = mark

    lines.extend(
        [
            "",
            (
                "CHECK nft reconstructs table/chain/rule text from ruleset state "
                "read when the monitor starts; changing the ruleset during capture "
                "can make printed rule text stale."
            ),
        ]
    )
    return "\n".join(lines)
