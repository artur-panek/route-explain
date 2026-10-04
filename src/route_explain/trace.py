from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from typing import Any

from .collect import CollectionError, namespace_prefix, run_command
from .model import Flow, NamespaceTarget, TraceEvent, TraceReport


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _trace_match_expression(flow: Flow) -> str:
    family = "ip6" if ":" in flow.destination else "ip"
    parts = [f"meta nfproto {'ipv6' if family == 'ip6' else 'ipv4'}", f"{family} daddr {flow.destination}"]
    if flow.source:
        parts.append(f"{family} saddr {flow.source}")
    if flow.iif:
        parts.append(f"iifname {_quote(flow.iif)}")
    if flow.oif:
        parts.append(f"oifname {_quote(flow.oif)}")
    if flow.protocol in {"tcp", "udp"}:
        parts.append(f"meta l4proto {flow.protocol}")
        if flow.source_port is not None:
            parts.append(f"{flow.protocol} sport {flow.source_port}")
        if flow.destination_port is not None:
            parts.append(f"{flow.protocol} dport {flow.destination_port}")
    elif flow.protocol in {"icmp", "icmpv6"}:
        parts.append(f"meta l4proto {flow.protocol}")
    return " ".join(parts)


def arm_script(flow: Flow, *, table_name: str, hook: str) -> str:
    if hook not in {"output", "prerouting"}:
        raise ValueError("trace hook must be output or prerouting")
    return "\n".join(
        [
            f"add table inet {table_name}",
            f"add chain inet {table_name} trace {{ type filter hook {hook} priority -301; policy accept; }}",
            f"add rule inet {table_name} trace {_trace_match_expression(flow)} meta nftrace set 1",
            "",
        ]
    )


def _arm(flow: Flow, *, target: NamespaceTarget | None, table_name: str, hook: str) -> None:
    proc = run_command(
        ["nft", "-f", "-"],
        target=target,
        input_text=arm_script(flow, table_name=table_name, hook=hook),
    )
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or f"exit code {proc.returncode}"
        raise CollectionError(f"failed to arm nft trace rule: {detail}")


def _disarm(*, target: NamespaceTarget | None, table_name: str) -> str | None:
    try:
        proc = run_command(
            ["nft", "delete", "table", "inet", table_name],
            target=target,
        )
    except CollectionError as exc:
        return str(exc)
    if proc.returncode != 0:
        return proc.stderr.strip() or proc.stdout.strip() or f"exit code {proc.returncode}"
    return None


def _find_trace_objects(value: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(value, dict):
        trace = value.get("trace")
        if isinstance(trace, dict):
            found.append(trace)
        for child in value.values():
            found.extend(_find_trace_objects(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(_find_trace_objects(child))
    return found


def _parse_text_trace(line: str) -> TraceEvent:
    trace_id_match = re.search(r"trace id ([0-9a-fA-F]+)", line)
    verdict_match = re.search(r"verdict\s+(\w+)", line)
    return TraceEvent(
        trace_id=trace_id_match.group(1) if trace_id_match else None,
        family=None,
        table=None,
        chain=None,
        event="text",
        verdict=verdict_match.group(1) if verdict_match else None,
        raw={"text": line},
    )


def parse_trace_output(text: str) -> list[TraceEvent]:
    events: list[TraceEvent] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            events.append(_parse_text_trace(line))
            continue
        trace_objects = _find_trace_objects(payload)
        if not trace_objects:
            continue
        for trace in trace_objects:
            events.append(
                TraceEvent(
                    trace_id=str(trace["id"]) if trace.get("id") is not None else None,
                    family=str(trace["family"]) if trace.get("family") is not None else None,
                    table=str(trace["table"]) if trace.get("table") is not None else None,
                    chain=str(trace["chain"]) if trace.get("chain") is not None else None,
                    event=str(trace["type"]) if trace.get("type") is not None else None,
                    verdict=str(trace["verdict"]) if trace.get("verdict") is not None else None,
                    raw=trace,
                )
            )
    return events


def capture_nft_trace(
    flow: Flow,
    *,
    target: NamespaceTarget | None = None,
    timeout: float = 3.0,
    arm: bool = False,
    hook: str | None = None,
    exec_command: list[str] | None = None,
) -> TraceReport:
    if shutil.which("nft") is None:
        raise CollectionError("nft command not found; install nftables")
    chosen_hook = hook or ("prerouting" if flow.iif else "output")
    table_name = f"route_explain_{os.getpid()}"
    notes: list[str] = []
    command_exit_code: int | None = None

    if arm:
        _arm(flow, target=target, table_name=table_name, hook=chosen_hook)
        notes.append(
            f"temporarily armed nftrace in inet/{table_name} on {chosen_hook}; cleanup is attempted automatically"
        )

    command = [*namespace_prefix(target), "nft", "-j", "monitor", "trace"]
    monitor: subprocess.Popen[str] | None = None
    stdout = ""
    stderr = ""
    try:
        monitor = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        time.sleep(0.15)
        if exec_command:
            try:
                proc = subprocess.run(
                    [*namespace_prefix(target), *exec_command],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=max(timeout, 1.0),
                )
            except subprocess.TimeoutExpired:
                command_exit_code = 124
                notes.append(f"probe command timed out after {max(timeout, 1.0):g}s")
            else:
                command_exit_code = proc.returncode
                if proc.returncode != 0:
                    detail = proc.stderr.strip() or proc.stdout.strip() or f"exit code {proc.returncode}"
                    notes.append(f"probe command exited non-zero: {detail}")
            time.sleep(min(0.5, timeout))
            monitor.terminate()
            stdout, stderr = monitor.communicate(timeout=1)
        else:
            try:
                stdout, stderr = monitor.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                monitor.terminate()
                try:
                    stdout, stderr = monitor.communicate(timeout=1)
                except subprocess.TimeoutExpired:
                    monitor.kill()
                    stdout, stderr = monitor.communicate()
    finally:
        if monitor is not None and monitor.poll() is None:
            monitor.kill()
            monitor.communicate()
        if arm:
            cleanup_error = _disarm(target=target, table_name=table_name)
            if cleanup_error:
                notes.append(
                    f"CHECK: failed to remove temporary nft table {table_name}: {cleanup_error}"
                )
            else:
                notes.append(f"removed temporary nft table inet/{table_name}")

    events = parse_trace_output(stdout)
    if stderr.strip():
        notes.append(f"nft monitor: {stderr.strip()}")
    if not events:
        if arm:
            notes.append(
                "no nft trace events were captured; generate a packet matching the requested flow while the monitor is active"
            )
        else:
            notes.append(
                "no nft trace events were captured; existing rules must set meta nftrace 1, or rerun with --arm"
            )
    return TraceReport(
        events=events,
        notes=notes,
        armed=arm,
        command_exit_code=command_exit_code,
        namespace=target.label if target else None,
    )
