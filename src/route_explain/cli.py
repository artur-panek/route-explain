from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from typing import Any

from . import __version__
from .collect import CollectionError
from .context import ContextError, resolve_context
from .diffing import diff_snapshots, render_diff, render_diff_json
from .doctor import doctor, render_doctor, render_doctor_json
from .model import Flow, Report
from .nfttrace import TraceError, collect_nft_trace, render_trace
from .render import render_json, render_text
from .snapshot import (
    capture_snapshot,
    load_snapshot,
    report_from_snapshot,
    save_snapshot,
)
from .why import explain_why_not

_SUBCOMMANDS = {"snapshot", "capture", "replay", "analyze", "diff", "doctor", "trace"}


def _ip_address(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _port(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= number <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return number


def _uint(value: str, *, bits: int, label: str) -> int:
    try:
        number = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"{label} must be an integer (decimal or 0x-prefixed)"
        ) from exc
    if not 0 <= number < (1 << bits):
        raise argparse.ArgumentTypeError(f"{label} must fit in {bits} bits")
    return number


def _mark(value: str) -> int:
    return _uint(value, bits=32, label="mark")


def _tos(value: str) -> int:
    return _uint(value, bits=8, label="tos")


def _add_context_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("execution context")
    group.add_argument("--netns", help="Run the lookup inside an iproute2 network namespace.")
    group.add_argument("--pid", type=int, help="Enter the network namespace of this process PID.")
    group.add_argument(
        "--container",
        help="Resolve a running Docker/Podman container and enter its network namespace.",
    )


def _add_flow_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("destination", type=_ip_address, help="Destination IPv4 or IPv6 address.")
    parser.add_argument(
        "--from",
        "--source",
        dest="source",
        type=_ip_address,
        help="Source address presented to the route lookup.",
    )
    parser.add_argument(
        "--protocol",
        choices=("tcp", "udp", "icmp", "icmpv6"),
        default="tcp",
        help="L4 protocol. Used by kernel lookup when a port is supplied. Default: tcp.",
    )
    parser.add_argument(
        "--port",
        "--dport",
        dest="destination_port",
        type=_port,
        help="Destination port.",
    )
    parser.add_argument("--sport", dest="source_port", type=_port, help="Source port.")
    parser.add_argument("--mark", type=_mark, help="Firewall mark (decimal or 0x-prefixed).")
    parser.add_argument(
        "--tos",
        type=_tos,
        help="IPv4 TOS / DS field value (decimal or 0x-prefixed).",
    )
    parser.add_argument("--iif", help="Incoming interface for a forwarded-packet lookup.")
    parser.add_argument("--oif", help="Force the output interface during lookup.")
    parser.add_argument("--vrf", help="Force lookup through a VRF device.")


def _flow_from_args(args: argparse.Namespace) -> Flow:
    if args.source:
        source_version = ipaddress.ip_address(args.source).version
        destination_version = ipaddress.ip_address(args.destination).version
        if source_version != destination_version:
            raise ValueError("source and destination address families differ")

    if (
        args.source_port is not None or args.destination_port is not None
    ) and args.protocol not in {"tcp", "udp"}:
        raise ValueError("ports require --protocol tcp or udp")

    return Flow(
        destination=args.destination,
        source=args.source,
        protocol=args.protocol,
        destination_port=args.destination_port,
        source_port=args.source_port,
        mark=args.mark,
        tos=args.tos,
        iif=args.iif,
        oif=args.oif,
        vrf=args.vrf,
    )


def _context_from_args(args: argparse.Namespace):
    return resolve_context(
        netns=getattr(args, "netns", None),
        pid=getattr(args, "pid", None),
        container=getattr(args, "container", None),
    )


def _render_report(report: Report, *, json_output: bool, why_not: str | None) -> str:
    if not json_output:
        text = render_text(report)
        if why_not:
            text += "\n\n" + explain_why_not(report, why_not)
        return text

    payload: dict[str, Any] = json.loads(render_json(report))
    if why_not:
        payload["why_not"] = {
            "target": why_not,
            "explanation": explain_why_not(report, why_not),
        }
    return json.dumps(payload, indent=2, sort_keys=True)


def _explain_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="route-explain",
        description=(
            "Ask the Linux kernel for a route, then explain the RPDB/FIB and overlay "
            "context around it."
        ),
    )
    _add_flow_args(parser)
    _add_context_args(parser)
    parser.add_argument(
        "--why-not",
        metavar="DEV_OR_TABLE",
        help="Explain why a device/table route was not selected (e.g. tailscale0 or table:52).",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _snapshot_parser(prog: str = "route-explain snapshot") -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=prog,
        description="Capture a flow-scoped routing evidence bundle for replay or diff.",
    )
    _add_flow_args(parser)
    _add_context_args(parser)
    parser.add_argument("-o", "--output", help="Write the snapshot to this file.")
    return parser


def _replay_parser(prog: str = "route-explain replay") -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=prog,
        description="Rebuild an explanation from a previously captured snapshot.",
    )
    parser.add_argument("snapshot", help="Snapshot JSON file.")
    parser.add_argument("--why-not", metavar="DEV_OR_TABLE")
    parser.add_argument("--json", action="store_true")
    return parser


def _diff_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="route-explain diff",
        description="Compare two flow-scoped routing snapshots.",
    )
    parser.add_argument("before")
    parser.add_argument("after")
    parser.add_argument("--json", action="store_true")
    return parser


def _doctor_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="route-explain doctor",
        description="Audit route tables, policy rules, overlays, and container bridge context.",
    )
    _add_context_args(parser)
    parser.add_argument("--json", action="store_true")
    return parser


def _trace_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="route-explain trace",
        description=(
            "Observe read-only nftables runtime trace evidence for a flow. "
            "The ruleset is never modified automatically."
        ),
    )
    _add_flow_args(parser)
    _add_context_args(parser)
    parser.add_argument(
        "--seconds",
        type=float,
        default=3.0,
        help="How long to observe nft trace events. Default: 3 seconds.",
    )
    parser.add_argument("--json", action="store_true")
    return parser


def _run_explain(argv: list[str]) -> int:
    args = _explain_parser().parse_args(argv)
    flow = _flow_from_args(args)
    context = _context_from_args(args)
    snapshot = capture_snapshot(flow, context)
    report = report_from_snapshot(snapshot)
    print(_render_report(report, json_output=args.json, why_not=args.why_not))
    return 0


def _run_snapshot(argv: list[str], *, alias: str = "snapshot") -> int:
    args = _snapshot_parser(f"route-explain {alias}").parse_args(argv)
    flow = _flow_from_args(args)
    context = _context_from_args(args)
    snapshot = capture_snapshot(flow, context)
    text = save_snapshot(snapshot, args.output)
    if args.output:
        print(f"snapshot written to {args.output}")
    else:
        print(text)
    return 0


def _run_replay(argv: list[str], *, alias: str = "replay") -> int:
    args = _replay_parser(f"route-explain {alias}").parse_args(argv)
    snapshot = load_snapshot(args.snapshot)
    report = report_from_snapshot(snapshot)
    print(_render_report(report, json_output=args.json, why_not=args.why_not))
    return 0


def _run_diff(argv: list[str]) -> int:
    args = _diff_parser().parse_args(argv)
    result = diff_snapshots(load_snapshot(args.before), load_snapshot(args.after))
    print(render_diff_json(result) if args.json else render_diff(result))
    return 0


def _run_doctor(argv: list[str]) -> int:
    args = _doctor_parser().parse_args(argv)
    context = _context_from_args(args)
    result = doctor(context)
    print(render_doctor_json(result) if args.json else render_doctor(result))
    return 0


def _run_trace(argv: list[str]) -> int:
    args = _trace_parser().parse_args(argv)
    if args.seconds <= 0 or args.seconds > 60:
        raise ValueError("--seconds must be greater than 0 and at most 60")
    flow = _flow_from_args(args)
    context = _context_from_args(args)
    events = collect_nft_trace(flow, context, seconds=args.seconds)
    if args.json:
        print(json.dumps({"schema_version": 1, "events": events}, indent=2, sort_keys=True))
    else:
        print(render_trace(events))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        if args and args[0] in _SUBCOMMANDS:
            command, rest = args[0], args[1:]
            if command in {"snapshot", "capture"}:
                return _run_snapshot(rest, alias=command)
            if command in {"replay", "analyze"}:
                return _run_replay(rest, alias=command)
            if command == "diff":
                return _run_diff(rest)
            if command == "doctor":
                return _run_doctor(rest)
            if command == "trace":
                return _run_trace(rest)
        return _run_explain(args)
    except (CollectionError, ContextError, TraceError, ValueError, OSError) as exc:
        print(f"route-explain: {exc}", file=sys.stderr)
        return 2
