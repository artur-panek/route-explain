from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

from . import __version__
from .analyze import build_context_report, build_report, explain_why_not
from .collect import (
    CollectionError,
    collect_links,
    collect_overlay_state,
    collect_route_get,
    collect_routes,
    collect_rules,
)
from .doctor import diagnose_snapshot
from .model import Flow, NamespaceTarget
from .render import (
    SCHEMA_VERSION,
    render_diff,
    render_doctor,
    render_json,
    render_text,
    render_trace,
    render_why_not,
)
from .snapshot import (
    capture_snapshot,
    diff_snapshots,
    dump_snapshot,
    find_probe,
    load_snapshot,
    snapshot_namespace_label,
    state_for_flow,
)
from .trace import capture_nft_trace

COMMANDS = {"explain", "capture", "analyze", "diff", "doctor", "trace"}


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


def _positive_int(value: str) -> str:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("PID must be an integer") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("PID must be positive")
    return str(number)


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


def _add_namespace_options(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--netns", help="Run collectors inside a named iproute2 network namespace.")
    group.add_argument("--pid", type=_positive_int, help="Enter the target process network namespace with nsenter.")


def _add_flow_options(parser: argparse.ArgumentParser, *, include_destination: bool = True) -> None:
    if include_destination:
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
    parser.add_argument("--port", "--dport", dest="destination_port", type=_port, help="Destination port.")
    parser.add_argument("--sport", dest="source_port", type=_port, help="Source port.")
    parser.add_argument("--mark", type=_mark, help="Firewall mark (decimal or 0x-prefixed).")
    parser.add_argument("--tos", type=_tos, help="IPv4 TOS / DS field value (decimal or 0x-prefixed).")
    parser.add_argument("--iif", help="Incoming interface for a forwarded-packet lookup.")
    parser.add_argument("--oif", help="Force the output interface during lookup.")
    parser.add_argument("--vrf", help="Force lookup through a VRF device.")


def _namespace_target(args: argparse.Namespace) -> NamespaceTarget | None:
    if getattr(args, "netns", None):
        return NamespaceTarget("netns", args.netns)
    if getattr(args, "pid", None):
        return NamespaceTarget("pid", args.pid)
    return None


def _flow_from_args(args: argparse.Namespace, *, destination: str | None = None) -> Flow:
    dest = destination or args.destination
    source = getattr(args, "source", None)
    if source and ipaddress.ip_address(source).version != ipaddress.ip_address(dest).version:
        raise ValueError("source and destination address families differ")
    protocol = getattr(args, "protocol", "tcp")
    source_port = getattr(args, "source_port", None)
    destination_port = getattr(args, "destination_port", None)
    if (source_port is not None or destination_port is not None) and protocol not in {"tcp", "udp"}:
        raise ValueError("ports require --protocol tcp or udp")
    return Flow(
        destination=dest,
        source=source,
        protocol=protocol,
        destination_port=destination_port,
        source_port=source_port,
        mark=getattr(args, "mark", None),
        tos=getattr(args, "tos", None),
        iif=getattr(args, "iif", None),
        oif=getattr(args, "oif", None),
        vrf=getattr(args, "vrf", None),
    )


def _legacy_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="route-explain",
        description="Ask the Linux kernel for a route, then explain the RPDB/FIB context around it.",
    )
    _add_flow_options(parser)
    _add_namespace_options(parser)
    parser.add_argument("--why-not", help="Explain why an interface or table was not selected. Use table:52 for a table.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _command_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="route-explain")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    explain = sub.add_parser("explain", help="Explain a live kernel routing decision.")
    _add_flow_options(explain)
    _add_namespace_options(explain)
    explain.add_argument("--why-not", help="Explain why an interface or table was not selected.")
    explain.add_argument("--json", action="store_true")

    capture = sub.add_parser("capture", help="Capture routing state for replay/diff/debugging.")
    capture.add_argument("--probe", action="append", type=_ip_address, default=[], help="Also record a kernel decision for DEST. Repeatable.")
    _add_flow_options(capture, include_destination=False)
    _add_namespace_options(capture)
    capture.add_argument("-o", "--output", default="-", help="Write snapshot to a file instead of stdout.")

    analyze = sub.add_parser("analyze", help="Analyze a captured snapshot without touching live state.")
    analyze.add_argument("snapshot", help="Snapshot JSON path, or - for stdin.")
    _add_flow_options(analyze)
    analyze.add_argument("--why-not", help="Explain why an interface or table was not selected in captured evidence.")
    analyze.add_argument("--json", action="store_true")

    diff = sub.add_parser("diff", help="Compare two routing snapshots.")
    diff.add_argument("before")
    diff.add_argument("after")
    diff.add_argument("destination", nargs="?", type=_ip_address, help="Optionally focus on one destination.")
    diff.add_argument("--json", action="store_true")

    doctor = sub.add_parser("doctor", help="Audit the host for suspicious routing context.")
    doctor.add_argument("--snapshot", help="Audit a saved snapshot instead of live state.")
    _add_namespace_options(doctor)
    doctor.add_argument("--json", action="store_true")

    trace = sub.add_parser("trace", help="Capture nftables trace evidence for a flow.")
    _add_flow_options(trace)
    _add_namespace_options(trace)
    trace.add_argument("--timeout", type=float, default=3.0, help="Monitor duration in seconds. Default: 3.")
    trace.add_argument("--arm", action="store_true", help="Temporarily add a narrowly matched nftrace rule, then remove it.")
    trace.add_argument("--hook", choices=("output", "prerouting"), help="Temporary trace hook used with --arm.")
    trace.add_argument("--json", action="store_true")
    trace.add_argument("--exec", dest="exec_command", nargs=argparse.REMAINDER, help="Run a command while trace monitoring is active. Put this option last.")
    return parser


def _collect_report(flow: Flow, target: NamespaceTarget | None) -> Any:
    route_get = collect_route_get(flow, target=target)
    try:
        fibmatch = collect_route_get(flow, fibmatch=True, target=target)
    except CollectionError:
        fibmatch = None
    return build_report(
        flow,
        route_get=route_get,
        fibmatch=fibmatch,
        rules=collect_rules(flow, target=target),
        routes=collect_routes(flow, target=target),
        links=collect_links(target=target),
        overlay_state=collect_overlay_state(target=target),
        namespace=target.label if target else None,
    )


def _bundle_json(report: Any, why_not: Any | None = None) -> str:
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "schema": "analysis",
        "report": asdict(report),
    }
    if why_not is not None:
        payload["why_not"] = asdict(why_not)
    return json.dumps(payload, indent=2, sort_keys=True)


def _run_explain(args: argparse.Namespace) -> int:
    flow = _flow_from_args(args)
    target = _namespace_target(args)
    report = _collect_report(flow, target)
    why_not = explain_why_not(report, args.why_not) if args.why_not else None
    if args.json:
        print(_bundle_json(report, why_not))
    else:
        print(render_text(report))
        if why_not:
            print("\n" + render_why_not(why_not))
    return 0


def _run_capture(args: argparse.Namespace) -> int:
    target = _namespace_target(args)
    flows = [_flow_from_args(args, destination=destination) for destination in args.probe]
    snapshot = capture_snapshot(target=target, probe_flows=flows)
    content = dump_snapshot(snapshot)
    if args.output == "-":
        print(content)
    else:
        Path(args.output).write_text(content + "\n", encoding="utf-8")
        print(f"route-explain: wrote snapshot to {args.output}", file=sys.stderr)
    return 0


def _run_analyze(args: argparse.Namespace) -> int:
    snapshot = load_snapshot(args.snapshot)
    flow = _flow_from_args(args)
    rules, routes = state_for_flow(snapshot, flow)
    state = snapshot["state"]
    probe = find_probe(snapshot, flow)
    namespace = snapshot_namespace_label(snapshot)
    if probe and probe.get("route_get") and not probe.get("error"):
        report = build_report(
            flow,
            route_get=probe["route_get"],
            fibmatch=probe.get("fibmatch"),
            rules=rules,
            routes=routes,
            links=list(state.get("links") or []),
            overlay_state=state.get("overlays") or {},
            namespace=namespace,
        )
    else:
        report = build_context_report(
            flow,
            rules=rules,
            routes=routes,
            links=list(state.get("links") or []),
            overlay_state=state.get("overlays") or {},
            namespace=namespace,
        )
        if probe and probe.get("error"):
            report.notes.append(f"captured probe failed: {probe['error']}")
    why_not = explain_why_not(report, args.why_not) if args.why_not else None
    if args.json:
        print(_bundle_json(report, why_not))
    else:
        print(render_text(report))
        if why_not:
            print("\n" + render_why_not(why_not))
    return 0


def _run_diff(args: argparse.Namespace) -> int:
    before = load_snapshot(args.before)
    after = load_snapshot(args.after)
    result = diff_snapshots(before, after, destination=args.destination)
    print(render_json(result, schema_name="snapshot-diff") if args.json else render_diff(result))
    return 0


def _run_doctor(args: argparse.Namespace) -> int:
    target = _namespace_target(args)
    snapshot = load_snapshot(args.snapshot) if args.snapshot else capture_snapshot(target=target)
    findings = diagnose_snapshot(snapshot)
    namespace = snapshot_namespace_label(snapshot)
    if args.json:
        print(
            render_json(
                {"namespace": namespace, "findings": [asdict(item) for item in findings]},
                schema_name="doctor",
            )
        )
    else:
        print(render_doctor(findings, namespace=namespace))
    return 0


def _run_trace(args: argparse.Namespace) -> int:
    if args.timeout <= 0:
        raise ValueError("--timeout must be positive")
    flow = _flow_from_args(args)
    target = _namespace_target(args)
    exec_command = args.exec_command or None
    if exec_command and exec_command[0] == "--":
        exec_command = exec_command[1:]
    report = capture_nft_trace(
        flow,
        target=target,
        timeout=args.timeout,
        arm=args.arm,
        hook=args.hook,
        exec_command=exec_command,
    )
    print(render_json(report, schema_name="nft-trace") if args.json else render_trace(report))
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        if not argv:
            parser = _command_parser()
            parser.epilog = "Legacy shorthand: route-explain DEST [flow options]"
            parser.print_help()
            return 0
        if argv[0] in {"-h", "--help"}:
            parser = _command_parser()
            parser.epilog = "Legacy shorthand: route-explain DEST [flow options]"
            parser.parse_args(argv)
            return 0
        if argv and argv[0] in COMMANDS:
            args = _command_parser().parse_args(argv)
            runners = {
                "explain": _run_explain,
                "capture": _run_capture,
                "analyze": _run_analyze,
                "diff": _run_diff,
                "doctor": _run_doctor,
                "trace": _run_trace,
            }
            return runners[args.command](args)
        args = _legacy_parser().parse_args(argv)
        return _run_explain(args)
    except (CollectionError, ValueError, OSError) as exc:
        print(f"route-explain: {exc}", file=sys.stderr)
        return 2
