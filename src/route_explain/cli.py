from __future__ import annotations

import argparse
import ipaddress
import sys

from . import __version__
from .analyze import build_report
from .collect import (
    CollectionError,
    collect_links,
    collect_route_get,
    collect_routes,
    collect_rules,
)
from .model import Flow
from .render import render_json, render_text


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
        raise argparse.ArgumentTypeError(f"{label} must be an integer (decimal or 0x-prefixed)") from exc
    if not 0 <= number < (1 << bits):
        raise argparse.ArgumentTypeError(f"{label} must fit in {bits} bits")
    return number


def _mark(value: str) -> int:
    return _uint(value, bits=32, label="mark")


def _tos(value: str) -> int:
    return _uint(value, bits=8, label="tos")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="route-explain",
        description="Ask the Linux kernel for a route, then explain the RPDB/FIB context around it.",
    )
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
    parser.add_argument("--json", action="store_true", help="Emit stable machine-readable JSON.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.source:
        source_version = ipaddress.ip_address(args.source).version
        destination_version = ipaddress.ip_address(args.destination).version
        if source_version != destination_version:
            print("route-explain: source and destination address families differ", file=sys.stderr)
            return 2

    if (args.source_port is not None or args.destination_port is not None) and args.protocol not in {
        "tcp",
        "udp",
    }:
        print("route-explain: ports require --protocol tcp or udp", file=sys.stderr)
        return 2

    flow = Flow(
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

    try:
        route_get = collect_route_get(flow)
        try:
            fibmatch = collect_route_get(flow, fibmatch=True)
        except CollectionError:
            # Older iproute2 builds may not support fibmatch. The resolved lookup remains useful.
            fibmatch = None

        report = build_report(
            flow,
            route_get=route_get,
            fibmatch=fibmatch,
            rules=collect_rules(flow),
            routes=collect_routes(flow),
            links=collect_links(),
        )
    except (CollectionError, ValueError) as exc:
        print(f"route-explain: {exc}", file=sys.stderr)
        return 2

    print(render_json(report) if args.json else render_text(report))
    return 0
