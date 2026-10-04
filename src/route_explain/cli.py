from __future__ import annotations

import argparse
import ipaddress
import sys

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
    number = int(value)
    if not 1 <= number <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return number


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="route-explain",
        description="Explain the Linux kernel's routing decision for a flow.",
    )
    parser.add_argument("destination", type=_ip_address, help="Destination IPv4 or IPv6 address.")
    parser.add_argument("--from", dest="source", type=_ip_address, help="Optional source address.")
    parser.add_argument(
        "--protocol",
        choices=("tcp", "udp"),
        default="tcp",
        help="Flow metadata for the report. Default: tcp.",
    )
    parser.add_argument("--port", type=_port, help="Destination port metadata for the report.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.source:
        source_version = ipaddress.ip_address(args.source).version
        destination_version = ipaddress.ip_address(args.destination).version
        if source_version != destination_version:
            print("route-explain: source and destination address families differ", file=sys.stderr)
            return 2

    flow = Flow(
        destination=args.destination,
        source=args.source,
        protocol=args.protocol,
        port=args.port,
    )

    try:
        report = build_report(
            flow,
            route_get=collect_route_get(flow),
            rules=collect_rules(),
            routes=collect_routes(),
            links=collect_links(),
        )
    except (CollectionError, ValueError) as exc:
        print(f"route-explain: {exc}", file=sys.stderr)
        return 2

    print(render_json(report) if args.json else render_text(report))
    return 0
