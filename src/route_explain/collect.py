from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

from .model import Flow


class CollectionError(RuntimeError):
    pass


def _run_ip(*args: str) -> list[dict[str, Any]]:
    if shutil.which("ip") is None:
        raise CollectionError("ip command not found; install iproute2")

    proc = subprocess.run(
        ["ip", "-j", *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or f"exit code {proc.returncode}"
        raise CollectionError(f"ip {' '.join(args)} failed: {detail}")

    try:
        payload = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise CollectionError(f"ip {' '.join(args)} returned invalid JSON") from exc

    if not isinstance(payload, list):
        raise CollectionError(f"ip {' '.join(args)} returned an unexpected JSON shape")
    return payload


def route_get_args(flow: Flow, *, fibmatch: bool = False) -> list[str]:
    args = ["route", "get"]
    if fibmatch:
        args.append("fibmatch")
    args.append(flow.destination)

    if flow.source:
        args.extend(["from", flow.source])
    if flow.iif:
        args.extend(["iif", flow.iif])
    if flow.oif:
        args.extend(["oif", flow.oif])
    if flow.mark is not None:
        args.extend(["mark", hex(flow.mark)])
    if flow.tos is not None:
        args.extend(["tos", hex(flow.tos)])
    if flow.vrf:
        args.extend(["vrf", flow.vrf])

    # Transport selectors only make sense when iproute2 also knows the L4 protocol.
    if flow.source_port is not None or flow.destination_port is not None:
        args.extend(["ipproto", flow.protocol])
        if flow.source_port is not None:
            args.extend(["sport", str(flow.source_port)])
        if flow.destination_port is not None:
            args.extend(["dport", str(flow.destination_port)])

    return args


def collect_route_get(flow: Flow, *, fibmatch: bool = False) -> list[dict[str, Any]]:
    return _run_ip(*route_get_args(flow, fibmatch=fibmatch))


def _family_flag(flow: Flow) -> str:
    return "-6" if ":" in flow.destination else "-4"


def collect_rules(flow: Flow) -> list[dict[str, Any]]:
    return _run_ip(_family_flag(flow), "rule", "show")


def collect_routes(flow: Flow) -> list[dict[str, Any]]:
    return _run_ip(_family_flag(flow), "route", "show", "table", "all")


def collect_links() -> list[dict[str, Any]]:
    return _run_ip("-d", "link", "show")
