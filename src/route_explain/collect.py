from __future__ import annotations

import json
import shutil
from typing import Any

from .context import ContextError, ExecutionContext, run_text
from .model import Flow


class CollectionError(RuntimeError):
    pass


def _run_ip(
    *args: str,
    context: ExecutionContext | None = None,
) -> list[dict[str, Any]]:
    context = context or ExecutionContext()
    if shutil.which("ip") is None:
        raise CollectionError("ip command not found; install iproute2")
    try:
        proc = run_text(context, ["ip", "-j", *args])
    except ContextError as exc:
        raise CollectionError(str(exc)) from exc
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or f"exit code {proc.returncode}"
        raise CollectionError(
            f"ip {' '.join(args)} failed in {context.label}: {detail}"
        )
    try:
        payload = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise CollectionError(
            f"ip {' '.join(args)} returned invalid JSON"
        ) from exc
    if not isinstance(payload, list):
        raise CollectionError(
            f"ip {' '.join(args)} returned an unexpected JSON shape"
        )
    return payload


def _collect(
    *args: str,
    context: ExecutionContext | None,
) -> list[dict[str, Any]]:
    # Keep the no-context call shape compatible with the v0.2 collector API and tests.
    if context is None:
        return _run_ip(*args)
    return _run_ip(*args, context=context)


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
    if flow.source_port is not None or flow.destination_port is not None:
        args.extend(["ipproto", flow.protocol])
        if flow.source_port is not None:
            args.extend(["sport", str(flow.source_port)])
        if flow.destination_port is not None:
            args.extend(["dport", str(flow.destination_port)])
    return args


def collect_route_get(
    flow: Flow,
    *,
    fibmatch: bool = False,
    context: ExecutionContext | None = None,
) -> list[dict[str, Any]]:
    return _collect(
        *route_get_args(flow, fibmatch=fibmatch),
        context=context,
    )


def _family_flag(flow: Flow) -> str:
    return "-6" if ":" in flow.destination else "-4"


def collect_rules(
    flow: Flow,
    *,
    context: ExecutionContext | None = None,
) -> list[dict[str, Any]]:
    return _collect(_family_flag(flow), "rule", "show", context=context)


def collect_routes(
    flow: Flow,
    *,
    context: ExecutionContext | None = None,
) -> list[dict[str, Any]]:
    return _collect(
        _family_flag(flow),
        "route",
        "show",
        "table",
        "all",
        context=context,
    )


def collect_links(
    *,
    context: ExecutionContext | None = None,
) -> list[dict[str, Any]]:
    return _collect("-d", "link", "show", context=context)
