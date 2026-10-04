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


def collect_route_get(flow: Flow) -> list[dict[str, Any]]:
    args = ["route", "get", flow.destination]
    if flow.source:
        args.extend(["from", flow.source])
    return _run_ip(*args)


def collect_rules() -> list[dict[str, Any]]:
    return _run_ip("rule", "show")


def collect_routes() -> list[dict[str, Any]]:
    return _run_ip("route", "show", "table", "all")


def collect_links() -> list[dict[str, Any]]:
    return _run_ip("link", "show")
