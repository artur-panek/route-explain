from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import asdict
from typing import Any

from .model import Flow, NamespaceTarget, OverlayRoute


class CollectionError(RuntimeError):
    pass


def namespace_prefix(target: NamespaceTarget | None) -> list[str]:
    if target is None:
        return []
    if target.kind == "netns":
        if shutil.which("ip") is None:
            raise CollectionError("ip command not found; install iproute2")
        return ["ip", "netns", "exec", target.value]
    if shutil.which("nsenter") is None:
        raise CollectionError("nsenter not found; install util-linux for --pid support")
    return ["nsenter", "--target", target.value, "--net"]


def run_command(
    command: list[str],
    *,
    target: NamespaceTarget | None = None,
    timeout: float | None = 10,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    executable = command[0]
    if shutil.which(executable) is None:
        raise CollectionError(f"{executable} command not found")
    full_command = [*namespace_prefix(target), *command]
    try:
        return subprocess.run(
            full_command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
        )
    except subprocess.TimeoutExpired as exc:
        raise CollectionError(f"{' '.join(full_command)} timed out") from exc


def _run_json_command(
    command: list[str],
    *,
    target: NamespaceTarget | None = None,
    expect_list: bool | None = None,
) -> Any:
    proc = run_command(command, target=target)
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or f"exit code {proc.returncode}"
        raise CollectionError(f"{' '.join(command)} failed: {detail}")
    try:
        payload = json.loads(proc.stdout or ("[]" if expect_list else "{}"))
    except json.JSONDecodeError as exc:
        raise CollectionError(f"{' '.join(command)} returned invalid JSON") from exc
    if expect_list is True and not isinstance(payload, list):
        raise CollectionError(f"{' '.join(command)} returned an unexpected JSON shape")
    if expect_list is False and not isinstance(payload, dict):
        raise CollectionError(f"{' '.join(command)} returned an unexpected JSON shape")
    return payload


def _run_ip(*args: str, target: NamespaceTarget | None = None) -> list[dict[str, Any]]:
    payload = _run_json_command(["ip", "-j", *args], target=target, expect_list=True)
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
    target: NamespaceTarget | None = None,
) -> list[dict[str, Any]]:
    return _run_ip(*route_get_args(flow, fibmatch=fibmatch), target=target)


def _family_flag(flow: Flow) -> str:
    return "-6" if ":" in flow.destination else "-4"


def collect_rules(flow: Flow, *, target: NamespaceTarget | None = None) -> list[dict[str, Any]]:
    return _run_ip(_family_flag(flow), "rule", "show", target=target)


def collect_routes(flow: Flow, *, target: NamespaceTarget | None = None) -> list[dict[str, Any]]:
    return _run_ip(_family_flag(flow), "route", "show", "table", "all", target=target)


def collect_rules_family(
    version: int,
    *,
    target: NamespaceTarget | None = None,
) -> list[dict[str, Any]]:
    return _run_ip("-6" if version == 6 else "-4", "rule", "show", target=target)


def collect_routes_family(
    version: int,
    *,
    target: NamespaceTarget | None = None,
) -> list[dict[str, Any]]:
    return _run_ip(
        "-6" if version == 6 else "-4",
        "route",
        "show",
        "table",
        "all",
        target=target,
    )


def collect_links(*, target: NamespaceTarget | None = None) -> list[dict[str, Any]]:
    return _run_ip("-d", "link", "show", target=target)


def collect_wireguard(*, target: NamespaceTarget | None = None) -> dict[str, Any]:
    if shutil.which("wg") is None:
        return {"available": False, "reason": "wg command not found", "routes": []}
    try:
        proc = run_command(["wg", "show", "all", "allowed-ips"], target=target)
    except CollectionError as exc:
        return {"available": False, "reason": str(exc), "routes": []}
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or f"exit code {proc.returncode}"
        return {"available": False, "reason": detail, "routes": []}

    routes: list[dict[str, Any]] = []
    interfaces: set[str] = set()
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(maxsplit=2)
        if len(parts) < 3:
            continue
        interface, _peer_key, prefixes_text = parts
        interfaces.add(interface)
        for prefix in prefixes_text.replace(",", " ").split():
            if "/" not in prefix:
                continue
            routes.append(
                asdict(
                    OverlayRoute(
                        kind="wireguard",
                        interface=interface,
                        prefix=prefix,
                        source="wg show all allowed-ips",
                    )
                )
            )
    return {"available": True, "interfaces": sorted(interfaces), "routes": routes}


def _tailscale_routes_from_node(node: dict[str, Any], *, peer: str | None) -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    for key in ("PrimaryRoutes", "AllowedIPs", "AdvertisedRoutes"):
        values = node.get(key)
        if not isinstance(values, list):
            continue
        for value in values:
            prefix = str(value)
            if "/" not in prefix:
                continue
            routes.append(
                asdict(
                    OverlayRoute(
                        kind="tailscale",
                        interface="tailscale0",
                        prefix=prefix,
                        peer=peer,
                        source=f"tailscale status --json:{key}",
                    )
                )
            )
    return routes


def collect_tailscale(*, target: NamespaceTarget | None = None) -> dict[str, Any]:
    if shutil.which("tailscale") is None:
        return {"available": False, "reason": "tailscale command not found", "routes": []}
    try:
        payload = _run_json_command(
            ["tailscale", "status", "--json"],
            target=target,
            expect_list=False,
        )
    except CollectionError as exc:
        return {"available": False, "reason": str(exc), "routes": []}

    routes: list[dict[str, Any]] = []
    self_node = payload.get("Self")
    if isinstance(self_node, dict):
        self_name = str(self_node.get("DNSName") or self_node.get("HostName") or "self")
        routes.extend(_tailscale_routes_from_node(self_node, peer=self_name))
    peers = payload.get("Peer")
    if isinstance(peers, dict):
        peer_nodes = [value for value in peers.values() if isinstance(value, dict)]
    elif isinstance(peers, list):
        peer_nodes = [value for value in peers if isinstance(value, dict)]
    else:
        peer_nodes = []
    for node in peer_nodes:
        peer_name = str(node.get("DNSName") or node.get("HostName") or node.get("ID") or "peer")
        routes.extend(_tailscale_routes_from_node(node, peer=peer_name))

    return {
        "available": True,
        "backend_state": payload.get("BackendState"),
        "peer_count": len(peer_nodes),
        "routes": routes,
        "format_warning": "tailscale status --json is documented as subject to change",
    }


def collect_overlay_state(*, target: NamespaceTarget | None = None) -> dict[str, Any]:
    return {
        "wireguard": collect_wireguard(target=target),
        "tailscale": collect_tailscale(target=target),
    }
