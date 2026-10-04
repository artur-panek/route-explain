from __future__ import annotations

import ipaddress
import json
import shutil
from typing import Any

from .context import ExecutionContext, run_text


def collect_wireguard(context: ExecutionContext) -> list[dict[str, Any]]:
    if shutil.which("wg") is None:
        return []
    proc = run_text(context, ["wg", "show", "all", "dump"])
    if proc.returncode != 0:
        return []

    interfaces: dict[str, dict[str, Any]] = {}
    for line in proc.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) == 5:
            interface = fields[0]
            interfaces[interface] = {
                "interface": interface,
                "listen_port": fields[3],
                "fwmark": fields[4],
                "peers": [],
            }
        elif len(fields) >= 9 and fields[0] in interfaces:
            interfaces[fields[0]]["peers"].append(
                {
                    "public_key": fields[1],
                    "endpoint": fields[3],
                    "allowed_ips": [item for item in fields[4].split(",") if item],
                    "latest_handshake": fields[5],
                }
            )
    return list(interfaces.values())


def collect_tailscale(context: ExecutionContext) -> dict[str, Any] | None:
    # tailscale status talks to a daemon over a Unix socket. Entering only another
    # network namespace would still use the host filesystem/socket and could
    # misattribute host daemon state to a container/netns.
    if context.kind != "host" or shutil.which("tailscale") is None:
        return None
    proc = run_text(context, ["tailscale", "status", "--json"])
    if proc.returncode != 0:
        return None
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _contains(
    destination: ipaddress.IPv4Address | ipaddress.IPv6Address,
    raw: object,
) -> bool:
    try:
        return destination in ipaddress.ip_network(str(raw), strict=False)
    except ValueError:
        return False


def overlay_evidence(
    destination: str,
    wireguard: list[dict[str, Any]],
    tailscale: dict[str, Any] | None,
) -> list[str]:
    address = ipaddress.ip_address(destination)
    messages: list[str] = []

    for interface in wireguard:
        for peer in interface.get("peers", []):
            matched = [
                raw
                for raw in peer.get("allowed_ips", [])
                if _contains(address, raw)
            ]
            if matched:
                messages.append(
                    f"WireGuard {interface.get('interface')} peer AllowedIPs contains "
                    f"destination via {', '.join(matched)}"
                )

    if tailscale:
        self_node = tailscale.get("Self") or {}
        if self_node.get("Online"):
            messages.append("Tailscale reports the local node online")

        peers = tailscale.get("Peer") or {}
        if isinstance(peers, dict):
            for peer in peers.values():
                if not isinstance(peer, dict):
                    continue
                name = peer.get("HostName") or peer.get("DNSName") or "unknown"
                exact_ips = peer.get("TailscaleIPs") or []
                if any(str(raw) == destination for raw in exact_ips):
                    messages.append(f"Tailscale peer {name} owns destination")

                subnet_fields = (
                    peer.get("PrimaryRoutes") or [],
                    peer.get("AllowedIPs") or [],
                )
                subnet_matches = sorted(
                    {
                        str(raw)
                        for values in subnet_fields
                        for raw in values
                        if _contains(address, raw)
                    }
                )
                if subnet_matches:
                    messages.append(
                        f"Tailscale peer {name} advertises/owns route(s) containing "
                        f"destination: {', '.join(subnet_matches)}"
                    )
    return messages
