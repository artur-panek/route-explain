from route_explain.nfttrace import render_trace
from route_explain.overlay import overlay_evidence


def test_wireguard_allowed_ips_are_explained():
    messages = overlay_evidence(
        "10.70.0.12",
        [
            {
                "interface": "wg0",
                "peers": [
                    {
                        "allowed_ips": ["10.70.0.0/24"],
                    }
                ],
            }
        ],
        None,
    )
    assert any("AllowedIPs" in message for message in messages)


def test_tailscale_primary_routes_are_explained():
    messages = overlay_evidence(
        "10.70.0.12",
        [],
        {
            "Self": {"Online": True},
            "Peer": {
                "node": {
                    "HostName": "subnet-router",
                    "PrimaryRoutes": ["10.70.0.0/24"],
                    "TailscaleIPs": ["100.64.0.2"],
                }
            },
        },
    )
    assert any("10.70.0.0/24" in message for message in messages)


def test_empty_nft_trace_is_explicitly_read_only():
    text = render_trace([])
    assert "meta nftrace set 1" in text
    assert "does not mutate your ruleset" in text


def test_nft_trace_renders_chain_and_packet_mark():
    events = [
        {
            "nftables": [
                {
                    "trace": {
                        "type": "rule",
                        "family": "ip",
                        "table": "mangle",
                        "chain": "prerouting",
                        "rule": "meta mark set 0x42",
                        "packet": {"meta": {"mark": "0x42"}},
                    }
                }
            ],
            "dst": "10.70.0.12",
        }
    ]
    text = render_trace(events)
    assert "ip mangle prerouting" in text
    assert "packet mark: 0x42" in text


def test_nft_trace_surfaces_mark_transition():
    events = [
        {
            "nftables": [
                {
                    "trace": {
                        "type": "rule",
                        "family": "ip",
                        "table": "mangle",
                        "chain": "prerouting",
                        "packet": {"meta": {"mark": "0x0"}},
                    }
                }
            ],
            "dst": "10.70.0.12",
        },
        {
            "nftables": [
                {
                    "trace": {
                        "type": "rule",
                        "family": "ip",
                        "table": "mangle",
                        "chain": "prerouting",
                        "rule": "meta mark set 0x42",
                        "packet": {"meta": {"mark": "0x42"}},
                    }
                }
            ],
            "dst": "10.70.0.12",
        },
    ]
    assert "MARK changed: 0x0 -> 0x42" in render_trace(events)
