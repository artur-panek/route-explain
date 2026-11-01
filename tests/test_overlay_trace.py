import pytest

from route_explain.model import Flow
from route_explain.nfttrace import filter_flow_trace, parse_native_trace_line, render_trace
from route_explain.overlay import overlay_evidence

OFFICIAL_PACKET = (
    'trace id 78653943 inet host-firewall trace-inbound packet: '
    'iif "lo" @ll,0,112 0x800 ip saddr 127.0.0.53 ip daddr 127.0.0.1 '
    'ip dscp cs0 ip ecn not-ect ip ttl 1 ip id 64669 ip protocol udp '
    'ip length 168 udp sport 53 udp dport 36520 udp length 148'
)
OFFICIAL_RULE = (
    'trace id 78653943 inet host-firewall trace-inbound rule '
    'meta l4proto udp meta nftrace set 1 (verdict continue)'
)
MARKED_PACKET = (
    'trace id 8e85e085 ip mangle PREROUTING packet: iif "enp8s0" '
    'ether saddr dc:9f:db:16:42:b5 ether daddr 38:ea:a7:ab:f8:bc '
    'ip saddr 172.23.2.132 ip daddr 8.8.8.8 ip protocol icmp '
    'ip length 60 icmp type echo-request'
)
MARK_ZERO = 'trace id 8e85e085 ip mangle PREROUTING mark 0x00000000'
MARK_THREE = (
    'trace id 8e85e085 ip mangle PREROUTING verdict continue mark 0x00000003'
)


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


def test_native_trace_packet_parses_official_shape():
    event = parse_native_trace_line(OFFICIAL_PACKET)
    assert event is not None
    assert event["trace_id"] == "78653943"
    assert event["family"] == "inet"
    assert event["table"] == "host-firewall"
    assert event["chain"] == "trace-inbound"
    assert event["type"] == "packet"
    assert event["packet"] == {
        "source": "127.0.0.53",
        "destination": "127.0.0.1",
        "protocol": "udp",
        "sport": 53,
        "dport": 36520,
        "iif": "lo",
        "oif": None,
    }


def test_native_trace_rule_parses_verdict():
    event = parse_native_trace_line(OFFICIAL_RULE)
    assert event is not None
    assert event["type"] == "rule"
    assert event["rule"] == "meta l4proto udp meta nftrace set 1"
    assert event["verdict"] == "continue"


def test_native_trace_mark_parses_real_shape():
    event = parse_native_trace_line(MARK_THREE)
    assert event is not None
    assert event["type"] == "verdict"
    assert event["verdict"] == "continue"
    assert event["mark"] == 3


def test_flow_filter_keeps_all_events_for_matching_trace_id():
    events = [
        parse_native_trace_line(OFFICIAL_PACKET),
        parse_native_trace_line(OFFICIAL_RULE),
        parse_native_trace_line(
            "trace id 78653943 inet host-firewall trace-inbound policy accept"
        ),
    ]
    parsed = [event for event in events if event is not None]
    matched = filter_flow_trace(
        parsed,
        Flow(
            destination="127.0.0.1",
            source="127.0.0.53",
            protocol="udp",
            source_port=53,
            destination_port=36520,
        ),
    )
    assert [event["type"] for event in matched] == ["packet", "rule", "policy"]


def test_empty_nft_trace_is_explicitly_read_only():
    text = render_trace([])
    assert "meta nftrace set 1" in text
    assert "does not mutate your ruleset" in text


def test_nft_trace_surfaces_mark_transition_and_cache_caveat():
    events = [
        parse_native_trace_line(MARKED_PACKET),
        parse_native_trace_line(MARK_ZERO),
        parse_native_trace_line(MARK_THREE),
    ]
    parsed = [event for event in events if event is not None]
    text = render_trace(parsed)
    assert "MARK changed: 0x0 -> 0x3" in text
    assert "changing the ruleset during capture" in text


@pytest.mark.parametrize(
    "packet_suffix,selectors",
    [
        ("", {"protocol": "tcp"}),
        (" ip protocol tcp", {"protocol": "tcp", "source_port": 50000}),
        (" ip protocol tcp", {"protocol": "tcp", "destination_port": 443}),
        (" ip protocol udp", {"protocol": "tcp"}),
        (" ip protocol tcp tcp sport 40000", {"source_port": 50000}),
        (" ip protocol tcp tcp dport 80", {"destination_port": 443}),
    ],
)
def test_flow_filter_requires_requested_packet_selectors(packet_suffix, selectors):
    # Truncated/unsupported packet headers cannot identify a requested L4 flow.
    packet = parse_native_trace_line(
        'trace id abc ip filter input packet: iif "eth0" '
        'ip saddr 192.0.2.1 ip daddr 192.0.2.2'
        + packet_suffix
    )
    mark = parse_native_trace_line(
        'trace id abc ip filter input verdict continue mark 0x42'
    )
    assert packet is not None and mark is not None
    assert filter_flow_trace(
        [packet, mark], Flow(destination="192.0.2.2", **selectors)
    ) == []


def test_flow_filter_still_accepts_address_only_packet_for_address_only_request():
    packet = parse_native_trace_line(
        'trace id abc ip filter input packet: iif "eth0" '
        'ip saddr 192.0.2.1 ip daddr 192.0.2.2'
    )
    assert packet is not None
    assert filter_flow_trace([packet], Flow(destination="192.0.2.2")) == [packet]


@pytest.mark.parametrize("partial_id", ["abc", "def"])
def test_flow_filter_needs_one_complete_matching_packet_in_each_trace(partial_id):
    partial = parse_native_trace_line(
        f'trace id {partial_id} ip filter input packet: iif "eth0" '
        'ip saddr 192.0.2.1 ip daddr 192.0.2.2 ip protocol tcp'
    )
    complete = parse_native_trace_line(
        'trace id def ip filter input packet: iif "eth0" '
        'ip saddr 192.0.2.1 ip daddr 192.0.2.2 ip protocol tcp '
        'tcp sport 50000 tcp dport 443'
    )
    mark = parse_native_trace_line(
        'trace id def ip filter input verdict continue mark 0x42'
    )
    assert partial is not None and complete is not None and mark is not None
    expected = [partial, complete, mark] if partial_id == "def" else [complete, mark]
    assert filter_flow_trace(
        [partial, complete, mark],
        Flow(destination="192.0.2.2", protocol="tcp", source_port=50000, destination_port=443),
    ) == expected
