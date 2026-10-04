from route_explain.analyze import (
    build_context_report,
    build_report,
    explain_why_not,
    parse_matching_routes,
    parse_rules,
)
from route_explain.model import Flow


def test_prefers_kernel_decision_and_surfaces_more_specific_other_table():
    flow = Flow(destination="10.70.0.12", source="10.10.0.24", destination_port=443)
    report = build_report(
        flow,
        route_get=[
            {
                "dst": "10.70.0.12",
                "gateway": "10.10.0.1",
                "dev": "eth0",
                "prefsrc": "10.10.0.24",
                "table": "main",
            }
        ],
        fibmatch=[
            {"dst": "default", "gateway": "10.10.0.1", "dev": "eth0", "table": "main"}
        ],
        rules=[
            {"priority": 32766, "src": "all", "dst": "all", "table": "main"},
            {"priority": 32767, "src": "all", "dst": "all", "table": "default"},
        ],
        routes=[
            {"dst": "10.70.0.0/24", "dev": "tailscale0", "table": 52},
            {"dst": "default", "gateway": "10.10.0.1", "dev": "eth0", "table": "main"},
        ],
        links=[{"ifname": "lo"}, {"ifname": "eth0"}, {"ifname": "tailscale0"}],
    )
    assert report.decision.dev == "eth0"
    assert report.decision.matched_prefix == "default"
    assert any("more-specific route exists in table 52" in item.message for item in report.evidence)


def test_matching_routes_are_sorted_by_specificity():
    flow = Flow(destination="10.70.0.12")
    routes = parse_matching_routes(
        flow,
        [
            {"dst": "default", "dev": "eth0", "table": "main"},
            {"dst": "10.70.0.0/24", "dev": "tailscale0", "table": 52},
            {"dst": "10.70.0.12/32", "dev": "wg0", "table": 100},
        ],
    )
    assert [route.destination for route in routes] == ["10.70.0.12/32", "10.70.0.0/24", "default"]


def test_policy_rule_filtering_uses_supported_selectors():
    flow = Flow(
        destination="10.70.0.12",
        source="10.10.0.24",
        protocol="tcp",
        destination_port=443,
        source_port=50000,
        mark=0x42,
        iif="lan0",
    )
    rules = parse_rules(
        flow,
        [
            {"priority": 100, "src": "10.10.0.0/24", "table": 100, "fwmark": "0x41"},
            {
                "priority": 200,
                "src": "10.10.0.0/24",
                "dst": "10.70.0.0/24",
                "table": 200,
                "fwmark": "0x42",
                "ipproto": "tcp",
                "dport": "443",
                "sport": "40000-60000",
                "iif": "lan0",
            },
        ],
    )
    assert [rule.priority for rule in rules] == [200]
    assert rules[0].certainty == "match"


def test_missing_source_context_is_maybe_not_false_negative():
    rules = parse_rules(
        Flow(destination="203.0.113.1"),
        [{"priority": 100, "src": "10.0.0.0/8", "dst": "all", "table": 100}],
    )
    assert len(rules) == 1
    assert rules[0].certainty == "indeterminate"
    assert rules[0].unknown_selectors == ("src",)


def test_fwmark_mask_is_respected():
    rules = parse_rules(
        Flow(destination="203.0.113.10", mark=0x142),
        [{"priority": 100, "src": "all", "dst": "all", "table": 100, "fwmark": "0x42", "fwmask": "0xff"}],
    )
    assert [rule.priority for rule in rules] == [100]
    assert rules[0].certainty == "match"


def test_not_rule_inverts_the_combined_selector():
    rules = parse_rules(
        Flow(destination="10.70.0.12", destination_port=443),
        [{"priority": 9002, "not": None, "src": "all", "dport": 53, "table": "main", "suppress_prefixlen": 0}],
    )
    assert len(rules) == 1
    assert rules[0].inverted is True
    assert rules[0].certainty == "match"


def test_overlay_metadata_is_explained():
    report = build_report(
        Flow(destination="10.70.0.12"),
        route_get=[{"dst": "10.70.0.12", "dev": "eth0", "table": "main"}],
        fibmatch=[{"dst": "default", "dev": "eth0", "table": "main"}],
        rules=[{"priority": 32766, "src": "all", "dst": "all", "table": "main"}],
        routes=[{"dst": "default", "dev": "eth0", "table": "main"}],
        links=[{"ifname": "tailscale0"}],
        overlay_state={
            "tailscale": {
                "routes": [
                    {"kind": "tailscale", "interface": "tailscale0", "prefix": "10.70.0.0/24", "peer": "router"}
                ]
            }
        },
    )
    assert any("tailscale metadata covers" in item.message for item in report.evidence)


def test_why_not_interface_explains_route_and_policy_context():
    report = build_report(
        Flow(destination="10.70.0.12"),
        route_get=[{"dst": "10.70.0.12", "dev": "eth0", "table": "main"}],
        fibmatch=[{"dst": "default", "dev": "eth0", "table": "main"}],
        rules=[{"priority": 32766, "src": "all", "dst": "all", "table": "main"}],
        routes=[
            {"dst": "default", "dev": "eth0", "table": "main"},
            {"dst": "10.70.0.0/24", "dev": "tailscale0", "table": 52},
        ],
        links=[{"ifname": "eth0"}, {"ifname": "tailscale0"}],
    )
    result = explain_why_not(report, "tailscale0")
    assert result.status == "available"
    assert any("kernel selected table main" in item.message for item in result.evidence)
    assert any("no selector-matching RPDB" in item.message for item in result.evidence)


def test_context_report_refuses_to_simulate_kernel():
    report = build_context_report(
        Flow(destination="192.0.2.1"),
        rules=[],
        routes=[{"dst": "192.0.2.0/24", "dev": "eth0", "table": "main"}],
        links=[{"ifname": "eth0"}],
    )
    assert any("not simulated offline" in item.message for item in report.evidence)
