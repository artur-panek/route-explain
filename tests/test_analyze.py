from route_explain.analyze import build_report, parse_matching_routes
from route_explain.model import Flow


def test_prefers_kernel_decision_and_surfaces_other_table():
    flow = Flow(destination="10.70.0.12", source="10.10.0.24", port=443)
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
    assert report.decision.table == "main"
    assert report.overlays == ["tailscale0"]
    assert any("other table(s): 52" in note for note in report.notes)


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

    assert [route.destination for route in routes] == [
        "10.70.0.12/32",
        "10.70.0.0/24",
        "default",
    ]


def test_basic_policy_rule_filtering_uses_source_and_destination():
    flow = Flow(destination="10.70.0.12", source="10.10.0.24")
    report = build_report(
        flow,
        route_get=[{"dst": "10.70.0.12", "dev": "eth0"}],
        rules=[
            {
                "priority": 100,
                "src": "192.168.0.0/16",
                "dst": "all",
                "table": 100,
            },
            {
                "priority": 200,
                "src": "10.10.0.0/24",
                "dst": "10.70.0.0/24",
                "table": 200,
            },
        ],
        routes=[],
        links=[],
    )

    assert [rule.priority for rule in report.candidate_rules] == [200]
