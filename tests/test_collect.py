from route_explain.collect import route_get_args
from route_explain.model import Flow


def test_route_get_args_include_real_flow_selectors():
    flow = Flow(
        destination="10.70.0.12",
        source="10.10.0.24",
        protocol="tcp",
        destination_port=443,
        source_port=50000,
        mark=0x42,
        tos=0x10,
        iif="lan0",
        oif="tailscale0",
        vrf="blue",
    )

    args = route_get_args(flow)

    assert args == [
        "route",
        "get",
        "10.70.0.12",
        "from",
        "10.10.0.24",
        "iif",
        "lan0",
        "oif",
        "tailscale0",
        "mark",
        "0x42",
        "tos",
        "0x10",
        "vrf",
        "blue",
        "ipproto",
        "tcp",
        "sport",
        "50000",
        "dport",
        "443",
    ]


def test_fibmatch_flag_precedes_destination():
    flow = Flow(destination="192.0.2.10")
    assert route_get_args(flow, fibmatch=True) == ["route", "get", "fibmatch", "192.0.2.10"]


def test_family_specific_collectors_are_selected_from_destination(monkeypatch):
    from route_explain import collect

    calls = []

    def fake_run_ip(*args):
        calls.append(args)
        return []

    monkeypatch.setattr(collect, "_run_ip", fake_run_ip)
    collect.collect_rules(Flow(destination="2001:db8::1"))
    collect.collect_routes(Flow(destination="192.0.2.1"))

    assert calls == [
        ("-6", "rule", "show"),
        ("-4", "route", "show", "table", "all"),
    ]
