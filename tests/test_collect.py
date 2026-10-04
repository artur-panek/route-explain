from route_explain.collect import namespace_prefix, route_get_args
from route_explain.model import Flow, NamespaceTarget


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
    assert route_get_args(flow) == [
        "route", "get", "10.70.0.12", "from", "10.10.0.24", "iif", "lan0", "oif", "tailscale0",
        "mark", "0x42", "tos", "0x10", "vrf", "blue", "ipproto", "tcp", "sport", "50000", "dport", "443",
    ]


def test_fibmatch_flag_precedes_destination():
    assert route_get_args(Flow(destination="192.0.2.10"), fibmatch=True) == [
        "route", "get", "fibmatch", "192.0.2.10"
    ]


def test_namespace_prefixes(monkeypatch):
    monkeypatch.setattr("route_explain.collect.shutil.which", lambda name: f"/usr/bin/{name}")
    assert namespace_prefix(NamespaceTarget("netns", "blue")) == ["ip", "netns", "exec", "blue"]
    assert namespace_prefix(NamespaceTarget("pid", "123")) == ["nsenter", "--target", "123", "--net"]


def test_wireguard_collector_discards_peer_keys(monkeypatch):
    from types import SimpleNamespace
    from route_explain import collect

    monkeypatch.setattr(collect.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        collect,
        "run_command",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout="wg0 SUPERSECRETPEERKEY 10.70.0.0/24, 10.80.0.0/16\n",
            stderr="",
        ),
    )
    result = collect.collect_wireguard()
    assert result["available"] is True
    assert [item["prefix"] for item in result["routes"]] == ["10.70.0.0/24", "10.80.0.0/16"]
    assert "SUPERSECRETPEERKEY" not in str(result)


def test_tailscale_collector_extracts_route_metadata(monkeypatch):
    from route_explain import collect

    monkeypatch.setattr(collect.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        collect,
        "_run_json_command",
        lambda *args, **kwargs: {
            "BackendState": "Running",
            "Peer": {
                "abc": {
                    "DNSName": "router.tail.ts.net.",
                    "PrimaryRoutes": ["10.70.0.0/24"],
                }
            },
        },
    )
    result = collect.collect_tailscale()
    assert result["backend_state"] == "Running"
    assert result["routes"][0]["prefix"] == "10.70.0.0/24"
    assert result["routes"][0]["peer"] == "router.tail.ts.net."
