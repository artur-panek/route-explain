from route_explain.model import Flow
from route_explain.snapshot import diff_snapshots, find_probe, state_for_flow


def _snapshot(route_dev="eth0", extra_route=None):
    routes = [{"dst": "default", "dev": route_dev, "table": "main"}]
    if extra_route:
        routes.append(extra_route)
    return {
        "snapshot_schema_version": 1,
        "created_at": "2026-10-04T00:00:00+00:00",
        "namespace": None,
        "state": {
            "rules_v4": [{"priority": 32766, "src": "all", "dst": "all", "table": "main"}],
            "rules_v6": [],
            "routes_v4": routes,
            "routes_v6": [],
            "links": [{"ifname": route_dev}],
            "overlays": {"wireguard": {"routes": []}, "tailscale": {"routes": []}},
        },
        "probes": [
            {
                "flow": {"destination": "1.1.1.1", "source": None, "protocol": "tcp", "destination_port": None, "source_port": None, "mark": None, "tos": None, "iif": None, "oif": None, "vrf": None},
                "route_get": [{"dst": "1.1.1.1", "dev": route_dev, "table": "main"}],
                "fibmatch": [{"dst": "default", "dev": route_dev, "table": "main"}],
            }
        ],
    }


def test_find_probe_requires_exact_flow():
    snapshot = _snapshot()
    assert find_probe(snapshot, Flow(destination="1.1.1.1")) is not None
    assert find_probe(snapshot, Flow(destination="1.1.1.1", mark=1)) is None


def test_state_for_flow_chooses_address_family():
    snapshot = _snapshot()
    rules, routes = state_for_flow(snapshot, Flow(destination="1.1.1.1"))
    assert len(rules) == 1
    assert len(routes) == 1


def test_diff_surfaces_decision_and_route_change():
    before = _snapshot("eth0")
    after = _snapshot("tailscale0", {"dst": "10.0.0.0/8", "dev": "tailscale0", "table": 52})
    result = diff_snapshots(before, after)
    assert result["decision_changes"]
    assert any("tailscale0" in item for item in result["added_routes"])
    assert any("eth0" in item for item in result["removed_routes"])
