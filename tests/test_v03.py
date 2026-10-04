from route_explain.context import ContextError, ExecutionContext, resolve_context
from route_explain.diffing import diff_snapshots, render_diff
from route_explain.model import Route
from route_explain.snapshot import report_from_snapshot
from route_explain.why import explain_why_not


def _snapshot(dev="eth0", table="main", prefix="default"):
    return {
        "snapshot_schema_version": 1,
        "captured_at": "2026-10-04T00:00:00+00:00",
        "context": {"kind": "host", "value": None, "label": "host"},
        "host": {"node": "test", "kernel": "test"},
        "flow": {
            "destination": "10.70.0.12",
            "source": None,
            "protocol": "tcp",
            "destination_port": None,
            "source_port": None,
            "mark": None,
            "tos": None,
            "iif": None,
            "oif": None,
            "vrf": None,
        },
        "evidence": {
            "route_get": [{"dst": "10.70.0.12", "dev": dev, "table": table}],
            "fibmatch": [{"dst": prefix, "dev": dev, "table": table}],
            "rules": [
                {
                    "priority": 32766,
                    "src": "all",
                    "dst": "all",
                    "table": table,
                }
            ],
            "routes": [{"dst": prefix, "dev": dev, "table": table}],
            "links": [{"ifname": dev}],
            "wireguard": [],
            "tailscale": None,
        },
    }


def test_snapshot_replay_builds_report():
    report = report_from_snapshot(_snapshot())
    assert report.decision.dev == "eth0"
    assert report.decision.matched_prefix == "default"


def test_snapshot_diff_detects_decision_change():
    result = diff_snapshots(
        _snapshot(),
        _snapshot("tailscale0", "52", "10.70.0.0/24"),
    )
    assert result["decision_changed"] is True
    assert result["before"]["table"] == "main"
    assert result["after"]["table"] == "52"
    rendered = render_diff(result)
    assert "ROUTING DECISION CHANGED" in rendered
    assert "+ route: 10.70.0.0/24 dev tailscale0 table 52" in rendered


def test_why_not_surfaces_existing_route():
    report = report_from_snapshot(_snapshot())
    report.matching_routes.append(
        Route("10.70.0.0/24", None, "tailscale0", "52")
    )
    text = explain_why_not(report, "tailscale0")
    assert "Route exists" in text
    assert "kernel selected table main" in text


def test_why_not_accepts_explicit_table_target():
    report = report_from_snapshot(_snapshot())
    report.matching_routes.append(
        Route("10.70.0.0/24", None, "tailscale0", "52")
    )
    assert "Route exists" in explain_why_not(report, "table:52")


def test_context_prefixes():
    assert ExecutionContext().prefix() == []
    assert ExecutionContext("netns", "blue").prefix() == [
        "ip",
        "netns",
        "exec",
        "blue",
    ]


def test_context_rejects_multiple_selectors():
    try:
        resolve_context(netns="blue", pid=123)
    except ContextError as exc:
        assert "only one" in str(exc)
    else:
        raise AssertionError("expected ContextError")
