from argparse import Namespace
from types import SimpleNamespace

from route_explain import correlation
from route_explain.analyze import build_report, parse_rules
from route_explain.cli import _expectation_failures
from route_explain.context import ExecutionContext
from route_explain.correlation import (
    correlate_trace,
    extract_observations,
    render_correlation,
)
from route_explain.model import Flow, RouteDecision
from route_explain.render import render_text


def _report():
    return build_report(
        Flow(destination="192.0.2.10"),
        route_get=[{"dst": "192.0.2.10", "dev": "eth0", "table": "main"}],
        fibmatch=[{"dst": "0.0.0.0/0", "dev": "eth0", "table": "main"}],
        rules=[{"priority": 32766, "src": "all", "dst": "all", "table": "main"}],
        routes=[{"dst": "default", "dev": "eth0", "table": "main"}],
        links=[{"ifname": "eth0"}],
    )


def _trace_event(mark="0x42", iif="lan0"):
    return {
        "nftables": [
            {
                "trace": {
                    "type": "rule",
                    "family": "ip",
                    "table": "mangle",
                    "chain": "prerouting",
                    "hook": "prerouting",
                    "rule": "meta mark set 0x42",
                    "packet": {"meta": {"mark": mark, "iifname": iif}},
                }
            }
        ]
    }


def test_source_specific_rule_without_source_is_maybe():
    rules = parse_rules(
        Flow(destination="203.0.113.10"),
        [
            {
                "priority": 100,
                "src": "10.10.0.0/24",
                "dst": "all",
                "table": 100,
            }
        ],
    )
    assert len(rules) == 1
    assert rules[0].certainty == "indeterminate"
    assert rules[0].unknown_selectors == ("src",)


def test_default_and_zero_prefix_are_same_selected_route():
    text = render_text(_report())
    assert " * default dev eth0 table main" in text


def test_expectations_accept_table_id_and_equivalent_default_prefix():
    args = Namespace(
        expect_dev="eth0",
        expect_table="254",
        expect_prefix="default",
    )
    assert _expectation_failures(_report(), args) == []


def test_expectations_surface_mismatch():
    args = Namespace(
        expect_dev="wg0",
        expect_table=None,
        expect_prefix=None,
    )
    assert _expectation_failures(_report(), args) == [
        "dev expected wg0, got eth0"
    ]


def test_trace_observations_are_route_relevant_and_deduplicated():
    events = [_trace_event(), _trace_event()]
    observations = extract_observations(events)
    assert len(observations) == 1
    assert observations[0]["mark"] == 0x42
    assert observations[0]["iif"] == "lan0"


def test_correlate_trace_reuses_observed_mark_for_kernel_probe(monkeypatch):
    baseline = RouteDecision(
        destination="10.70.0.12",
        gateway="10.0.0.1",
        dev="eth0",
        source="10.0.0.20",
        table="main",
        matched_prefix="default",
    )
    changed = RouteDecision(
        destination="10.70.0.12",
        gateway=None,
        dev="tailscale0",
        source="100.64.0.1",
        table="52",
        matched_prefix="10.70.0.0/24",
    )

    monkeypatch.setattr(
        correlation,
        "report_from_snapshot",
        lambda snapshot: SimpleNamespace(decision=baseline),
    )

    def fake_probe(flow, context, baseline_snapshot):
        assert flow.mark == 0x42
        assert flow.iif == "lan0"
        return changed

    monkeypatch.setattr(correlation, "_probe", fake_probe)

    result = correlate_trace(
        Flow(destination="10.70.0.12"),
        [_trace_event()],
        ExecutionContext(),
        baseline_snapshot={},
    )

    assert result["lookups"][0]["decision_changed"] is True
    assert result["lookups"][0]["lookup_flow"]["mark"] == 0x42
    assert result["lookups"][0]["decision"]["dev"] == "tailscale0"


def test_correlation_output_keeps_forensic_caveat():
    result = {
        "baseline": {
            "table": "main",
            "matched_prefix": "default",
            "dev": "eth0",
            "gateway": "10.0.0.1",
        },
        "lookups": [],
        "note": correlation.CORRELATION_NOTE,
    }
    text = render_correlation(result)
    assert "CHECK no route-relevant" in text
    assert "does not by itself prove" in text
