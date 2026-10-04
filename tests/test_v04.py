from argparse import Namespace
from types import SimpleNamespace

from route_explain import correlation
from route_explain.analyze import build_report, parse_rules
from route_explain.cli import _expectation_failures
from route_explain.context import ExecutionContext
from route_explain.correlation import correlate_trace, extract_observations, render_correlation
from route_explain.model import Flow, RouteDecision
from route_explain.nfttrace import parse_native_trace_line
from route_explain.render import render_text

PACKET = (
    'trace id 8e85e085 ip mangle PREROUTING packet: iif "lan0" '
    'ip saddr 10.10.0.24 ip daddr 10.70.0.12 ip protocol tcp '
    'tcp sport 50000 tcp dport 443'
)
MARK = 'trace id 8e85e085 ip mangle PREROUTING verdict continue mark 0x42'


def _report():
    return build_report(
        Flow(destination="192.0.2.10"),
        route_get=[{"dst": "192.0.2.10", "dev": "eth0", "table": "main"}],
        fibmatch=[{"dst": "0.0.0.0/0", "dev": "eth0", "table": "main"}],
        rules=[{"priority": 32766, "src": "all", "dst": "all", "table": "main"}],
        routes=[{"dst": "default", "dev": "eth0", "table": "main"}],
        links=[{"ifname": "eth0"}],
    )


def _native_events():
    return [
        event
        for event in (
            parse_native_trace_line(PACKET),
            parse_native_trace_line(MARK),
        )
        if event is not None
    ]


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


def test_trace_observations_carry_interface_state_into_mark_event():
    observations = extract_observations(_native_events())
    assert observations[0]["mark"] is None
    assert observations[0]["iif"] == "lan0"
    assert observations[-1]["mark"] == 0x42
    assert observations[-1]["iif"] == "lan0"


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

    probed = []

    def fake_probe(flow, context, baseline_snapshot):
        probed.append(flow)
        return changed if flow.mark == 0x42 else baseline

    monkeypatch.setattr(correlation, "_probe", fake_probe)

    result = correlate_trace(
        Flow(
            destination="10.70.0.12",
            source="10.10.0.24",
            protocol="tcp",
            source_port=50000,
            destination_port=443,
        ),
        _native_events(),
        ExecutionContext(),
        baseline_snapshot={},
    )

    assert probed[-1].mark == 0x42
    assert probed[-1].iif == "lan0"
    assert result["lookups"][-1]["decision_changed"] is True
    assert result["lookups"][-1]["decision"]["dev"] == "tailscale0"
    assert result["schema_version"] == 2


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
