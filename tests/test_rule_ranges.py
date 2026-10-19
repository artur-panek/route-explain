import json

import pytest

from route_explain.analyze import build_report, parse_rules
from route_explain.model import Flow
from route_explain.render import render_json, render_text


@pytest.mark.parametrize("selector,flow_field", [("sport", "source_port"), ("dport", "destination_port")])
@pytest.mark.parametrize("port,matches", [(999, False), (1000, True), (1500, True), (2000, True), (2001, False)])
def test_native_port_ranges_match_only_inside_the_bounds(selector, flow_field, port, matches):
    # iproute2 ip/iprule.c emits separate *_start and *_end JSON fields.
    rule = {
        "priority": 100,
        "src": "all",
        "table": 100,
        f"{selector}_start": 1000,
        f"{selector}_end": 2000,
    }
    flow = Flow(destination="192.0.2.1", protocol="tcp", **{flow_field: port})

    parsed = parse_rules(flow, [rule])

    assert bool(parsed) is matches
    if matches:
        assert parsed[0].certainty == "match"
        assert parsed[0].selectors[selector] == "1000-2000"
        assert parsed[0].raw == rule


@pytest.mark.parametrize("selector", ["sport", "dport"])
def test_native_port_range_without_flow_port_is_indeterminate(selector):
    parsed = parse_rules(
        Flow(destination="192.0.2.1"),
        [{"table": 100, f"{selector}_start": 1000, f"{selector}_end": 2000}],
    )

    assert parsed[0].certainty == "indeterminate"
    assert parsed[0].unknown_selectors == (selector,)


@pytest.mark.parametrize("port,matches", [(443, True), (1500, False), (None, True)])
def test_native_range_inversion_preserves_unknown_context(port, matches):
    parsed = parse_rules(
        Flow(destination="192.0.2.1", destination_port=port),
        [{"table": 100, "not": None, "dport_start": 1000, "dport_end": 2000}],
    )

    assert bool(parsed) is matches
    if matches:
        assert parsed[0].certainty == ("indeterminate" if port is None else "match")


@pytest.mark.parametrize("inverted", [False, True])
def test_native_uid_range_remains_indeterminate(inverted):
    rule = {"table": 100, "uid_start": 1000, "uid_end": 1000}
    if inverted:
        rule["not"] = None

    parsed = parse_rules(Flow(destination="192.0.2.1"), [rule])

    assert parsed[0].certainty == "indeterminate"
    assert parsed[0].unknown_selectors == ("uidrange",)
    assert parsed[0].selectors["uidrange"] == "1000-1000"


def test_missing_uid_does_not_override_a_known_port_mismatch():
    parsed = parse_rules(
        Flow(destination="192.0.2.1", destination_port=443),
        [{"table": 100, "dport_start": 1000, "dport_end": 2000, "uid_start": 1000, "uid_end": 2000}],
    )

    assert parsed == []


@pytest.mark.parametrize("bound", ["start", "end"])
def test_incomplete_native_range_is_not_confirmed(bound):
    parsed = parse_rules(
        Flow(destination="192.0.2.1", destination_port=443),
        [{"table": 100, f"dport_{bound}": 1000}],
    )

    assert parsed[0].certainty == "indeterminate"
    assert parsed[0].unknown_selectors == ("dport",)


def test_reports_show_native_range_constraints():
    report = build_report(
        Flow(destination="192.0.2.1", destination_port=1500),
        route_get=[{"dst": "192.0.2.1", "table": 100, "dev": "eth0"}],
        rules=[{"table": 100, "dport_start": 1000, "dport_end": 2000, "uid_start": 1000, "uid_end": 2000}],
        routes=[],
        links=[],
    )

    text = render_text(report)
    payload = json.loads(render_json(report))

    assert "MAYBE" in text
    assert "dport=1000-2000" in text
    assert "uidrange=1000-2000" in text
    assert "needs uidrange" in text
    assert payload["candidate_rules"][0]["certainty"] == "indeterminate"
    assert payload["candidate_rules"][0]["selectors"] == {
        "dport": "1000-2000",
        "uidrange": "1000-2000",
    }
