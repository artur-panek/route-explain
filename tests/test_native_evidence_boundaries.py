import copy
import json

import pytest
from test_v03 import _snapshot

from route_explain.analyze import parse_rules
from route_explain.cli import main
from route_explain.diffing import diff_snapshots, render_diff
from route_explain.model import Flow
from route_explain.snapshot import load_snapshot


@pytest.mark.parametrize("ecn", range(4))
def test_dscp_uses_six_upper_tos_bits(ecn):
    rule = {"priority": 100, "table": 100, "dscp": "0x2e", "dscp_mask": "0x3f"}
    assert parse_rules(Flow("192.0.2.1", tos=(46 << 2) | ecn), [rule])[0].certainty == "match"
    assert parse_rules(Flow("192.0.2.1", tos=0), [rule]) == []
    assert parse_rules(Flow("192.0.2.1"), [rule])[0].unknown_selectors == ("dscp",)


def test_dscp_mask_and_inversion():
    rule = {"priority": 100, "table": 100, "dscp": "0x2e", "dscp_mask": "0x30"}
    assert parse_rules(Flow("192.0.2.1", tos=0x80), [rule])[0].certainty == "match"
    assert parse_rules(Flow("192.0.2.1", tos=0x80), [{**rule, "not": None}]) == []


@pytest.mark.parametrize(
    "selector",
    [
        {"flowlabel": "0x12345", "flowlabel_mask": "0xfffff"},
        {"sport_start": 100, "sport_end": 100, "sport_mask": "0xff00"},
    ],
)
def test_unsupported_native_predicates_remain_unknown(selector):
    rule = {"priority": 100, "table": 100, **selector}
    candidate = parse_rules(Flow("2001:db8::1", source_port=200), [rule])[0]
    assert candidate.certainty == "indeterminate"
    assert set(selector) & candidate.selectors.keys()
    assert parse_rules(Flow("2001:db8::1"), [{**rule, "dst": "2001:db8:1::/64"}]) == []
    inverted = parse_rules(Flow("2001:db8::1"), [{**rule, "not": None}])[0]
    assert inverted.certainty == "indeterminate"


def test_diff_reports_tos_and_nested_nexthops_without_counter_noise():
    before = _snapshot()
    after = copy.deepcopy(before)
    before["evidence"]["routes"][0]["nexthops"] = [
        {"dev": "eth0", "gateway": "192.0.2.1", "weight": 1, "packets": 10}
    ]
    after["evidence"]["routes"][0]["nexthops"] = [
        {"dev": "eth0", "gateway": "192.0.2.2", "weight": 1, "packets": 20}
    ]
    after["evidence"]["rules"][0]["tos"] = "0x10"
    diff = diff_snapshots(before, after)
    assert len(diff["routes_added"]) == len(diff["routes_removed"]) == 1
    assert "192.0.2.2" in render_diff(diff)
    assert "tos=0x10" in render_diff(diff)
    before["evidence"]["routes"][0]["nexthops"][0]["gateway"] = "192.0.2.2"
    assert diff_snapshots(before, after)["routes_added"] == []


@pytest.mark.parametrize(
    "mutate",
    [
        lambda s: s.clear(),
        lambda s: s.update(snapshot_schema_version=True),
        lambda s: s.pop("flow"),
        lambda s: s["flow"].update(extra=True),
        lambda s: s["flow"].update(destination=[]),
        lambda s: s["evidence"].update(route_get=[]),
        lambda s: s["evidence"].update(rules=[[]]),
        lambda s: s["evidence"].update(links=[{"linkinfo": []}]),
        lambda s: s["evidence"]["routes"][0].update(nexthops=[[]]),
    ],
)
def test_malformed_snapshot_is_cli_error_with_filename(tmp_path, capsys, mutate):
    snapshot = _snapshot()
    mutate(snapshot)
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(snapshot))
    with pytest.raises(ValueError, match="bad.json"):
        load_snapshot(path)
    assert main(["replay", str(path)]) == 2
    assert "Traceback" not in capsys.readouterr().err
