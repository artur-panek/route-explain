import json

import pytest

from route_explain.context import ContextError, ExecutionContext, resolve_context
from route_explain.diffing import diff_snapshots, render_diff, render_diff_json
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


@pytest.mark.parametrize("inverted_before", [False, True])
def test_snapshot_diff_detects_rule_inversion(inverted_before):
    before = _snapshot()
    after = _snapshot()
    for snapshot in (before, after):
        snapshot["evidence"]["rules"][0]["src"] = "192.0.2.0/24"
    inverted = before if inverted_before else after
    # Native iproute2 JSON encodes inversion as a null-valued flag.
    inverted["evidence"]["rules"][0]["not"] = None

    diff = diff_snapshots(before, after)

    assert diff["decision_changed"] is False
    assert diff["rules_removed"] == before["evidence"]["rules"]
    assert diff["rules_added"] == after["evidence"]["rules"]
    rendered = render_diff(diff)
    inverted_sign = "-" if inverted_before else "+"
    plain_sign = "+" if inverted_before else "-"
    assert f"{inverted_sign} rule: 32766: not from 192.0.2.0/24" in rendered
    assert f"{plain_sign} rule: 32766: from 192.0.2.0/24" in rendered


def test_snapshot_diff_keeps_positive_and_inverted_rules_distinct():
    before = _snapshot()
    after = _snapshot()
    inverted = {**before["evidence"]["rules"][0], "not": None}
    before["evidence"]["rules"].append(inverted)

    diff = diff_snapshots(before, after)

    assert diff["rules_removed"] == [inverted]
    assert diff["rules_added"] == []


def test_snapshot_diff_keeps_unchanged_inverted_rules():
    before = _snapshot()
    after = _snapshot()
    for snapshot in (before, after):
        snapshot["evidence"]["rules"][0]["not"] = None

    diff = diff_snapshots(before, after)

    assert diff["rules_added"] == diff["rules_removed"] == []


def test_snapshot_diff_warns_when_context_changes():
    before = _snapshot()
    after = _snapshot()
    after["context"] = {"kind": "netns", "value": "blue", "label": "netns blue"}

    diff = diff_snapshots(before, after)

    assert diff["decision_changed"] is False
    assert diff["context_changed"] is True
    assert diff["host_changed"] is False
    assert "CHECK snapshots use different execution contexts" in render_diff(diff)


@pytest.mark.parametrize(
    ("prefix", "selector"), [("sport", "sport"), ("dport", "dport"), ("uid", "uidrange")]
)
@pytest.mark.parametrize("bound", ["start", "end"])
def test_snapshot_diff_detects_rule_range_changes(prefix, selector, bound):
    before = _snapshot()
    after = _snapshot()
    for snapshot in (before, after):
        snapshot["evidence"]["rules"][0].update(
            {f"{prefix}_start": 0, f"{prefix}_end": 2000}
        )
    unchanged = diff_snapshots(before, after)
    assert unchanged["rules_added"] == unchanged["rules_removed"] == []

    after["evidence"]["rules"][0][f"{prefix}_{bound}"] += 1

    diff = diff_snapshots(before, after)

    assert diff["rules_removed"] == before["evidence"]["rules"]
    assert diff["rules_added"] == after["evidence"]["rules"]
    assert diff["decision_changed"] is False
    rendered = render_diff(diff)
    changed_range = "1-2000" if bound == "start" else "0-2001"
    assert f"{selector}=0-2000" in rendered
    assert f"{selector}={changed_range}" in rendered


@pytest.mark.parametrize("selector", ["sport", "dport", "uidrange"])
def test_snapshot_diff_keeps_legacy_rule_ranges(selector):
    before = _snapshot()
    after = _snapshot()
    before["evidence"]["rules"][0][selector] = "1000-2000"
    after["evidence"]["rules"][0][selector] = "1000-3000"

    diff = diff_snapshots(before, after)

    assert diff["rules_removed"] == before["evidence"]["rules"]
    assert diff["rules_added"] == after["evidence"]["rules"]
    rendered = render_diff(diff)
    assert f"{selector}=1000-2000" in rendered
    assert f"{selector}=1000-3000" in rendered


def test_snapshot_diff_warns_when_host_name_changes():
    before = _snapshot()
    after = _snapshot()
    after["host"] = {"node": "other-host", "kernel": "test"}

    diff = diff_snapshots(before, after)

    assert diff["decision_changed"] is False
    assert diff["context_changed"] is False
    assert diff["host_changed"] is True
    assert "CHECK snapshots report different host names" in render_diff(diff)


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


@pytest.mark.parametrize("selector", ["src", "dst"])
@pytest.mark.parametrize(
    "address,before_length,after_length",
    [
        ("192.0.2.0", 24, 25),
        ("2001:db8::", 64, 65),
        ("0.0.0.0", 0, 1),
        ("::", 0, 1),
        ("192.0.2.0", None, 24),
        ("2001:db8::", 64, None),
    ],
)
def test_snapshot_diff_preserves_native_prefix_lengths(
    selector, address, before_length, after_length
):
    before, after = _snapshot(), _snapshot()
    for snapshot, length in ((before, before_length), (after, after_length)):
        if ":" in address:
            snapshot["flow"]["destination"] = "2001:db8::1"
            snapshot["evidence"]["route_get"][0]["dst"] = "2001:db8::1"
        rule = snapshot["evidence"]["rules"][0]
        rule[selector] = address
        if length is not None:
            rule[f"{selector}len"] = length

    diff = diff_snapshots(before, after)

    assert diff["rules_removed"] == before["evidence"]["rules"]
    assert diff["rules_added"] == after["evidence"]["rules"]
    assert diff["decision_changed"] is False
    direction = "from" if selector == "src" else "to"
    rendered = render_diff(diff)
    for length in (before_length, after_length):
        prefix = address if length is None else f"{address}/{length}"
        assert f"{direction} {prefix} " in rendered


@pytest.mark.parametrize("selector", ["src", "dst"])
def test_snapshot_diff_keeps_distinct_prefix_lengths_and_unchanged_rules(selector):
    before, after = _snapshot(), _snapshot()
    rule = {"priority": 100, selector: "192.0.2.0", f"{selector}len": 24, "table": 100}
    other = {**rule, f"{selector}len": 25}
    before["evidence"]["rules"] = [rule, other]
    after["evidence"]["rules"] = [rule]

    unchanged = diff_snapshots(before, before)
    diff = diff_snapshots(before, after)

    assert unchanged["rules_added"] == unchanged["rules_removed"] == []
    assert diff["rules_removed"] == [other]
    assert diff["rules_added"] == []


@pytest.mark.parametrize(
    "field,before_value,after_value,rendered_before,rendered_after",
    [
        ("suppress_prefixlen", 0, 1, "suppress_prefixlen=0", "suppress_prefixlen=1"),
        ("suppress_ifgroup", "0", "1", "suppress_ifgroup=0", "suppress_ifgroup=1"),
        ("goto", 1000, 2000, "goto 1000", "goto 2000"),
        ("action", "blackhole", "unreachable", "blackhole", "unreachable"),
    ],
)
def test_snapshot_diff_preserves_rule_actions_and_suppressors(
    field, before_value, after_value, rendered_before, rendered_after
):
    before, after = _snapshot(), _snapshot()
    for snapshot, value in ((before, before_value), (after, after_value)):
        rule = snapshot["evidence"]["rules"][0]
        rule[field] = value
        if field in {"goto", "action"}:
            del rule["table"]

    diff = diff_snapshots(before, after)
    unchanged = diff_snapshots(before, before)

    assert unchanged["rules_added"] == unchanged["rules_removed"] == []
    assert diff["rules_removed"] == before["evidence"]["rules"]
    assert diff["rules_added"] == after["evidence"]["rules"]
    assert diff["decision_changed"] is False
    rendered = render_diff(diff)
    assert rendered_before in rendered
    assert rendered_after in rendered
    if field in {"goto", "action"}:
        assert "lookup unspecified" not in rendered


@pytest.mark.parametrize("nop_before", [False, True])
def test_snapshot_diff_preserves_null_nop_action(nop_before):
    before, after = _snapshot(), _snapshot()
    for snapshot in (before, after):
        snapshot["evidence"]["rules"] = []
    target = before if nop_before else after
    target["evidence"]["rules"] = [{"priority": 100, "src": "all", "nop": None}]

    diff = diff_snapshots(before, after)

    assert diff["rules_removed"] == before["evidence"]["rules"]
    assert diff["rules_added"] == after["evidence"]["rules"]
    assert diff["decision_changed"] is False
    rendered = render_diff(diff)
    sign = "-" if nop_before else "+"
    assert f"{sign} rule: 100: from all to all nop" in rendered
    assert "lookup unspecified" not in rendered
    payload = json.loads(render_diff_json(diff))
    assert payload["schema_version"] == 1
    changed = "rules_removed" if nop_before else "rules_added"
    assert "nop" in payload[changed][0]
    assert payload[changed][0]["nop"] is None


def test_snapshot_diff_keeps_legacy_inline_prefixes():
    before, after = _snapshot(), _snapshot()
    before["evidence"]["rules"][0]["src"] = "192.0.2.0/24"
    after["evidence"]["rules"][0]["src"] = "192.0.2.0/25"

    diff = diff_snapshots(before, after)

    assert diff["rules_removed"] == before["evidence"]["rules"]
    assert diff["rules_added"] == after["evidence"]["rules"]
    rendered = render_diff(diff)
    assert "from 192.0.2.0/24 to all" in rendered
    assert "from 192.0.2.0/25 to all" in rendered
