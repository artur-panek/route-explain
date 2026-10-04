import json

from route_explain.analyze import build_report
from route_explain.model import Flow
from route_explain.render import render_json, render_text


def _report():
    return build_report(
        Flow(destination="192.0.2.10"),
        route_get=[{"dst": "192.0.2.10", "dev": "eth0", "table": "main"}],
        fibmatch=[{"dst": "192.0.2.0/24", "dev": "eth0", "table": "main"}],
        rules=[{"priority": 32766, "src": "all", "dst": "all", "table": "main"}],
        routes=[{"dst": "192.0.2.0/24", "dev": "eth0", "table": "main"}],
        links=[{"ifname": "eth0"}],
    )


def test_text_output_explains_match_semantics():
    text = render_text(_report())
    assert "matched prefix: 192.0.2.0/24" in text
    assert "MATCH 32766" in text
    assert "MATCH means the selector matches" in text


def test_json_output_has_schema_version():
    payload = json.loads(render_json(_report()))
    assert payload["schema_version"] == 3
    assert payload["decision"]["matched_prefix"] == "192.0.2.0/24"
