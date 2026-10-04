from route_explain.model import Flow
from route_explain.trace import arm_script, parse_trace_output


def test_arm_script_is_narrowly_matched():
    script = arm_script(
        Flow(destination="203.0.113.10", source="10.0.0.2", protocol="tcp", destination_port=443, mark=0x42),
        table_name="route_explain_123",
        hook="output",
    )
    assert "add table inet route_explain_123" in script
    assert "ip daddr 203.0.113.10" in script
    assert "ip saddr 10.0.0.2" in script
    assert "tcp dport 443" in script
    assert "meta nftrace set 1" in script
    assert "meta mark 0x42" not in script


def test_parse_json_trace_output():
    text = '{"nftables":[{"trace":{"id":123,"type":"rule","family":"ip","table":"filter","chain":"output","verdict":"accept"}}]}'
    events = parse_trace_output(text)
    assert len(events) == 1
    assert events[0].trace_id == "123"
    assert events[0].table == "filter"
    assert events[0].verdict == "accept"
