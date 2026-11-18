from route_explain.context import ExecutionContext
from route_explain.doctor import doctor, render_doctor


def test_doctor_surfaces_unreferenced_table_and_bridges(monkeypatch):
    import route_explain.doctor as doctor_module

    monkeypatch.setattr(
        doctor_module,
        "collect_links",
        lambda **kwargs: [
            {
                "ifname": "docker0",
                "linkinfo": {"info_kind": "bridge"},
            }
        ],
    )

    def routes(flow, **kwargs):
        if ":" in flow.destination:
            return []
        return [
            {"dst": "default", "dev": "eth0", "table": "main"},
            {"dst": "10.70.0.0/24", "dev": "wg0", "table": "52"},
        ]

    monkeypatch.setattr(doctor_module, "collect_routes", routes)
    monkeypatch.setattr(
        doctor_module,
        "collect_rules",
        lambda flow, **kwargs: [
            {"priority": 32766, "table": "main"},
        ],
    )

    result = doctor(ExecutionContext())
    text = render_doctor(result)
    assert "table 52" in text
    assert "docker0" in text


def test_doctor_checks_table_references_per_address_family(monkeypatch):
    import route_explain.doctor as doctor_module

    monkeypatch.setattr(doctor_module, "collect_links", lambda **kwargs: [])

    def routes(flow, **kwargs):
        destination = "2001:db8::/32" if ":" in flow.destination else "192.0.2.0/24"
        return [{"dst": destination, "dev": "eth0", "table": "52"}]

    def rules(flow, **kwargs):
        return [{"priority": 100, "table": "52"}] if ":" in flow.destination else []

    monkeypatch.setattr(doctor_module, "collect_routes", routes)
    monkeypatch.setattr(doctor_module, "collect_rules", rules)

    result = doctor(ExecutionContext())

    assert result["findings"] == [{
        "level": "CHECK",
        "message": "ipv4 table 52 has 1 route(s) but no direct RPDB lookup rule",
    }]
    assert result["route_count"] == 2
    assert result["rule_count"] == 1
