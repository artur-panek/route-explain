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
