from route_explain.doctor import diagnose_snapshot


def test_doctor_finds_orphan_table_and_fwmark():
    snapshot = {
        "state": {
            "rules_v4": [{"priority": 100, "fwmark": "0x42", "table": 100}],
            "rules_v6": [],
            "routes_v4": [
                {"dst": "default", "dev": "eth0", "table": "main"},
                {"dst": "10.0.0.0/8", "dev": "wg0", "table": 52},
            ],
            "routes_v6": [],
            "links": [],
            "overlays": {},
        },
        "probes": [],
    }
    findings = diagnose_snapshot(snapshot)
    codes = {item.code for item in findings}
    assert "ipv4.table-without-rule" in codes
    assert "ipv4.fwmark-routing" in codes
