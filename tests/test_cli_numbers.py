import json

import pytest

from route_explain import cli


@pytest.mark.parametrize("option", ["mark", "tos"])
@pytest.mark.parametrize("value, expected", [
    ("0008", 8), ("+0008", 8), ("0010", 10), ("0x10", 16),
])
def test_snapshot_accepts_decimal_and_hex_selectors(monkeypatch, capsys, option, value, expected):
    def capture(flow, context):
        return {option: getattr(flow, option)}

    monkeypatch.setattr(cli, "capture_snapshot", capture)

    assert cli.main(["snapshot", "192.0.2.1", f"--{option}", value]) == 0
    assert json.loads(capsys.readouterr().out) == {option: expected}


@pytest.mark.parametrize("option, value", [
    ("mark", "04294967296"), ("tos", "0256"), ("mark", "-0001"), ("tos", "-0001"),
])
def test_zero_padded_selectors_still_obey_unsigned_bounds(capsys, option, value):
    with pytest.raises(SystemExit) as error:
        cli.main(["snapshot", "192.0.2.1", f"--{option}={value}"])

    assert error.value.code == 2
    assert "must fit in" in capsys.readouterr().err
