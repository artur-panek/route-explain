import tomllib
from pathlib import Path

import route_explain


def test_package_version_matches_pyproject():
    metadata = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    assert route_explain.__version__ == metadata["project"]["version"]


def test_release_version_is_v04():
    assert route_explain.__version__ == "0.4.0"
