# Contributing

Contributions are welcome, especially reproducible routing edge cases and sanitized snapshots.

The project has one non-negotiable rule: **do not turn an inference into a verdict unless the implementation has evidence for it**.

## Local setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
ruff check .
pytest
```

## Good bug reports

Please include, when possible:

- the `route-explain` command you ran;
- sanitized `route-explain --json` output;
- or a sanitized `route-explain capture --probe ...` snapshot;
- relevant `ip -j rule show` / `ip -j route show table all` context;
- the result you expected and why.

Snapshots can contain internal IPs, interface names and Tailscale peer names. Review them before posting publicly. WireGuard peer keys are not persisted by the built-in collector.

## nft trace changes

Changes involving `trace --arm` must preserve these properties:

- mutation is opt-in;
- rules are narrowly matched;
- the temporary table is uniquely named;
- cleanup happens in `finally`-style error paths;
- cleanup failures are surfaced to the user;
- trace rules must not change packet verdicts.
