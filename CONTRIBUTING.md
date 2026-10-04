# Contributing

Contributions are welcome, especially reproducible routing edge cases.

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

Please include:

- the `route-explain` command you ran;
- sanitized `route-explain --json` output when possible;
- relevant `ip -j rule show` and `ip -j route show table all` output;
- the result you expected and why.

Never post secrets, private keys or credentials. Public IPs and internal topology may also be sensitive, so sanitize them if needed.
