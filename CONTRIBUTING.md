# Contributing

Contributions are welcome, especially reproducible routing edge cases.

The project has two non-negotiable rules:

1. **Do not turn an inference into a verdict unless the implementation has evidence for it.**
2. **Prefer read-only evidence collection over state mutation.** A feature that changes routes, firewall rules, VPN policy, or other network state needs an explicit opt-in design and must not become the normal diagnostic path.

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
