# route-explain

**`EXPLAIN`, but for the Linux routing stack.**

By [Artur Panek](https://artur.panek.tech/) · [Project page](https://artur.panek.tech/work/route-explain/)

`route-explain` asks the running Linux kernel how it will route a flow, then explains the policy-routing, route-table, and overlay context around that decision.

It is not a prettier `traceroute`. It is for questions like:

- Why is this destination leaving through `eth0` instead of `tailscale0`?
- Which routing table did the kernel actually choose?
- Is there a more-specific route in another table?
- Which `ip rule` entries are plausible candidates for this lookup?

> Early alpha. v0.1 explains routing decisions. nftables/NAT analysis is deliberately not guessed yet.

## Example

```console
$ route-explain 10.70.0.12 --from 10.10.0.24 --port 443
ROUTE-EXPLAIN
flow:  tcp 10.70.0.12:443 from 10.10.0.24

Kernel routing decision
  destination: 10.70.0.12
  via:         10.10.0.1
  dev:         eth0
  source:      10.10.0.24
  table:       main

Candidate policy rule(s)
  32766: from all to all lookup main

Matching routes across all tables
   10.70.0.0/24 dev tailscale0 table 52
 * default via 10.10.0.1 dev eth0 table main

Notes
  - overlay interface(s) present but not selected: tailscale0
  - matching routes also exist in other table(s): 52
  - firewall/NAT policy is not evaluated in v0.1; no verdict is fabricated
```

The selected route comes from the kernel's `ip route get` result. Routes from other tables are context, not a claim that Linux considered them in that order.

## Requirements

- Linux
- Python 3.11+
- iproute2 with JSON output

## Install from source

```bash
git clone https://github.com/artur-panek/route-explain.git
cd route-explain
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

## Usage

Basic lookup:

```bash
route-explain 10.70.0.12
```

Specify the source address and flow metadata:

```bash
route-explain 10.70.0.12 --from 10.10.0.24 --protocol tcp --port 443
```

Machine-readable output:

```bash
route-explain 10.70.0.12 --json
```

`--protocol` and `--port` describe the flow for the report. v0.1 does not pretend to evaluate firewall rules from them.

## What v0.1 explains

- the kernel's selected route from `ip -j route get`
- source address, next hop, output interface, and table
- policy rules whose basic source/destination selectors match the flow
- every route prefix matching the destination across all tables
- likely overlay interfaces such as Tailscale and WireGuard
- suspicious context, such as matching routes in a non-selected table

## What it deliberately does not claim yet

`route-explain` does **not** currently simulate nftables, NAT, conntrack state, packet marks, or every advanced `ip rule` selector.

Those are easy places to produce a confident-looking but wrong verdict. Until they are modeled properly, the tool says that they were not evaluated.

## Design goals

1. **Kernel decision first.** Prefer authoritative runtime evidence over reimplementing Linux routing.
2. **Explain context.** Show why another route looks tempting without claiming it was selected.
3. **No fake green checks.** Unknown firewall/NAT state stays unknown.
4. **Machine-readable core.** Human output is a renderer over structured evidence.

## Roadmap

- [ ] nftables rule-path evidence
- [ ] conntrack/NAT correlation
- [ ] packet-mark and advanced policy-rule explanation
- [ ] network namespace support
- [ ] Docker/Podman bridge context
- [ ] Tailscale route-advertisement context
- [ ] WireGuard peer AllowedIPs context
- [ ] `route-explain diff` for before/after network changes

## Development

```bash
python -m pip install -e '.[dev]'
ruff check .
pytest
```

## License

MIT
