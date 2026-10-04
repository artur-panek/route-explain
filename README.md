# route-explain

**`EXPLAIN`, but for the Linux routing stack.**

By [Artur Panek](https://artur.panek.tech/) · [Project page](https://artur.panek.tech/work/route-explain/)

`route-explain` asks the running Linux kernel how it will route a specific flow, then explains the routing-policy and FIB context around that decision.

It is not a prettier `traceroute`, and it does not reimplement the kernel's route selection in Python. It is for the annoying questions that appear when policy routing, multiple tables, VPNs and overlays all look plausible at once:

- Why is this destination leaving through `eth0` instead of `tailscale0`?
- Which routing table did the kernel actually select?
- Which prefix won inside that table?
- Does a more-specific route exist somewhere else?
- Which `ip rule` selectors definitely match this flow, and which are still ambiguous?
- Would a firewall mark, input interface or L4 port change the lookup?

> Alpha software. v0.2 explains RPDB/FIB decisions with kernel-backed evidence. nftables, NAT and conntrack are intentionally reported as outside the current evidence boundary.

## The useful bit

```console
$ route-explain 10.70.0.12 \
    --from 10.10.0.24 \
    --protocol tcp --sport 51123 --dport 443 \
    --mark 0x42
ROUTE-EXPLAIN
flow:  tcp 10.70.0.12:443 from 10.10.0.24:51123
meta:  mark=0x42

Kernel decision
  destination:    10.70.0.12
  matched prefix: default
  route type:     unicast
  via:            10.10.0.1
  dev:            eth0
  source:         10.10.0.24
  table:          main
Why this path
  KERNEL kernel resolved the flow through table main on eth0
  KERNEL efibmatch selected prefix default in table main
  INFO   policy rule selector(s) at priority 32766 match and reference the selected table
  CHECK  a more-specific route exists in table 52: 10.70.0.0/24 via tailscale0; policy routing kept it out of the selected path
  CHECK  firewall, NAT, conntrack, and packet-mark mutation are not traced; routing evidence stops at the FIB/RPDB boundary

Policy-rule candidates
  MATCH 32766: from all to all lookup main [selected table]
  MATCH 32767: from all to all lookup default
  note: MATCH means the selector matches, not that the rule necessarily terminated the RPDB walk

Matching routes across all tables
   10.70.0.0/24 dev tailscale0 table 52
 * default via 10.10.0.1 dev eth0 table main
```

The distinction is intentional: the selected route comes from the kernel's `ip route get`, the exact matched prefix comes from `fibmatch`, and routes in other tables are context. `route-explain` does not pretend that Linux evaluated those tables in longest-prefix order across the whole machine.

## Requirements

- Linux
- Python 3.11+
- `iproute2` with JSON output
- recent `iproute2` recommended for `fibmatch` and full flow selectors

No root privileges are required for ordinary read-only lookups on a normal Linux host.

## Install from source

```bash
git clone https://github.com/artur-panek/route-explain.git
cd route-explain
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

## Usage

Basic kernel lookup:

```bash
route-explain 10.70.0.12
```

Model a local TCP connection:

```bash
route-explain 10.70.0.12 \
  --source 10.10.0.24 \
  --protocol tcp \
  --sport 51123 \
  --dport 443
```

Model marked traffic:

```bash
route-explain 10.70.0.12 --mark 0x42
```

Model a forwarded packet arriving on an interface:

```bash
route-explain 10.70.0.12 --from 10.10.0.24 --iif lan0
```

Force an output device or VRF exactly as `ip route get` can:

```bash
route-explain 203.0.113.10 --oif wg0
route-explain 203.0.113.10 --vrf blue
```

Machine-readable output:

```bash
route-explain 10.70.0.12 --json
```

The JSON includes a `schema_version` field so scripts can reject incompatible future formats cleanly.

## What v0.2 actually evaluates

The kernel lookup can include:

- source and destination address
- incoming and forced outgoing interface
- firewall mark
- TOS / DS field
- VRF
- IP protocol plus TCP/UDP source and destination ports

For policy rules, `route-explain` currently evaluates source/destination prefixes plus `fwmark`/mask, `iif`, `oif`, `tos`, `ipproto`, `sport`, and `dport`. If a rule needs selector state you did not provide, it is shown as `MAYBE` rather than silently treated as a match.

## Evidence model

`route-explain` deliberately separates three kinds of statements:

- **KERNEL** — directly backed by an `ip route get` / `fibmatch` result.
- **INFO** — derived from current route/rule/link state without claiming it was the kernel's exact execution trace.
- **CHECK** — an important limitation or conflict worth investigating.

That split is the core design rule of the project: **unknown is better than confidently wrong**.

## What it deliberately does not claim yet

`route-explain` does **not** currently trace:

- nftables/iptables rule traversal
- NAT transformations
- conntrack state
- packet-mark changes performed before a later route lookup
- every advanced RPDB selector (`uidrange`, `tun_id`, `l3mdev`, etc.)
- suppressor semantics as a full RPDB execution trace

Those layers are easy to render convincingly and still get wrong. Until they have evidence-backed collectors, they stay outside the verdict.

## Design goals

1. **Kernel decision first.** Ask Linux instead of cloning Linux routing logic in Python.
2. **Exact FIB evidence.** Use `fibmatch` for the selected prefix when available.
3. **Explain conflicts.** Surface more-specific routes and overlay paths that exist but lost due to policy context.
4. **Honest ambiguity.** A rule with missing selector context is `MAYBE`, not green.
5. **Machine-readable core.** Text output is a renderer over structured evidence.
6. **Read-only by default.** Diagnostics should not mutate network state.

## Roadmap

- [x] kernel-backed full-flow selectors (`mark`, `iif`, `oif`, ports, TOS, VRF)
- [x] `fibmatch` selected-prefix evidence
- [x] selector-aware RPDB candidate evaluation
- [ ] `route-explain diff` for before/after network changes
- [ ] network namespace support
- [ ] richer VRF/l3mdev explanation
- [ ] Tailscale route-advertisement context
- [ ] WireGuard peer `AllowedIPs` context
- [ ] Docker/Podman bridge and namespace context
- [ ] nftables trace evidence
- [ ] conntrack/NAT correlation

## Development

```bash
python -m pip install -e '.[dev]'
ruff check .
pytest
```

See [`docs/design.md`](docs/design.md) for the evidence model and the boundary between observation and inference.

## License

MIT
