# route-explain

**`EXPLAIN`, but for the Linux routing stack.**

By [Artur Panek](https://artur.panek.tech/) · [Project page](https://artur.panek.tech/work/route-explain/)

`route-explain` asks the running Linux kernel how it will route a specific flow, then explains the RPDB, FIB, namespace, and overlay context around that decision.

It is not a prettier `traceroute`, and it does not reimplement the kernel's route selection in Python. It is for the annoying cases where policy routing, multiple tables, VPNs, containers, marks, and overlays all look plausible at once.

> Alpha software. v0.3 adds flow snapshots, replay/diff, network-namespace execution, `--why-not`, a routing doctor, WireGuard/Tailscale context, and read-only nftables trace observation.

## Quick example

```console
$ route-explain 10.70.0.12 \
    --from 10.10.0.24 \
    --protocol tcp --sport 51123 --dport 443 \
    --mark 0x42 \
    --why-not tailscale0

ROUTE-EXPLAIN
flow:  tcp 10.70.0.12:443 from 10.10.0.24:51123
meta:  mark=0x42

Kernel decision
  matched prefix: default
  dev:            eth0
  table:          main

Why this path
  KERNEL kernel resolved the flow through table main on eth0
  KERNEL fibmatch selected prefix default in table main
  CHECK  a more-specific route exists in table 52: 10.70.0.0/24 via tailscale0

WHY NOT tailscale0?

Route exists:
  10.70.0.0/24 dev tailscale0 table 52

But:
  kernel selected table main on eth0
```

The selected path is kernel evidence. Routes in other tables are context, not a fake simulation of the RPDB walk.

## Requirements

- Linux
- Python 3.11+
- `iproute2` with JSON output
- `nsenter` from util-linux for `--pid` / `--container`
- optional: `wg` for WireGuard peer context
- optional: `tailscale` for host Tailscale context
- optional: `nft` for runtime trace observation

Ordinary route lookups are read-only. Some namespace and nftables operations may require privileges depending on the host.

## Install from source

```bash
git clone https://github.com/artur-panek/route-explain.git
cd route-explain
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

## Core lookup

```bash
route-explain 10.70.0.12
```

Model a specific TCP flow:

```bash
route-explain 10.70.0.12 \
  --source 10.10.0.24 \
  --protocol tcp \
  --sport 51123 \
  --dport 443 \
  --mark 0x42
```

Supported kernel lookup context includes source, mark, TOS, incoming/output interface, VRF, protocol, and TCP/UDP ports.

## Why not this route?

```bash
route-explain 10.70.0.12 --why-not tailscale0
route-explain 10.70.0.12 --why-not dev:wg0
route-explain 10.70.0.12 --why-not table:52
```

`--why-not` checks whether a matching route exists on the requested device/table, shows relevant policy-rule candidates, and contrasts that context with the kernel-selected path.

It deliberately does **not** claim to know a single “losing rule” unless there is runtime evidence for it.

## Network namespaces and containers

Run the same explanation inside an iproute2 namespace:

```bash
route-explain 1.1.1.1 --netns blue
```

Enter an existing process network namespace:

```bash
route-explain 1.1.1.1 --pid 18422
```

Resolve a running Docker or Podman container and enter its network namespace:

```bash
route-explain 1.1.1.1 --container api
```

The same context switches are available to `snapshot`, `doctor`, and `trace`.

## Snapshot and replay

A snapshot is **flow-scoped**. It stores the kernel lookup for one flow plus the route/rule/link and overlay evidence used to explain it.

```bash
route-explain snapshot 10.70.0.12 --mark 0x42 > before.json
route-explain replay before.json
```

Aliases are available for the earlier terminology:

```bash
route-explain capture 10.70.0.12 > case.json
route-explain analyze case.json
```

Write directly to a file:

```bash
route-explain snapshot 10.70.0.12 -o case.json
```

Replay never asks the current kernel for a new decision. It rebuilds the report from the stored evidence.

### Snapshot privacy

Snapshots can contain internal IPs, route topology, interface names, WireGuard peer public keys/endpoints, and Tailscale metadata. They contain diagnostic state, not private keys, but you should still sanitize snapshots before attaching them to a public issue.

## Before/after diff

```bash
route-explain snapshot 10.70.0.12 -o before.json

# change a VPN, route or policy rule

route-explain snapshot 10.70.0.12 -o after.json
route-explain diff before.json after.json
```

Example:

```text
ROUTE-EXPLAIN DIFF

ROUTING DECISION CHANGED
  before:
    table:  main
    prefix: default
    dev:    eth0
  after:
    table:  52
    prefix: 10.70.0.0/24
    dev:    tailscale0

WHY
  + routes: [...]
  + rules: [...]
```

Diffs compare the selected decision plus route/rule set changes. If snapshots describe different flows, the output explicitly warns about it.

## Routing doctor

```bash
route-explain doctor
route-explain doctor --netns blue
route-explain doctor --container api
```

Current doctor checks include:

- non-standard route tables with no direct RPDB lookup rule
- multiple default-route paths within the same address family
- advanced RPDB selectors/modifiers
- overlay-like interfaces
- Docker/Podman/CNI bridge and veth context

The doctor is intentionally conservative. It reports suspicious structure; it does not label every unusual topology as broken.

## WireGuard and Tailscale context

When available, snapshots and live explanations add overlay evidence:

- WireGuard peer `AllowedIPs` containing the destination
- Tailscale peer ownership of an exact Tailscale IP
- Tailscale `PrimaryRoutes` / `AllowedIPs` containing the destination

Tailscale daemon status is only collected in host context. `tailscale status` communicates through a Unix socket, so attributing host daemon state to a namespace/container would be misleading.

## nftables runtime trace

```bash
sudo route-explain trace 10.70.0.12 \
  --from 10.10.0.24 \
  --seconds 5
```

This runs a **read-only** `nft -j monitor trace` observer and filters trace events for the supplied flow.

Important: nftables only emits trace events for packets already marked for tracing, typically by a rule containing:

```text
meta nftrace set 1
```

`route-explain` does **not** inject that rule, change the ruleset, or generate packets automatically. If trace events expose packet marks, they are surfaced next to chain/rule/verdict context.

## Evidence model

The human report separates three levels:

- **KERNEL** — direct `ip route get` / `fibmatch` evidence.
- **INFO** — useful context derived from current route/rule/link/overlay state.
- **CHECK** — ambiguity, a conflict, or an evidence boundary worth investigating.

The project rule is simple: **unknown is better than confidently wrong**.

## Machine-readable output

Normal explain:

```bash
route-explain 10.70.0.12 --json
```

Other workflows also support JSON where useful:

```bash
route-explain replay case.json --json
route-explain diff before.json after.json --json
route-explain doctor --json
route-explain trace 10.70.0.12 --json
```

The main report JSON retains its existing schema version. Snapshot, diff, doctor, and trace payloads have their own schema/version markers.

## What v0.3 still does not claim

`route-explain` still does **not** automatically reconstruct:

- every nftables/iptables traversal when `nftrace` is not enabled
- NAT transformations end-to-end
- conntrack state/correlation
- where a packet mark originally came from unless trace evidence shows it
- every advanced RPDB selector
- suppressor/goto semantics as a complete RPDB execution trace
- arbitrary offline route decisions for destinations that were not captured

Snapshots are flow-scoped specifically to avoid turning replay into an invented userspace routing simulator.

## Roadmap

- [x] kernel-backed full-flow selectors
- [x] `fibmatch` selected-prefix evidence
- [x] selector-aware RPDB candidate evaluation
- [x] `--why-not` device/table explanation
- [x] flow-scoped snapshot + replay
- [x] before/after `diff`
- [x] network namespace / PID / Docker / Podman context
- [x] routing `doctor`
- [x] WireGuard `AllowedIPs` context
- [x] Tailscale peer/subnet-route context
- [x] read-only nftables trace observation
- [ ] richer VRF/l3mdev explanation
- [ ] conntrack/NAT correlation
- [ ] opt-in assisted nft trace setup with explicit confirmation
- [ ] richer snapshot redaction tooling

## Development

```bash
python -m pip install -e '.[dev]'
ruff check .
pytest
```

See [`docs/design.md`](docs/design.md) for the evidence model and [`docs/snapshots.md`](docs/snapshots.md) for snapshot semantics.

## License

MIT
