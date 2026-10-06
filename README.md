# route-explain

**Kernel-backed Linux routing forensics. Ask why a flow took this path.**

By [Artur Panek](https://artur.panek.tech/) · [Project page](https://artur.panek.tech/work/route-explain/) · [Routing evidence note](https://artur.panek.tech/notes/linux-routing-kernel-evidence/) · [PyPI](https://pypi.org/project/route-explain/) · [Releases](https://github.com/artur-panek/route-explain/releases)

`route-explain` is a **read-only Linux networking forensic CLI**. It asks the running kernel for the authoritative routing decision for a specific flow, then correlates RPDB, FIB, namespace, overlay, snapshot, and optional nftables trace evidence around that answer.

It is intentionally **not** a routing controller, split-tunnel manager, background daemon, or userspace route simulator. It does not install routes, reconcile desired state, manage VPN policy, or replace the kernel with its own idea of what should have happened.

> Alpha software. v0.4.1 fixes native nftables trace ingestion and makes explicit protocol selectors reach the kernel lookup even when no ports are supplied.

## Why this is different

The project sits between low-level networking primitives and control-plane software:

| Tool category | Typical job | `route-explain` |
| --- | --- | --- |
| `iproute2` | expose authoritative kernel routing state and lookups | uses those primitives as evidence, then explains and correlates them |
| routing / split-tunnel controllers | install routes, manage policy, run daemons, reconcile state | **does not control routing state** |
| userspace route simulators | calculate what route should win from a state dump | **does not replace the kernel decision** |
| network troubleshooting toolboxes | collect many useful commands in one environment | builds one flow-scoped explanation with explicit evidence levels |

The kernel remains the routing oracle. `ip route get` and `fibmatch` establish the selected path; everything else is labelled as context, inference, or a limitation.

### Non-goals

`route-explain` is deliberately not trying to:

- install, remove, or reconcile routes;
- manage VPN or split-tunnel policy;
- run a persistent privileged daemon;
- emulate the full Linux RPDB/FIB decision tree in userspace;
- turn incomplete state into a confident verdict.

That boundary is a feature: the tool is meant to help investigate a running system without becoming another component that can change the system being investigated.

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

## Install

Available on [PyPI](https://pypi.org/project/route-explain/).

For a system CLI, `pipx` or `uv tool` is recommended:

```bash
pipx install route-explain
# or
uv tool install route-explain
```

Install from source for development:

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

Supported kernel lookup context includes source, mark, TOS, incoming/output interface, VRF, protocol, and TCP/UDP ports. An explicit `--protocol` is sent to the kernel even without ports; when ports are supplied without `--protocol`, TCP is assumed.

## Automation expectations

A live lookup can also act as a routing assertion. A mismatch exits with status **3**, distinct from collection/input errors (status 2):

```bash
route-explain 10.70.0.12 \
  --expect-dev tailscale0 \
  --expect-table 52 \
  --expect-prefix 10.70.0.0/24
```

This is useful in smoke tests, VPN checks and network-change validation without turning route-explain into a routing controller.

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

This runs a **read-only** `nft monitor trace` observer, parses nftables' native `trace id ...` records, groups related packet/rule/policy events by trace ID, and filters them to the supplied flow.

Important: nftables only emits trace events for packets already marked for tracing, typically by a rule containing:

```text
meta nftrace set 1
```

`route-explain` does **not** inject that rule, change the ruleset, or generate packets automatically. Native nftables trace records are normalized into route-explain's trace JSON schema. If trace events expose packet marks, they are surfaced next to chain/rule/verdict context.

`nft` reconstructs printed table/chain/rule text from ruleset state read when the monitor starts, so changing the ruleset while a trace capture is running can make that printed rule text stale. route-explain surfaces this as a `CHECK` rather than silently treating it as immutable evidence.

### Correlate observed nft state with a kernel lookup

```bash
sudo route-explain trace 10.70.0.12 \
  --from 10.10.0.24 \
  --seconds 5 \
  --correlate
```

With `--correlate`, route-explain extracts **observed** routing-relevant state from matching nft trace events (currently packet mark and named input interface), then asks the kernel again using those observed selectors:

```text
nft runtime trace
      ↓
observed mark / iif
      ↓
kernel re-lookup with observed selectors
      ↓
RPDB context
      ↓
selected FIB result
      ↓
baseline vs observed-state comparison
```

An observed output interface is shown as context but is not forced into the re-lookup, because doing so would turn an observation after route selection into an artificial input.

The report also keeps an explicit caveat: a correlated re-lookup proves what the kernel returns **for that observed selector state**. It does not by itself prove that Linux actually performed a reroute at that nftables hook.

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

The main report JSON retains its existing schema version. Snapshot, diff, doctor, and trace payloads have their own schema/version markers. Native nftables trace output is normalized as trace schema version 2 with `source_format: "nft-native-trace"`.

## What v0.4 still does not claim

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
- [x] correlate nft trace → observed mark/iif → kernel re-lookup → RPDB/FIB result
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

See [`docs/design.md`](docs/design.md) for the evidence model, [`docs/positioning.md`](docs/positioning.md) for the product boundary, [`docs/snapshots.md`](docs/snapshots.md) for snapshot semantics, and [`docs/releasing.md`](docs/releasing.md) for the Trusted Publishing release flow.

## License

MIT
