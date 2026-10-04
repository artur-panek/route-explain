# route-explain

**`EXPLAIN`, but for the Linux routing stack.**

By [Artur Panek](https://artur.panek.tech/) · [Project page](https://artur.panek.tech/work/route-explain/)

`route-explain` asks the running Linux kernel how it will route a flow, then builds an evidence-backed explanation around the result. It is deliberately not a Python reimplementation of the RPDB/FIB, and it does not turn missing state into a confident-looking verdict.

It is for questions like:

- Why did Linux use `eth0` instead of `tailscale0` or `wg0`?
- Which table and prefix actually won?
- Which `ip rule` selectors match this flow?
- Why **didn't** table 52 or a specific interface win?
- What changed between two network configurations?
- What does the same routing stack look like inside a container/netns?
- Does WireGuard/Tailscale metadata cover the destination even though the kernel chose another path?
- Did nftables change a packet mark before routing?

> Alpha software. v0.3 keeps the core read-only and kernel-backed. Temporary nftables mutation only happens when you explicitly opt into `trace --arm`, and the tool removes its own trace table afterward.

## Quick example

```console
$ route-explain 10.70.0.12 --from 10.10.0.24 --dport 443 --why-not tailscale0
ROUTE-EXPLAIN
flow:  tcp 10.70.0.12:443 from 10.10.0.24

Kernel decision
  matched prefix: default
  dev:            eth0
  table:          main

Why this path
  KERNEL kernel resolved the flow through table main on eth0
  KERNEL fibmatch selected prefix default in table main
  CHECK  a more-specific route exists in table 52: 10.70.0.0/24 via tailscale0; policy routing kept it out of the selected path

WHY NOT tailscale0?
status: available

  INFO   route 10.70.0.0/24 exists in table 52 via tailscale0
  KERNEL kernel selected table main on eth0 instead of tailscale0
  INFO   no selector-matching RPDB candidate in the supplied context references table 52
```

## Install

Requirements:

- Linux
- Python 3.11+
- `iproute2` with JSON output
- optional: `wireguard-tools` for WireGuard `AllowedIPs` context
- optional: Tailscale CLI for local Tailscale status/route metadata
- optional: `nft` for runtime nftables tracing
- optional: `nsenter` (util-linux) for `--pid` namespace entry

```bash
git clone https://github.com/artur-panek/route-explain.git
cd route-explain
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

## Commands

The original shorthand remains valid:

```bash
route-explain 1.1.1.1
```

The explicit form is also available:

```bash
route-explain explain 1.1.1.1
```

Top-level commands:

```text
explain   live kernel decision + RPDB/FIB/overlay context
capture   snapshot routing state and optional kernel probes
analyze   replay/analyze a saved snapshot
diff      compare before/after snapshots
doctor    audit suspicious routing context
trace     collect nftables runtime trace evidence
```

(`diff` is lowercase in the CLI; the capitalized spelling above is only prose.)

## Flow-aware kernel lookup

The same flow metadata is sent to `ip route get` and, when supported, `fibmatch`:

```bash
route-explain 10.70.0.12 \
  --source 10.10.0.24 \
  --protocol tcp \
  --sport 51123 \
  --dport 443 \
  --mark 0x42 \
  --iif lan0
```

Supported kernel lookup context includes source address, `iif`, forced `oif`, mark, TOS/DS field, VRF, protocol, source port and destination port.

For `ip rule`, v0.3 evaluates source/destination prefixes, `fwmark`/mask, `iif`, `oif`, TOS, IP protocol, source port and destination port. Missing selector state becomes `MAYBE`, not a false green match.

## `--why-not`

Ask why a route target was not selected:

```bash
route-explain 10.70.0.12 --why-not tailscale0
route-explain 10.70.0.12 --why-not dev:wg0
route-explain 10.70.0.12 --why-not table:52
```

`route-explain` will distinguish:

- no matching route exists for that target;
- a matching route exists, but the kernel selected another path;
- matching RPDB selectors reference the target table but do not prove the walk terminated there;
- missing flow metadata keeps the explanation uncertain.

## Network namespaces and containers

Run the entire collector stack inside a named netns:

```bash
route-explain 1.1.1.1 --netns blue
route-explain doctor --netns blue
```

Or enter the network namespace of a process/container PID:

```bash
route-explain 1.1.1.1 --pid 18422
route-explain doctor --pid 18422
```

Named namespaces use `ip netns exec`; PID-based entry uses `nsenter --target PID --net`. Only the network namespace is entered.

## Snapshots, replay and diff

Capture the host routing state:

```bash
route-explain capture > host.json
```

Record one or more authoritative kernel probes as part of the snapshot:

```bash
route-explain capture \
  --probe 10.70.0.12 \
  --probe 1.1.1.1 \
  -o before.json
```

Replay a recorded flow:

```bash
route-explain analyze before.json 10.70.0.12
```

If the exact flow was not probed during capture, offline analysis **does not simulate the kernel**. It shows route/rule/overlay context and labels the missing kernel verdict explicitly.

Compare network state before and after a change:

```bash
route-explain diff before.json after.json
route-explain diff before.json after.json 10.70.0.12
```

When the same probe exists in both snapshots, decision changes are compared directly as well.

See [`docs/snapshots.md`](docs/snapshots.md).

## Doctor

```bash
route-explain doctor
route-explain doctor --netns blue
route-explain doctor --snapshot host.json
```

Current checks surface things such as:

- custom routing tables with routes but no explicit RPDB reference;
- default routes spread across multiple tables;
- fwmark-based policy routing;
- suppress/goto/l3mdev rules;
- blackhole/unreachable/prohibit/throw routes;
- bridge/veth/VRF topology hints;
- WireGuard/Tailscale prefixes without identical kernel routes;
- Tailscale backend not in `Running` state.

Doctor output is deliberately advisory. `CHECK` means “investigate this”, not “this is broken”.

## WireGuard and Tailscale context

If `wg` is available, `route-explain` reads `wg show all allowed-ips` and records only:

- interface;
- prefix/`AllowedIPs`.

Peer keys are intentionally discarded from the snapshot.

If the Tailscale CLI is available, `tailscale status --json` is inspected defensively for route metadata such as `PrimaryRoutes`/`AllowedIPs`. Tailscale documents that this JSON format may change, so the collector is optional context rather than routing authority.

The kernel route decision still comes from `ip route get`.

## nftables runtime trace

Read-only mode listens for packets that already have `nftrace` enabled:

```bash
sudo route-explain trace 1.1.1.1 --protocol icmp --timeout 5
```

Opt-in armed mode creates a temporary table and a narrowly matched `nftrace` rule, monitors the trace, and removes the table afterward:

```bash
sudo route-explain trace 1.1.1.1 \
  --protocol icmp \
  --arm \
  --exec ping -c 1 1.1.1.1
```

For forwarded traffic:

```bash
sudo route-explain trace 10.70.0.12 \
  --from 10.10.0.24 \
  --iif lan0 \
  --hook prerouting \
  --arm
```

The temporary trace selector intentionally does **not** require the final packet mark, so a trace can reveal mark changes that happen before policy routing.

See [`docs/nft-trace.md`](docs/nft-trace.md) before using `--arm` on production firewalls.

## Evidence model

Output separates three kinds of claims:

- **KERNEL** — direct evidence from `ip route get` / `fibmatch` or a captured kernel probe;
- **INFO** — derived context from current/snapshotted rules, routes, links and overlay metadata;
- **CHECK** — ambiguity, unsupported state or a conflict worth investigating.

The project rule is simple: **unknown is better than confidently wrong**.

## JSON

Live reports, doctor output, diffs and nft traces support `--json`. Report JSON uses a schema marker; snapshot files use their own `snapshot_schema_version` so incompatible replay formats can fail clearly rather than silently misparse.

## What v0.3 still does not pretend to do

- full RPDB execution simulation for suppressors/goto/l3mdev;
- conntrack/NAT reconstruction;
- automatically prove where a mark came from without a captured nft trace;
- simulate a kernel route decision from a topology-only snapshot;
- infer container orchestration semantics from Docker/Podman/Kubernetes APIs.

Namespaces are entered directly, which keeps the routing evidence close to the kernel rather than adding an orchestration-specific abstraction layer.

## Development

```bash
python -m pip install -e '.[dev]'
ruff check .
pytest
```

## License

MIT
