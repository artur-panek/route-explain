# Design notes

## Principle: evidence before simulation

Linux routing may involve the RPDB, multiple FIB tables, marks, interfaces, VRFs, route types, suppressors, namespaces and overlay software. Reimplementing that decision tree in an early diagnostic CLI would produce answers that look precise long before they are trustworthy.

`route-explain` therefore treats the running kernel as the routing oracle and builds an explanation around its answer.

## Product boundary: forensic layer, not control plane

`route-explain` is designed as an observational layer over Linux networking.

It does not maintain desired routing state, install policy, reconcile VPN routes, or run a background routing daemon. Those are control-plane responsibilities. Mixing them into the same process that explains a fault would make the diagnostic tool part of the system it is diagnosing.

It also does not treat a route/rule dump as sufficient input for an authoritative userspace routing simulator. Linux remains the oracle for the selected path.

The intended architecture is:

```text
kernel/runtime evidence
        ↓
normalization
        ↓
correlation
        ↓
KERNEL / INFO / CHECK explanation
```

This is closer to forensics and observability than to routing management.
## Evidence levels

### KERNEL

Authoritative runtime evidence returned by the kernel for the requested lookup.

Two lookups are useful:

1. `ip -j route get ...` returns the resolved destination entry and chosen path.
2. `ip -j route get fibmatch ...` returns the full matched FIB route, which identifies the selected prefix rather than forcing us to guess it from `ip route show table all`.

The same supported flow selectors are sent to both lookups so the evidence refers to the same hypothetical packet.

### INFO

Derived context that is useful but is **not** an execution trace. Examples:

- policy rules whose selectors match the supplied flow metadata;
- route prefixes in other tables that also contain the destination;
- overlay interfaces present on the host but not selected by the lookup.

### CHECK

A limitation, ambiguity or conflict that changes how confidently the output should be read. Examples:

- a policy rule contains selectors for which the user did not provide context;
- a more-specific route exists in another table;
- firewall/NAT/conntrack behavior is outside the current evidence boundary.

## RPDB candidate semantics

The routing policy database is processed in priority order. A selector match does not prove that a rule terminated the walk: a table lookup can fail, a throw route can continue processing, and suppressors can reject a result.

For that reason the CLI says `MATCH` for **selector match**, not “winning rule”. Rules whose selector truth cannot be established from the supplied flow are shown as `MAYBE`.

Supported rule selector evaluation in v0.2:

- `from` / `to`
- `fwmark` + mask
- `iif`
- `oif`
- `tos`
- `ipproto`
- `sport`
- `dport`

Known but intentionally indeterminate today:

- `uidrange`
- `tun_id`
- `l3mdev`

Rule action modifiers such as `suppress_prefixlength` are preserved as context but are not simulated as a complete RPDB trace.

## FIB context

`ip route show table all` answers “what else exists?” It must not be presented as the order in which Linux compared routes across tables. Longest-prefix selection happens inside the table(s) reached through policy routing; the RPDB decides which table lookups happen.

A route in another table can therefore be more specific than the selected route and still be irrelevant to the final path. That is often exactly the bug the operator is trying to see.

## Firewall and NAT boundary

Not evaluated in v0.2.

A future implementation should prefer runtime tracing and native rule representations instead of trying to infer packet traversal from pretty-printed rules. Packet marks are especially important: `route-explain --mark` can explain a lookup **given** a mark, but it does not yet prove where that mark came from.

## Failure mode we optimize against

The most dangerous output for a networking diagnostic tool is a confident green answer built from incomplete state.

When evidence is incomplete, print `MAYBE`, `CHECK`, or “not evaluated”.


## v0.3 execution contexts

A live collector can run in one of four contexts:

- host;
- `ip netns exec NAME`;
- `nsenter -t PID -n`;
- Docker/Podman container resolved to its host PID, then entered with `nsenter`.

Only the network namespace is entered. This matters for daemon-backed tooling: Tailscale status is intentionally host-only because a Unix socket in the host mount namespace could otherwise make host daemon state look like namespace-local state.

## v0.3 snapshots and replay

Snapshots are flow-scoped evidence bundles, not generic routing-state dumps.

The captured `route_get` and `fibmatch` results remain the KERNEL evidence on replay. Route/rule/link/overlay data remains contextual evidence.

This deliberately prevents replay from becoming an unverified userspace FIB/RPDB simulator.

## nftables tracing

`route-explain trace` is observational.

v0.4.1 consumes the native `nft monitor trace` stream. nftables emits related records with a shared trace ID: a packet record can contain the addresses, protocol, ports and interfaces needed to identify the flow, while later rule/policy/verdict records can contain the state transition of interest. route-explain first identifies matching packet trace IDs, then retains all records belonging to those IDs and normalizes them into its own stable trace schema.

It does not add `meta nftrace set 1`, modify the ruleset, or generate traffic. Automatic trace setup would be a mutation and therefore requires a future explicit opt-in workflow rather than happening behind a diagnostic command.

nftables reconstructs table/chain/rule text using ruleset state read when the monitor starts. If the ruleset changes while capture is running, printed rule text may become stale; this is a contextual limitation and is surfaced as a CHECK.


## Cross-layer correlation

v0.4 introduces runtime correlation across nftables and routing.

When nft trace evidence exposes a packet mark or named input interface, route-explain can correlate that observed state with a second kernel route lookup using those observed selectors. The output compares that probe with the baseline RPDB/FIB result.

The correlation must preserve provenance:

1. nftables event: runtime evidence;
2. observed mark/interface: extracted fact;
3. second `ip route get`: new kernel evidence;
4. comparison between the two lookups: derived explanation.

A missing trace event, missing mark, or ambiguous hook must remain a CHECK. The project should never reconstruct an invisible packet transformation just because a plausible rule exists.

### Correlation boundary

The re-lookup is a probe, not a claim that a reroute happened at the observed nftables hook. Output-interface evidence is retained as context but is not forced into the probe. This avoids feeding an output of route selection back into the lookup as though it were an input.

The implementation intentionally deduplicates unchanged mark/iif observations so repeated trace events do not produce misleadingly repetitive kernel probes.


## Protocol selector semantics

Protocol is optional flow evidence. If the operator explicitly supplies `--protocol`, it is passed to the kernel lookup as `ipproto` even when no ports are supplied. If neither protocol nor ports are supplied, route-explain does not invent a protocol and protocol-specific RPDB rules stay indeterminate. Ports without an explicit protocol use TCP as the CLI/programmatic convenience default.
