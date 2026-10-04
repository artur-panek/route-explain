# Design notes

## Principle: evidence before simulation

Linux routing may involve the RPDB, multiple FIB tables, marks, interfaces, VRFs, namespaces, route types, suppressors, nftables and overlay software. `route-explain` treats the running kernel as the route-selection oracle and builds explanations around observable evidence.

The tool should fail toward uncertainty, not confidence.

## Evidence levels

### KERNEL

Direct runtime evidence:

- `ip -j route get ...` for the resolved path;
- `ip -j route get fibmatch ...` for the selected FIB prefix;
- a saved snapshot probe containing those exact results;
- nftables runtime trace events when trace mode is used.

### INFO

Derived context that is useful but not an execution trace:

- selector-compatible RPDB rules;
- matching prefixes in other tables;
- bridge/veth/VRF topology;
- WireGuard `AllowedIPs`;
- Tailscale status route metadata;
- snapshot state changes.

### CHECK

A limitation or conflict worth investigating:

- a more-specific route exists in a non-selected table;
- required rule selector context is missing;
- a custom table has routes but no obvious RPDB reference;
- overlay metadata says a prefix exists but the kernel route dump does not mirror it;
- offline replay lacks a captured kernel probe.

## RPDB semantics

A selector match does not prove a rule terminated the RPDB walk. Table lookup may fail, `throw` can continue, suppressors can reject results, and `goto`/l3mdev change control flow.

For that reason `MATCH` means **selector match**. `MAYBE` means the selector cannot be resolved from the supplied flow metadata.

Supported selector evaluation in v0.3:

- `from` / `to`;
- `fwmark` + mask;
- `iif`;
- `oif`;
- `tos`;
- `ipproto`;
- `sport`;
- `dport`.

`uidrange`, `tun_id` and `l3mdev` remain explicitly indeterminate unless future collectors provide enough state to resolve them correctly.

## Namespaces

Named namespaces are entered with `ip netns exec NAME`. Process namespaces are entered with `nsenter --target PID --net`.

Only the network namespace is entered. This means route tables, rules, links, nftables, WireGuard and Tailscale collectors are executed against the selected network namespace while keeping the caller's mount/user namespace unless the underlying utility behaves otherwise.

## Snapshots

A snapshot contains:

- IPv4 and IPv6 RPDB rules;
- IPv4 and IPv6 routes across all tables;
- link metadata;
- sanitized overlay context;
- namespace metadata;
- optional exact kernel probes.

A topology-only snapshot is not enough to reproduce kernel route selection safely. Therefore offline `analyze` only emits an authoritative decision when an exact flow probe was captured. Otherwise it produces a `ContextReport` and explicitly states that the kernel verdict is unavailable.

## `--why-not`

`--why-not` is intentionally asymmetric:

1. kernel result says what *did* happen;
2. route/rule/overlay context says whether the requested alternative exists;
3. RPDB candidates explain whether a selector-compatible path to that table is visible;
4. the tool does not claim to know the exact missed control-flow step unless evidence proves it.

## Overlay context

### WireGuard

The collector uses `wg show all allowed-ips`. Peer public keys are not retained. `AllowedIPs` are useful routing/cryptokey-routing context but do not replace the kernel FIB verdict.

### Tailscale

The collector uses `tailscale status --json` and defensively inspects route-like fields such as `PrimaryRoutes`, `AllowedIPs` and `AdvertisedRoutes`. Tailscale documents this JSON as subject to change, so parsing failures must degrade to missing optional context rather than breaking route analysis.

## nftables trace

Read-only trace mode runs `nft -j monitor trace` and consumes events for packets whose `nftrace` bit is already enabled.

`--arm` is an explicit mutation mode. It creates a uniquely named temporary `inet` table, adds one early base chain (`output` or `prerouting`) and a narrowly matched rule that sets `meta nftrace 1`. The table is removed in `finally` cleanup.

The temporary selector deliberately does not match on the requested final fwmark. Otherwise it could miss the exact event we want to observe: an earlier nftables rule changing the mark.

Trace mode reports observed nft events. It does not reconstruct conntrack/NAT state beyond what the trace itself contains.

## Failure mode we optimize against

The most dangerous output for a networking diagnostic is a precise-looking answer built from incomplete state.

When evidence is incomplete, print `MAYBE`, `CHECK`, or “not recorded”.
