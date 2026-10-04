# Snapshot semantics

A route-explain snapshot is a **flow-scoped evidence bundle**.

It exists to make routing bugs reproducible without pretending route-explain can reproduce the entire Linux forwarding stack offline.

## What is captured

For one requested flow:

- resolved `ip route get` result;
- optional `fibmatch` result;
- address-family-specific RPDB rules;
- routes from all tables for that address family;
- detailed link state;
- WireGuard peer metadata when `wg` is available;
- host Tailscale status when available;
- execution context metadata.

## What replay means

`route-explain replay case.json` rebuilds the explanation from the stored evidence.

Replay does not:

- run a new kernel lookup;
- modify the stored flow;
- calculate a new authoritative route for another destination;
- contact Tailscale or WireGuard again.

This keeps KERNEL-labelled evidence tied to the kernel answer captured at snapshot time.

## Why snapshots are flow-scoped

A full route/rule dump is not enough to reproduce every Linux routing decision correctly in userspace. RPDB suppressors, throw routes, namespaces, marks, VRFs, l3mdev behavior, and kernel implementation details make a generic offline simulator easy to get subtly wrong.

A snapshot therefore stores the authoritative lookup itself.

## Diff semantics

`route-explain diff before.json after.json` compares:

- selected table;
- selected prefix;
- device/gateway/source/type/metric;
- route-set fingerprints;
- RPDB rule fingerprints.

If the stored flows differ, the diff marks that fact as a CHECK.

## Sharing snapshots

Snapshots are JSON and intentionally inspectable.

They may contain:

- private IP addresses;
- internal route topology;
- interface and namespace names;
- public WireGuard peer keys;
- peer endpoints;
- Tailscale node and route metadata.

No WireGuard private keys are collected, but diagnostic metadata can still be sensitive. Sanitize before posting publicly.
