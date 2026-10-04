# Positioning

## One sentence

**route-explain is read-only, kernel-backed Linux routing forensics: ask why a flow took this path without installing routes, running a control daemon, or replacing the kernel with a userspace simulator.**

## The problem it owns

Linux already exposes powerful primitives through iproute2, nftables, network namespaces, WireGuard, and overlay-specific tooling. The hard part during an incident is usually not the lack of commands; it is connecting their outputs without overstating what they prove.

route-explain owns that correlation layer.

Its job is to answer questions such as:

- Why did this flow leave through this interface?
- Why did a more-specific route in another table not win?
- Which policy-rule selectors match the flow?
- What changed between two routing states?
- What does a WireGuard or Tailscale route imply for this destination?
- Did runtime nftables evidence expose a mark change that affects routing?

## What it is not

### Not a routing controller

It does not install routes, manage split tunnelling, reconcile desired state, or keep a privileged daemon running.

A routing controller changes the system. route-explain investigates the system.

### Not a userspace route simulator

It does not declare a route authoritative because its own Python implementation calculated that route from a dump.

The selected path comes from the running Linux kernel. Userspace analysis adds context around that result.

### Not an iproute2 replacement

iproute2 remains the source of the core routing evidence.

route-explain composes those primitives into a flow-scoped explanation and gives each statement a provenance level.

### Not just a toolbox

A toolbox gives the operator commands.

route-explain aims to give the operator a reviewable chain of evidence for one networking question.

## Product principles

1. **Kernel first.** Ask Linux whenever Linux can answer directly.
2. **Read-only by default.** Diagnostics should not become part of the failure.
3. **Provenance is visible.** KERNEL, INFO, and CHECK are different classes of statement.
4. **Flow-scoped over generic simulation.** Snapshots preserve authoritative lookup results.
5. **Correlation over guesswork.** Cross-layer conclusions require evidence from each layer.
6. **Unknown is a valid result.** Missing evidence must remain missing.

## Current differentiator

v0.4 implements the first cross-layer packet-path correlation path:

```text
nft runtime trace
      ↓
observed mark / interface / hook
      ↓
kernel re-lookup with observed selectors
      ↓
RPDB context
      ↓
FIB result
      ↓
before/after explanation
```

This keeps route-explain in the forensic role: it does not manufacture packet state. When runtime evidence exposes mark/input-interface state, it asks the kernel what that observed state means for routing and labels the result as a correlated probe rather than an asserted reroute.
