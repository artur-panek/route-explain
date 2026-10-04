# Design notes

## Why route-explain starts with `ip route get`

Linux routing can involve policy rules, multiple tables, packet marks, namespaces, VRFs, and overlay software. Reimplementing that decision tree in an early CLI would be a good way to produce plausible but wrong answers.

v0.1 therefore treats the running kernel's `ip route get` response as the selected-route evidence. Other data is explanatory context.

## Evidence levels

### Selected route

Authoritative runtime evidence returned by the kernel for the lookup requested by `route-explain`.

### Candidate policy rules

Rules whose basic source and destination selectors match the requested flow. Rules with advanced selectors are shown, but the tool explicitly notes that v0.1 does not fully evaluate those selectors.

### Matching routes

Route prefixes from every table that contain the destination. They answer "what else exists?" rather than "what did Linux definitely inspect?"

### Firewall and NAT

Not evaluated in v0.1.

A future implementation should use nftables' own rule representation and, where possible, runtime tracing/evidence instead of trying to infer packet traversal from rendered rules alone.

## Principle

When evidence is incomplete, print "not evaluated" rather than a green check mark.
