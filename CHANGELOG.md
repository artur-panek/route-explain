# Changelog

All notable user-facing changes are documented here.

## 0.3.0

- add live `--why-not` explanations for interfaces and routing tables;
- add named network namespace (`--netns`) and process namespace (`--pid`) collection;
- add snapshot capture, offline analysis/replay and before/after `diff`;
- preserve authoritative kernel replay only for flows explicitly probed during capture;
- add `doctor` checks for RPDB/table conflicts, marks, advanced rules, special routes, bridges, veths, VRFs and overlay mismatches;
- add optional WireGuard `AllowedIPs` context without persisting peer keys;
- add optional Tailscale status/route metadata context;
- add nftables runtime trace collection;
- add opt-in `trace --arm` with a temporary narrow `nftrace` rule and automatic cleanup;
- add container/network-namespace topology hints;
- bump report JSON schema to v3 and introduce snapshot schema v1;
- expand tests for replay, diff, doctor, namespaces, overlays and nft tracing.

## 0.2.0

- send flow selectors such as marks, interfaces, TOS and TCP/UDP ports into the real kernel route lookup;
- add `fibmatch` evidence for the exact selected FIB prefix;
- evaluate common RPDB selectors instead of treating every source/destination-compatible rule as equally plausible;
- distinguish `MATCH` from `MAYBE` when selector context is missing;
- add structured `KERNEL`, `INFO` and `CHECK` evidence to human and JSON reports;
- make selected-route highlighting prefix-aware;
- version the JSON schema;
- expand tests and CI to Python 3.13.

## 0.1.0

- initial kernel-backed routing decision report;
- policy-rule, all-table route and overlay context;
- text and JSON output.
