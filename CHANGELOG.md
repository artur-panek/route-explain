# Changelog

All notable user-facing changes are documented here.

## 0.3.0

- add flow-scoped snapshot capture and evidence-only replay;
- add before/after route and RPDB diffing;
- add `--why-not` explanations for devices and route tables;
- add host, iproute2 netns, PID, Docker, and Podman network-namespace execution;
- add a conservative routing `doctor` for table/RPDB/default-route/overlay/bridge context;
- add WireGuard peer `AllowedIPs` evidence;
- add Tailscale exact-IP and subnet-route context in host mode;
- add read-only nftables runtime trace observation without mutating the ruleset;
- expand regression coverage for the new workflows;
- keep the existing v0.2 explain invocation backward compatible.

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
