# Changelog

All notable user-facing changes are documented here.

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
