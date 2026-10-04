# Design notes

## Principle: evidence before simulation

Linux routing may involve the RPDB, multiple FIB tables, marks, interfaces, VRFs, route types, suppressors, namespaces and overlay software. Reimplementing that decision tree in an early diagnostic CLI would produce answers that look precise long before they are trustworthy.

`route-explain` therefore treats the running kernel as the routing oracle and builds an explanation around its answer.

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
