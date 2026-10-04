# nftables trace mode

`route-explain trace` integrates nftables runtime evidence without pretending that a static ruleset dump is an execution trace.

## Read-only monitoring

```bash
sudo route-explain trace 1.1.1.1 --timeout 5
```

This only runs `nft monitor trace`. It will see packets only when some existing rule has already set `meta nftrace 1`.

## Temporary arming

```bash
sudo route-explain trace 1.1.1.1 \
  --protocol icmp \
  --arm \
  --exec ping -c 1 1.1.1.1
```

`--arm` requires sufficient netfilter privileges (normally root/CAP_NET_ADMIN). It creates a temporary `inet` table named `route_explain_<pid>`, adds a narrowly matched rule, and removes the entire table during cleanup.

For forwarded traffic, use the prerouting hook:

```bash
sudo route-explain trace 10.70.0.12 \
  --source 10.10.0.24 \
  --iif lan0 \
  --hook prerouting \
  --arm
```

## Safety model

- no nftables mutation happens without `--arm`;
- the temporary rule only sets `nftrace`; it does not accept/drop/redirect packets;
- cleanup is attempted even when monitoring/probe execution fails;
- cleanup failure is printed as a `CHECK` note with the exact temporary table name;
- the arm selector intentionally omits fwmark matching so the trace can reveal mark mutation;
- on production systems, inspect the generated behavior and prefer read-only mode first.

## What trace output means

Trace events are direct Netfilter runtime evidence. They can show tables/chains/rules/verdicts and, depending on nftables JSON output, packet metadata such as marks.

They do not automatically reconstruct every conntrack/NAT transformation into a single synthetic packet history yet.
