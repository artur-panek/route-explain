# Snapshots and replay

Snapshots exist for three jobs: reproducible bug reports, before/after diffs, and offline inspection.

## Capture

```bash
route-explain capture -o host.json
```

This captures route/rule/link/overlay state without inventing a route decision.

To make a flow replayable, capture a probe:

```bash
route-explain capture --probe 10.70.0.12 -o host.json
```

Flow selectors apply to every probe in that invocation:

```bash
route-explain capture \
  --probe 10.70.0.12 \
  --source 10.10.0.24 \
  --protocol tcp \
  --dport 443 \
  --mark 0x42 \
  -o host.json
```

## Replay

```bash
route-explain analyze host.json 10.70.0.12 \
  --source 10.10.0.24 \
  --protocol tcp \
  --dport 443 \
  --mark 0x42
```

The flow must match a recorded probe exactly to receive a saved kernel verdict. A different mark, port or source is a different routing lookup.

When no exact probe exists, analysis remains useful but context-only.

## Diff

```bash
route-explain diff before.json after.json
```

Focus route changes on one destination:

```bash
route-explain diff before.json after.json 10.70.0.12
```

If both snapshots contain the same exact probe, the kernel decisions are compared too.

## Privacy

Snapshots can reveal private topology: internal addresses, interface names, route tables and Tailscale peer names. WireGuard peer keys are deliberately discarded, but snapshots should still be reviewed/sanitized before posting publicly.
