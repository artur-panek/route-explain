# Security

route-explain inspects Linux networking state that can expose sensitive topology and host metadata.

## Reporting a security issue

Do not open a public issue containing credentials, private IP addressing you do not want disclosed, VPN endpoints, authentication material, unsanitized snapshots, or production nftables traces.

For a potential vulnerability, prefer GitHub's private vulnerability reporting from the repository Security tab when it is available. Otherwise contact `contact@panek.tech` with a short description first and avoid attaching sensitive evidence until a private channel is agreed.

For ordinary parsing or diagnostic bugs, use the bug-report form with the smallest sanitized fixture that reproduces the problem.

## Data handling

route-explain is a local, read-only-by-default CLI. It invokes local networking tools such as iproute2 and, when requested, nftables/WireGuard/Tailscale tooling. It does not require a hosted service or database.

Snapshots and reports can contain internal IP addresses, route topology, interface or namespace names, public WireGuard peer metadata, endpoints, and Tailscale metadata. Review and sanitize generated output before sharing it outside your environment.

The `trace` workflow observes existing nftables trace events; route-explain does not automatically inject tracing rules or mutate the firewall ruleset.
