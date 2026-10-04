from __future__ import annotations

from .model import Report, Route


def _matches_target(route: Route, target: str) -> bool:
    if target.startswith("table:"):
        return route.table == target.split(":", 1)[1]
    if target.startswith("dev:"):
        return route.dev == target.split(":", 1)[1]
    return route.dev == target or route.table == target


def explain_why_not(report: Report, target: str) -> str:
    selected = report.decision
    if target in {selected.dev, selected.table, f"dev:{selected.dev}", f"table:{selected.table}"}:
        return f"WHY NOT {target}?\n\nIt is selected for this lookup."
    routes = [route for route in report.matching_routes if _matches_target(route, target)]
    lines = [f"WHY NOT {target}?", ""]
    if not routes:
        lines.append("No matching route for the destination was found on that device/table.")
        return "\n".join(lines)
    lines.append("Route exists:")
    for route in routes[:6]:
        via = f" via {route.gateway}" if route.gateway else ""
        dev = f" dev {route.dev}" if route.dev else ""
        lines.append(f"  {route.destination}{via}{dev} table {route.table}")
    target_tables = {route.table for route in routes}
    matching_rules = [rule for rule in report.candidate_rules if rule.table in target_tables]
    lines.extend(["", "But:"])
    if not matching_rules:
        lines.append("  no confirmed/possible policy-rule candidate references the target table")
    else:
        for rule in matching_rules[:6]:
            status = "MATCH" if rule.certainty == "match" else "MAYBE"
            lines.append(f"  {status} rule {rule.priority} references table {rule.table}")
    lines.append(f"  kernel selected table {selected.table}" + (f" on {selected.dev}" if selected.dev else ""))
    lines.extend(["", "Result:", "  the target route exists as context, but it was not the selected FIB path for this flow"])
    return "\n".join(lines)
