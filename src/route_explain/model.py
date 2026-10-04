from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class Flow:
    destination: str
    source: str | None = None
    protocol: str = "tcp"
    port: int | None = None


@dataclass(frozen=True, slots=True)
class RouteDecision:
    destination: str
    gateway: str | None
    dev: str | None
    source: str | None
    table: str
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class PolicyRule:
    priority: int
    source: str
    destination: str
    table: str
    selectors: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Route:
    destination: str
    gateway: str | None
    dev: str | None
    table: str
    metric: int | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Report:
    flow: Flow
    decision: RouteDecision
    candidate_rules: list[PolicyRule]
    matching_routes: list[Route]
    overlays: list[str]
    notes: list[str]
