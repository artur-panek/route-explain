from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

RuleCertainty = Literal["match", "indeterminate"]
EvidenceLevel = Literal["kernel", "derived", "caution"]


@dataclass(frozen=True, slots=True)
class Flow:
    destination: str
    source: str | None = None
    protocol: str | None = None
    destination_port: int | None = None
    source_port: int | None = None
    mark: int | None = None
    tos: int | None = None
    iif: str | None = None
    oif: str | None = None
    vrf: str | None = None

    @property
    def port(self) -> int | None:
        """Backward-compatible alias for the original v0.1 field name."""
        return self.destination_port


@dataclass(frozen=True, slots=True)
class RouteDecision:
    destination: str
    gateway: str | None
    dev: str | None
    source: str | None
    table: str
    matched_prefix: str | None = None
    route_type: str = "unicast"
    metric: int | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    fibmatch_raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class PolicyRule:
    priority: int
    source: str
    destination: str
    table: str
    action: str
    certainty: RuleCertainty
    inverted: bool = False
    selectors: dict[str, Any] = field(default_factory=dict)
    unknown_selectors: tuple[str, ...] = ()
    modifiers: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Route:
    destination: str
    gateway: str | None
    dev: str | None
    table: str
    metric: int | None = None
    route_type: str = "unicast"
    protocol: str | None = None
    scope: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Evidence:
    level: EvidenceLevel
    message: str


@dataclass(slots=True)
class Report:
    flow: Flow
    decision: RouteDecision
    candidate_rules: list[PolicyRule]
    matching_routes: list[Route]
    overlays: list[str]
    evidence: list[Evidence]
    notes: list[str]
