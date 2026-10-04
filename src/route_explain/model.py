from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

RuleCertainty = Literal["match", "indeterminate"]
EvidenceLevel = Literal["kernel", "derived", "caution"]
FindingLevel = Literal["ok", "info", "check"]


@dataclass(frozen=True, slots=True)
class NamespaceTarget:
    kind: Literal["netns", "pid"]
    value: str

    @property
    def label(self) -> str:
        return f"{self.kind}:{self.value}"


@dataclass(frozen=True, slots=True)
class Flow:
    destination: str
    source: str | None = None
    protocol: str = "tcp"
    destination_port: int | None = None
    source_port: int | None = None
    mark: int | None = None
    tos: int | None = None
    iif: str | None = None
    oif: str | None = None
    vrf: str | None = None

    @property
    def port(self) -> int | None:
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


@dataclass(frozen=True, slots=True)
class OverlayRoute:
    kind: Literal["wireguard", "tailscale"]
    interface: str
    prefix: str
    peer: str | None = None
    source: str | None = None


@dataclass(slots=True)
class Report:
    flow: Flow
    decision: RouteDecision
    candidate_rules: list[PolicyRule]
    matching_routes: list[Route]
    overlays: list[str]
    evidence: list[Evidence]
    notes: list[str]
    overlay_routes: list[OverlayRoute] = field(default_factory=list)
    namespace: str | None = None


@dataclass(slots=True)
class ContextReport:
    flow: Flow
    candidate_rules: list[PolicyRule]
    matching_routes: list[Route]
    overlays: list[str]
    evidence: list[Evidence]
    notes: list[str]
    overlay_routes: list[OverlayRoute] = field(default_factory=list)
    namespace: str | None = None


@dataclass(frozen=True, slots=True)
class WhyNotResult:
    target: str
    status: Literal["selected", "available", "missing", "uncertain"]
    evidence: tuple[Evidence, ...]


@dataclass(frozen=True, slots=True)
class DoctorFinding:
    level: FindingLevel
    code: str
    message: str


@dataclass(frozen=True, slots=True)
class TraceEvent:
    trace_id: str | None
    family: str | None
    table: str | None
    chain: str | None
    event: str | None
    verdict: str | None
    raw: dict[str, Any]


@dataclass(slots=True)
class TraceReport:
    events: list[TraceEvent]
    notes: list[str]
    armed: bool = False
    command_exit_code: int | None = None
    namespace: str | None = None
