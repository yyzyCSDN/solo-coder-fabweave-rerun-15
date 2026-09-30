from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from fabweave.core.decision import Decision, allow, deny
from fabweave.core.events import EventLog
from fabweave.genealogy.carrier import GenealogyGraph
from fabweave.holds.release import HoldState

DISPOSITION = "disposition"
RETEST = "retest"
CONTAINMENT_BLOCKER = "yield_containment"


@dataclass(frozen=True, slots=True)
class Route:
    route_id: str
    steps: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.steps or len(set(self.steps)) != len(self.steps):
            raise ValueError("route steps must be present and unique")

    def index_of(self, step: str) -> int:
        try:
            return self.steps.index(step)
        except ValueError:
            raise ValueError(f"step not on route {self.route_id}: {step}") from None


@dataclass(frozen=True, slots=True)
class LotPosition:
    """Where an active work-in-progress lot currently sits."""

    lot_id: str
    route_id: str
    step: str


def last_confirmed_good_point(checks: list[tuple[str, bool]], alarm_step: str) -> str | None:
    """Last passing checkpoint at or before the statistical alarm step."""

    good: str | None = None
    for step, passed in checks:
        if step == alarm_step:
            if passed:
                raise ValueError("alarm step shows no anomaly")
            return good
        if passed:
            good = step
    raise ValueError("alarm step was not observed")


def affected_scope(
    route: Route,
    positions: Mapping[str, LotPosition],
    graph: GenealogyGraph,
    last_good_step: str | None,
    max_depth: int,
) -> tuple[str, ...]:
    """Active WIP exposed since the confirmed-good point, by route or lineage.

    Route window is half-open: material sitting exactly on the confirmed-good
    step is trusted, everything strictly past it is suspect. Genealogy then
    expands the seeds in both directions, but only lots that are still
    work-in-progress can enter the containment scope.
    """

    boundary = -1 if last_good_step is None else route.index_of(last_good_step)
    route_lots = {
        lot_id
        for lot_id, position in positions.items()
        if position.route_id == route.route_id and route.index_of(position.step) > boundary
    }

    def exposed(lot_id: str) -> bool:
        position = positions.get(lot_id)
        if position is None:  # scrapped or otherwise no longer in process
            return False
        # On another route the lineage link is the only evidence we have.
        return position.route_id != route.route_id or route.index_of(position.step) > boundary

    impacted = set(route_lots)
    for seed in route_lots:
        impacted.update(relative for relative in graph.related(seed, "upstream", max_depth) if exposed(relative))
        impacted.update(relative for relative in graph.related(seed, "downstream", max_depth) if exposed(relative))
    return tuple(sorted(impacted))


@dataclass(frozen=True, slots=True)
class ContainmentState:
    incident_id: str
    failing_step: str
    last_good_step: str | None
    scope: tuple[str, ...]
    dispositions: Mapping[str, str]
    retests: frozenset[str]
    opened_at: int
    last_event_at: int
    released_at: int | None = None

    @property
    def is_open(self) -> bool:
        return self.released_at is None


def _stream(incident_id: str) -> str:
    return f"yield-incident:{incident_id}"


def project(log: EventLog, incident_id: str) -> ContainmentState | None:
    events = log.read(_stream(incident_id))
    if not events:
        return None
    opened = events[0]
    if opened.kind != "yield_anomaly_opened":
        raise ValueError("incident stream must open with a yield anomaly")
    dispositions: dict[str, str] = {}
    retests: set[str] = set()
    released_at: int | None = None
    scope = tuple(opened.data["scope"])
    for event in events[1:]:
        lot_id = event.data.get("lot_id")
        if event.kind == "disposition_recorded":
            if lot_id not in scope:
                raise ValueError("disposition outside frozen containment scope")
            dispositions.setdefault(lot_id, event.data["disposition"])
        elif event.kind == "retest_recovered":
            if lot_id not in scope:
                raise ValueError("retest outside frozen containment scope")
            retests.add(lot_id)
        elif event.kind == "incident_released":
            released_at = event.occurred_at
        else:
            raise ValueError(f"unknown yield incident event: {event.kind}")
    return ContainmentState(
        incident_id,
        opened.data["failing_step"],
        opened.data.get("last_good_step"),
        scope,
        MappingProxyType(dispositions),
        frozenset(retests),
        opened.occurred_at,
        events[-1].occurred_at,
        released_at,
    )


def _scope_evidence(state: ContainmentState) -> dict[str, object]:
    return {
        "incident_id": state.incident_id,
        "scope": state.scope,
        "last_good_step": state.last_good_step,
    }


def open_yield_incident(
    log: EventLog,
    incident_id: str,
    route: Route,
    positions: Mapping[str, LotPosition],
    graph: GenealogyGraph,
    failing_step: str,
    checks: list[tuple[str, bool]],
    triggered_rules: tuple[str, ...],
    at: int,
    max_depth: int = 3,
) -> Decision:
    state = project(log, incident_id)
    if state is not None:
        sequence = len(log.read(_stream(incident_id)))
        return allow(replay=True, event_sequence=sequence, **_scope_evidence(state), failing_step=state.failing_step)
    if not triggered_rules:
        return deny("no_statistical_signal")
    last_good_step = last_confirmed_good_point(checks, failing_step)
    scope = affected_scope(route, positions, graph, last_good_step, max_depth)
    event = log.append(
        _stream(incident_id),
        0,
        f"yield-open:{incident_id}",
        at,
        "yield_anomaly_opened",
        {"failing_step": failing_step, "last_good_step": last_good_step, "scope": list(scope), "triggered_rules": list(triggered_rules)},
    )
    return allow(
        event_sequence=event.sequence,
        failing_step=failing_step,
        triggered_rules=triggered_rules,
        incident_id=incident_id,
        scope=scope,
        last_good_step=last_good_step,
    )


def record_disposition(
    log: EventLog,
    incident_id: str,
    lot_id: str,
    disposition: str,
    at: int,
) -> Decision:
    state = project(log, incident_id)
    if state is None:
        return deny("incident_not_opened", incident_id=incident_id)
    if state.released_at is not None:
        return deny("incident_already_released", released_at=state.released_at)
    if at < state.last_event_at:
        return deny("late_event", last_event_at=state.last_event_at, occurred_at=at)
    if lot_id not in state.scope:
        return deny(f"outside_scope:{lot_id}", **_scope_evidence(state))
    recorded = state.dispositions.get(lot_id)
    if recorded is not None:
        evidence = {**_scope_evidence(state), "lot_id": lot_id, "disposition": recorded}
        if recorded != disposition:
            return deny("disposition_already_recorded", **evidence)
        return allow(replay=True, **evidence)
    event = log.append(
        _stream(incident_id),
        log.read(_stream(incident_id))[-1].sequence,
        f"yield-disposition:{incident_id}:{lot_id}",
        at,
        "disposition_recorded",
        {"lot_id": lot_id, "disposition": disposition},
    )
    return allow(event_sequence=event.sequence, **_scope_evidence(state), lot_id=lot_id, disposition=disposition)


def record_retest_recovery(log: EventLog, incident_id: str, lot_id: str, at: int) -> Decision:
    state = project(log, incident_id)
    if state is None:
        return deny("incident_not_opened", incident_id=incident_id)
    if state.released_at is not None:
        return deny("incident_already_released", released_at=state.released_at)
    if at < state.last_event_at:
        return deny("late_event", last_event_at=state.last_event_at, occurred_at=at)
    if lot_id not in state.scope:
        return deny(f"outside_scope:{lot_id}", **_scope_evidence(state))
    if lot_id not in state.dispositions:
        return deny(f"disposition_incomplete:{lot_id}", **_scope_evidence(state))
    if lot_id in state.retests:
        return allow(replay=True, **_scope_evidence(state), lot_id=lot_id)
    event = log.append(
        _stream(incident_id),
        log.read(_stream(incident_id))[-1].sequence,
        f"yield-retest:{incident_id}:{lot_id}",
        at,
        "retest_recovered",
        {"lot_id": lot_id},
    )
    return allow(event_sequence=event.sequence, **_scope_evidence(state), lot_id=lot_id)


def containment_release_decision(state: ContainmentState, at: int) -> Decision:
    evidence = _scope_evidence(state)
    if state.released_at is not None:
        return allow(replay=True, released_at=state.released_at, evaluated_at=at, **evidence)
    reasons = [
        reason
        for lot_id in state.scope
        for reason in (
            f"pending_disposition:{lot_id}" if lot_id not in state.dispositions else "",
            f"pending_retest:{lot_id}" if lot_id not in state.retests else "",
        )
        if reason
    ]
    return deny(*reasons, evaluated_at=at, **evidence) if reasons else allow(evaluated_at=at, **evidence)


def release_incident(log: EventLog, incident_id: str, at: int) -> Decision:
    state = project(log, incident_id)
    if state is None:
        return deny("incident_not_opened", incident_id=incident_id)
    decision = containment_release_decision(state, at)
    if state.released_at is not None:
        return decision
    # Event ordering is enforced before gate reasoning: a late release attempt
    # must never rewrite history even if the disposition/retest gates are open.
    if at < state.last_event_at:
        return deny("late_event", last_event_at=state.last_event_at, occurred_at=at, **_scope_evidence(state))
    if not decision.allowed:
        return decision
    event = log.append(
        _stream(incident_id),
        log.read(_stream(incident_id))[-1].sequence,
        f"yield-release:{incident_id}",
        at,
        "incident_released",
        {"scope": list(state.scope)},
    )
    return allow(event_sequence=event.sequence, released_at=at, **_scope_evidence(state))


def incident_holds(state: ContainmentState) -> dict[str, HoldState]:
    """Per-lot holds that stay active until the whole incident is released."""

    required = frozenset({DISPOSITION, RETEST})
    holds: dict[str, HoldState] = {}
    for lot_id in state.scope:
        completed: set[str] = set()
        if lot_id in state.dispositions:
            completed.add(DISPOSITION)
        if lot_id in state.retests:
            completed.add(RETEST)
        blockers = frozenset() if state.released_at is not None else frozenset({CONTAINMENT_BLOCKER})
        holds[lot_id] = HoldState(
            f"{state.incident_id}:{lot_id}",
            1 + len(completed),
            required,
            frozenset(completed),
            blockers,
            state.released_at,
        )
    return holds
