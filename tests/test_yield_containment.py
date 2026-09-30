from __future__ import annotations

import pytest

from fabweave.core.events import EventLog
from fabweave.dispatch.priority import DispatchCandidate
from fabweave.genealogy.carrier import GenealogyGraph
from fabweave.workflows.control import rank_releasable
from fabweave.workflows.yield_containment import (
    CONTAINMENT_BLOCKER,
    DISPOSITION,
    RETEST,
    LotPosition,
    Route,
    affected_scope,
    containment_release_decision,
    incident_holds,
    last_confirmed_good_point,
    open_yield_incident,
    project,
    record_disposition,
    record_retest_recovery,
    release_incident,
)

ROUTE = Route("R-1", ("CLEAN", "DEP", "ETCH", "CMP", "TEST"))
CHECKS = [("CLEAN", True), ("DEP", True), ("ETCH", True), ("CMP", False)]
PARENT_OF = {
    "L-A": None,
    "L-B": "L-A",
    "L-C": "L-B",
    "L-D": "L-B",
    "L-E": "L-C",
    "L-SCRAP": "L-D",
}
POSITIONS = {
    "L-A": LotPosition("L-A", "R-1", "DEP"),
    "L-B": LotPosition("L-B", "R-1", "ETCH"),
    "L-C": LotPosition("L-C", "R-1", "CMP"),
    "L-D": LotPosition("L-D", "R-1", "TEST"),
    "L-E": LotPosition("L-E", "R-2", "OTHER"),
}


def test_last_confirmed_good_point_is_the_passing_step_before_the_alarm():
    assert last_confirmed_good_point(CHECKS, "CMP") == "ETCH"
    assert last_confirmed_good_point([("CLEAN", False)], "CLEAN") is None
    with pytest.raises(ValueError):
        last_confirmed_good_point(CHECKS, "TEST")
    with pytest.raises(ValueError):
        last_confirmed_good_point([("CLEAN", True)], "CLEAN")


def test_scope_combines_route_window_and_genealogy_for_active_wip_only():
    graph = GenealogyGraph(PARENT_OF)
    scope = affected_scope(ROUTE, POSITIONS, graph, "ETCH", max_depth=3)
    # L-B sits exactly on the confirmed-good step: trusted.
    # L-C/L-D are past it on the route; L-E joins by lineage; L-SCRAP is no
    # longer work-in-progress and stays out of the hold.
    assert scope == ("L-C", "L-D", "L-E")


def test_scope_with_no_confirmed_good_point_starts_at_route_beginning():
    graph = GenealogyGraph(PARENT_OF)
    scope = affected_scope(ROUTE, POSITIONS, graph, None, max_depth=3)
    assert scope == ("L-A", "L-B", "L-C", "L-D", "L-E")


def _open(log: EventLog, incident_id: str = "INC-1", at: int = 100) -> object:
    return open_yield_incident(
        log,
        incident_id,
        ROUTE,
        POSITIONS,
        GenealogyGraph(PARENT_OF),
        "CMP",
        CHECKS,
        ("one_beyond_3_sigma",),
        at,
    )


def test_opening_incident_freezes_scope_and_appends_one_event():
    log = EventLog()
    decision = _open(log)
    assert decision.allowed
    assert decision.evidence["scope"] == ("L-C", "L-D", "L-E")
    assert decision.evidence["last_good_step"] == "ETCH"
    assert len(log.read("yield-incident:INC-1")) == 1


def test_opening_without_statistical_signal_is_fail_closed():
    decision = open_yield_incident(
        EventLog(), "INC-X", ROUTE, POSITIONS, GenealogyGraph(PARENT_OF), "CMP", CHECKS, (), 100
    )
    assert decision.reasons == ("no_statistical_signal",)
    assert project(EventLog(), "INC-X") is None


def test_duplicate_open_replays_without_growing_the_log_or_scope():
    log = EventLog()
    first = _open(log)
    replay = _open(log, at=101)
    assert replay.allowed and replay.evidence["replay"] is True
    assert replay.evidence["scope"] == first.evidence["scope"]
    assert len(log.read("yield-incident:INC-1")) == 1


def test_disposition_outside_scope_cannot_grow_the_hold():
    log = EventLog()
    _open(log)
    decision = record_disposition(log, "INC-1", "L-A", "rework", 110)
    assert decision.reasons == ("outside_scope:L-A",)
    assert "L-A" not in project(log, "INC-1").dispositions


def test_retest_requires_a_finished_disposition_first():
    log = EventLog()
    _open(log)
    assert record_retest_recovery(log, "INC-1", "L-C", 110).reasons == ("disposition_incomplete:L-C",)
    assert record_disposition(log, "INC-1", "L-C", "rework", 110).allowed
    assert record_retest_recovery(log, "INC-1", "L-C", 120).allowed


def test_release_waits_for_every_disposition_and_retest_in_scope():
    log = EventLog()
    _open(log)
    state = project(log, "INC-1")
    reasons = containment_release_decision(state, 150).reasons
    assert reasons == (
        "pending_disposition:L-C",
        "pending_retest:L-C",
        "pending_disposition:L-D",
        "pending_retest:L-D",
        "pending_disposition:L-E",
        "pending_retest:L-E",
    )
    for clock, lot_id in enumerate(("L-C", "L-D", "L-E"), start=110):
        assert record_disposition(log, "INC-1", lot_id, "use-as-is", clock).allowed
    release = release_incident(log, "INC-1", 114)
    assert "pending_retest:L-C" in release.reasons and "event_sequence" not in release.evidence
    for clock, lot_id in enumerate(("L-C", "L-D", "L-E"), start=120):
        assert record_retest_recovery(log, "INC-1", lot_id, clock).allowed
    release = release_incident(log, "INC-1", 130)
    assert release.allowed and release.evidence["released_at"] == 130
    assert project(log, "INC-1").released_at == 130


def test_late_events_are_rejected_and_cannot_move_state_backwards():
    log = EventLog()
    _open(log, at=100)
    assert record_disposition(log, "INC-1", "L-C", "rework", 99).reasons == ("late_event",)
    assert record_disposition(log, "INC-1", "L-C", "rework", 110).allowed
    assert release_incident(log, "INC-1", 105).reasons == ("late_event",)
    # A backdated disposition after the incident was released is also refused.
    for clock, lot_id in enumerate(("L-C", "L-D", "L-E"), start=110):
        record_disposition(log, "INC-1", lot_id, "use-as-is", clock)
    for clock, lot_id in enumerate(("L-C", "L-D", "L-E"), start=120):
        record_retest_recovery(log, "INC-1", lot_id, clock)
    assert release_incident(log, "INC-1", 130).allowed
    assert record_disposition(log, "INC-1", "L-C", "scrap", 125).reasons == ("incident_already_released",)


def test_duplicate_events_are_idempotent_including_event_identity():
    log = EventLog()
    _open(log)
    first = record_disposition(log, "INC-1", "L-C", "rework", 110)
    replay = record_disposition(log, "INC-1", "L-C", "rework", 115)
    assert replay.allowed and replay.evidence["replay"] is True
    assert len(log.read("yield-incident:INC-1")) == first.evidence["event_sequence"]
    retest = record_retest_recovery(log, "INC-1", "L-C", 120)
    retest_again = record_retest_recovery(log, "INC-1", "L-C", 125)
    assert retest_again.allowed and retest_again.evidence["replay"] is True
    assert len(log.read("yield-incident:INC-1")) == retest.evidence["event_sequence"]


def test_repeated_disposition_cannot_shrink_or_change_the_recorded_state():
    log = EventLog()
    _open(log)
    assert record_disposition(log, "INC-1", "L-C", "rework", 110).allowed
    conflict = record_disposition(log, "INC-1", "L-C", "scrap", 115)
    assert conflict.reasons == ("disposition_already_recorded",)
    assert project(log, "INC-1").dispositions["L-C"] == "rework"


def test_incident_holds_block_dispatch_until_the_whole_incident_releases():
    log = EventLog()
    _open(log)
    state = project(log, "INC-1")
    holds = incident_holds(state)
    candidates = [DispatchCandidate("L-C", 1, 2), DispatchCandidate("L-F", 2, 2)]
    assert [item.lot_id for item in rank_releasable(candidates, 100, holds, {})] == ["L-F"]

    for clock, lot_id in enumerate(("L-C", "L-D", "L-E"), start=110):
        record_disposition(log, "INC-1", lot_id, "use-as-is", clock)
    for clock, lot_id in enumerate(("L-C", "L-D", "L-E"), start=120):
        record_retest_recovery(log, "INC-1", lot_id, clock)
    assert release_incident(log, "INC-1", 130).allowed

    released = incident_holds(project(log, "INC-1"))
    held_lot = released["L-C"]
    assert held_lot.active_blockers == frozenset() and held_lot.released_at == 130
    candidates = [DispatchCandidate("L-C", 1, 2), DispatchCandidate("L-F", 2, 2)]
    assert [item.lot_id for item in rank_releasable(candidates, 140, released, {})] == ["L-C", "L-F"]


def test_hold_versions_advance_with_completed_steps_but_blocker_remains():
    log = EventLog()
    _open(log)
    holds = incident_holds(project(log, "INC-1"))
    assert holds["L-C"].required_dispositions == frozenset({DISPOSITION, RETEST})
    assert holds["L-C"].active_blockers == frozenset({CONTAINMENT_BLOCKER})
    assert "L-A" not in holds

    record_disposition(log, "INC-1", "L-C", "rework", 110)
    record_retest_recovery(log, "INC-1", "L-C", 120)
    in_progress = incident_holds(project(log, "INC-1"))["L-C"]
    # Both per-lot gates are done, but the incident is still open, so the
    # blocker keeps the lot from dispatching.
    assert in_progress.completed_dispositions == frozenset({DISPOSITION, RETEST})
    assert in_progress.active_blockers == frozenset({CONTAINMENT_BLOCKER})
