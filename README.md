# FabWeave Operations Lab

FabWeave is a dependency-light Python reference project for semiconductor-fab
operations.  Its production modules model queue-time protection, dispatch,
reticle reservations, recipe qualification, SPC, metrology sampling,
maintenance, chamber matching, holds, genealogy, chemical aging, cleanroom
excursions, demand control, rework, lot merging, equipment dedication,
contamination, takt, route yield and shipment commitments.

The cross-domain workflow layer composes these services for material
readiness, dispatch-after-hold, qualified reservations and assignments,
metrology/SPC gates, containment, powered scheduling, rework release,
merge-to-commit, performance reporting and yield-anomaly containment.  It
preserves domain rejection reasons instead of replacing them with a generic
success or failure.

Yield-anomaly containment starts at the last confirmed-good checkpoint,
combines the route window with bidirectional genealogy to freeze an active-WIP
scope, and keeps every scoped lot held until all dispositions finish and
retests recover.  Duplicate and late events are idempotent and can never grow,
shrink or roll back the frozen scope or recorded state.

Shared infrastructure supplies half-open time intervals, versioned policy
history, immutable decisions, quantity conservation and an append-only event
log with optimistic concurrency.  Domain services use these primitives to keep
event-time, idempotency and fail-closed behavior consistent.

Run the tests with `python -m pytest -q`.
