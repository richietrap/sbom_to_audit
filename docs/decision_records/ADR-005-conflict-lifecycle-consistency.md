# ADR-005: Conflict Lifecycle Consistency

- **Status:** Accepted
- **Date:** 2026-07-19
- **Version:** 0.2.4

## Context

The Ghost-Logger scenario intentionally creates a scoped contradiction at T+10h between a supplier CSAF/VEX `known_not_affected` assertion and local runtime evidence supporting product affectedness. At T+14h, a registered adjudication artefact supersedes the supplier assertion for the affected deployment scope.

Stage 2 correctly used only active claims when calculating `C_t`, so the recommendation moved from `Escalate` to `Report-Ready`. However, the historical conflict collection captured the first detected conflict and never updated its lifecycle status. The final conflict report could therefore contain `C_t=false` while the retained historical record still said `status=active`.

## Decision

Conflict history is append-preserving but lifecycle-aware.

Each detected conflict records:

- a stable conflict identifier;
- detection event and timestamp;
- implicated claims and sources;
- initial `active` status; and
- a lifecycle transition list.

When an explicit conflict-resolution artefact supersedes an implicated source, the historical record is updated to `resolved` and records:

- replay event and resolution-record event;
- resolution timestamp;
- resolution artefact identifiers; and
- adjudication rationale.

The audit ledger contains separate `evidence_conflict_detected` and `evidence_conflict_resolved` events. Historical detection is never deleted.

A fail-closed invariant requires:

```text
final C_t == presence of conflict-history records with status=active
```

The generated conflict report also publishes active and resolved conflict counts.

## Consequences

- audit history now distinguishes “previously detected” from “currently active”;
- state calculation and report semantics are mutually consistent;
- the Stage 2 conflict-resolution claim becomes directly traceable;
- later scenarios may reopen an equivalent contradiction as a new lifecycle occurrence;
- ontology-level semantic conflict matching remains deferred to Stage 3.
