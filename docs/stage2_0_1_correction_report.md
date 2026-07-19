# Stage 2.0.1 Conflict-Lifecycle Correction Report

**Package version:** 0.2.4  
**Status:** corrective pilot build  
**Affected prior build:** 0.2.3

## Intentional scenario condition

The T+10h conflict is intentional. Ghost-Logger is designed to test whether the artefact detects a contradiction between:

1. a supplier CSAF/VEX assertion that the product is `known_not_affected`; and
2. local telemetry showing execution and reachability in the affected deployment.

This contradiction should force `Escalate` while both scoped claims are active.

## Defect

The unintended error was confined to the retained conflict-history record. At T+14h, the adjudication artefact correctly superseded the supplier claim and the scoring engine correctly set `C_t=false`. The historical conflict collection, however, only captured detection and did not record resolution, leaving its status text as `active`.

## Root cause

Stage 2 implemented two separate concepts:

- active-claim evaluation for the current state; and
- append-preserving conflict history for audit reporting.

The current-state path was complete. The historical-reporting path lacked a lifecycle transition from `active` to `resolved`.

## Why existing safeguards did not catch it

The safeguards verified:

- expected state transitions;
- final `C_t=false`;
- one seeded conflict was detected;
- deterministic outputs;
- schema validity;
- traceability and audit reconstruction.

They did not assert the cross-output invariant that final `C_t` must agree with the status of every retained conflict record. JSON Schema could not catch the issue because conflict reports are sidecars and the existing schema only checked structure, not lifecycle semantics. Determinism reproduced the same error consistently; it does not prove semantic correctness.

## Correction

Version 0.2.4 adds:

- detection and resolution timestamps and event IDs;
- resolution artefact and rationale linkage;
- explicit lifecycle transitions;
- separate resolution audit events;
- active/resolved report counts;
- a fail-closed `C_t` versus active-history invariant; and
- regression tests for the exact defect.

## Research impact

The core Stage 2 trajectory, scores, authorization result, source hashes, and deadline posture are unchanged. Therefore, the defect does not invalidate the prototype's T+10h escalation or T+14h return to `Report-Ready`.

It does affect the auditability claim if the uncorrected conflict report were cited. The prior conflict-history output and any table derived from it must not be used. Pilot assets are regenerated after the correction, and final manuscript claims must use a tagged, checkpointed 0.2.4-or-later run.

## Safeguard assessment

| Existing safeguard | What it proved | Why it did not detect BUG-004 | New control |
|---|---|---|---|
| State-oracle tests | The five recommendations matched the frozen scenario | They checked current `C_t`, not historical conflict status | Lifecycle and cross-output assertions |
| Schema validation | EvidencePack v0.2 was structurally valid | The conflict report is a sidecar and structural schemas do not infer lifecycle meaning | CLI consistency guard and sidecar regression tests |
| Deterministic replay | Identical inputs produced identical bytes | It reproduced the defect deterministically | Determinism retained, but paired with semantic invariants |
| Branch coverage | Most implementation branches executed | Coverage does not establish that the assertions are correct or complete | Exact defect regression and fail-closed branch test |
| GitHub and Colab | The repository reproduced in independent environments | Both ran the same incomplete test oracle | Human semantic review plus explicit invariant inventory |

## Final local validation

The corrective build passed the clean-export release gate with:

- 65 automated tests;
- 84.27% branch-aware coverage;
- strict validation of 15 source artefacts;
- EvidencePack Schema v0.2 and 34 mandatory EC fields preserved;
- Ruff, Mypy, Codespell, Yamllint, dependency, compilation, and manifest checks passed; and
- six byte-identical deterministic outputs.

GitHub Actions and the short Colab checkpoint must still be rerun against the exact
corrective commit before the pilot is tagged or made manuscript-eligible.
