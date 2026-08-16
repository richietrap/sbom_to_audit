# Stage 5.5.1 Historical EPSS Verification Report

## Objective

Replace the provisional CVE-2024-3400 historical EPSS reconstruction with a
fail-closed, dual-source authoritative verification workflow.

## Verification contract

Target record:

- CVE: `CVE-2024-3400`
- score date: `2024-04-15`
- EPSS: `0.00371`
- percentile: `0.72343`
- model version: `v2023.03.01`
- archive commit: `ca26ecd7b9b806badabd6aedffdc8c4472ce6e85`

The mandatory online gate downloads the FIRST date-specific API response and
the pinned official daily gzip archive. Acceptance requires exact decimal
agreement on score and percentile, exact CVE/date agreement, and matching archive
model metadata.

## Fail-closed behaviour

The gate rejects:

- absent or duplicated CVE records;
- an unexpected score date;
- a different model version;
- score or percentile disagreement;
- invalid JSON, CSV or gzip content;
- unsuccessful or empty downloads.

Offline release checks validate the committed verification contract but clearly
state that this does not replace online verification.

## Ablation

The synthetic historical reference replay is executed both with and without the
EPSS source. The state trajectory and final exploitation score are unchanged.
This demonstrates that the historical result is not manufactured by the EPSS
value: public exploitation reporting and KEV evidence already dominate `E_t`.

## Eligibility

The historical replay is `PILOT_VERIFICATION_CANDIDATE`. It becomes eligible for
later evaluation freezing only after the GitHub quality workflow and isolated
Colab checkpoint pass for the exact commit and the Colab evidence bundle is
preserved.

## Later project-level verification status — 2026-08-16

Stage 5.5.1 itself remains a rejected historical candidate and is not rewritten as a pass.
The project-level historical EPSS gate was subsequently completed against the corrected
Stage 5.5.2 record using a fresh date-specific FIRST response and the same pinned official
archive commit. The preserved verification evidence ZIP SHA-256 is
`77a68d509acffc67306584e43b447f214304fbbb93db5dde5c5f502aac2dda29`.
The machine-readable current repository state records `online_gate_required: false`. This
later closure does not reconstruct or replace the rejected Stage 5.5.1 evidence.
