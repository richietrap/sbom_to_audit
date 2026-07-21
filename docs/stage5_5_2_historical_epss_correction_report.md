# Stage 5.5.2 Historical EPSS Correction Report

## Executive summary

Stage 5.5.1 was rejected by the mandatory authoritative online gate. The FIRST
date-specific API response and the pinned official daily archive agreed with one
another but disagreed with the repository's prefilled normalized candidate.
The observed authoritative record was:

- CVE: `CVE-2024-3400`
- score date: `2024-04-15`
- EPSS: `0.00371`
- percentile: `0.72343`
- model version: `v2023.03.01`
- pinned archive commit: `ca26ecd7b9b806badabd6aedffdc8c4472ce6e85`

Stage 5.5.2 corrects the normalized record while retaining the same fail-closed
requirement: the corrected value is not accepted for evaluation freezing until
the exact GitHub commit independently passes both the online GitHub quality gate
and the isolated Colab checkpoint.

## Why all four remote checks failed

The quality job downloaded both authoritative sources successfully. Their CVE,
date, score, percentile and model metadata agreed, but the score and percentile
did not match the incorrect prefilled candidate. The verifier therefore failed
on the expected-value comparison, as intended.

The three regression jobs failed for a separate repository-integrity reason. A
raw API response had been committed at repository root. It was a mutable runtime
download, absent from `MANIFEST.md`, so both manifest equality and strict
repository validation failed on Python 3.10, 3.11 and 3.12.

The Colab failure was the same substantive EPSS candidate mismatch as the
quality job. It did not indicate an independent third value.

## Root cause

The rejected `0.95732` / `0.99721` candidate was taken from an unverified
secondary example and associated with the wrong historical date. It should not
have entered the normalized fixture before authoritative retrieval. This was a
source-selection and verification-order error.

The root API file was created during manual diagnosis and was then included by a
non-deleting repository synchronization followed by `git add .`.

## Corrections

- replaced all normalized 2024-04-15 EPSS fixtures with `0.00371` and
  percentile `0.72343`;
- retained the pinned EPSS v3 archive metadata and commit;
- preserved raw API/archive evidence before semantic comparison;
- made failed online verification emit a structured diagnostic report containing
  observed API, archive and normalized records;
- added root-only ignore rules for online verification downloads;
- added a fail-closed repository invariant rejecting those files at root;
- marked the Stage 5.5.1 run records as failed and superseded;
- created new Stage 5.5.2 corrected-candidate run and environment records;
- regenerated historical figures, tables, hashes and paper-claim lineage;
- added a corrected Stage 5.5.2 Colab notebook;
- required deletion-aware repository replacement using `rsync --delete` and
  `git add -A`.

## Research impact

No recommendation, state transition, conflict, deadline posture, authorization,
submission event, final exploitation score or historical conclusion changes.
The EPSS ablation remains unchanged: removing EPSS does not change the synthetic
reference-deployment trajectory because KEV and published exploitation evidence
dominate after disclosure.

The following Stage 5.5.1 material is rejected and must not be cited:

- its historical EPSS figure and verification table;
- its EPSS-specific fixture and provenance hashes;
- any claim that Stage 5.5.1 passed authoritative verification;
- its failed GitHub or Colab run as positive evidence.

The failed run remains useful as transparent development evidence that the
fail-closed gate worked.

## Validation completed before packaging

- clean dependency installation and `pip check`: passed;
- Ruff lint and formatting: passed;
- Mypy across 35 source files: passed;
- Codespell and Yamllint: passed;
- strict repository and source validation: passed;
- automated tests: **131 passed**;
- branch-aware coverage: **82.55%**;
- EvidencePack Schema: v0.2 unchanged;
- Evidence Completeness denominator: 34 fields unchanged;
- deterministic outputs: **53 of 53** byte-identical;
- clean-export installation and release gate: passed;
- development-tree and clean-export deterministic hashes: identical.

## Remaining acceptance steps

Stage 5.5.2 remains `PILOT_VERIFICATION_CANDIDATE` until:

1. the corrected GitHub Regression suite is green;
2. the corrected GitHub Quality gates workflow completes the authoritative
   online comparison successfully;
3. the corrected Stage 5.5.2 Colab notebook passes;
4. the exact tested Git commit and Colab evidence-bundle SHA-256 are preserved.
