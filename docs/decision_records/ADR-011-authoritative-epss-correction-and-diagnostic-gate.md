# ADR-011: Authoritative EPSS Correction and Diagnostic Gate

**Status:** Accepted for Stage 5.5.2  
**Date:** 2026-07-21

## Context

The Stage 5.5.1 online gate downloaded the date-specific FIRST API response and
pinned daily archive successfully. The API and archive agreed with each other,
but both disagreed with the repository's prefilled candidate values. The gate
therefore failed correctly. The observed API record was `0.00371` with
percentile `0.72343`; the rejected candidate had been `0.95732` with percentile
`0.99721`.

A raw API response was also present at repository root. It was runtime evidence,
not a source-controlled fixture, and caused the manifest and repository-integrity
tests to fail.

## Decision

1. Replace the rejected candidate values with the values independently observed
   in the FIRST API and pinned archive.
2. Continue to require exact API/archive/normalized-record agreement online.
3. Preserve raw downloads before semantic comparison so failed verification is
   diagnosable.
4. Emit a structured failure report containing observed records and failed
   checks before returning a non-zero exit code.
5. Reject and ignore mutable verification downloads at repository root; retain
   them only under `outputs/validation` or in checkpoint bundles.
6. Keep EPSS as predictive context. It remains neither KEV evidence nor proof of
   organisation-local exploitation.

## Consequences

The Stage 5.5.1 failed run remains development evidence showing the gate worked.
Only Stage 5.5.2-or-later outputs may support the historical EPSS claim. The
reference-deployment trajectory is unchanged because the EPSS ablation already
showed that KEV and public exploitation evidence dominate the final result.
