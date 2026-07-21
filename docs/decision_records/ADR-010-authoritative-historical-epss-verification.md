# ADR-010 — Authoritative historical EPSS verification

**Status:** Accepted for Stage 5.5.1  
**Date:** 2026-07-21

## Context

Stage 5.5 included a 2024-04-15 EPSS value for CVE-2024-3400 that was
traceable but labelled as a provisional secondary reconstruction. That record
could not support a manuscript-eligible historical replay.

## Decision

Historical EPSS is accepted only when a required online gate independently
retrieves and compares:

1. the date-specific FIRST EPSS API record; and
2. the official daily archive pinned to an immutable repository commit.

The comparison must agree on CVE, score date, score and percentile. The archive
metadata must additionally identify model version `v2023.03.01`. Any mismatch,
missing record, download failure or metadata drift fails closed.

The source repository stores the deterministic expected row and verification
contract. Raw API and gzip evidence, extracted row, source hashes and online
report are preserved in the Colab checkpoint evidence bundle. GitHub's quality
gate performs the same online comparison.

EPSS remains predictive context and is not treated as evidence that exploitation
was observed. A paired ablation omits EPSS from the synthetic reference replay
to identify whether the state trajectory depends on it.

## Consequences

- Stage 5.5's EPSS eligibility blocker is removed only for commits that pass the
  required GitHub and Colab online gates.
- The historical replay becomes eligible for later evaluation freezing, but is
  not automatically a frozen result.
- The current CVE-2024-3400 trajectory is unchanged when EPSS is omitted because
  public exploitation reporting and KEV evidence dominate the exploitation
  score after disclosure.
- Network unavailability correctly fails the online acceptance gate rather than
  silently accepting the normalized row.
