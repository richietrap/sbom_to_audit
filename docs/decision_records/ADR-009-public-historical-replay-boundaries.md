# ADR-009: Separate public historical replay from synthetic reference deployment

**Status:** Accepted  
**Version:** 0.5.5  
**Decision date:** 2026-07-20

## Context

Public reporting about CVE-2024-3400 establishes vulnerability, affected-product, exploitation,
mitigation, and publication chronology facts. It cannot establish whether an unnamed organisation
actually deployed an affected configuration, observed local execution, suffered impact, authorized
a report, or completed a statutory notification.

A single full EvidencePack built entirely from public sources would therefore require invented
organisation-local evidence and would blur occurrence time with publication time.

## Decision

The historical replay has two explicitly different modes.

1. **Historical public replay.** It validates source files, publication timing, provenance, and
   retrospective observation lag. It does not produce an EvidencePack. Local evidence, impact,
   authorization, submission, and legal applicability are recorded as unavailable.
2. **Historical reference deployment.** It combines the public chronology with visibly synthetic
   deployment inputs. It may produce a full EvidencePack, but it is classified separately and
   cannot be presented as evidence about a real organisation.

A public source may contribute an exploitation claim only after its publication/availability time.
The claim is stored under vulnerability intelligence and must not populate local telemetry.

Date-only publications use an end-of-day UTC normalization. This deliberately delays availability
rather than granting evidence early.

The historical EPSS value is provisional until directly verified from an authoritative FIRST
historical response or daily archive. Its presence blocks frozen-evaluation and manuscript
eligibility.

## Consequences

- Temporal leakage from retrospective observations is fail-closed.
- The four controlled scenario families remain unchanged.
- The reference replay is executable but is not a fifth controlled family.
- Public evidence improves external plausibility without manufacturing internal facts.
- Final paper use requires authoritative EPSS verification or removal of the provisional value.
