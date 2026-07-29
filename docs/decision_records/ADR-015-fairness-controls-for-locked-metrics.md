# ADR-015: Add Fairness Controls Without Changing the Locked Metrics

- **Status:** Accepted for Stage 6.1 implementation
- **Date:** 2026-07-24
- **Version:** 0.6.1

## Context

The locked metrics EC, TR, CD, CA, AR, SC, and EPG are part of the EvidencePack v0.2
design freeze. In the Stage 6 pilot, baseline EC, strict TR, CA, and EPG were partly determined
by excluding orchestration-specific fields, confidence, the automatic `tau_E` safeguard, and
EvidencePack output classes. Changing the locked metrics would cause design drift; reporting
them without contextual controls would overstate the comparison.

## Decision

Retain all seven locked metrics unchanged and add the following supplemental controls:

1. common-field completeness over fields both workflows can reasonably record;
2. partial lineage ratio over the four non-confidence provenance elements;
3. event-level conflict precision against ADR-014's independent oracle;
4. equivalent record-bundle generation alongside locked EPG;
5. distinct source artifacts accessed using the same counting unit;
6. human Time to Decision from the manual timing log;
7. automatic clock-safeguard ablation interpreted separately from human clock awareness.

Analyst confidence is permitted and required for an observation to satisfy strict TR. Missing
confidence remains missing and is never imputed.

## Consequences

The paper can report the locked metrics while showing which differences reflect EvidencePack
standardization and which reflect shared evidence-recording performance. Supplemental
controls do not alter the schema, the 34-field denominator, or the metric equations.
