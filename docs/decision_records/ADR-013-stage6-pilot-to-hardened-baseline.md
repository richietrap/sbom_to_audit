# ADR-013: Preserve the Stage 6 Pilot and Introduce a Hardened Manual Baseline

- **Status:** Accepted for Stage 6.1 implementation
- **Date:** 2026-07-24
- **Version:** 0.6.1

## Context

Stage 6 implemented a deterministic structured-but-unorchestrated computational proxy. The
proxy is reproducible and useful for isolating scope reasoning, claim confidence, automatic
clock escalation, and EvidencePack construction. Methodological review established that it
does not implement the previously planned manual-assisted PSIRT baseline and that several
headline differences are structurally influenced by the intervention-specific schema.

Deleting or rewriting Stage 6 would remove valid development evidence and obscure the
Design Science refinement process. Treating the pilot as the final matched evaluation would
overstate what it demonstrates.

## Decision

1. Preserve Stage 6, `baseline_protocol_v0.1.yaml`, ADR-012, pilot outputs, and pilot paper
   assets unchanged as a deterministic computational ablation pilot.
2. Add Stage 6.1 as a separate manual-assisted matched-baseline protocol.
3. Mark Stage 6.1 outputs as manuscript-ineligible until protocol freeze, completed manual
   execution, immutable Git reference, and clean Colab reproduction.
4. Use Stage 6 pilot results only as development or feature-ablation evidence.
5. Use Stage 6.1 results, once frozen, for the final RQ5 baseline comparison.

## Consequences

The repository retains a transparent chronology:

`Stage 6 pilot -> methodological scrutiny -> Stage 6.1 hardening -> final matched evaluation`.

Stage 6.1 requires new worksheets, source-release packets, independent oracles, fairness
controls, import provenance, validation, and Colab evidence. It does not modify EvidencePack
Schema v0.2, the 34-field EC denominator, or the seven locked metrics.
