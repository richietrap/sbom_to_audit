# ADR-012: Matched structured-but-unorchestrated PSIRT baseline

- **Status:** Accepted for Stage 6 pilot evaluation
- **Date:** 2026-07-21
- **Decision owner:** Research artefact author

## Context

RQ5 requires a comparison between the orchestration artefact and an un-orchestrated PSIRT workflow. A deliberately weak baseline would inflate the apparent contribution, while a human analyst study is not currently available. The comparison therefore needs a reproducible computational proxy that is useful but explicitly bounded.

## Decision

Stage 6 uses `evaluation/baseline_protocol_v0.1.yaml` as a frozen, matched baseline protocol.

The baseline receives the same source bytes, source-release events, timestamps, source validation, and parser-derived observations as the orchestration artefact. Sharing parsers prevents extraction quality from becoming a hidden confound.

The baseline is a structured worksheet review. It intentionally does not use:

- the normalized claim graph or claim confidence model;
- product-variant scope overlap;
- numerical `E_t`, `A_t`, `I_t`, `M_t`, `U_t`, or `C_t`;
- automated conflict lifecycle tracking;
- the internal `tau_E=18h` escalation safeguard; or
- EvidencePack generation.

The controlled scenario oracles are consulted only after each decision for evaluation.

## Fairness controls

- The baseline retains source IDs, URIs, hashes, timestamps, parser names, and validation status.
- It tracks configured deadlines and separate authorization/submission evidence.
- It can detect a direct supplier-versus-local contradiction.
- It can use operational context and local applicability to reach `Report-Ready`.
- It is allowed to tie the artefact where its simpler records are sufficient.

Consequently, Stage 6 reports equal `AR` and equal seeded-conflict recall rather than suppressing those ties. Conflict precision is reported separately because the scope-blind baseline also flags a false contradiction in False Comfort.

## Consequences

The comparison can support controlled functional claims about the orchestration layer. It cannot establish:

- real analyst time savings;
- reduced cognitive workload;
- legal correctness;
- industrial effectiveness; or
- superiority to every existing PSIRT process.

Those limitations must accompany every Stage 6 result.
