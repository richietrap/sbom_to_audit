# Stage 6.5 audit remediation report

## Scope

This remediation addresses only the two MAJOR findings from the completed Stage 6.5 Phase C/D audit.

### S65-F001 — Audit Reconstructability conformance

The frozen specification in `docs/metrics.md` requires a stable event identifier, timestamp, actor, action, relevant input references, and an output hash or state. The accepted Stage 6.4 implementation required `output_state` specifically. Version 0.6.5 changes only the output-identification predicate to `(output_hash OR output_state)` while retaining all common mandatory fields, the same denominator, and the existing `_populated` semantics.

The regression matrix is:

| output_hash | output_state | Expected |
|---|---|---|
| populated | absent | reconstructable |
| absent | populated | reconstructable |
| populated | populated | reconstructable |
| absent | absent | not reconstructable |

The existing Stage 6.3 safety test remains unchanged. Its historical exact-text mutant `S63-MT-002` remains part of immutable Stage 6.3 evidence; it is not rewritten to target the changed v0.6.5 source.

### S65-F004 — raw peak-RSS provenance

The accepted Stage 6.4 runner measures `resource.getrusage(resource.RUSAGE_SELF).ru_maxrss` after three warm-ups and ten measured replays in a fresh worker. Therefore, the genuine raw memory granularity is one high-water observation per workload worker.

The remediation protocol repeats the complete Stage 6.4 workload design and writes `stage6_5_memory_observations.csv`. Each row stores the raw `ru_maxrss` value, native unit, normalized byte value, API, measured-process scope, capture point, warm-up/measured counts and decision fingerprint. The workload summary peak RSS must equal the normalized raw observation.

The remediation does not infer historical memory observations, duplicate a worker value into ten trial rows, or overwrite the historical Stage 6.4 result bundle.

## CV clarification

Stage 6.4 production code historically used `statistics.stdev(wall) / statistics.fmean(wall)`. Protocol v0.1 named `wall_cv` without stating sample versus population standard deviation. Protocol v0.2 explicitly records the sample-standard-deviation convention. The historical ambiguity remains documented.

## Acceptance boundary

After the local full performance rerun and repository quality gate pass, both findings remained `REMEDIATION_IMPLEMENTED_AWAITING_INDEPENDENT_REAUDIT`. The targeted independent Stage 6.5 closure re-audit then independently adjudicated `S65-F001` and `S65-F004` as `RESOLVED`. The closure evidence ZIP SHA-256 is `1c03387e3dfbc5e3bee4e115cca8d2a93ba0a5f17602f0b5ab950502be9530c8`. The post-audit repository gate, GitHub Actions, exact-commit Stage 6.5 Colab checkpoint (`0478690b15246dce3ecb5fb0c860b89cffb08ea4`; evidence ZIP SHA-256 `6c02406ffd4724f97ff5046cbc70dc49e20bf85171edb459ec0979d20be5a2a2`) and historical EPSS online-verification gate (evidence ZIP SHA-256 `77a68d509acffc67306584e43b447f214304fbbb93db5dde5c5f502aac2dda29`) are now complete. This still does not accept or freeze the repository; Stage 6.5 remains `CANDIDATE_NOT_FROZEN` and `manuscript_eligible: false` pending the deferred manual baseline and final evaluation freeze.


## Independent closure evidence

The targeted closure re-audit independently verified the pre-audit candidate provenance and original audit boundary before adjudicating the two MAJOR findings.

- `S65-F001`: `RESOLVED`; 40/40 AR semantic cases matched, historical AR changed in 0/157 evaluated audit entries, and the registered Stage 6.3 historical evidence remained byte-identical.
- `S65-F004`: `RESOLVED`; 20 workloads, 200 timing rows and 20 genuine worker-level RSS observations were independently parsed, with 260/260 recomputation cells, 40/40 endpoint cells, 8/8 figure polylines and 20/20 decision-equivalent workloads matching.
- closure evidence ZIP SHA-256: `1c03387e3dfbc5e3bee4e115cca8d2a93ba0a5f17602f0b5ab950502be9530c8`.
- closure summary SHA-256: `c3db7a357a233aad959f783e0bbcb7a3e8ba726dba3e998c37743dabf1502444`.

The original findings and original Stage 6.5 audit remain historical evidence and must not be deleted or rewritten. Historical Stage 6.4 RSS remains non-raw-recomputable; F004 is closed by the new versioned Stage 6.5 measurement run, not by retroactive reconstruction of Stage 6.4 memory evidence.
