# Stage 6.2 robustness and sensitivity evaluation

## Status

Stage 6.2 is an **implementation and local candidate-result package**. It is not an accepted or frozen experimental result until the exact tree passes the repository's full quality workflow, GitHub Actions, and exact-commit Colab reproduction. The blinded manual baseline remains deferred and unchanged.

## Objective

Stage 6.2 tests whether the temporal evidence-orchestration prototype responds deterministically, explainably, and fail-closed when registered inputs or prototype parameters are varied. It does not seek to prove legal correctness, optimal thresholds, production performance, or industrial effectiveness.

## Registered evaluation layers

| Layer | Scope | Primary output |
|---|---|---|
| Threshold sensitivity | Seven scenarios; baseline and offsets -0.10, -0.05, +0.05, +0.10 | Event-level score/state transition matrix |
| Clock sensitivity | Rapid Pivot and matched control; 14, 16, 18, 20, 22 hours | Clock safeguard transition matrix |
| Single-factor sensitivity | Twelve factors and 38 registered values | One-factor-at-a-time state and score changes |
| Negative cases | Eight malformed, missing, unsafe, or temporally invalid cases | Fail-closed rejection evidence |

## Candidate outputs

The runner writes deterministic files under `evaluation/stage6_2_candidate/`:

- `stage6_2_threshold_sensitivity.csv`;
- `stage6_2_clock_sensitivity.csv`;
- `stage6_2_factor_sensitivity.csv`;
- `stage6_2_negative_cases.csv`;
- `stage6_2_scenario_stability.csv`;
- `stage6_2_robustness_report.json`;
- `stage6_2_output_manifest.json`.

The paper asset builder consumes those outputs and creates two SVG figures and five CSV tables. Every asset is registered as `CANDIDATE_NOT_FROZEN` and `manuscript_eligible: false`.

## Candidate observations

The locally generated candidate contains 140 threshold rows, 60 clock rows, 266 factor rows, and eight negative cases. Twenty-four non-baseline threshold rows, three clock rows, and 42 factor rows change state. All eight negative cases are rejected as registered. These counts are useful for checking the implementation, but they are not final paper results until the external acceptance gates and final evaluation freeze are complete.

## Temporal-integrity correction

During pre-release Stage 6.2 work, the replay pipeline was found to rely on the valid chronology of existing scenarios without enforcing that chronology as a fail-closed invariant. The pipeline now rejects duplicate event IDs, events before the clock start, out-of-order events, and releases of future-dated evidence. Existing accepted scenario trajectories remain unchanged.

## Reproduction

Run:

```bash
python scripts/run_stage6_2_robustness.py --destination evaluation/stage6_2_candidate
python scripts/validate_stage6_2_evaluation.py   --results evaluation/stage6_2_candidate
python scripts/build_stage6_2_paper_assets.py   evaluation/stage6_2_candidate --destination paper_assets
python scripts/validate_repository.py --strict-sources
```

The Stage 6.2 Colab notebook repeats result and asset generation twice from an exact detached commit, compares each tree byte-for-byte, and packages the protocol, reports, tables, figures, command logs, and checksums.

## Claims that remain prohibited

Do not claim that Stage 6.2:

- validates CRA or NIS2 legal determinations;
- establishes an optimal reporting threshold;
- demonstrates production scalability;
- represents an industrial case study;
- proves superiority over human PSIRT practice;
- completes RQ5 while the blinded manual baseline is outstanding.
