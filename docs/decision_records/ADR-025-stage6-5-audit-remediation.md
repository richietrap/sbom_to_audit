# ADR-025 — Stage 6.5 independent-audit remediation and historical-evidence preservation

## Status

Accepted for the Stage 6.5 remediation candidate. Targeted independent closure re-audit resolved `S65-F001` and `S65-F004`; repository checkpoint acceptance remains pending the post-audit GitHub and exact-commit Colab sequence.

## Context

The Stage 6.5 same-provider adversarial technical audit completed independent recomputation against the accepted Stage 6.4 checkpoint and classified the checkpoint `ACCEPT_WITH_REMEDIATION`. It reported no CRITICAL findings and two MAJOR findings relevant to production/evaluation evidence.

`S65-F001` found that the frozen Audit Reconstructability specification accepts an audit event whose common reconstruction fields are populated and whose output is identified by either an output hash or output state. The accepted production implementation required `output_state`, making it narrower than the frozen specification. Existing historical AR values were not shown to change because the evaluated records contain `output_state`.

`S65-F004` found that Stage 6.4 preserved raw wall/CPU observations but only a workload-level `peak_rss_bytes` summary. The accepted runner obtains `resource.getrusage(resource.RUSAGE_SELF).ru_maxrss` after all warm-ups and measured replays in each fresh workload worker, so the genuine lowest-level memory observation is one worker high-water mark per workload.

## Decision

Stage 6.5 makes one production-semantic change only: `audit_reconstructability()` now requires the existing common audit fields plus a populated `output_hash OR output_state`. The denominator and existing population rules remain unchanged.

Historical Stage 6.3 mutation evidence remains immutable and bound to the target-source hashes stored in `stage6_3_mutation_summary.json`. The Stage 6.3 protocol deliberately uses exact-text mutations. Later source evolution therefore must not be treated as evidence that the historical mutation experiment became invalid. The historical validator gains an explicit historical-source mode, while v0.6.5 adds new specification-derived AR conformance tests.

Stage 6.4 protocol v0.1 and its observed evidence remain immutable. A new protocol v0.2 repeats the same complete workload matrix but writes a raw memory-evidence file containing one genuine RSS high-water observation per workload worker. The summary `peak_rss_bytes` must derive from that observation. Historical memory values are not reconstructed or backfilled.

Protocol v0.2 explicitly defines wall CV as sample standard deviation divided by arithmetic mean, matching the historical implementation. This records a previously implicit convention without rewriting the wording of v0.1.

## Research boundary

- No state, threshold, scenario, oracle, EvidencePack, EC-denominator, identity, deadline, or authorisation semantics are changed.
- Stage 6.2 and Stage 6.3 historical evidence is not regenerated to make it fit v0.6.5.
- Original Stage 6.4 F12/T30/T31 assets are not overwritten.
- The remediation performance run is a new environment-specific candidate and does not need to reproduce Stage 6.4 latency values numerically.
- Any decision-semantic divergence is a stop condition.
- Development validation cannot close `S65-F001` or `S65-F004`; targeted independent re-audit is mandatory.


## Targeted independent closure re-audit

The targeted independent Stage 6.5 closure re-audit completed after the immutable pre-audit candidate snapshot was created. It independently reconstructed the candidate Git tree, verified the accepted Stage 6.4 parent and original Stage 6.5 audit provenance, and adjudicated both MAJOR findings as resolved.

For `S65-F001`, 40/40 independently derived AR conformance cases matched the corrected implementation, seven historical scenario replays covering 157 audit entries produced zero historical AR-value changes, and the registered Stage 6.3 historical protocol/result files remained byte-identical.

For `S65-F004`, independent recomputation began from the raw timing and memory evidence. The audit confirmed 20 workloads, 200 timing rows, 20 genuine one-per-worker memory observations, 260/260 recomputed workload/metric cells, 40/40 endpoint-table cells, 8/8 figure polylines, and 20/20 decision-equivalent workloads. The historical Stage 6.4 performance evidence remained unchanged.

Closure evidence is preserved separately from the repository candidate:

- closure re-audit evidence ZIP SHA-256: `1c03387e3dfbc5e3bee4e115cca8d2a93ba0a5f17602f0b5ab950502be9530c8`;
- machine-readable closure summary SHA-256: `c3db7a357a233aad959f783e0bbcb7a3e8ba726dba3e998c37743dabf1502444`.

The audit environment could not collect `tests/test_properties.py` because Hypothesis was unavailable in that sandbox. This did not block either targeted finding because those property tests concern identity-confidence uncertainty monotonicity and conflict precedence rather than AR semantics or performance evidence. The repository-wide regression and release gate must therefore be rerun locally after these post-audit tracked metadata/documentation edits.

## Post-audit acceptance boundary

Resolving `S65-F001` and `S65-F004` does not by itself create an accepted Stage 6.5 checkpoint. The candidate remains `CANDIDATE_NOT_FROZEN` and `manuscript_eligible: false` until the post-audit repository gate passes, the candidate is committed and pushed, GitHub Actions pass, the exact 40-character commit is recorded, and the Stage 6.5 Colab checkpoint reproduces that immutable commit with a preserved evidence ZIP and SHA-256. The deferred manual baseline and final evaluation freeze remain separate later gates.
