# ADR-026: Stage 6.1.5 controlled-exception clean-room reproduction

- **Status:** Accepted
- **Date:** 2026-08-17
- **Decision owners:** Artefact implementation and evaluation workflow
- **Preserves:** ADR-012 through ADR-025, the Stage 6.1 protocol freeze, Phase 1 candidate-v2.1, all locked metrics and all analyst evidence

## Context

Phase 1 closed against immutable candidate-v2.1 after the completed manual-assisted baseline was
strictly validated. The strict validator correctly remains `valid: false` because four registered
zero-release events contain no source-access rows. The analyst separately clarified that no
previously released registered evidence artefact was reopened at those events. The exact error
and adjudication were admitted through the controlled-exception mechanism added during Phase 1.

The historical Stage 6.1.5 clean-room notebook predates that adjudicated result. Its optional
manual path treats every non-zero strict validation return code as fatal and invokes the importer
without a controlled-exception adjudication. Re-running it unchanged would therefore reject the
accepted Phase 1 input, while altering the analyst source-access log would rewrite evidence.

## Decision

The Stage 6.1.5 reproduction checkpoint will preserve the strict result and adapt only the
admission boundary:

1. `MANUAL_RESULTS_ZIP` remains the canonical completed manual bundle; governance files are not
   inserted into that six-file bundle.
2. `CONTROLLED_EXCEPTION_JSON` is a separate optional input resolved before checkout changes the
   working directory.
3. Strict `--require-complete` validation is executed and logged. Return codes 0 and 1 may be
   recorded; RC=1 is not itself admission.
4. A strict-valid bundle proceeds without an exception and rejects an unnecessary adjudication.
5. A strict-invalid bundle must have exactly one recorded strict error and requires the separate
   adjudication input.
6. The existing `import_manual_baseline_results.py --controlled-exception` path remains the sole
   policy authority for matching the exact registered error and adjudication fields. The notebook
   does not duplicate or weaken that policy.
7. After import, the notebook verifies that the importer preserved the strict report verbatim,
   that admission is true, that strict validity remains false, that admission errors equal the
   strict errors, and that the adjudication hash matches the supplied file.
8. The manual ZIP and adjudication file are re-hashed after processing to detect input mutation.
9. The checkpoint archive preserves the strict validation report, original adjudication,
   controlled-exception admission, import evidence, comparison evidence and command logs.

## Rejected alternatives

- Adding synthetic source-access rows: rejected because the analyst confirmed no registered
  evidence was reopened at the four zero-release events.
- Rewriting strict validation to `valid: true`: rejected because it would erase the distinction
  between strict validation and controlled governance admission.
- Embedding the adjudication in the canonical manual ZIP: rejected because it would change the
  six-file manual execution bundle and weaken the clean-room input boundary.
- Creating a second admission implementation in the notebook: rejected because the importer
  already contains the tested fail-closed admission policy.

## Research impact

None. This change affects clean-room reproduction governance and evidence preservation only. It
does not modify the manual evidence, frozen protocol, oracles, scenarios, metric definitions,
normalization semantics, comparison definitions, Phase 1 results or Phase 1 candidate-v2.1.

## Provenance boundary

Phase 1 remains bound to execution commit
`170f46b746a687f7149c0b48a1a2571abbc158b8`. The reproduction-governance adaptation must be
committed later and the final Colab run must use that later exact commit, preserving both
historical roles rather than rewriting Phase 1 provenance.
