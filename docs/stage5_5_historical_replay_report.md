# Stage 5.5 Historical Replay Report

## Scope

Stage 5.5 implements a public historical reconstruction for CVE-2024-3400 / Operation
MidnightEclipse and a separate synthetic reference deployment.

## Public-evidence-only replay

The public replay registers seven research-normalized source extracts and replays eight chronology
events. It preserves the distinction between:

- occurrence time;
- publication time;
- conservative availability time; and
- replay ingestion time.

No full EvidencePack is generated. Organisation-local reachability, execution, impact, mitigation,
authorization, submission, and legal applicability remain unavailable.

## Synthetic reference deployment

The reference replay uses a research-normalized CycloneDX SBOM, public CVE/NVD/KEV/advisory
context, a public exploitation report, and explicitly synthetic asset, telemetry, mitigation,
authorization, and submission evidence.

Expected state trajectory:

`Monitor → Report-Ready → Report-Ready → Report-Ready → Report-Ready → Report-Ready`

The public exploitation report raises exploitation evidence without becoming local telemetry.

## Provisional boundary

The 2024-04-15 EPSS value is marked `provisional_secondary_reconstruction`. This is sufficient to
test provenance and temporal handling, but it prevents the historical replay from entering the
frozen evaluation or final paper results until authoritative verification is completed.

## Evaluation status

`PILOT_PROVISIONAL / NOT_MANUSCRIPT_ELIGIBLE`

## Quality and reproducibility gates

The Stage 5.5 release gate covers eight executable scenario manifests, producing six outputs each,
plus three deterministic public-historical outputs. The public and reference replay records resolve
to a registered Stage 5.5 execution environment and carry final source/output hashes.

Pre-release validation results:

- 111 automated tests passed;
- 83.72% branch-aware coverage;
- strict validation passed for all scenario and historical source files;
- 275 repository files are declared and present in `MANIFEST.md`;
- 51 deterministic outputs were reproduced byte-for-byte;
- EvidencePack Schema v0.2 and the 34-field EC denominator remain unchanged.

The strengthened registry gate also exposed and corrected two pre-release metadata omissions: the missing Stage 5.5 environment record (`BUG-006`) and a missing False Comfort control scenario-registry row (`BUG-007`). Neither affected replay logic or results.

These are pilot reproducibility results. The exact GitHub commit and Colab evidence-bundle SHA-256
must still be preserved, and the provisional historical EPSS source must be authoritatively verified
or removed before the replay can enter the frozen evaluation or manuscript results.
