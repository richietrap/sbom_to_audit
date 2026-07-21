# Evaluation Registry

This directory records research runs and scenario definitions used to support the paper. It does not replace raw outputs under `outputs/` or archived run bundles in persistent storage.

Run classifications:

- `DEVELOPMENT`: implementation debugging only;
- `PILOT`: structured pre-evaluation run, not final paper evidence;
- `FROZEN_EVALUATION`: approved result eligible for the paper;
- `NEGATIVE_CONTROL`, `SENSITIVITY`, `BASELINE`, and `PUBLIC_REPLAY`: specialised evaluation runs.

Every frozen run must record an exact Git commit, environment identifier, input-manifest hash, output-manifest hash, and preservation location.

## Stage 5

Stage 5 adds `rapid_pivot` and `rapid_pivot_control`. Their source catalogs, target, deadline profile, source timestamps, and event clock are matched. The treatment is the release time of the identity, EPSS, VEX, and reachability artefacts. The primary replay exercises an eligible Clock-Aware Escalation opportunity; the control resolves uncertainty before the safeguard.

## Stage 5.5

Stage 5.5 adds a publication-aware CVE-2024-3400 public replay and a separately
classified synthetic reference deployment. The public replay does not generate a
full EvidencePack because public reporting cannot establish organisation-local
reachability, execution, impact, authorization, submission, or legal applicability.
The Stage 5.5 value was provisional and blocked manuscript eligibility.

The repository validator now checks run-to-scenario and run-to-environment references,
duplicate IDs, commit markers, and SHA-256 formatting so a pilot cannot silently refer
to an unregistered execution environment.

## Stage 5.5.1 verification runs

The Stage 5.5.1 historical rows preserve the earlier provisional Stage 5.5
runs and add verified-not-frozen runs. Acceptance requires the online GitHub and
Colab dual-source EPSS checks. The run registry intentionally retains both
states rather than rewriting the provisional development history.

## Stage 5.5.1 aggregate hash convention

For Stage 5.5.1 candidate runs, `input_manifest_hash` is SHA-256 over the source-manifest JSON serialized with sorted keys and compact separators. `output_manifest_hash` is SHA-256 over a sorted JSON mapping from each registered output path to that file's SHA-256, serialized the same way. This convention is deterministic and excludes timestamps external to the generated outputs.


## Stage 5.5.2 corrected verification runs

Stage 5.5.2 preserves the failed Stage 5.5.1 candidate as development history,
corrects the normalized EPSS record to the values observed from both authoritative
sources, and adds new corrected-candidate runs. The corrected rows remain
non-eligible until GitHub and Colab repeat the dual-source online verification.
