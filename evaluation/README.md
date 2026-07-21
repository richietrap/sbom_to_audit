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
The historical EPSS value remains provisional and blocks manuscript eligibility.

The repository validator now checks run-to-scenario and run-to-environment references,
duplicate IDs, commit markers, and SHA-256 formatting so a pilot cannot silently refer
to an unregistered execution environment.
