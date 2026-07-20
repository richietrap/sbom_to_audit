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
