# Evaluation Registry

This directory records research runs and scenario definitions used to support the paper. It does not replace raw outputs under `outputs/` or archived run bundles in persistent storage.

Run classifications:

- `DEVELOPMENT`: implementation debugging only;
- `PILOT`: structured pre-evaluation run, not final paper evidence;
- `FROZEN_EVALUATION`: approved result eligible for the paper;
- `NEGATIVE_CONTROL`, `SENSITIVITY`, `BASELINE`, and `PUBLIC_REPLAY`: specialised evaluation runs.

Every frozen run must record an exact Git commit, environment identifier, input-manifest hash, output-manifest hash, and preservation location.
