# Paper Asset Pipeline

This directory contains data-driven candidate figures and tables. Stage 2 files are labelled `PILOT`; they demonstrate the asset-generation workflow but are not final manuscript results.

Rules:

1. figures and tables must be generated from registered outputs;
2. every asset must name its source run and generation script;
3. editable vector output (`.svg`) is preferred for figures;
4. final manuscript assets require a `FROZEN_EVALUATION` source run;
5. manually altered result figures are prohibited.

## Stage 3 pilot assets

`build_stage3_assets.py` consumes the deterministic outputs for Ghost-Logger, False Comfort, and the False Comfort negative control. It generates a cross-scenario summary, the False Comfort event replay, a scope-applicability comparison table, and an SVG comparison figure. All remain `PILOT` and `NOT_ELIGIBLE` until regenerated from a tagged commit and reproduced in Colab.
