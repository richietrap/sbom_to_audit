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

## Stage 5 pilot assets

- `figures/rapid_pivot_clock_comparison.svg` compares uncertainty and state trajectories when identical resolving evidence arrives before versus after the internal 18-hour safeguard;
- `tables/rapid_pivot_event_replay.csv` preserves the main temporal replay;
- `tables/rapid_pivot_clock_comparison.csv` provides matched event-level values for the main and control replays;
- `tables/stage5_scenario_summary.csv` summarizes all seven controlled replay manifests.

These remain `PILOT / NOT_ELIGIBLE` until regenerated from a tagged commit and preserved through the Stage 5 Colab checkpoint.

## Stage 5.5.1 and Stage 5.5.2 assets

The Stage 5.5.1 online gate rejected an incorrect normalized EPSS candidate.
Stage 5.5.2 regenerates the verification figure and ablation tables from the
corrected normalized record (`0.00371`, percentile `0.72343`) and records them
under `stage552_asset_manifest.json`. They remain
`PILOT_CORRECTED_VERIFICATION_CANDIDATE` until the exact GitHub commit passes
the authoritative online quality and Colab gates.
