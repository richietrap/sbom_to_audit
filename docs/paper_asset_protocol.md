# Paper Asset Accumulation Protocol

## Purpose

Figures and tables must be generated from registered machine-readable runs rather than reconstructed from memory or manually edited screenshots.

## Status classes

- `DEVELOPMENT`: debugging only;
- `PILOT`: structured pre-evaluation evidence;
- `FROZEN_EVALUATION`: approved for results reporting;
- `NEGATIVE_CONTROL`, `SENSITIVITY`, `BASELINE`, and `PUBLIC_REPLAY`: specialised evaluation records.

## Required lineage

Each paper asset must identify:

1. asset ID and provisional title;
2. paper section;
3. source run IDs;
4. generation script;
5. input and output hashes;
6. status and verification date; and
7. whether the asset is approved for the manuscript.

## Stage 2 pilot assets

- F01: prototype evidence pipeline;
- F02: Ghost-Logger temporal evidence trajectory;
- T01: source artefact inventory;
- T02: event replay table.

These assets demonstrate the generation mechanism only. They must be regenerated after the GitHub and Colab Stage 2 checkpoints before use in the final manuscript.

## Prohibited practices

- manually altering plotted result values;
- citing `PILOT` assets as final evaluation evidence;
- using a figure without preserving its source data;
- changing a frozen scenario after seeing results without an ADR and rerun;
- omitting failed or boundary-sensitive runs from the evaluation register.
