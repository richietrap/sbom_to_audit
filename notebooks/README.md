# Notebooks

Google Colab is the intended clean-room runtime. Notebooks remain thin orchestration layers that import and execute the tested `sbom_to_audit` package; no scoring, conflict, state, or metric logic may exist only in a notebook.

## Stage 2 checkpoint

`stage2_colab_checkpoint.ipynb`:

1. clones an exact GitHub branch or tag;
2. creates an isolated Python environment;
3. installs the package and development dependencies;
4. runs the canonical release gate and deterministic double replay;
5. executes the real-format Ghost-Logger vertical slice;
6. validates the EvidencePack v0.2 schema and five-event trajectory;
7. regenerates pilot paper assets from machine-readable outputs; and
8. creates a downloadable checkpoint evidence bundle.

Before a run is treated as manuscript-eligible, set `REF` to an immutable Git tag, preserve the generated bundle, and record its hash in the evaluation registry.

## Stage 3 checkpoint

`stage3_colab_checkpoint.ipynb` clones a clean GitHub reference, installs the project in an isolated environment, runs the complete multi-scenario release gate, checks Ghost-Logger conflict preservation, verifies False Comfort scope mismatch and its scope-matched negative control, regenerates Stage 3 pilot assets, and emits a hashed evidence bundle.

- `stage5_colab_checkpoint.ipynb` — clean-room Stage 5 verification for Rapid Pivot, its temporal control, 42 deterministic outputs, clock-aware escalation, and checkpoint lineage preservation.

- `stage551_colab_checkpoint.ipynb` performs the authoritative online historical
  EPSS comparison, complete release gate, EPSS ablation and raw-evidence bundle
  preservation for Stage 5.5.1.

- `stage552_colab_checkpoint.ipynb` repeats the Stage 5.5.2 corrected online
  comparison, preserves raw API/archive evidence, runs the complete release gate,
  regenerates corrected paper assets, and emits a hashed checkpoint bundle.
