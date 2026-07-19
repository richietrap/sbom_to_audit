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
