# Reproduction Guide

## 1. Reference environment

The supported runtime is Python 3.10–3.12. GitHub is the source of truth. Google Colab is the independent clean-room runtime; Google Drive may preserve generated run bundles but must not supply hidden dependencies.

## 2. Local execution

```bash
git clone https://github.com/richietrap/sbom_to_audit.git
cd sbom_to_audit
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\\Scripts\\activate
python -m pip install -e ".[dev]"
python scripts/validate_repository.py --strict-sources
python -m sbom_to_audit.cli --scenario data/scenarios/ghost_logger.yaml
python paper_assets/scripts/build_stage2_assets.py \
  --output-root outputs \
  --destination paper_assets
python paper_assets/scripts/build_stage3_assets.py \
  --output-root outputs \
  --destination paper_assets
python paper_assets/scripts/build_stage4_assets.py \
  --output-root outputs \
  --destination paper_assets
python -m pytest
python scripts/release_check.py
```

## 3. Generated outputs

Each scenario replay generates six deterministic products; for Ghost-Logger these are:

```text
outputs/evidence_packs/ghost_logger.json
outputs/state_logs/ghost_logger.csv
outputs/conflict_reports/ghost_logger.json
outputs/metrics/ghost_logger_metrics.json
outputs/source_manifests/ghost_logger_sources.json
outputs/audit_ledgers/ghost_logger.jsonl
```

Generated files under `outputs/` are intentionally ignored by Git. Tests always create temporary outputs so clean checkouts do not depend on local generated files.

## 4. Determinism

The scenario fixes source-release times, event times, target identifiers, expected oracles, and configured milestone parameters. The implementation computes source hashes and derived claims from committed files. It does not insert wall-clock timestamps into replay outputs.

Re-running the same commit should produce byte-identical outputs. The canonical release check performs two independent replays and compares all six products.

## 5. Colab checkpoint

Use an isolated virtual environment inside Colab rather than Colab's global package set. The checkpoint should:

1. clone the exact branch or tag;
2. create an isolated environment;
3. install `.[dev]`;
4. run `pip check` inside that environment;
5. run strict repository validation;
6. run the full release check;
7. preserve the report and output hashes.

## 6. Paper assets

`paper_assets/scripts/build_stage2_assets.py`, `build_stage3_assets.py`, and `build_stage4_assets.py` generate pilot SVG figures and CSV tables from registered replay outputs. Assets remain `PILOT` until the exact Git commit, GitHub checks, Colab evidence bundle, and SHA-256 are preserved and the final evaluation is frozen.

## Stage 5 checkpoint

After GitHub regression and quality workflows pass, run `notebooks/stage5_colab_checkpoint.ipynb` from the exact GitHub reference. Download `stage5_colab_checkpoint_evidence.zip` and preserve both the 40-character tested commit and the printed SHA-256 digest. The bundle includes all seven scenario outputs, the Stage 5 release report, regenerated paper assets, and environment metadata. Do not mark Stage 5 assets manuscript-eligible solely because the notebook executed; checkpoint registration and later evaluation freeze remain separate steps.

## Stage 5.5.1 online historical EPSS gate

The local release checker validates the committed verification contract. The
remote acceptance workflow must additionally run:

```bash
python scripts/verify_historical_epss.py \
  --online \
  --output-dir /tmp/historical-epss \
  --report /tmp/historical-epss/report.json
```

The Stage 5.5.1 Colab checkpoint preserves the raw API response, complete pinned
gzip archive, extracted CVE row, hashes and online report in its downloadable
evidence bundle. Record the exact Git commit and evidence-bundle SHA-256.


## Stage 5.5.2 corrected historical EPSS gate

The normalized 2024-04-15 record is `0.00371` with percentile `0.72343`.
Online acceptance still requires the date-specific FIRST API and pinned daily
archive to agree exactly with each other and with the normalized record.

Verification downloads belong under `outputs/validation` or in an external
checkpoint bundle. Do not place or commit them at repository root. A failed
comparison writes a diagnostic JSON report containing the observed records and
failed checks before returning a non-zero exit code.

## Stage 5.5.2 repository replacement

Stage 5.5.1 left a mutable FIRST API download at repository root. Replace the
repository using deletion-aware synchronization so files absent from the
corrected release are removed while `.git/` is preserved:

```bash
rsync -a --delete --exclude='.git/' /tmp/sbom-stage552/sbom-to-audit/ ~/sbom_to_audit/
cd ~/sbom_to_audit
git add -A
git status
```

The root-level API JSON, extracted row, gzip archive and verification report are
runtime evidence. They must be stored under `outputs/validation/` or in a Colab
checkpoint bundle, never as source-controlled root files.
