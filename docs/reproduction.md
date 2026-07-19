# Reproduction Guide

## 1. Environment

The reference runtime is Python 3.10 or later. GitHub is the source of truth; Google Colab is the intended hosted runtime. Google Drive may be mounted for persistent outputs and cached API snapshots, but replay correctness must not depend on Drive.

## 2. Local execution

```bash
git clone https://github.com/<YOUR-GITHUB-OWNER>/sbom-to-audit.git
cd sbom-to-audit
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\\Scripts\\activate
python -m pip install -e .[dev]
python -m sbom_to_audit.cli --scenario data/scenarios/ghost_logger.yaml
pytest
python scripts/validate_repository.py
python scripts/release_check.py
```

## 3. Colab execution

```python
!git clone https://github.com/<YOUR-GITHUB-OWNER>/sbom-to-audit.git
%cd sbom-to-audit
!python -m pip install -e .
!python -m sbom_to_audit.cli --scenario data/scenarios/ghost_logger.yaml
!pytest -q
!python scripts/validate_repository.py
```

A Drive mount is optional:

```python
from google.colab import drive
drive.mount('/content/drive')
```

Copy generated outputs to Drive only after the deterministic replay has completed.

## 4. Determinism

The controlled scenario YAML supplies:

- `clock_start_time`;
- replay event timestamps;
- seeded source hashes;
- expected states;
- active claim identifiers; and
- expected conflict counts.

The CLI uses the final replay timestamp as `generated_at`; it does not insert the current wall-clock time. Re-running the same commit and scenario should therefore produce byte-stable JSON and CSV outputs, subject only to platform newline conventions.

## 5. Public-source snapshots

OSV, KEV, and EPSS clients support saving raw responses into their respective snapshot directories. A paper evaluation run should record:

- retrieval timestamp;
- request coordinates or CVE identifier;
- source URI;
- SHA-256 hash; and
- parser version or repository commit.

Network-fetched data should be frozen before final evaluation so later API changes do not alter the reported results.

## 6. Validation

Run:

```bash
python -m jsonschema -i outputs/evidence_packs/ghost_logger.json schemas/evidencepack_v0.2.schema.json
pytest -q
```

Then verify that all four output files exist and that `ghost_logger_metrics.json` reports `EPG: 1`. Generated outputs are not committed; schema and integration tests generate their own temporary EvidencePacks so a clean checkout is sufficient.
