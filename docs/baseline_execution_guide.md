# Stage 6.1 Baseline Execution Guide

## Before execution

- Use a fresh working directory.
- Verify `evaluation/freeze/stage6_1_protocol_freeze.json`.
- Export packets with `scripts/export_stage6_1_baseline_packets.py`.
- Copy the blank CSV/YAML templates or use the Excel workbook.
- Do not open `evaluation/oracles/` or Stage 6 automated outputs.

## During execution

For every event, record the review start, every source access, observations with provenance
and confidence, conflict assessment, recommended state, rationale, authorization, clock
concern, and decision time. Do not revise earlier rows after later evidence arrives.

## After execution

Export workbook sheets to the canonical filenames, complete `declaration.yaml`, preserve an
untouched copy, then run:

```bash
python scripts/validate_manual_baseline_worksheet.py <bundle> --require-complete
python scripts/import_manual_baseline_results.py <bundle> --destination <import-dir>
python scripts/run_stage6_1_comparison.py \
  <import-dir>/normalized/stage6_1_manual_baseline_normalized.json \
  --destination <comparison-dir>
```

Candidate results remain non-final until the exact commit passes the isolated Colab checkpoint.
