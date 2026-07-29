# Stage 6.1 Manual Baseline Templates

The Excel workbook is the analyst-facing form. The CSV and YAML files are the canonical
machine-readable exchange format used by the validation and import scripts.

Rules:

1. Do not view state, conflict, or clock oracles before completing the baseline.
2. Record values as observed. Leave `value` blank when evidence is unavailable; do not
   enter `unknown` merely to increase completeness.
3. Record confidence explicitly from 0.0 to 1.0. Confidence is never imputed.
4. Record each source access in `source_access_log.csv`.
5. Preserve the original completed files. The importer hashes them before normalization.
6. Export the workbook sheets to the exact CSV filenames supplied in this directory, or
   complete the CSV files directly.
