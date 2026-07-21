# Historical EPSS verification

This directory stores the deterministic verification contract for the
CVE-2024-3400 EPSS record dated 2024-04-15.

The source repository intentionally stores only the normalized expected row and
verification contract. The required online quality gate and Colab checkpoint
independently download and compare:

1. the date-specific FIRST API response; and
2. the official daily archive pinned to commit
   `ca26ecd7b9b806badabd6aedffdc8c4472ce6e85`.

The raw API response, complete gzip archive, extracted row, hashes and online
verification report are preserved in the Colab checkpoint evidence bundle.
Verification fails closed on a missing record, date/model mismatch or any EPSS
or percentile disagreement.
