# Stage 6.1.5 Colab checkpoint correction report

## Correction boundary

Stage 6.1.5 corrects the Stage 6.1.4 checkpoint's use of the shared Colab kernel environment. The
observed `pip check` failure arose after `.[dev]` was installed into that shared environment, so
`pip check` assessed both project dependencies and unrelated packages preinstalled by Colab.

No manual baseline was imported, no Stage 6.1 comparison was accepted, and no manuscript-eligible
result existed when the failure occurred.

## Notebook-wide audit

The complete checkpoint was reviewed rather than patching the failing cell alone. The audit found
and corrected these risks:

- project installation and `pip check` used the global kernel interpreter;
- later validation, test, replay, and export commands also used global `python`;
- the reference placeholder failed before offering an interactive configuration path;
- a relative manual-result ZIP path could change meaning after the notebook changed directory;
- manual ZIP extraction did not explicitly reject traversal or symbolic links;
- stale optional-output directories were not uniformly cleared;
- command failures did not preserve named, complete stdout/stderr logs for every retry;
- the final evidence bundle did not include a checksum inventory for its contents;
- notebook code cells were not compiled and contract-checked as a release gate;
- online historical EPSS verification was absent from the Stage 6.1.4 checkpoint.

## Stage 6.1.5 controls

The replacement notebook:

- requires an exact 40-character commit SHA and verifies detached checkout equality;
- creates `/content/sbom_to_audit_stage615_venv`;
- installs and checks `.[dev]` only inside that environment;
- executes the canonical release checker and verifies its required check inventory;
- retains online dual-source historical EPSS verification and verified replay generation;
- verifies packet count against the frozen state-oracle event universe;
- safely extracts an optional manual-result ZIP and rejects traversal, duplicate paths, symbolic links, encrypted members, special files, and oversized archives;
- preserves every command-attempt log, frozen controls, packet outputs, release evidence and checksums;
- verifies the generated ZIP before presenting it;
- is statically validated by `scripts/validate_stage6_1_colab_notebook.py` and regression tests.
- includes negative validator tests proving that global `pip check` and syntactically invalid code cells are rejected.

The negative pre-release tests exposed and corrected BUG-023: canonical notebook JSON may store a cell source as a list of lines, so the validator now normalises both list and string representations before compilation or scanning.

A second pre-release negative test exposed and corrected BUG-024: ZIP entries written by some tools may carry permission bits without a Unix file-type bit. The initial special-file check treated those ordinary files as unsupported. The corrected logic isolates the file-type bits with `stat.S_IFMT`, accepts type `0` as well as regular files and directories, and still rejects links and special files.

A final adversarial archive review exposed and corrected BUG-025 before packaging. Raw ZIP names can map to the same normalized destination or create file-parent collisions even when traversal is rejected. Stage 6.1.5 now rejects non-canonical and duplicate normalized paths, backslash paths, file/directory collisions, corrupt members, and existing destinations. It no longer calls bulk extraction: each validated regular file is written exclusively in bounded chunks, with the extraction-size limit enforced again while streaming.

The same full-notebook review exposed BUG-026: packet export was checked for event count and manifest presence but the checkpoint did not independently validate registry hashes, copied source hashes, manifest identity, path containment, or forbidden oracle keys. Stage 6.1.5 now verifies all of those boundaries and includes notebook-derived tampering, traversal, and blinding regression tests.

## Preserved research boundary

Stage 6.1.5 does not alter:

- `evaluation/baseline_protocol_v0.2.yaml`;
- the Stage 6.1 freeze record;
- state, conflict, or clock-opportunity oracle values;
- fairness mappings;
- scenarios or source artefacts;
- EvidencePack Schema v0.2 or its 34 mandatory fields;
- EC, TR, CD, CA, AR, SC, or EPG.

## Acceptance boundary

Stage 6.1.5 remains a corrective candidate until all GitHub jobs pass and the exact successful
commit completes the replacement Colab notebook with checkpoint status `PASS`. The resulting ZIP
and SHA-256 must be preserved before manual execution proceeds.
