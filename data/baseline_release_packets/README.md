# Manual Baseline Release Packets

Each scenario directory contains a manifest that preserves the event chronology and source
artefacts available to the manual-assisted baseline. The manifests contain no generated
claims, expected states, conflict labels, or artefact decisions.

Use `scripts/export_stage6_1_baseline_packets.py` to copy the appropriate files into a clean
execution directory. The analyst must receive only the released packet for the current event.
