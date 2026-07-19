# Notebooks

Google Colab is the intended interactive runtime. Notebooks should remain thin orchestration layers that import the tested `sbom_to_audit` package rather than duplicating scoring or state logic.

A future reproduction notebook should:

1. clone or open the exact tagged repository commit;
2. install the package;
3. optionally mount Google Drive;
4. run all controlled scenarios;
5. validate EvidencePack JSON against the v0.2 schema;
6. display state trajectories and metric tables; and
7. copy immutable outputs to the selected archive location.

Do not place unreviewed logic only in a notebook.
