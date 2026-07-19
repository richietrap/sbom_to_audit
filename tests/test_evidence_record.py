from sbom_to_audit.model.evidence_record import EvidenceClaim, SourceArtifact


def test_evidence_records_are_serializable_and_traceable() -> None:
    source = SourceArtifact("a", "telemetry", "file:data/a.json", "0" * 64, "2026-01-01T00:00:00Z")
    claim = EvidenceClaim(
        "c",
        "malicious_exploitation_observed",
        True,
        source.artifact_id,
        source.source_uri,
        source.source_hash,
        source.timestamp,
        0.9,
    )
    assert source.to_dict()["artifact_id"] == "a"
    assert claim.is_traceable() is True
    assert claim.to_dict()["confidence"] == 0.9
