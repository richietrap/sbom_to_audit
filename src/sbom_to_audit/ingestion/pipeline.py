"""Scenario-agnostic real-format ingestion and temporal replay pipeline."""

from __future__ import annotations

import json
from copy import deepcopy
from typing import Any

from sbom_to_audit.ingestion.source_registry import SourceRegistry
from sbom_to_audit.model.authorization import (
    apply_human_authorization,
    authorization_audit_event,
    authorization_from_mapping,
    milestone_satisfaction_audit_event,
    satisfaction_evidence_from_mapping,
)
from sbom_to_audit.model.conflict_engine import active_claims, detect_conflicts
from sbom_to_audit.model.deadline_engine import (
    DeadlineMilestone,
    deadline_status_audit_event,
    evaluate_deadline_profile,
)
from sbom_to_audit.model.identity import identity_confidence
from sbom_to_audit.model.scope import assertion_applies, canonicalize_scope, validate_scope
from sbom_to_audit.model.scoring import compute_scores
from sbom_to_audit.model.state_machine import recommend_state
from sbom_to_audit.parsers.csaf_parser import product_scope_for, product_status_for
from sbom_to_audit.parsers.cyclonedx_parser import component_by_purl, dependency_path
from sbom_to_audit.parsers.epss_client import extract_percentile
from sbom_to_audit.parsers.kev_client import kev_entry
from sbom_to_audit.parsers.osv_client import cve_aliases
from sbom_to_audit.parsers.telemetry_parser import (
    execution_observed,
    malicious_exploitation_observed,
    reachability_confirmed,
)
from sbom_to_audit.utils.hashing import sha256_json
from sbom_to_audit.utils.time import delta_hours


def _claim(
    source: Any,
    *,
    suffix: str,
    proposition: str,
    value: Any,
    confidence: float,
    scope: dict[str, Any],
    timestamp: str | None = None,
    status: str = "active",
    derivation_rule: str,
) -> dict[str, Any]:
    return {
        "claim_id": f"CLAIM-{source.artifact_id}-{suffix}",
        "proposition": proposition,
        "value": value,
        "scope": validate_scope(scope),
        "source_artifact_id": source.artifact_id,
        "source_uri": source.source_uri,
        "source_hash": source.source_hash,
        "timestamp": timestamp or source.timestamp,
        "confidence": float(confidence),
        "status": status,
        "source_artifact_type": source.artifact_type,
        "derivation": {
            "parser": source.parser,
            "rule": derivation_rule,
        },
    }


def _sources_of_type(registry: SourceRegistry, released: set[str], artifact_type: str) -> list[Any]:
    items = [
        registry.parsed(artifact_id)
        for artifact_id in released
        if registry.source(artifact_id).artifact_type == artifact_type
    ]
    return sorted(items, key=lambda item: (item.source.timestamp, item.source.artifact_id))


def _latest_source(registry: SourceRegistry, released: set[str], artifact_type: str) -> Any:
    items = _sources_of_type(registry, released, artifact_type)
    if not items:
        raise ValueError(f"no released source of type {artifact_type!r}")
    return items[-1]


def _scope(
    target: dict[str, Any],
    *,
    dimensions: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "product_purl": target["product_purl"],
        "component_purl": target["component_purl"],
        "cve_id": target["cve_id"],
    }
    for key in ("product_variant", "deployment_id", "environment"):
        value = (dimensions or {}).get(key)
        if value is not None and str(value).strip():
            result[key] = str(value).strip()
    return canonicalize_scope(result)


def _target_scope(target: dict[str, Any], asset_context: dict[str, Any]) -> dict[str, Any]:
    return _scope(target, dimensions=asset_context)


def _derive_claims(
    registry: SourceRegistry,
    released: set[str],
    target: dict[str, Any],
) -> list[dict[str, Any]]:
    claims: list[dict[str, Any]] = []
    general_scope = _scope(target)
    asset_items = _sources_of_type(registry, released, "asset_context")
    asset_context = asset_items[-1].data if asset_items else {}
    assert isinstance(asset_context, dict)
    deployment_scope = _target_scope(target, asset_context)

    for artifact_id in sorted(released):
        parsed = registry.parsed(artifact_id)
        source = parsed.source
        data = parsed.data

        if source.artifact_type == "cyclonedx_sbom":
            assert isinstance(data, dict)
            component = component_by_purl(data, target["component_purl"])
            path = dependency_path(data, target["component_purl"])
            claims.append(
                _claim(
                    source,
                    suffix="COMPONENT-PRESENT",
                    proposition="component_present",
                    value=component is not None,
                    confidence=1.0,
                    scope=general_scope,
                    derivation_rule="exact_component_purl_presence",
                )
            )
            claims.append(
                _claim(
                    source,
                    suffix="TRANSITIVE-PATH",
                    proposition="transitive_dependency",
                    value=bool(path and len(path) > 2),
                    confidence=1.0,
                    scope=general_scope,
                    derivation_rule="root_to_component_dependency_path",
                )
            )
        elif source.artifact_type == "csaf_vex":
            assert isinstance(data, dict)
            status = product_status_for(
                data,
                cve_id=target["cve_id"],
                product_id=target["csaf_product_id"],
            )
            if status is None:
                raise ValueError("CSAF/VEX did not contain a target product status")
            affected_value = status in {"known_affected", "first_affected", "last_affected"}
            supplier_scope = _scope(
                target,
                dimensions=product_scope_for(data, target["csaf_product_id"]),
            )
            claims.append(
                _claim(
                    source,
                    suffix="AFFECTEDNESS",
                    proposition="product_affectedness",
                    value=affected_value,
                    confidence=0.85,
                    scope=supplier_scope,
                    derivation_rule=f"csaf_product_status:{status}",
                )
            )
        elif source.artifact_type == "osv_snapshot":
            assert isinstance(data, dict)
            aliases = cve_aliases(data)
            claims.append(
                _claim(
                    source,
                    suffix="CVE-ALIAS",
                    proposition="osv_cve_alias_match",
                    value=target["cve_id"] in aliases,
                    confidence=0.9,
                    scope=general_scope,
                    derivation_rule="osv_alias_contains_target_cve",
                )
            )
        elif source.artifact_type == "kev_snapshot":
            assert isinstance(data, dict)
            claims.append(
                _claim(
                    source,
                    suffix="KEV",
                    proposition="vulnerability_exploited_in_wild",
                    value=kev_entry(data, target["cve_id"]) is not None,
                    confidence=0.95,
                    scope=general_scope,
                    derivation_rule="cisa_kev_catalog_membership",
                )
            )
        elif source.artifact_type == "epss_snapshot":
            assert isinstance(data, dict)
            percentile = extract_percentile(data)
            claims.append(
                _claim(
                    source,
                    suffix="EPSS",
                    proposition="epss_percentile",
                    value=percentile,
                    confidence=0.9,
                    scope=general_scope,
                    derivation_rule="first_epss_record_percentile",
                )
            )
        elif source.artifact_type == "runtime_telemetry":
            assert isinstance(data, list)
            for index, record in enumerate(data, 1):
                record_scope = _scope(target, dimensions=record)
                record_timestamp = str(record.get("timestamp") or source.timestamp)
                claims.extend(
                    [
                        _claim(
                            source,
                            suffix=f"EXECUTION-{index:03d}",
                            proposition="vulnerable_function_execution",
                            value=bool(record.get("execution_observed")),
                            confidence=0.95,
                            scope=record_scope,
                            timestamp=record_timestamp,
                            derivation_rule="telemetry_execution_observed",
                        ),
                        _claim(
                            source,
                            suffix=f"REACHABILITY-{index:03d}",
                            proposition="reachability_confirmed",
                            value=bool(record.get("reachability_confirmed")),
                            confidence=0.95,
                            scope=record_scope,
                            timestamp=record_timestamp,
                            derivation_rule="telemetry_reachability_confirmed",
                        ),
                    ]
                )
                if bool(record.get("execution_observed")) or bool(
                    record.get("reachability_confirmed")
                ):
                    claims.append(
                        _claim(
                            source,
                            suffix=f"AFFECTEDNESS-{index:03d}",
                            proposition="product_affectedness",
                            value=True,
                            confidence=0.95,
                            scope=record_scope,
                            timestamp=record_timestamp,
                            derivation_rule="local_execution_or_reachability_supports_affectedness",
                        )
                    )
                if bool(record.get("malicious_exploitation_observed")):
                    claims.append(
                        _claim(
                            source,
                            suffix=f"MALICIOUS-EXPLOITATION-{index:03d}",
                            proposition="malicious_exploitation_observed",
                            value=True,
                            confidence=0.98,
                            scope=record_scope,
                            timestamp=record_timestamp,
                            derivation_rule="telemetry_malicious_exploitation_observed",
                        )
                    )
        elif source.artifact_type == "asset_context":
            assert isinstance(data, dict)
            claims.extend(
                [
                    _claim(
                        source,
                        suffix="CRITICALITY",
                        proposition="asset_criticality",
                        value=data.get("asset_criticality"),
                        confidence=0.95,
                        scope=deployment_scope,
                        derivation_rule="asset_context_field",
                    ),
                    _claim(
                        source,
                        suffix="DEPLOYMENT-SCOPE",
                        proposition="deployment_scope",
                        value=data.get("deployment_scope"),
                        confidence=0.95,
                        scope=deployment_scope,
                        derivation_rule="asset_context_field",
                    ),
                ]
            )
        elif source.artifact_type == "mitigation_context":
            assert isinstance(data, dict)
            claims.append(
                _claim(
                    source,
                    suffix="MITIGATION",
                    proposition="mitigation_status",
                    value=data.get("mitigation_status"),
                    confidence=0.95,
                    scope=general_scope,
                    derivation_rule="mitigation_context_field",
                )
            )
    return claims


def _apply_temporal_supersession(claims: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Supersede earlier observations within the same evidence class and scope.

    Sequential telemetry and mitigation updates are not treated as simultaneous
    conflicts. Cross-class contradictions, such as supplier VEX versus local
    telemetry, remain active until an explicit adjudication record resolves them.
    """

    updated = deepcopy(claims)
    temporal_types = {"runtime_telemetry", "mitigation_context", "asset_context"}
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for claim in updated:
        artifact_type = str(claim.get("source_artifact_type") or "")
        if artifact_type not in temporal_types:
            continue
        key = (
            str(claim.get("proposition") or ""),
            repr(claim.get("scope") or {}),
            artifact_type,
        )
        grouped.setdefault(key, []).append(claim)
    for group in grouped.values():
        if len(group) <= 1:
            continue
        latest = max(
            group, key=lambda item: (str(item.get("timestamp") or ""), str(item.get("claim_id")))
        )
        for claim in group:
            if claim is not latest:
                claim["status"] = "superseded"
    return updated


def _apply_conflict_resolutions(
    registry: SourceRegistry,
    released: set[str],
    claims: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    superseded_sources: set[str] = set()
    for parsed in _sources_of_type(registry, released, "conflict_resolution"):
        assert isinstance(parsed.data, dict)
        superseded_sources.update(
            str(item) for item in (parsed.data.get("supersede_source_artifact_ids") or [])
        )
    updated = deepcopy(claims)
    for claim in updated:
        if str(claim.get("source_artifact_id")) in superseded_sources:
            claim["status"] = "superseded"
    return updated


def _conflict_resolution_records(
    registry: SourceRegistry,
    released: set[str],
) -> list[dict[str, Any]]:
    """Return normalized, deterministic metadata for released resolution artefacts."""

    records: list[dict[str, Any]] = []
    for parsed in _sources_of_type(registry, released, "conflict_resolution"):
        assert isinstance(parsed.data, dict)
        records.append(
            {
                "artifact_id": parsed.source.artifact_id,
                "event_id": str(parsed.data.get("event_id") or parsed.source.artifact_id),
                "timestamp": str(parsed.data.get("timestamp") or parsed.source.timestamp),
                "supersede_source_artifact_ids": sorted(
                    str(item) for item in (parsed.data.get("supersede_source_artifact_ids") or [])
                ),
                "actor_id": str(parsed.data.get("actor_id") or ""),
                "actor_role": str(parsed.data.get("actor_role") or ""),
                "rationale": str(parsed.data.get("rationale") or ""),
            }
        )
    return records


def _matching_conflict_resolutions(
    conflict: dict[str, Any],
    resolution_records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return explicit resolution records that supersede a conflict source."""

    conflict_sources = {str(item) for item in conflict.get("sources") or [] if item}
    matches = [
        record
        for record in resolution_records
        if conflict_sources.intersection(record["supersede_source_artifact_ids"])
    ]
    return sorted(matches, key=lambda item: (item["timestamp"], item["artifact_id"]))


def _build_snapshot(
    registry: SourceRegistry,
    released: set[str],
    target: dict[str, Any],
) -> dict[str, Any]:
    sbom = _latest_source(registry, released, "cyclonedx_sbom")
    assert isinstance(sbom.data, dict)
    root = sbom.data.get("metadata_component") or {}
    component = component_by_purl(sbom.data, target["component_purl"])
    if component is None:
        raise ValueError("target component PURL is absent from the released SBOM")
    path = dependency_path(sbom.data, target["component_purl"])
    if not path:
        raise ValueError("target component is not reachable in the SBOM dependency graph")

    osv = _latest_source(registry, released, "osv_snapshot")
    kev = _latest_source(registry, released, "kev_snapshot")
    epss = _latest_source(registry, released, "epss_snapshot")
    vex = _latest_source(registry, released, "csaf_vex")
    asset = _latest_source(registry, released, "asset_context")
    mitigation = _latest_source(registry, released, "mitigation_context")
    telemetry_sources = _sources_of_type(registry, released, "runtime_telemetry")

    assert isinstance(osv.data, dict)
    assert isinstance(kev.data, dict)
    assert isinstance(epss.data, dict)
    assert isinstance(vex.data, dict)
    assert isinstance(asset.data, dict)
    assert isinstance(mitigation.data, dict)

    telemetry_records: list[dict[str, Any]] = []
    for parsed in telemetry_sources:
        assert isinstance(parsed.data, list)
        telemetry_records.extend(parsed.data)
    latest_telemetry = telemetry_sources[-1].source

    vex_status = product_status_for(
        vex.data,
        cve_id=target["cve_id"],
        product_id=target["csaf_product_id"],
    )
    if vex_status is None:
        raise ValueError("target VEX status could not be resolved")
    supplier_scope = _scope(
        target,
        dimensions=product_scope_for(vex.data, target["csaf_product_id"]),
    )
    deployed_scope = _target_scope(target, asset.data)
    vex_applies = assertion_applies(supplier_scope, deployed_scope)
    effective_vex_status = vex_status if vex_applies else "not_applicable_scope_mismatch"
    aliases = cve_aliases(osv.data)
    if target["cve_id"] not in aliases:
        raise ValueError("OSV snapshot did not bridge the component to the target CVE")
    percentile = extract_percentile(epss.data)
    if percentile is None:
        raise ValueError("EPSS snapshot did not contain a percentile")

    return {
        "product_context": {
            "product_id": root.get("name"),
            "product_version": root.get("version"),
            "purl": root.get("purl"),
            "sbom_reference": sbom.source.relative_path,
            "transitive_component_purl": target["component_purl"],
            "dependency_path": path,
        },
        "identity_resolution": {
            "primary_identifier": target["component_purl"],
            "matching_method": "exact_versioned_purl",
            "gamma_id": identity_confidence("exact_versioned_purl"),
            "selected_component": component,
            "dependency_depth": len(path) - 1,
        },
        "vulnerability_intelligence": {
            "cve_id": target["cve_id"],
            "cisa_kev_status": kev_entry(kev.data, target["cve_id"]) is not None,
            "epss_percentile": percentile,
            "osv_aliases": aliases,
            "osv_reference": osv.source.relative_path,
            "kev_reference": kev.source.relative_path,
            "epss_reference": epss.source.relative_path,
        },
        "supplier_assertions": {
            "csaf_vex_status": effective_vex_status,
            "asserted_csaf_vex_status": vex_status,
            "csaf_reference": vex.source.relative_path,
            "csaf_product_id": target["csaf_product_id"],
            "assertion_scope": supplier_scope,
            "target_scope": deployed_scope,
            "scope_applicability": "applicable" if vex_applies else "scope_mismatch",
        },
        "local_evidence": {
            "execution_observed": execution_observed(telemetry_records),
            "reachability_confirmed": reachability_confirmed(telemetry_records),
            "malicious_exploitation_observed": malicious_exploitation_observed(telemetry_records),
            "telemetry_reference": latest_telemetry.relative_path,
            "telemetry_record_count": len(telemetry_records),
        },
        "asset_context": deepcopy(asset.data),
        "mitigation_context": deepcopy(mitigation.data),
    }


def _deadline_milestones(
    profile: dict[str, Any],
) -> tuple[list[DeadlineMilestone], dict[str, bool]]:
    milestones: list[DeadlineMilestone] = []
    applicability: dict[str, bool] = {}
    for item in profile.get("milestones") or []:
        milestone = DeadlineMilestone(
            milestone_id=str(item["milestone_id"]),
            deadline_hours=float(item["deadline_hours"]),
            due_soon_lead_hours=float(item["due_soon_lead_hours"]),
            breach_imminent_lead_hours=float(item["breach_imminent_lead_hours"]),
        )
        milestones.append(milestone)
        applicability[milestone.milestone_id] = bool(item.get("applicable", False))
    return milestones, applicability


def replay_real_format_scenario(
    scenario: dict[str, Any],
    *,
    repository_root: str,
) -> dict[str, Any]:
    """Replay one source-catalog scenario and derive all evidence from files."""

    target = scenario.get("target") or {}
    required_target = {"product_purl", "component_purl", "cve_id", "csaf_product_id"}
    if not required_target.issubset(target):
        raise ValueError(f"scenario target requires: {sorted(required_target)}")
    registry = SourceRegistry(repository_root, target_cve=str(target["cve_id"]))
    catalog = scenario.get("source_catalog") or []
    if not isinstance(catalog, list) or not catalog:
        raise ValueError("real-format scenario requires a non-empty source_catalog")
    registry.register_catalog(catalog)

    source_ids = {item["artifact_id"] for item in catalog}
    t0 = scenario["case_metadata"]["clock_start_time"]
    milestones, milestone_applicability = _deadline_milestones(
        scenario.get("deadline_profile") or {}
    )

    released: set[str] = set()
    previous_state: str | None = None
    authorized_state: str | None = None
    satisfaction_evidence: dict[str, dict[str, Any]] = {}
    previous_deadline: dict[str, str | None] = {item.milestone_id: None for item in milestones}
    state_rows: list[dict[str, Any]] = []
    audit_log: list[dict[str, Any]] = []
    conflict_history: list[dict[str, Any]] = []
    active_conflict_indexes: dict[str, int] = {}
    final_claims: list[dict[str, Any]] = []
    final_snapshot: dict[str, Any] | None = None
    final_scores: dict[str, Any] | None = None
    final_deadlines: dict[str, str] = {}
    final_rationale = ""
    final_timestamp = t0

    for event in scenario.get("replay_events") or []:
        new_ids = {str(item) for item in (event.get("release_artifact_ids") or [])}
        unknown = sorted(new_ids - source_ids)
        if unknown:
            raise ValueError(f"event {event['event_id']} releases unknown sources: {unknown}")
        released.update(new_ids)

        for artifact_id in sorted(new_ids):
            source = registry.source(artifact_id)
            audit_log.append(
                {
                    "event_id": f"INGEST-{event['event_id']}-{artifact_id}",
                    "timestamp": event["timestamp"],
                    "actor": "sbom_to_audit.source_registry",
                    "action": "source_artifact_ingested",
                    "input_references": [source.source_uri],
                    "output_state": previous_state or "Monitor",
                    "artifact_id": artifact_id,
                    "source_hash": source.source_hash,
                    "validation_status": source.validation_status,
                    "parser": source.parser,
                }
            )

        claims = _derive_claims(registry, released, target)
        claims = _apply_temporal_supersession(claims)
        claims = _apply_conflict_resolutions(registry, released, claims)
        resolution_records = _conflict_resolution_records(registry, released)
        conflicts = detect_conflicts(claims)
        current_conflict_keys: set[str] = set()
        for conflict in conflicts:
            key = sha256_json(
                {
                    "proposition": conflict["proposition"],
                    "scope": conflict["scope"],
                    "claim_ids": sorted(conflict["claim_ids"]),
                }
            )
            current_conflict_keys.add(key)
            if key not in active_conflict_indexes:
                record = deepcopy(conflict)
                record["conflict_id"] = f"CONFLICT-{len(conflict_history) + 1:03d}"
                record.update(
                    {
                        "status": "active",
                        "detected_at_event_id": event["event_id"],
                        "detected_at": event["timestamp"],
                        "resolved_at_event_id": None,
                        "resolved_at": None,
                        "resolution_artifact_ids": [],
                        "resolution_event_ids": [],
                        "resolution_rationale": None,
                        "lifecycle": [
                            {
                                "status": "active",
                                "event_id": event["event_id"],
                                "timestamp": event["timestamp"],
                            }
                        ],
                    }
                )
                conflict_history.append(record)
                active_conflict_indexes[key] = len(conflict_history) - 1
                audit_log.append(
                    {
                        "event_id": (
                            f"CONFLICT-DETECTED-{event['event_id']}-{len(conflict_history):03d}"
                        ),
                        "timestamp": event["timestamp"],
                        "actor": "sbom_to_audit.conflict_engine",
                        "action": "evidence_conflict_detected",
                        "input_references": conflict["claim_ids"],
                        "output_state": "Escalate",
                        "conflict_id": record["conflict_id"],
                    }
                )

        resolved_this_event: list[dict[str, Any]] = []
        for key, index in list(active_conflict_indexes.items()):
            if key in current_conflict_keys:
                continue
            record = conflict_history[index]
            matches = _matching_conflict_resolutions(record, resolution_records)
            if matches:
                resolution_artifact_ids = [item["artifact_id"] for item in matches]
                resolution_event_ids = [item["event_id"] for item in matches]
                resolution_timestamp = matches[-1]["timestamp"]
                rationale = (
                    " | ".join(item["rationale"] for item in matches if item["rationale"])
                    or "Explicit conflict-resolution artefact superseded a conflicting source."
                )
                record.update(
                    {
                        "status": "resolved",
                        "resolved_at_event_id": event["event_id"],
                        "resolved_at": resolution_timestamp,
                        "resolution_artifact_ids": resolution_artifact_ids,
                        "resolution_event_ids": resolution_event_ids,
                        "resolution_rationale": rationale,
                    }
                )
                record["lifecycle"].append(
                    {
                        "status": "resolved",
                        "event_id": event["event_id"],
                        "timestamp": resolution_timestamp,
                        "resolution_artifact_ids": resolution_artifact_ids,
                    }
                )
                resolved_this_event.append(record)
            else:
                raise AssertionError(
                    "active conflict disappeared without an explicit registered "
                    f"resolution artefact: {record['conflict_id']}"
                )
            del active_conflict_indexes[key]

        snapshot = _build_snapshot(registry, released, target)
        score_obj = compute_scores(snapshot, conflict=bool(conflicts), claims=active_claims(claims))
        scores = score_obj.to_dict()
        event_delta = delta_hours(t0, event["timestamp"])
        recommended_state, rationale = recommend_state(scores, event_delta, previous_state)

        for resolved_conflict in resolved_this_event:
            audit_log.append(
                {
                    "event_id": (
                        f"CONFLICT-RESOLVED-{event['event_id']}-{resolved_conflict['conflict_id']}"
                    ),
                    "timestamp": resolved_conflict["resolved_at"],
                    "actor": "sbom_to_audit.conflict_engine",
                    "action": "evidence_conflict_resolved",
                    "input_references": sorted(
                        [
                            *resolved_conflict["claim_ids"],
                            *resolved_conflict["resolution_artifact_ids"],
                        ]
                    ),
                    "output_state": recommended_state,
                    "conflict_id": resolved_conflict["conflict_id"],
                    "resolution_event_ids": resolved_conflict["resolution_event_ids"],
                    "rationale": resolved_conflict["resolution_rationale"],
                }
            )

        for parsed in _sources_of_type(registry, released, "human_authorization"):
            assert isinstance(parsed.data, dict)
            auth_event = authorization_from_mapping(parsed.data)
            if (
                auth_event.timestamp <= event["timestamp"]
                and authorized_state != auth_event.authorized_state
            ):
                authorized_state = apply_human_authorization(authorized_state, auth_event)
                authorization_entry = authorization_audit_event(
                    auth_event, recommended_state=recommended_state
                )
                authorization_entry["input_references"] = [parsed.source.artifact_id]
                audit_log.append(authorization_entry)

        for parsed in _sources_of_type(registry, released, "milestone_satisfaction"):
            assert isinstance(parsed.data, dict)
            evidence = satisfaction_evidence_from_mapping(parsed.data)
            if evidence.timestamp <= event["timestamp"]:
                if evidence.milestone_id not in satisfaction_evidence:
                    satisfaction_evidence[evidence.milestone_id] = evidence.to_dict()
                    audit_log.append(
                        milestone_satisfaction_audit_event(
                            evidence,
                            output_state=recommended_state,
                        )
                    )

        deadline_results = evaluate_deadline_profile(
            milestones,
            delta_t_hours=event_delta,
            applicability=milestone_applicability,
            satisfaction_evidence=satisfaction_evidence,
        )
        deadline_posture = {key: value.status for key, value in deadline_results.items()}
        for milestone_id, result in deadline_results.items():
            if previous_deadline[milestone_id] != result.status:
                audit_log.append(
                    deadline_status_audit_event(
                        result,
                        event_id=f"DEADLINE-{event['event_id']}-{milestone_id}",
                        timestamp=event["timestamp"],
                        previous_status=previous_deadline[milestone_id],
                        output_state=recommended_state,
                        input_references=[
                            item
                            for item in (
                                result.satisfaction_evidence_id,
                                scenario["case_metadata"].get("clock_basis"),
                            )
                            if item
                        ],
                    )
                )
            previous_deadline[milestone_id] = result.status

        expected_deadline = event.get("expected_deadline_posture") or {}
        state_rows.append(
            {
                "event_id": event["event_id"],
                "timestamp": event["timestamp"],
                "delta_t_hours": event_delta,
                **scores,
                "previous_state": previous_state or "",
                "observed_state": recommended_state,
                "expected_state": event["expected_state"],
                "state_match": recommended_state == event["expected_state"],
                "authorized_state": authorized_state or "",
                "expected_authorized_state": event.get("expected_authorized_state") or "",
                "authorization_match": (authorized_state or "")
                == (event.get("expected_authorized_state") or ""),
                "deadline_posture": json.dumps(deadline_posture, sort_keys=True),
                "expected_deadline_posture": json.dumps(expected_deadline, sort_keys=True),
                "deadline_match": deadline_posture == expected_deadline,
                "released_artifact_ids": json.dumps(sorted(released)),
                "active_claim_ids": json.dumps(
                    sorted(str(claim["claim_id"]) for claim in active_claims(claims))
                ),
                "rationale": rationale,
            }
        )
        audit_log.append(
            {
                "event_id": event["event_id"],
                "timestamp": event["timestamp"],
                "actor": "sbom_to_audit.state_machine",
                "action": "evaluate_temporal_state",
                "input_references": sorted(
                    str(claim["claim_id"]) for claim in active_claims(claims)
                ),
                "input_hash": sha256_json(
                    {
                        "snapshot": snapshot,
                        "claims": active_claims(claims),
                        "delta_t_hours": event_delta,
                    }
                ),
                "output_state": recommended_state,
                "expected_state": event["expected_state"],
                "rationale": rationale,
            }
        )

        previous_state = recommended_state
        final_claims = claims
        final_snapshot = snapshot
        final_scores = scores
        final_deadlines = deadline_posture
        final_rationale = rationale
        final_timestamp = event["timestamp"]

    if final_snapshot is None or final_scores is None:
        raise ValueError("scenario must contain at least one replay event")

    active_historical_conflicts = [
        conflict for conflict in conflict_history if conflict["status"] == "active"
    ]
    if bool(active_historical_conflicts) != bool(final_scores["C_t"]):
        raise AssertionError(
            "conflict lifecycle inconsistency: final C_t must equal the presence "
            "of active conflict-history records"
        )

    final_delta = delta_hours(t0, final_timestamp)
    pack = {
        "schema_version": "0.2",
        "case_metadata": {
            "case_id": scenario["case_metadata"]["case_id"],
            "generated_at": final_timestamp,
            "clock_start_time": t0,
            "delta_t_hours": final_delta,
            "clock_basis": scenario["case_metadata"].get("clock_basis"),
        },
        **deepcopy(final_snapshot),
        "orchestration_metrics": final_scores,
        "decision_state": {
            "recommended_state": previous_state,
            "authorized_state": authorized_state,
            "human_authorization_required": True,
            "rationale": final_rationale,
            "deadline_posture": final_deadlines,
        },
        "claims": final_claims,
        "source_artifacts": [item.to_pack_dict() for item in registry.released(released)],
        "audit_log": audit_log,
    }
    return {
        "pack": pack,
        "state_rows": state_rows,
        "conflicts": conflict_history,
        "source_manifest": registry.manifest(),
        "audit_ledger": audit_log,
    }
