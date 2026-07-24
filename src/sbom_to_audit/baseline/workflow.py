"""Deterministic structured-but-unorchestrated PSIRT worksheet replay.

The baseline shares source validation and format parsing with the artefact so the
comparison isolates the orchestration layer rather than parser quality. It does
not build normalized claims, calculate E/A/I/M/U/C, use the scope-overlap engine,
retain a conflict lifecycle, or apply the 18-hour automatic escalation safeguard.
"""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from sbom_to_audit.baseline.protocol import BaselineProtocol
from sbom_to_audit.ingestion.source_registry import SourceRegistry
from sbom_to_audit.model.deadline_engine import (
    DeadlineMilestone,
    evaluate_deadline_profile,
)
from sbom_to_audit.model.metrics import (
    MANDATORY_FIELDS,
    audit_reconstructability,
    clock_aware_escalation,
    conflict_detection,
    evidence_completeness,
    state_correctness,
)
from sbom_to_audit.parsers.csaf_parser import product_status_for
from sbom_to_audit.parsers.cyclonedx_parser import (
    component_by_name_version,
    component_by_purl,
    dependency_path,
    dependency_path_by_bom_ref,
)
from sbom_to_audit.parsers.epss_client import extract_percentile
from sbom_to_audit.parsers.kev_client import kev_entry
from sbom_to_audit.parsers.nvd_client import extract_cvss_metrics
from sbom_to_audit.parsers.osv_client import cve_aliases
from sbom_to_audit.parsers.telemetry_parser import (
    execution_observed,
    malicious_exploitation_observed,
    reachability_confirmed,
)
from sbom_to_audit.utils.time import delta_hours

BASELINE_STATE_FIELDS: tuple[str, ...] = (
    "event_id",
    "timestamp",
    "delta_t_hours",
    "previous_state",
    "observed_state",
    "expected_state",
    "state_match",
    "authorized_state",
    "expected_authorized_state",
    "authorization_match",
    "deadline_posture",
    "expected_deadline_posture",
    "deadline_match",
    "supplier_status",
    "kev_status",
    "epss_percentile",
    "execution_observed",
    "reachability_confirmed",
    "malicious_exploitation_observed",
    "asset_criticality",
    "deployment_scope",
    "conflict_flag",
    "released_artifact_ids",
    "reviewed_artifact_count",
    "rationale",
)

BASELINE_SOURCE_FIELDS: tuple[str, ...] = (
    "artifact_id",
    "artifact_type",
    "source_uri",
    "source_hash",
    "timestamp",
    "parser",
    "validation_status",
    "first_reviewed_event_id",
)


_NOT_AFFECTED_DEFAULTS = {"known_not_affected", "first_fixed", "fixed"}


def _sources_of_type(
    registry: SourceRegistry,
    released: set[str],
    artifact_type: str,
) -> list[Any]:
    parsed = [
        registry.parsed(artifact_id)
        for artifact_id in released
        if registry.source(artifact_id).artifact_type == artifact_type
    ]
    return sorted(parsed, key=lambda item: (item.source.timestamp, item.source.artifact_id))


def _latest(
    registry: SourceRegistry,
    released: set[str],
    artifact_type: str,
) -> Any | None:
    items = _sources_of_type(registry, released, artifact_type)
    return items[-1] if items else None


def _identity_snapshot(sbom_data: dict[str, Any], target: dict[str, Any]) -> dict[str, Any]:
    selected = component_by_purl(sbom_data, str(target["component_purl"]))
    method = "exact_versioned_purl"
    if selected is None:
        name = str(target.get("component_name") or "").strip()
        version = str(target.get("component_version") or "").strip() or None
        if not name:
            raise ValueError("baseline could not locate target component in SBOM")
        selected = component_by_name_version(sbom_data, name, version)
        method = "name_version_lookup" if version else "name_lookup"
    if selected is None:
        raise ValueError("baseline could not locate target component in SBOM")
    bom_ref = str(selected.get("bom_ref") or selected.get("purl") or "")
    path = dependency_path_by_bom_ref(sbom_data, bom_ref)
    if path is None and selected.get("purl"):
        path = dependency_path(sbom_data, str(selected["purl"]))
    return {
        "selected_component": selected,
        "matching_method": method,
        "dependency_path": path or [],
    }


def _deadline_configuration(
    scenario: dict[str, Any],
) -> tuple[list[DeadlineMilestone], dict[str, bool]]:
    milestones: list[DeadlineMilestone] = []
    applicability: dict[str, bool] = {}
    for item in (scenario.get("deadline_profile") or {}).get("milestones") or []:
        milestone = DeadlineMilestone(
            milestone_id=str(item["milestone_id"]),
            deadline_hours=float(item["deadline_hours"]),
            due_soon_lead_hours=float(item["due_soon_lead_hours"]),
            breach_imminent_lead_hours=float(item["breach_imminent_lead_hours"]),
        )
        milestones.append(milestone)
        applicability[milestone.milestone_id] = bool(item.get("applicable", False))
    return milestones, applicability


def _observation_snapshot(
    registry: SourceRegistry,
    released: set[str],
    target: dict[str, Any],
) -> dict[str, Any]:
    sbom = _latest(registry, released, "cyclonedx_sbom")
    if sbom is None or not isinstance(sbom.data, dict):
        raise ValueError("baseline requires a released CycloneDX SBOM")
    identity = _identity_snapshot(sbom.data, target)
    root_component = sbom.data.get("metadata_component") or {}

    osv = _latest(registry, released, "osv_snapshot")
    kev = _latest(registry, released, "kev_snapshot")
    epss = _latest(registry, released, "epss_snapshot")
    nvd = _latest(registry, released, "nvd_snapshot")
    vex = _latest(registry, released, "csaf_vex")
    public_exploit = _latest(registry, released, "public_exploitation_report")
    asset = _latest(registry, released, "asset_context")
    mitigation = _latest(registry, released, "mitigation_context")

    telemetry_sources = _sources_of_type(registry, released, "runtime_telemetry")
    telemetry_records: list[dict[str, Any]] = []
    for source in telemetry_sources:
        if not isinstance(source.data, list):
            raise ValueError("runtime telemetry must contain a list of records")
        telemetry_records.extend(source.data)

    supplier_status: str | None = None
    if vex is not None:
        if not isinstance(vex.data, dict):
            raise ValueError("CSAF/VEX parser output must be an object")
        supplier_status = product_status_for(
            vex.data,
            cve_id=str(target["cve_id"]),
            product_id=str(target["csaf_product_id"]),
        )

    kev_status: bool | None = None
    if kev is not None:
        if not isinstance(kev.data, dict):
            raise ValueError("KEV parser output must be an object")
        kev_status = kev_entry(kev.data, str(target["cve_id"])) is not None

    epss_percentile: float | None = None
    if epss is not None:
        if not isinstance(epss.data, dict):
            raise ValueError("EPSS parser output must be an object")
        epss_percentile = extract_percentile(epss.data)

    aliases: list[str] = []
    if osv is not None:
        if not isinstance(osv.data, dict):
            raise ValueError("OSV parser output must be an object")
        aliases = cve_aliases(osv.data)

    cvss: dict[str, Any] | None = None
    if nvd is not None:
        if not isinstance(nvd.data, dict):
            raise ValueError("NVD parser output must be an object")
        cvss = extract_cvss_metrics(nvd.data, str(target["cve_id"]))

    asset_data = deepcopy(asset.data) if asset is not None else {}
    mitigation_data = deepcopy(mitigation.data) if mitigation is not None else {}
    if not isinstance(asset_data, dict) or not isinstance(mitigation_data, dict):
        raise ValueError("asset and mitigation records must be objects")

    public_exploitation_observed: bool | None = None
    if public_exploit is not None:
        if not isinstance(public_exploit.data, dict):
            raise ValueError("public exploitation report must be an object")
        public_exploitation_observed = bool(
            public_exploit.data.get("malicious_exploitation_observed")
        )

    return {
        "product_id": root_component.get("name"),
        "product_version": root_component.get("version"),
        "product_purl": root_component.get("purl"),
        "sbom_reference": sbom.source.relative_path,
        "component_purl": target["component_purl"],
        "matching_method": identity["matching_method"],
        "dependency_path": identity["dependency_path"],
        "cve_id": target["cve_id"],
        "osv_alias_match": target["cve_id"] in aliases,
        "kev_status": kev_status,
        "epss_percentile": epss_percentile,
        "cvss": cvss,
        "supplier_status": supplier_status,
        "csaf_reference": vex.source.relative_path if vex is not None else None,
        "telemetry_present": bool(telemetry_sources),
        "execution_observed": execution_observed(telemetry_records) if telemetry_sources else None,
        "reachability_confirmed": (
            reachability_confirmed(telemetry_records) if telemetry_sources else None
        ),
        "malicious_exploitation_observed": (
            malicious_exploitation_observed(telemetry_records) if telemetry_sources else None
        ),
        "telemetry_reference": (
            telemetry_sources[-1].source.relative_path if telemetry_sources else None
        ),
        "public_exploitation_observed": public_exploitation_observed,
        "asset_context": asset_data,
        "mitigation_context": mitigation_data,
        "identity_resolution_present": bool(
            _sources_of_type(registry, released, "identity_resolution")
        ),
        "conflict_resolution_present": bool(
            _sources_of_type(registry, released, "conflict_resolution")
        ),
    }


def _high_impact(snapshot: dict[str, Any], protocol: BaselineProtocol) -> bool:
    asset = snapshot.get("asset_context") or {}
    criticality = str(asset.get("asset_criticality") or "").lower()
    deployment_scope = str(asset.get("deployment_scope") or "").lower()
    if criticality == "critical":
        return True
    return criticality in {
        value.lower() for value in protocol.high_impact_criticalities
    } and deployment_scope in {value.lower() for value in protocol.broad_deployment_scopes}


def _review_decision(
    snapshot: dict[str, Any],
    protocol: BaselineProtocol,
) -> tuple[str, bool, str]:
    """Apply the frozen worksheet rules without orchestration scores or scope reasoning."""

    supplier_status = str(snapshot.get("supplier_status") or "")
    not_affected = supplier_status in (set(protocol.not_affected_statuses) | _NOT_AFFECTED_DEFAULTS)
    local_positive = bool(snapshot.get("execution_observed")) or bool(
        snapshot.get("reachability_confirmed")
    )
    exploitation_signal = bool(snapshot.get("kev_status")) or bool(
        snapshot.get("public_exploitation_observed")
    )
    conflict = not_affected and local_positive
    if snapshot.get("conflict_resolution_present"):
        conflict = False

    if conflict:
        return (
            "Escalate",
            True,
            "The worksheet records a direct supplier-versus-local contradiction but does not "
            "evaluate product-variant scope.",
        )
    if bool(snapshot.get("malicious_exploitation_observed")):
        return (
            "Report-Ready",
            False,
            "Organisation-local malicious exploitation is recorded in the worksheet.",
        )
    if local_positive and exploitation_signal and _high_impact(snapshot, protocol):
        return (
            "Report-Ready",
            False,
            "Local applicability, exploitation intelligence, and high operational context are "
            "all present in the worksheet.",
        )
    if not_affected and not local_positive:
        return (
            "Document No-Report",
            False,
            "The supplier records a not-affected or fixed status and no positive local runtime "
            "evidence is present; assertion scope is not independently adjudicated.",
        )
    incomplete_review = (
        not snapshot.get("telemetry_present")
        or snapshot.get("supplier_status") is None
        or snapshot.get("matching_method") in {"name_lookup", "name_version_lookup"}
    )
    if exploitation_signal and incomplete_review:
        return (
            "Prepare",
            False,
            "Exploitation intelligence is present, but the worksheet still lacks one or more "
            "supplier, runtime, or exact-identity inputs.",
        )
    return (
        "Monitor",
        False,
        "The worksheet does not meet its configured report-ready or no-report conditions.",
    )


def _fact_rows(
    registry: SourceRegistry,
    released: set[str],
    event_id: str,
    snapshot: dict[str, Any],
) -> list[dict[str, Any]]:
    facts: list[tuple[str, Any, str | None]] = [
        ("component_present", bool(snapshot.get("dependency_path")), "cyclonedx_sbom"),
        ("kev_status", snapshot.get("kev_status"), "kev_snapshot"),
        ("epss_percentile", snapshot.get("epss_percentile"), "epss_snapshot"),
        ("supplier_status", snapshot.get("supplier_status"), "csaf_vex"),
        ("execution_observed", snapshot.get("execution_observed"), "runtime_telemetry"),
        ("reachability_confirmed", snapshot.get("reachability_confirmed"), "runtime_telemetry"),
        (
            "asset_criticality",
            (snapshot.get("asset_context") or {}).get("asset_criticality"),
            "asset_context",
        ),
        (
            "deployment_scope",
            (snapshot.get("asset_context") or {}).get("deployment_scope"),
            "asset_context",
        ),
        (
            "mitigation_status",
            (snapshot.get("mitigation_context") or {}).get("mitigation_status"),
            "mitigation_context",
        ),
    ]
    rows: list[dict[str, Any]] = []
    for proposition, value, artifact_type in facts:
        sources = _sources_of_type(registry, released, str(artifact_type)) if artifact_type else []
        source = sources[-1].source if sources else None
        rows.append(
            {
                "observation_id": f"BASE-{event_id}-{proposition}",
                "event_id": event_id,
                "proposition": proposition,
                "value": value,
                "source_artifact_id": source.artifact_id if source else None,
                "source_uri": source.source_uri if source else None,
                "source_hash": source.source_hash if source else None,
                "timestamp": source.timestamp if source else None,
                "confidence": None,
            }
        )
    return rows


def _partial_traceability(observations: list[dict[str, Any]]) -> float:
    if not observations:
        return 0.0
    fields = ("source_artifact_id", "source_uri", "source_hash", "timestamp", "confidence")
    populated = 0
    total = len(observations) * len(fields)
    for observation in observations:
        populated += sum(
            observation.get(field) is not None and str(observation.get(field)).strip() != ""
            for field in fields
        )
    return round(populated / total, 6)


def _strict_traceability(observations: list[dict[str, Any]]) -> float:
    if not observations:
        return 0.0
    fields = ("source_artifact_id", "source_uri", "source_hash", "timestamp", "confidence")
    complete = sum(
        all(
            observation.get(field) is not None and str(observation.get(field)).strip() != ""
            for field in fields
        )
        for observation in observations
    )
    return round(complete / len(observations), 6)


def _baseline_case_record(
    scenario: dict[str, Any],
    snapshot: dict[str, Any],
    final_row: dict[str, Any],
    sources: list[dict[str, Any]],
    audit_log: list[dict[str, Any]],
) -> dict[str, Any]:
    asset = snapshot.get("asset_context") or {}
    mitigation = snapshot.get("mitigation_context") or {}
    return {
        "record_type": "structured_unorchestrated_psirt_worksheet",
        "schema_version": "baseline-0.1",
        "case_metadata": {
            "case_id": scenario["case_metadata"]["case_id"],
            "generated_at": final_row["timestamp"],
            "clock_start_time": scenario["case_metadata"]["clock_start_time"],
            "delta_t_hours": final_row["delta_t_hours"],
        },
        "product_context": {
            "product_id": snapshot.get("product_id"),
            "product_version": snapshot.get("product_version"),
            "purl": snapshot.get("product_purl"),
            "sbom_reference": snapshot.get("sbom_reference"),
        },
        "identity_resolution": {
            "primary_identifier": snapshot.get("component_purl"),
            "matching_method": snapshot.get("matching_method"),
            "gamma_id": None,
        },
        "vulnerability_intelligence": {
            "cve_id": snapshot.get("cve_id"),
            "cisa_kev_status": snapshot.get("kev_status"),
            "epss_percentile": snapshot.get("epss_percentile"),
        },
        "supplier_assertions": {
            "csaf_vex_status": snapshot.get("supplier_status"),
            "csaf_reference": snapshot.get("csaf_reference"),
        },
        "local_evidence": {
            "execution_observed": snapshot.get("execution_observed"),
            "reachability_confirmed": snapshot.get("reachability_confirmed"),
            "telemetry_reference": snapshot.get("telemetry_reference"),
        },
        "asset_context": {
            "asset_criticality": asset.get("asset_criticality"),
            "deployment_scope": asset.get("deployment_scope"),
        },
        "mitigation_context": {
            "mitigation_status": mitigation.get("mitigation_status"),
        },
        "orchestration_metrics": {
            "E_t": None,
            "A_t": None,
            "I_t": None,
            "M_t": None,
            "U_t": None,
            "C_t": None,
        },
        "decision_state": {
            "recommended_state": final_row["observed_state"],
            "human_authorization_required": final_row["observed_state"] == "Report-Ready",
            "rationale": final_row["rationale"],
        },
        "claims": [],
        "source_artifacts": sources,
        "audit_log": audit_log,
    }


def run_baseline_scenario(
    scenario: dict[str, Any],
    *,
    repository_root: str | Path,
    protocol: BaselineProtocol,
) -> dict[str, Any]:
    """Replay one scenario through the frozen structured worksheet baseline."""

    scenario_id = str((scenario.get("scenario") or {}).get("scenario_id") or "")
    if scenario_id not in protocol.scenario_ids:
        raise ValueError(f"scenario {scenario_id!r} is not in the baseline protocol")
    target = scenario.get("target") or {}
    registry = SourceRegistry(repository_root, target_cve=str(target["cve_id"]))
    catalog = scenario.get("source_catalog") or []
    registry.register_catalog(catalog)
    source_ids = {str(item["artifact_id"]) for item in catalog}
    milestones, applicability = _deadline_configuration(scenario)

    released: set[str] = set()
    first_reviewed: dict[str, str] = {}
    previous_state: str | None = None
    authorized_state: str | None = None
    satisfaction: dict[str, dict[str, Any]] = {}
    decision_rows: list[dict[str, Any]] = []
    audit_log: list[dict[str, Any]] = []
    observation_rows: list[dict[str, Any]] = []
    conflict_episodes = 0
    previous_conflict = False
    cumulative_source_reviews = 0
    final_snapshot: dict[str, Any] | None = None

    for event in scenario.get("replay_events") or []:
        event_id = str(event["event_id"])
        new_ids = {str(item) for item in (event.get("release_artifact_ids") or [])}
        unknown = new_ids - source_ids
        if unknown:
            raise ValueError(f"baseline event releases unknown sources: {sorted(unknown)}")
        released.update(new_ids)
        for artifact_id in sorted(new_ids):
            first_reviewed.setdefault(artifact_id, event_id)
            parsed = registry.parsed(artifact_id)
            if parsed.source.artifact_type == "human_authorization":
                if not isinstance(parsed.data, dict):
                    raise ValueError("human authorization record must be an object")
                authorized_state = str(parsed.data.get("authorized_state") or "") or None
            if parsed.source.artifact_type == "milestone_satisfaction":
                if not isinstance(parsed.data, dict):
                    raise ValueError("milestone satisfaction record must be an object")
                milestone_id = str(parsed.data.get("milestone_id") or "")
                satisfaction[milestone_id] = parsed.data

        snapshot = _observation_snapshot(registry, released, target)
        observed_state, conflict_flag, rationale = _review_decision(snapshot, protocol)
        if conflict_flag and not previous_conflict:
            conflict_episodes += 1
        previous_conflict = conflict_flag
        delta_t = delta_hours(
            str(scenario["case_metadata"]["clock_start_time"]),
            str(event["timestamp"]),
        )
        deadlines = evaluate_deadline_profile(
            milestones,
            delta_t_hours=delta_t,
            applicability=applicability,
            satisfaction_evidence=satisfaction,
        )
        deadline_posture = {key: value.status for key, value in deadlines.items()}
        expected_deadline = event.get("expected_deadline_posture") or {}
        cumulative_source_reviews += len(released)
        row = {
            "event_id": event_id,
            "timestamp": event["timestamp"],
            "delta_t_hours": delta_t,
            "previous_state": previous_state,
            "observed_state": observed_state,
            "expected_state": event.get("expected_state"),
            "state_match": observed_state == event.get("expected_state"),
            "authorized_state": authorized_state,
            "expected_authorized_state": event.get("expected_authorized_state"),
            "authorization_match": authorized_state == event.get("expected_authorized_state"),
            "deadline_posture": deadline_posture,
            "expected_deadline_posture": expected_deadline,
            "deadline_match": deadline_posture == expected_deadline,
            "supplier_status": snapshot.get("supplier_status"),
            "kev_status": snapshot.get("kev_status"),
            "epss_percentile": snapshot.get("epss_percentile"),
            "execution_observed": snapshot.get("execution_observed"),
            "reachability_confirmed": snapshot.get("reachability_confirmed"),
            "malicious_exploitation_observed": snapshot.get("malicious_exploitation_observed"),
            "asset_criticality": (snapshot.get("asset_context") or {}).get("asset_criticality"),
            "deployment_scope": (snapshot.get("asset_context") or {}).get("deployment_scope"),
            "conflict_flag": conflict_flag,
            "released_artifact_ids": sorted(new_ids),
            "reviewed_artifact_count": len(released),
            "rationale": rationale,
        }
        decision_rows.append(row)
        observation_rows.extend(_fact_rows(registry, released, event_id, snapshot))
        audit_log.append(
            {
                "event_id": f"BASELINE-REVIEW-{event_id}",
                "timestamp": event["timestamp"],
                "actor": "psirt_reviewer:structured_worksheet",
                "action": "unorchestrated_case_review",
                "input_references": sorted(released),
                "output_state": observed_state,
                "rationale": rationale,
            }
        )
        previous_state = observed_state
        final_snapshot = snapshot

    if final_snapshot is None or not decision_rows:
        raise ValueError("baseline scenario has no replay events")
    source_rows = []
    for source in registry.manifest()["sources"]:
        source_rows.append(
            {
                "artifact_id": source["artifact_id"],
                "artifact_type": source["artifact_type"],
                "source_uri": source["source_uri"],
                "source_hash": source["source_hash"],
                "timestamp": source["timestamp"],
                "parser": source["parser"],
                "validation_status": source["validation_status"],
                "first_reviewed_event_id": first_reviewed.get(source["artifact_id"]),
            }
        )
    case_record = _baseline_case_record(
        scenario,
        final_snapshot,
        decision_rows[-1],
        source_rows,
        audit_log,
    )
    safeguard_hours = 18.0
    clock_opportunities = [
        row
        for row in decision_rows
        if row.get("previous_state") == "Prepare" and float(row["delta_t_hours"]) >= safeguard_hours
    ]
    strict_tr = _strict_traceability(observation_rows)
    baseline_metrics = {
        "scenario_id": scenario_id,
        "baseline_protocol_version": protocol.protocol_version,
        "baseline_protocol_id": protocol.protocol_id,
        "evaluation_status": "PILOT_BASELINE",
        "EC": evidence_completeness(case_record),
        "TR": strict_tr,
        "CD": conflict_detection(
            conflict_episodes,
            int((scenario.get("scenario") or {}).get("seeded_conflicts", 0)),
        ),
        "CA": clock_aware_escalation(clock_opportunities),
        "CA_status": "not_applicable" if not clock_opportunities else "applicable",
        "AR": audit_reconstructability(audit_log),
        "SC": state_correctness(decision_rows),
        "EPG": 0,
        "supplemental": {
            "partial_traceability_ratio": _partial_traceability(observation_rows),
            "observation_count": len(observation_rows),
            "decision_event_count": len(decision_rows),
            "conflict_episode_count": conflict_episodes,
            "false_positive_conflict_count": (
                conflict_episodes
                if int((scenario.get("scenario") or {}).get("seeded_conflicts", 0)) == 0
                else 0
            ),
            "clock_safeguard_opportunities": len(clock_opportunities),
            "clock_safeguard_triggers": sum(
                row["observed_state"] == "Escalate" for row in clock_opportunities
            ),
            "cumulative_source_review_count": cumulative_source_reviews,
            "unique_source_count": len(source_rows),
            "authorization_correctness": round(
                sum(bool(row["authorization_match"]) for row in decision_rows) / len(decision_rows),
                6,
            ),
            "deadline_posture_correctness": round(
                sum(bool(row["deadline_match"]) for row in decision_rows) / len(decision_rows),
                6,
            ),
            "mandatory_field_denominator": len(MANDATORY_FIELDS),
        },
        "limitations": list(protocol.limitations),
    }
    return {
        "case_record": case_record,
        "source_rows": source_rows,
        "decision_rows": decision_rows,
        "observation_rows": observation_rows,
        "audit_log": audit_log,
        "metrics": baseline_metrics,
    }
