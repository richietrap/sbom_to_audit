"""CycloneDX JSON parser for product, component, and dependency identity."""

from __future__ import annotations

from collections import deque
from pathlib import Path
from typing import Any

from sbom_to_audit.utils.io import read_json


def parse_cyclonedx(path: str | Path) -> dict[str, Any]:
    document = read_json(path)
    if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
        raise ValueError("input is not a CycloneDX JSON document")
    if not str(document.get("specVersion") or "").strip():
        raise ValueError("CycloneDX document is missing specVersion")

    components: list[dict[str, Any]] = []
    for component in document.get("components") or []:
        if not isinstance(component, dict):
            raise ValueError("CycloneDX components must be objects")
        components.append(
            {
                "bom_ref": component.get("bom-ref"),
                "type": component.get("type"),
                "group": component.get("group"),
                "name": component.get("name"),
                "version": component.get("version"),
                "purl": component.get("purl"),
                "cpe": component.get("cpe"),
            }
        )

    dependency_graph: dict[str, list[str]] = {}
    for dependency in document.get("dependencies") or []:
        if not isinstance(dependency, dict):
            raise ValueError("CycloneDX dependencies must be objects")
        reference = str(dependency.get("ref") or "").strip()
        if reference:
            dependency_graph[reference] = [
                str(item) for item in (dependency.get("dependsOn") or []) if str(item).strip()
            ]

    metadata_component = (document.get("metadata") or {}).get("component") or {}
    if not isinstance(metadata_component, dict):
        raise ValueError("CycloneDX metadata.component must be an object")
    return {
        "serial_number": document.get("serialNumber"),
        "spec_version": document.get("specVersion"),
        "metadata_timestamp": (document.get("metadata") or {}).get("timestamp"),
        "metadata_component": metadata_component,
        "components": components,
        "dependency_graph": dependency_graph,
    }


def component_by_purl(document: dict[str, Any], purl: str) -> dict[str, Any] | None:
    """Return the exact component matching a versioned PURL."""

    for component in document.get("components") or []:
        if isinstance(component, dict) and component.get("purl") == purl:
            return component
    metadata = document.get("metadata_component") or {}
    if isinstance(metadata, dict) and metadata.get("purl") == purl:
        return metadata
    return None


def component_by_name_version(
    document: dict[str, Any], name: str, version: str | None = None
) -> dict[str, Any] | None:
    """Return a unique component matching normalized name and optional version."""

    normalized_name = str(name).strip().lower().replace("_", "-")
    normalized_version = str(version).strip() if version is not None else None
    matches: list[dict[str, Any]] = []
    candidates = [*(document.get("components") or []), document.get("metadata_component") or {}]
    for component in candidates:
        if not isinstance(component, dict):
            continue
        candidate_name = str(component.get("name") or "").strip().lower().replace("_", "-")
        candidate_version = str(component.get("version") or "").strip()
        if candidate_name != normalized_name:
            continue
        if normalized_version is not None and candidate_version != normalized_version:
            continue
        matches.append(component)
    if len(matches) > 1:
        raise ValueError(f"component identity is ambiguous for name={name!r}, version={version!r}")
    return matches[0] if matches else None


def dependency_path_by_bom_ref(document: dict[str, Any], target_bom_ref: str) -> list[str] | None:
    """Find the shortest root-to-component path using a selected BOM reference."""

    metadata = document.get("metadata_component") or {}
    root_ref = str(metadata.get("bom-ref") or metadata.get("purl") or "").strip()
    target_ref = str(target_bom_ref or "").strip()
    if not root_ref or not target_ref:
        return None

    graph = document.get("dependency_graph") or {}
    queue: deque[tuple[str, list[str]]] = deque([(root_ref, [root_ref])])
    visited: set[str] = set()
    while queue:
        current, path = queue.popleft()
        if current == target_ref:
            return path
        if current in visited:
            continue
        visited.add(current)
        for child in graph.get(current, []):
            queue.append((str(child), [*path, str(child)]))
    return None


def dependency_path(document: dict[str, Any], target_purl: str) -> list[str] | None:
    """Find the shortest root-to-target dependency path using BOM references."""

    metadata = document.get("metadata_component") or {}
    root_ref = str(metadata.get("bom-ref") or metadata.get("purl") or "").strip()
    target = component_by_purl(document, target_purl)
    if target is None:
        return None
    target_ref = str(target.get("bom_ref") or target.get("purl") or "").strip()
    if not root_ref or not target_ref:
        return None

    graph = document.get("dependency_graph") or {}
    queue: deque[tuple[str, list[str]]] = deque([(root_ref, [root_ref])])
    visited: set[str] = set()
    while queue:
        current, path = queue.popleft()
        if current == target_ref:
            return path
        if current in visited:
            continue
        visited.add(current)
        for child in graph.get(current, []):
            queue.append((str(child), [*path, str(child)]))
    return None
