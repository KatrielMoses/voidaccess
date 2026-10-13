"""
api/routes/export.py — Export endpoints for STIX, MISP, Sigma, YARA, Snort,
                       Suricata, and the full IOC package.

GET  /export/{investigation_id}/stix                       — STIX 2.1 bundle (JSON)
GET  /export/{investigation_id}/misp                       — MISP event (JSON)
GET  /export/{investigation_id}/sigma                      — Sigma rules (ZIP)
GET  /export/{investigation_id}/yara                       — YARA rules (.yar)
GET  /export/{investigation_id}/snort?format=snort|suricata — Snort/Suricata rules
GET  /export/{investigation_id}/package                    — full IOC package (ZIP)

POST /export/{investigation_id}/<fmt>/selected             — same exports restricted
                                                            to a chosen entity subset
"""

from __future__ import annotations

import io
import json
import logging
import os
import re
import uuid
import zipfile

from api.ownership import require_resource_owner
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, Field
from api.auth import CurrentUser, get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(dependencies=[Depends(require_resource_owner)])


class ExportSelectedBody(BaseModel):
    """Subset of entity primary keys to include in an export bundle."""

    entity_ids: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Auth helper
# ---------------------------------------------------------------------------


def _check_investigation_owner(investigation_id: str, current_user: CurrentUser) -> None:
    """Raise 404 if the investigation does not exist, 403 if the user does not own it."""
    try:
        uid = uuid.UUID(investigation_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid investigation ID format")
    if not os.getenv("DATABASE_URL"):
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        from db.session import get_session
        from db.queries import get_investigation_by_id_or_run
        with get_session() as session:
            inv = get_investigation_by_id_or_run(session, uid)
            if inv is None:
                raise HTTPException(status_code=404, detail="Investigation not found")
            if str(inv.user_id) != str(current_user.user.id):
                raise HTTPException(status_code=404, detail="Not found")
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("_check_investigation_owner failed: %s", exc)
        raise HTTPException(status_code=500, detail="Internal error")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/{investigation_id}/stix")
async def export_stix(
    investigation_id: str,
    current_user: CurrentUser = Depends(get_current_user),
) -> Response:
    """
    Return STIX 2.1 bundle as JSON download.

    Content-Type: application/json
    Content-Disposition: attachment; filename="voidaccess_{id}_stix.json"
    """
    _check_investigation_owner(investigation_id, current_user)
    _validate_uuid(investigation_id)
    try:
        from export.stix import investigation_to_stix_bundle, bundle_to_json, _load_entities_for_investigation  # noqa: PLC0415

        internal_id = _resolve_internal_investigation_id(investigation_id)
        entities = _load_entities_for_investigation(str(internal_id))
        if not entities:
            raise HTTPException(
                status_code=422,
                detail=(
                    "No exportable entities found for this investigation. "
                    "Ensure the investigation has completed successfully."
                ),
            )
        bundle = investigation_to_stix_bundle(str(internal_id))
        json_str = bundle_to_json(bundle)
        filename = f"voidaccess_{investigation_id}_stix.json"
        return Response(
            content=json_str,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("export_stix failed: %s", exc)
        raise HTTPException(status_code=500, detail="STIX export failed")


@router.get("/{investigation_id}/misp")
async def export_misp(
    investigation_id: str,
    current_user: CurrentUser = Depends(get_current_user),
) -> Response:
    """
    Return MISP event as JSON download.

    Content-Type: application/json
    Content-Disposition: attachment; filename="voidaccess_{id}_misp.json"
    """
    _check_investigation_owner(investigation_id, current_user)
    _validate_uuid(investigation_id)
    try:
        from export.misp import investigation_to_misp_event, misp_event_to_json  # noqa: PLC0415
        from export.stix import _load_entities_for_investigation  # noqa: PLC0415

        internal_id = _resolve_internal_investigation_id(investigation_id)
        entities = _load_entities_for_investigation(str(internal_id))
        if not entities:
            raise HTTPException(
                status_code=422,
                detail=(
                    "No exportable entities found for this investigation. "
                    "Ensure the investigation has completed successfully."
                ),
            )
        event = investigation_to_misp_event(str(internal_id))
        json_str = misp_event_to_json(event)
        filename = f"voidaccess_{investigation_id}_misp.json"
        return Response(
            content=json_str,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("export_misp failed: %s", exc)
        raise HTTPException(status_code=500, detail="MISP export failed")


@router.get("/{investigation_id}/sigma")
async def export_sigma(
    investigation_id: str,
    current_user: CurrentUser = Depends(get_current_user),
) -> StreamingResponse:
    """
    Generate Sigma rules and return as a ZIP download.

    Content-Type: application/zip
    Content-Disposition: attachment; filename="voidaccess_{id}_sigma.zip"
    """
    _check_investigation_owner(investigation_id, current_user)
    _validate_uuid(investigation_id)
    try:
        from export.sigma import (  # noqa: PLC0415
            entities_to_sigma_rules,
            sigma_rule_to_yaml,
        )
        from export.stix import _load_entities_for_investigation  # noqa: PLC0415

        internal_id = _resolve_internal_investigation_id(investigation_id)
        entities = _load_entities_for_investigation(str(internal_id))
        if not entities:
            raise HTTPException(
                status_code=422,
                detail=(
                    "No exportable entities found for this investigation. "
                    "Ensure the investigation has completed successfully."
                ),
            )
        rules = entities_to_sigma_rules(entities)
        if not rules:
            raise HTTPException(
                status_code=422,
                detail=(
                    "No Sigma-compatible entities found (requires IP_ADDRESS, "
                    "ONION_URL, CVE_NUMBER, MALWARE_FAMILY, or RANSOMWARE_GROUP)."
                ),
            )

        # Build zip in memory
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            for rule in rules:
                rule_id = rule.get("id", str(uuid.uuid4()))
                yaml_content = sigma_rule_to_yaml(rule)
                zf.writestr(f"{rule_id}.yml", yaml_content)
        buf.seek(0)

        filename = f"voidaccess_{investigation_id}_sigma.zip"
        return StreamingResponse(
            buf,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("export_sigma failed: %s", exc)
        raise HTTPException(status_code=500, detail="Sigma export failed")


@router.post("/{investigation_id}/stix/selected")
async def export_stix_selected(
    investigation_id: str,
    body: ExportSelectedBody,
    current_user: CurrentUser = Depends(get_current_user),
) -> Response:
    """STIX bundle including only the given entity rows (or all if *entity_ids* is empty)."""
    _check_investigation_owner(investigation_id, current_user)
    _validate_uuid(investigation_id)
    try:
        from export.stix import investigation_to_stix_bundle, bundle_to_json  # noqa: PLC0415

        internal_id = _resolve_internal_investigation_id(investigation_id)
        bundle = investigation_to_stix_bundle(
            str(internal_id),
            entity_ids=body.entity_ids or None,
        )
        json_str = bundle_to_json(bundle)
        filename = f"voidaccess_{investigation_id}_stix.json"
        return Response(
            content=json_str,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("export_stix_selected failed: %s", exc)
        raise HTTPException(status_code=500, detail="STIX export failed")


@router.post("/{investigation_id}/misp/selected")
async def export_misp_selected(
    investigation_id: str,
    body: ExportSelectedBody,
    current_user: CurrentUser = Depends(get_current_user),
) -> Response:
    """MISP JSON including only the given entities (or all if *entity_ids* is empty)."""
    _check_investigation_owner(investigation_id, current_user)
    _validate_uuid(investigation_id)
    try:
        from export.misp import investigation_to_misp_event, misp_event_to_json  # noqa: PLC0415

        internal_id = _resolve_internal_investigation_id(investigation_id)
        event = investigation_to_misp_event(
            str(internal_id),
            entity_ids=body.entity_ids or None,
        )
        json_str = misp_event_to_json(event)
        filename = f"voidaccess_{investigation_id}_misp.json"
        return Response(
            content=json_str,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("export_misp_selected failed: %s", exc)
        raise HTTPException(status_code=500, detail="MISP export failed")


@router.post("/{investigation_id}/sigma/selected")
async def export_sigma_selected(
    investigation_id: str,
    body: ExportSelectedBody,
    current_user: CurrentUser = Depends(get_current_user),
) -> StreamingResponse:
    """Sigma ZIP built from a subset of entities (or all if *entity_ids* is empty)."""
    _check_investigation_owner(investigation_id, current_user)
    _validate_uuid(investigation_id)
    try:
        from export.sigma import (  # noqa: PLC0415
            entities_to_sigma_rules,
            sigma_rule_to_yaml,
        )
        from export.stix import _load_entities_for_investigation  # noqa: PLC0415

        internal_id = _resolve_internal_investigation_id(investigation_id)
        filter_ids = None
        if body.entity_ids:
            filter_ids = []
            for raw in body.entity_ids:
                try:
                    filter_ids.append(uuid.UUID(str(raw)))
                except (ValueError, AttributeError):
                    continue
        entities = _load_entities_for_investigation(
            str(internal_id),
            entity_ids=filter_ids,
        )
        rules = entities_to_sigma_rules(entities)

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            for rule in rules:
                rule_id = rule.get("id", str(uuid.uuid4()))
                yaml_content = sigma_rule_to_yaml(rule)
                zf.writestr(f"{rule_id}.yml", yaml_content)
        buf.seek(0)

        filename = f"voidaccess_{investigation_id}_sigma.zip"
        return StreamingResponse(
            buf,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("export_sigma_selected failed: %s", exc)
        raise HTTPException(status_code=500, detail="Sigma export failed")


@router.get("/{investigation_id}/yara")
async def export_yara(
    investigation_id: str,
    current_user: CurrentUser = Depends(get_current_user),
) -> Response:
    """
    Return YARA rules file as a text/plain download.

    Content-Type: text/plain
    Content-Disposition: attachment; filename="voidaccess-{query}.yar"
    """
    _check_investigation_owner(investigation_id, current_user)
    _validate_uuid(investigation_id)
    try:
        from export.yara_export import generate_yara_rules
        from export.stix import _load_entities_for_investigation  # noqa: PLC0415

        internal_id = _resolve_internal_investigation_id(investigation_id)
        entities = _load_entities_for_investigation(str(internal_id))
        investigation_dict = _load_investigation_meta(internal_id)
        yara_text = generate_yara_rules(entities, investigation_dict)
        filename = _safe_download_filename(
            investigation_dict, investigation_id, suffix=".yar"
        )
        return Response(
            content=yara_text,
            media_type="text/plain",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("export_yara failed: %s", exc)
        raise HTTPException(status_code=500, detail="YARA export failed")


@router.get("/{investigation_id}/snort")
async def export_snort(
    investigation_id: str,
    format: str = Query(
        "snort",
        pattern="^(snort|suricata)$",
        description="Snort (default) or Suricata rule format.",
    ),
    current_user: CurrentUser = Depends(get_current_user),
) -> Response:
    """
    Return Snort or Suricata detection rules as a text/plain download.

    Use ``?format=suricata`` to switch to the Suricata flavour (adds a
    ``metadata:`` block and emits ``tls.sni`` / ``filemd5:`` rules).
    """
    _check_investigation_owner(investigation_id, current_user)
    _validate_uuid(investigation_id)
    try:
        from export.snort_export import generate_snort_rules
        from export.stix import _load_entities_for_investigation  # noqa: PLC0415

        internal_id = _resolve_internal_investigation_id(investigation_id)
        entities = _load_entities_for_investigation(str(internal_id))
        investigation_dict = _load_investigation_meta(internal_id)
        rules_text = generate_snort_rules(
            entities,
            investigation_dict,
            format=format,
        )
        suffix = ".rules"
        filename = _safe_download_filename(
            investigation_dict, investigation_id, suffix=suffix
        )
        return Response(
            content=rules_text,
            media_type="text/plain",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("export_snort failed: %s", exc)
        raise HTTPException(status_code=500, detail="Snort export failed")


@router.get("/{investigation_id}/package")
async def export_package(
    investigation_id: str,
    tlp: str = Query(
        "white",
        pattern="^(white|green|amber|red)$",
        description="Traffic Light Protocol marker (TLP:WHITE default).",
    ),
    redact_credentials: bool = Query(
        True,
        description="Partially redact credential values in the package.",
    ),
    include_raw: bool = Query(
        False,
        description="Include raw scraped page content under pages/ in the ZIP.",
    ),
    current_user: CurrentUser = Depends(get_current_user),
) -> StreamingResponse:
    """
    Generate a full IOC package ZIP for the investigation.

    Returns a streaming ZIP download containing:
      README.md, metadata.json, iocs/*, threat_intel/* (STIX, MISP),
      detections/* (Sigma, Snort, YARA), reports/* (summary, entities CSV),
      and optionally pages/* raw content.

    Content-Type: application/zip
    Content-Disposition: attachment; filename="voidaccess-{query}-{date}.zip"
    """
    _check_investigation_owner(investigation_id, current_user)
    _validate_uuid(investigation_id)
    try:
        from export.ioc_package import (
            build_package_filename,
            generate_ioc_package,
        )
        from export.stix import _load_entities_for_investigation  # noqa: PLC0415

        internal_id = _resolve_internal_investigation_id(investigation_id)
        entities = _load_entities_for_investigation(str(internal_id))

        # Load the investigation record for header metadata.
        investigation_dict: dict = {
            "id": str(internal_id),
            "query": "",
            "summary": "",
            "sources_used": {},
            "created_at": None,
        }
        try:
            from db.session import get_session  # noqa: PLC0415
            from db.queries import get_investigation_by_id_or_run  # noqa: PLC0415
            with get_session() as session:
                inv = get_investigation_by_id_or_run(session, internal_id)
                if inv is not None:
                    investigation_dict["id"] = str(inv.id)
                    investigation_dict["run_id"] = str(inv.run_id) if inv.run_id else None
                    investigation_dict["query"] = inv.query or ""
                    investigation_dict["summary"] = inv.summary or ""
                    investigation_dict["created_at"] = (
                        inv.created_at.isoformat() if inv.created_at else None
                    )
                    # Backfill sources_used from investigation metadata, the
                    # same place the CLI export reads it (adapters/sqlite.py
                    # ``_investigation_row``). ``metadata_json`` is a dict on
                    # Postgres and may be a JSON string on legacy SQLite rows.
                    metadata_raw = getattr(inv, "metadata_json", None)
                    if isinstance(metadata_raw, str):
                        try:
                            metadata_parsed = json.loads(metadata_raw) if metadata_raw.strip() else {}
                        except (ValueError, TypeError):
                            metadata_parsed = {}
                    elif isinstance(metadata_raw, dict):
                        metadata_parsed = metadata_raw
                    else:
                        metadata_parsed = {}
                    investigation_dict["sources_used"] = metadata_parsed.get("sources_used") or {}
        except Exception as exc:
            logger.warning("export_package: investigation lookup failed: %s", exc)

        zip_bytes = await generate_ioc_package(
            investigation_id=str(internal_id),
            entities=entities,
            investigation=investigation_dict,
            session=None,
            tlp=tlp,
            redact_credentials=redact_credentials,
            include_raw=include_raw,
        )

        filename = build_package_filename(investigation_dict, str(internal_id))
        return StreamingResponse(
            io.BytesIO(zip_bytes),
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("export_package failed: %s", exc)
        raise HTTPException(status_code=500, detail="IOC package export failed")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resolve_internal_investigation_id(investigation_id: str) -> uuid.UUID:
    """Map URL *investigation_id* (primary key or ``run_id``) to internal investigation PK."""
    if not os.getenv("DATABASE_URL"):
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        uid = uuid.UUID(investigation_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid investigation ID format")
    try:
        from db.session import get_session  # noqa: PLC0415
        from db.queries import get_investigation_by_id_or_run  # noqa: PLC0415

        with get_session() as session:
            inv = get_investigation_by_id_or_run(session, uid)
            if inv is None:
                raise HTTPException(status_code=404, detail="Investigation not found")
            return inv.id
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("_resolve_internal_investigation_id failed: %s", exc)
        raise HTTPException(status_code=500, detail="Internal error")


def _validate_uuid(value: str) -> None:
    """Raise HTTPException 422 if value is not a valid UUID string."""
    try:
        uuid.UUID(value)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid investigation ID format")


def _load_investigation_meta(internal_id: uuid.UUID) -> dict:
    """Return a dict with id / query / summary / created_at for the investigation.

    Returns a minimal placeholder dict when the investigation or DB is
    unavailable so that downstream exporters (YARA, Snort) can still
    render a syntactically valid file with whatever metadata they have.
    """
    meta: dict = {
        "id": str(internal_id),
        "query": "",
        "summary": "",
        "created_at": None,
    }
    try:
        from db.session import get_session  # noqa: PLC0415
        from db.queries import get_investigation_by_id_or_run  # noqa: PLC0415

        with get_session() as session:
            inv = get_investigation_by_id_or_run(session, internal_id)
            if inv is not None:
                meta["id"] = str(inv.id)
                meta["run_id"] = str(inv.run_id) if inv.run_id else None
                meta["query"] = inv.query or ""
                meta["summary"] = inv.summary or ""
                meta["created_at"] = (
                    inv.created_at.isoformat() if inv.created_at else None
                )
    except Exception as exc:
        logger.warning("_load_investigation_meta failed: %s", exc)
    return meta


_FILENAME_SAFE = re.compile(r"[^A-Za-z0-9_-]+")


def _safe_download_filename(
    investigation: dict,
    investigation_id: str,
    *,
    suffix: str,
) -> str:
    """Return ``voidaccess-{query}-{id}{suffix}`` with a query segment that's
    safe to use as a Content-Disposition filename."""
    raw_query = (investigation or {}).get("query") or ""
    segment = _FILENAME_SAFE.sub("-", raw_query).strip("-_")
    if not segment:
        segment = investigation_id[:8] or "investigation"
    segment = segment[:60]
    return f"voidaccess-{segment}{suffix}"
