"""
Incident-report route: generate a plain-text AI incident report for an existing
alert via the LOCAL LLM. Advisory only; read-only on the database. Gated on
view.dashboard. Returns 503 if the local LLM is unavailable so the dashboard
degrades gracefully. Mirrors the router pattern used elsewhere in src/serve.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from src.auth.rbac import require_permission
from src.utils import db
from src.utils.helpers import get_mitigation
from src.llm import report

router = APIRouter(prefix="/report", tags=["report"])


class ReportResponse(BaseModel):
    report: str
    model: str
    alert_id: int


@router.get("/{alert_id}", response_model=ReportResponse)
def incident_report(
    alert_id: int,
    request: Request,
    current_user: dict = Depends(require_permission("view.dashboard")),
):
    print(f"[report] >>> request received for alert_id={alert_id}", flush=True)
    # Read the alert + its detection + mitigation row (read-only).
    conn = db.get_conn()
    try:
        row = conn.execute(
            """
            SELECT a.id AS alert_id, a.severity AS severity, a.created_at AS created_at,
                   d.score AS score, d.attack_type AS attack_type,
                   t.src_ip AS src_ip, t.dst_port AS dst_port,
                   m.description AS description, m.recommendations_json AS recommendations_json
            FROM alert a
            JOIN detection_result d ON a.detection_id = d.id
            JOIN traffic_flow t ON d.flow_id = t.id
            LEFT JOIN mitigation_record m ON m.alert_id = a.id
            WHERE a.id = ?
            """,
            (alert_id,),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        raise HTTPException(status_code=404, detail=f"alert {alert_id} not found")

    keys = ["alert_id", "severity", "created_at", "score", "attack_type",
            "src_ip", "dst_port", "description", "recommendations_json"]
    alert = {k: row[i] for i, k in enumerate(keys)}

    import json
    recs = []
    if alert.get("recommendations_json"):
        try:
            recs = json.loads(alert["recommendations_json"])
        except (ValueError, TypeError):
            recs = []
    # Fall back to the canonical mitigation text if the stored row was sparse.
    if not recs:
        m = get_mitigation(alert.get("attack_type") or "", alert.get("severity") or "Low")
        recs = m.get("recommendations", [])
        if not alert.get("description"):
            alert["description"] = m.get("description", "")

    print(f"[report] alert data loaded, calling local LLM (model={report.OLLAMA_MODEL})…", flush=True)
    try:
        text = report.generate_report(alert, recommendations=recs, description=alert.get("description") or "")
    except report.ReportUnavailable as e:
        print(f"[report] !!! LLM unavailable: {e}", flush=True)
        raise HTTPException(status_code=503, detail=f"Report service unavailable: {e}")

    print(f"[report] <<< LLM returned {len(text)} chars, sending response", flush=True)
    return ReportResponse(report=text, model=report.OLLAMA_MODEL, alert_id=alert_id)
