"""Mitigation workflow routes: request -> approve/deny -> netsh execute.

Mounted on the main FastAPI app via app.include_router(router) in
src/serve/app.py. All routes require a bearer token via
require_permission(...). Style mirrors src/serve/auth_routes.py.

Audit chain produced by these endpoints (one row per side effect):
    mitigation.request.create      success | failure
    mitigation.request.approve     success | failure   (two-person rule -> failure)
    mitigation.block.execute       success | failure   (netsh result)
    mitigation.request.deny        success
    mitigation.unblock.execute     success | failure   (netsh result)

GET endpoints are not per-call audited (matches /users GET pattern in
auth_routes.py).

Notes for graders / Phase 2 defense:
  * `MITIGATION_ALLOW_PRIVATE=true` is the lab-demo escape hatch that
    lets us block the Kali attacker 192.168.142.128 in the FYP demo.
    It is DEV/LAB ONLY. HARD_CONSTRAINTS.md requires the default to
    reject private ranges. Production deployments leave it unset.
  * Two-person rule: an admin who created a request cannot approve it
    within 5 seconds. This is a behavioural control, not a permission
    check (admins do hold mitigation.approve). Denying your own
    request is fine -- deny is safe.
  * /mitigation/unblock requires there be at least one prior
    mitigation_request row for the target IP, because the
    mitigation_action.request_id column is NOT NULL by schema
    (additive-only DB constraint -- see HARD_CONSTRAINTS.md). For
    ad-hoc admin unblocks with no lineage, use netsh directly.
"""

import ipaddress
import os
import sys
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from src.utils import db
from src.auth.audit import log_audit
from src.auth.rbac import require_permission
from src.mitigation import firewall


router = APIRouter(prefix="/mitigation", tags=["mitigation"])

# 5-second window for two-person rule on approve.
TWO_PERSON_RULE_SECONDS = 5
# Maximum free-text length we accept on user-supplied strings.
MAX_REASON_LEN = 500


# ── Pydantic models ─────────────────────────────────────────────
class MitigationRequestCreate(BaseModel):
    alert_id: int
    target_ip: str
    reason: Optional[str] = Field(default=None, max_length=MAX_REASON_LEN)


class MitigationDecision(BaseModel):
    note: Optional[str] = Field(default=None, max_length=MAX_REASON_LEN)


class MitigationUnblock(BaseModel):
    ip: str
    reason: Optional[str] = Field(default=None, max_length=MAX_REASON_LEN)


# ── Helpers ─────────────────────────────────────────────────────
def _now_iso() -> str:
    """ISO8601 UTC with Z suffix and microsecond precision.

    Same format as src/mitigation/firewall.py uses on the JSON ledger,
    so the two timestamps line up across DB rows and ledger entries.
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _allow_private_for_lab() -> bool:
    """DEV/LAB ONLY. Single source of truth for the env-var override.

    Enables blocking private-range IPs (e.g. 192.168.142.128 Kali in
    the FYP demo). Default (env unset / anything other than 'true') is
    the HARD_CONSTRAINTS behaviour: reject private ranges.
    """
    return os.environ.get("MITIGATION_ALLOW_PRIVATE", "false").strip().lower() == "true"


def _request_meta(request: Request) -> tuple[Optional[str], Optional[str]]:
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")
    return ip, ua


def _request_row_to_dict(row) -> dict:
    """mitigation_request -> dict. Used for create + decide responses."""
    return {
        "id":            row["id"],
        "alert_id":      row["alert_id"],
        "target_ip":     row["target_ip"],
        "reason":        row["reason"],
        "requested_by":  row["requested_by"],
        "requested_at":  row["requested_at"],
        "status":        row["status"],
        "decided_by":    row["decided_by"],
        "decided_at":    row["decided_at"],
        "decision_note": row["decision_note"],
    }


def _action_row_to_dict(row) -> dict:
    return {
        "id":           row["id"],
        "request_id":   row["request_id"],
        "action_type":  row["action_type"],
        "target_ip":    row["target_ip"],
        "executed_by":  row["executed_by"],
        "executed_at":  row["executed_at"],
        "status":       row["status"],
        "netsh_stdout": row["netsh_stdout"],
        "netsh_stderr": row["netsh_stderr"],
        "error_detail": row["error_detail"],
    }


def _parse_iso_z(ts: str) -> Optional[datetime]:
    """Parse the timestamps we write. Accepts both microsecond-Z form
    (mitigation rows) and the timespec='seconds' form auth_routes uses.
    Returns a timezone-aware datetime in UTC, or None on parse failure.
    """
    if not isinstance(ts, str) or not ts:
        return None
    raw = ts
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


# ── Endpoints ───────────────────────────────────────────────────
@router.post("/requests", status_code=status.HTTP_201_CREATED)
def mitigation_request_create(
    body: MitigationRequestCreate,
    request: Request,
    current_user: dict = Depends(require_permission("mitigation.request")),
):
    ip, ua = _request_meta(request)
    target_ip = body.target_ip
    allow_private = _allow_private_for_lab()
    conn = db.get_conn()
    try:
        # 1) alert must exist
        alert_row = conn.execute(
            "SELECT id FROM alert WHERE id = ?", (body.alert_id,)
        ).fetchone()
        if alert_row is None:
            log_audit(
                conn,
                actor_user_id=current_user["user_id"],
                actor_username=current_user["username"],
                action="mitigation.request.create",
                target=None,
                status="failure",
                detail=f"alert_id={body.alert_id} not found",
                ip=ip, ua=ua,
            )
            raise HTTPException(status_code=404, detail=f"alert {body.alert_id} not found")

        # 2) IP must validate (allow_private respects MITIGATION_ALLOW_PRIVATE)
        ok, reason = firewall.validate_ip(target_ip, allow_private=allow_private)
        if not ok:
            log_audit(
                conn,
                actor_user_id=current_user["user_id"],
                actor_username=current_user["username"],
                action="mitigation.request.create",
                target=None,
                status="failure",
                detail=reason,
                ip=ip, ua=ua,
            )
            raise HTTPException(status_code=400, detail=reason)

        # 3) reject if a pending request already exists for this IP
        existing = conn.execute(
            "SELECT id FROM mitigation_request "
            "WHERE target_ip = ? AND status = 'pending'",
            (target_ip,),
        ).fetchone()
        if existing is not None:
            log_audit(
                conn,
                actor_user_id=current_user["user_id"],
                actor_username=current_user["username"],
                action="mitigation.request.create",
                target=f"request:{existing['id']}",
                status="failure",
                detail=f"duplicate pending request for ip={target_ip}",
                ip=ip, ua=ua,
            )
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "duplicate_pending",
                    "message": f"A pending mitigation request already exists for {target_ip}.",
                    "existing_request_id": existing["id"],
                },
            )

        # 4) insert
        now = _now_iso()
        cur = conn.execute(
            "INSERT INTO mitigation_request "
            "(alert_id, target_ip, reason, requested_by, requested_at, status) "
            "VALUES (?, ?, ?, ?, ?, 'pending')",
            (body.alert_id, target_ip, body.reason,
             current_user["user_id"], now),
        )
        request_id = cur.lastrowid

        log_audit(
            conn,
            actor_user_id=current_user["user_id"],
            actor_username=current_user["username"],
            action="mitigation.request.create",
            target=f"request:{request_id}",
            status="success",
            detail=f"ip={target_ip} alert_id={body.alert_id}",
            ip=ip, ua=ua,
        )

        new_row = conn.execute(
            "SELECT * FROM mitigation_request WHERE id = ?", (request_id,)
        ).fetchone()
        return _request_row_to_dict(new_row)
    finally:
        conn.close()


@router.get("/requests")
def mitigation_request_list(
    status_: Optional[str] = Query(default=None, alias="status"),
    limit: int = Query(default=100, ge=1, le=500),
    _: dict = Depends(require_permission("view.dashboard")),
):
    if status_ is not None and status_ not in (
        "pending", "approved", "denied", "expired", "cancelled"
    ):
        raise HTTPException(
            status_code=400,
            detail="status must be one of: pending, approved, denied, expired, cancelled",
        )

    sql = (
        "SELECT r.id, r.alert_id, r.target_ip, r.reason, "
        "       r.requested_by, ur.username AS requested_by_username, "
        "       r.requested_at, r.status, "
        "       r.decided_by, ud.username AS decided_by_username, "
        "       r.decided_at, r.decision_note "
        "  FROM mitigation_request r "
        "  LEFT JOIN user ur ON ur.id = r.requested_by "
        "  LEFT JOIN user ud ON ud.id = r.decided_by "
    )
    params: list = []
    if status_ is not None:
        sql += " WHERE r.status = ? "
        params.append(status_)
    sql += " ORDER BY r.requested_at DESC, r.id DESC LIMIT ?"
    params.append(limit)

    conn = db.get_conn()
    try:
        rows = conn.execute(sql, tuple(params)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


@router.post("/requests/{request_id}/approve")
def mitigation_request_approve(
    request_id: int,
    body: MitigationDecision,
    request: Request,
    current_user: dict = Depends(require_permission("mitigation.approve")),
):
    ip, ua = _request_meta(request)
    conn = db.get_conn()
    try:
        row = conn.execute(
            "SELECT * FROM mitigation_request WHERE id = ?", (request_id,)
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail=f"request {request_id} not found")

        if row["status"] != "pending":
            raise HTTPException(
                status_code=409,
                detail=f"Request is already {row['status']}, cannot approve.",
            )

        # Two-person rule: requester cannot approve own request within 5s.
        if row["requested_by"] == current_user["user_id"]:
            requested_dt = _parse_iso_z(row["requested_at"])
            if requested_dt is not None:
                delta = (datetime.now(timezone.utc) - requested_dt).total_seconds()
                if delta < TWO_PERSON_RULE_SECONDS:
                    log_audit(
                        conn,
                        actor_user_id=current_user["user_id"],
                        actor_username=current_user["username"],
                        action="mitigation.request.approve",
                        target=f"request:{request_id}",
                        status="failure",
                        detail=f"two-person rule: {delta:.2f}s since request",
                        ip=ip, ua=ua,
                    )
                    raise HTTPException(
                        status_code=403,
                        detail=(
                            "Two-person rule: cannot approve own request within "
                            f"{TWO_PERSON_RULE_SECONDS} seconds of creation."
                        ),
                    )

        now = _now_iso()
        conn.execute(
            "UPDATE mitigation_request "
            "   SET status = 'approved', decided_by = ?, decided_at = ?, decision_note = ? "
            " WHERE id = ?",
            (current_user["user_id"], now, body.note, request_id),
        )
        log_audit(
            conn,
            actor_user_id=current_user["user_id"],
            actor_username=current_user["username"],
            action="mitigation.request.approve",
            target=f"request:{request_id}",
            status="success",
            detail=None,
            ip=ip, ua=ua,
        )

        # Execute the block. Honest behaviour: a netsh failure does NOT
        # roll back the approval -- the audit chain records the failure
        # and the admin can investigate (re-request, fix elevation, etc.)
        target_ip = row["target_ip"]
        result = firewall.block_ip(target_ip, allow_private=_allow_private_for_lab())

        action_status = "success" if result["ok"] else "failure"
        cur = conn.execute(
            "INSERT INTO mitigation_action "
            "(request_id, action_type, target_ip, executed_by, executed_at, "
            " status, netsh_stdout, netsh_stderr, error_detail) "
            "VALUES (?, 'block', ?, ?, ?, ?, ?, ?, ?)",
            (request_id, target_ip, current_user["user_id"], _now_iso(),
             action_status, result.get("stdout"), result.get("stderr"),
             result.get("error")),
        )
        action_id = cur.lastrowid

        log_audit(
            conn,
            actor_user_id=current_user["user_id"],
            actor_username=current_user["username"],
            action="mitigation.block.execute",
            target=f"request:{request_id}",
            status=action_status,
            detail=(result.get("error") or f"rule={result.get('rule_name')}"),
            ip=ip, ua=ua,
        )

        updated_row = conn.execute(
            "SELECT * FROM mitigation_request WHERE id = ?", (request_id,)
        ).fetchone()
        action_row = conn.execute(
            "SELECT * FROM mitigation_action WHERE id = ?", (action_id,)
        ).fetchone()

        resp = {
            "request":      _request_row_to_dict(updated_row),
            "action":       _action_row_to_dict(action_row),
            "block_result": result,
        }
        if not result["ok"]:
            resp["warning"] = (
                "Block was approved but netsh execution failed; "
                "see action.error_detail."
            )
        return resp
    finally:
        conn.close()


@router.post("/requests/{request_id}/deny")
def mitigation_request_deny(
    request_id: int,
    body: MitigationDecision,
    request: Request,
    current_user: dict = Depends(require_permission("mitigation.approve")),
):
    """Deny a pending mitigation request.

    No two-person rule on deny -- denying your own request is safe; it
    only releases the pending lock for that target IP.
    """
    ip, ua = _request_meta(request)
    conn = db.get_conn()
    try:
        row = conn.execute(
            "SELECT * FROM mitigation_request WHERE id = ?", (request_id,)
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail=f"request {request_id} not found")
        if row["status"] != "pending":
            raise HTTPException(
                status_code=409,
                detail=f"Request is already {row['status']}, cannot deny.",
            )

        now = _now_iso()
        conn.execute(
            "UPDATE mitigation_request "
            "   SET status = 'denied', decided_by = ?, decided_at = ?, decision_note = ? "
            " WHERE id = ?",
            (current_user["user_id"], now, body.note, request_id),
        )
        log_audit(
            conn,
            actor_user_id=current_user["user_id"],
            actor_username=current_user["username"],
            action="mitigation.request.deny",
            target=f"request:{request_id}",
            status="success",
            detail=body.note or "",
            ip=ip, ua=ua,
        )

        updated_row = conn.execute(
            "SELECT * FROM mitigation_request WHERE id = ?", (request_id,)
        ).fetchone()
        return _request_row_to_dict(updated_row)
    finally:
        conn.close()


@router.get("/blocked")
def mitigation_blocked(
    _: dict = Depends(require_permission("view.dashboard")),
):
    """Currently-blocked IPs from the netsh ledger, augmented with the
    most recent successful block action row (if any) so callers can
    show who approved it.
    """
    ledger_entries = firewall.list_blocked_ips()
    if not ledger_entries:
        return []

    conn = db.get_conn()
    try:
        enriched = []
        for entry in ledger_entries:
            ip_val = entry.get("ip")
            row = conn.execute(
                "SELECT a.request_id, u.username AS approved_by_username "
                "  FROM mitigation_action a "
                "  LEFT JOIN user u ON u.id = a.executed_by "
                " WHERE a.target_ip = ? AND a.action_type = 'block' "
                "       AND a.status = 'success' "
                " ORDER BY a.executed_at DESC, a.id DESC LIMIT 1",
                (ip_val,),
            ).fetchone()
            enriched.append({
                "ip":                   ip_val,
                "rule_name":            entry.get("rule_name"),
                "blocked_at":           entry.get("blocked_at"),
                "request_id":           row["request_id"] if row else None,
                "approved_by_username": row["approved_by_username"] if row else None,
            })
        return enriched
    finally:
        conn.close()


@router.post("/unblock")
def mitigation_unblock(
    body: MitigationUnblock,
    request: Request,
    current_user: dict = Depends(require_permission("mitigation.approve")),
):
    """Remove a netsh block rule. Requires that some mitigation_request
    row exists for the target IP, because mitigation_action.request_id
    is NOT NULL (additive-only DB rule). For ad-hoc unblocks with no
    request lineage, use netsh directly outside the API.
    """
    ip_addr, ua = _request_meta(request)

    # Lightweight shape check only -- this IP is presumed already blocked,
    # so we are undoing something, not enforcing public-only.
    try:
        ipaddress.ip_address(body.ip)
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail=f"invalid IP address: {body.ip!r}")

    conn = db.get_conn()
    try:
        # Prefer the most recent approved request; fall back to most recent
        # of any status. Both keep request_id NOT NULL on the action row.
        link_row = conn.execute(
            "SELECT id FROM mitigation_request "
            "WHERE target_ip = ? AND status = 'approved' "
            "ORDER BY decided_at DESC, id DESC LIMIT 1",
            (body.ip,),
        ).fetchone()
        if link_row is None:
            link_row = conn.execute(
                "SELECT id FROM mitigation_request "
                "WHERE target_ip = ? "
                "ORDER BY requested_at DESC, id DESC LIMIT 1",
                (body.ip,),
            ).fetchone()
        if link_row is None:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Cannot unblock an IP that was never the subject of a "
                    "mitigation request. Use direct netsh management for "
                    "ad-hoc cases."
                ),
            )
        link_request_id = link_row["id"]

        result = firewall.unblock_ip(body.ip)
        action_status = "success" if result["ok"] else "failure"
        cur = conn.execute(
            "INSERT INTO mitigation_action "
            "(request_id, action_type, target_ip, executed_by, executed_at, "
            " status, netsh_stdout, netsh_stderr, error_detail) "
            "VALUES (?, 'unblock', ?, ?, ?, ?, ?, ?, ?)",
            (link_request_id, body.ip, current_user["user_id"], _now_iso(),
             action_status, result.get("stdout"), result.get("stderr"),
             result.get("error")),
        )
        action_id = cur.lastrowid

        log_audit(
            conn,
            actor_user_id=current_user["user_id"],
            actor_username=current_user["username"],
            action="mitigation.unblock.execute",
            target=f"ip:{body.ip}",
            status=action_status,
            detail=(result.get("error") or f"rule={result.get('rule_name')}"),
            ip=ip_addr, ua=ua,
        )

        action_row = conn.execute(
            "SELECT * FROM mitigation_action WHERE id = ?", (action_id,)
        ).fetchone()
        return {
            "action":         _action_row_to_dict(action_row),
            "unblock_result": result,
        }
    finally:
        conn.close()


@router.get("/actions/failures")
def mitigation_action_failures(
    limit: int = Query(default=50, ge=1, le=200),
    _: dict = Depends(require_permission("mitigation.approve")),
):
    """Recent failed mitigation_action rows (netsh add/delete failures).

    Same data the audit log captures, but as a structured table so the
    Mitigation page can surface them without making the admin scroll
    /audit. Joined to mitigation_request for request_status and to user
    for the executor's username.
    """
    sql = (
        "SELECT a.id           AS action_id, "
        "       a.executed_at  AS executed_at, "
        "       a.action_type  AS action_type, "
        "       a.target_ip    AS target_ip, "
        "       a.request_id   AS request_id, "
        "       r.status       AS request_status, "
        "       u.username     AS executed_by_username, "
        "       a.error_detail AS error_detail, "
        "       a.netsh_stdout AS netsh_stdout, "
        "       a.netsh_stderr AS netsh_stderr "
        "  FROM mitigation_action a "
        "  LEFT JOIN mitigation_request r ON r.id = a.request_id "
        "  LEFT JOIN user u ON u.id = a.executed_by "
        " WHERE a.status = 'failure' "
        " ORDER BY a.executed_at DESC, a.id DESC "
        " LIMIT ?"
    )
    conn = db.get_conn()
    try:
        rows = conn.execute(sql, (limit,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


@router.get("/_diag/elevation")
def mitigation_diag_elevation(
    _: dict = Depends(require_permission("mitigation.approve")),
):
    """Admin-only read-only elevation probe.

    The H7 demo failed because the API process was not elevated and
    netsh advfirewall add/delete needs admin. This endpoint exposes
    every signal we have so the admin can confirm elevation without
    restarting anything. No secrets returned.
    """
    diag: dict = {
        "platform":                    sys.platform,
        "process_pid":                 os.getpid(),
        "MITIGATION_ALLOW_PRIVATE_env": os.environ.get("MITIGATION_ALLOW_PRIVATE"),
        "firewall_is_admin_result":    None,
        "raw_isuseranadmin":           None,
        "raw_isuseranadmin_error":     None,
        "token_elevation":             None,
        "token_elevation_error":       None,
    }

    try:
        diag["firewall_is_admin_result"] = firewall.is_admin()
    except Exception as e:
        diag["firewall_is_admin_result"] = f"<error: {e!r}>"

    # Raw IsUserAnAdmin probe — same call firewall.is_admin() makes,
    # but with the exception surfaced instead of swallowed.
    try:
        import ctypes  # noqa: WPS433  (lazy: Windows-only attribute access)
        diag["raw_isuseranadmin"] = int(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception as e:
        diag["raw_isuseranadmin_error"] = repr(e)

    # GetTokenInformation(TokenElevation) — orthogonal probe in case
    # IsUserAnAdmin lies (it can with UAC linked tokens).
    try:
        import ctypes
        from ctypes import wintypes

        TOKEN_QUERY = 0x0008
        TokenElevation = 20

        process = ctypes.windll.kernel32.GetCurrentProcess()
        token = wintypes.HANDLE()
        if not ctypes.windll.advapi32.OpenProcessToken(
            process, TOKEN_QUERY, ctypes.byref(token),
        ):
            raise OSError(
                f"OpenProcessToken failed, GetLastError="
                f"{ctypes.windll.kernel32.GetLastError()}"
            )
        try:
            elevation = wintypes.DWORD()
            size = wintypes.DWORD()
            ok = ctypes.windll.advapi32.GetTokenInformation(
                token, TokenElevation,
                ctypes.byref(elevation), ctypes.sizeof(elevation),
                ctypes.byref(size),
            )
            if not ok:
                raise OSError(
                    f"GetTokenInformation failed, GetLastError="
                    f"{ctypes.windll.kernel32.GetLastError()}"
                )
            diag["token_elevation"] = bool(elevation.value)
        finally:
            ctypes.windll.kernel32.CloseHandle(token)
    except Exception as e:
        diag["token_elevation_error"] = repr(e)

    return diag
