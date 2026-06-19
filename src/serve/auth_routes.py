"""Routes for authentication, user management, and audit-log read.

Mounted on the main FastAPI app via app.include_router(router) in
src/serve/app.py. All routes (other than POST /auth/login) require a
bearer token via require_permission(...).
"""

from datetime import datetime
import re
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel

from src.utils import db
from src.auth.passwords import (
    hash_password, verify_password, needs_rehash, verify_dummy_for_timing,
)
from src.auth.tokens import create_session, revoke_token
from src.auth.audit import log_audit
from src.auth.rbac import require_permission, PERMISSIONS, _extract_bearer


router = APIRouter()

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
PASSWORD_MIN_LEN = 12
VALID_ROLES = ("admin", "analyst")

# C3 fix: per-user login lockout (W4-Sub4d)
LOGIN_LOCKOUT_THRESHOLD = 5
LOGIN_LOCKOUT_MINUTES = 15


# ── Pydantic models ─────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    token: str
    expires_at: str
    username: str
    role: str


class MeResponse(BaseModel):
    user_id: int
    username: str
    role: str
    session_id: int
    permissions: list[str]


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str


class PatchUserRequest(BaseModel):
    role: Optional[str] = None
    password: Optional[str] = None
    disabled: Optional[bool] = None


# ── Helpers ─────────────────────────────────────────────────────
def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _user_row_to_dict(row) -> dict:
    return {
        "id":            row["id"],
        "username":      row["username"],
        "role":          row["role"],
        "created_at":    row["created_at"],
        "created_by":    row["created_by"],
        "disabled_at":   row["disabled_at"],
        "last_login_at": row["last_login_at"],
    }


def _request_meta(request: Request) -> tuple[Optional[str], Optional[str]]:
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")
    return ip, ua


# ── Auth ────────────────────────────────────────────────────────
@router.post("/auth/login", response_model=LoginResponse)
def auth_login(body: LoginRequest, request: Request):
    ip, ua = _request_meta(request)
    conn = db.get_conn()
    try:
        # C3 fix: per-user lockout — reject before any password work if the
        # account is currently locked. Compared entirely in SQLite (UTC) so
        # there is no Python/SQLite datetime-format skew. (W4-Sub4d)
        locked = conn.execute(
            "SELECT locked_until FROM login_attempts "
            "WHERE username = ? AND locked_until IS NOT NULL "
            "AND locked_until > datetime('now')",
            (body.username,),
        ).fetchone()
        if locked is not None:
            log_audit(
                conn,
                actor_user_id=None,
                actor_username=body.username,
                action="auth.login.locked",
                target=None,
                status="failure",
                detail=f"account locked until {locked['locked_until']} UTC",
                ip=ip, ua=ua,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
            )

        row = conn.execute(
            "SELECT id, username, password_hash, role, disabled_at "
            "FROM user WHERE username = ?",
            (body.username,),
        ).fetchone()

        # Failure path: user missing, disabled, or password mismatch.
        # Reason recorded in audit_log.detail but NOT leaked to the caller.
        fail_reason = None
        user_id_for_audit = row["id"] if row else None

        if row is None:
            # C3 fix: equalize timing to prevent username enumeration (W4-Sub4d)
            verify_dummy_for_timing()
            fail_reason = "invalid credentials"
        elif row["disabled_at"] is not None:
            # W4-Sub4e: equalize timing on the disabled-user branch too
            verify_dummy_for_timing()
            fail_reason = "user disabled"
        elif not verify_password(body.password, row["password_hash"]):
            fail_reason = "invalid credentials"

        if fail_reason is not None:
            # C3 fix: record failed attempt + maybe lock, for EXISTING users
            # only (writing on the missing-user path would leak username
            # existence via DB growth). Atomic upsert so concurrent failures
            # don't lose increments. (W4-Sub4d)
            if row is not None and fail_reason == "invalid credentials":
                conn.execute(
                    """INSERT INTO login_attempts
                           (username, failure_count, last_failure_at)
                       VALUES (?, 1, datetime('now'))
                       ON CONFLICT(username) DO UPDATE SET
                           failure_count   = failure_count + 1,
                           last_failure_at = datetime('now'),
                           locked_until    = CASE
                               WHEN failure_count + 1 >= ?
                                   THEN datetime('now', ?)
                               ELSE locked_until
                           END""",
                    (body.username, LOGIN_LOCKOUT_THRESHOLD,
                     f"+{LOGIN_LOCKOUT_MINUTES} minutes"),
                )
            log_audit(
                conn,
                actor_user_id=user_id_for_audit,
                actor_username=body.username,
                action="login",
                target=None,
                status="failure",
                detail=fail_reason,
                ip=ip, ua=ua,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
            )

        # C3 fix: clear the failure counter on successful auth so prior
        # failures below the threshold don't accumulate across sessions. (W4-Sub4d)
        conn.execute(
            "DELETE FROM login_attempts WHERE username = ?",
            (body.username,),
        )

        # Success: opportunistic rehash if cost factor has moved.
        if needs_rehash(row["password_hash"]):
            new_hash = hash_password(body.password)
            conn.execute(
                "UPDATE user SET password_hash = ? WHERE id = ?",
                (new_hash, row["id"]),
            )

        now = _now_iso()
        conn.execute(
            "UPDATE user SET last_login_at = ? WHERE id = ?",
            (now, row["id"]),
        )
        sess = create_session(conn, row["id"], ip=ip, ua=ua)
        log_audit(
            conn,
            actor_user_id=row["id"],
            actor_username=row["username"],
            action="login",
            target=None,
            status="success",
            detail=None,
            ip=ip, ua=ua,
        )
        return LoginResponse(
            token=sess["token"],
            expires_at=sess["expires_at"],
            username=row["username"],
            role=row["role"],
        )
    finally:
        conn.close()


@router.post("/auth/logout")
def auth_logout(
    request: Request,
    current_user: dict = Depends(require_permission("view.dashboard")),
):
    ip, ua = _request_meta(request)
    token = _extract_bearer(request)  # already validated by dependency
    conn = db.get_conn()
    try:
        revoke_token(conn, token)
        log_audit(
            conn,
            actor_user_id=current_user["user_id"],
            actor_username=current_user["username"],
            action="logout",
            target=None,
            status="success",
            detail=None,
            ip=ip, ua=ua,
        )
        return {"status": "logged_out"}
    finally:
        conn.close()


@router.get("/auth/me", response_model=MeResponse)
def auth_me(current_user: dict = Depends(require_permission("view.dashboard"))):
    perms = sorted(PERMISSIONS.get(current_user["role"], set()))
    return MeResponse(
        user_id=current_user["user_id"],
        username=current_user["username"],
        role=current_user["role"],
        session_id=current_user["session_id"],
        permissions=perms,
    )


# ── Users ───────────────────────────────────────────────────────
@router.get("/users")
def users_list(_: dict = Depends(require_permission("users.read"))):
    conn = db.get_conn()
    try:
        rows = conn.execute(
            "SELECT id, username, role, created_at, created_by, "
            "disabled_at, last_login_at FROM user ORDER BY id ASC"
        ).fetchall()
        return [_user_row_to_dict(r) for r in rows]
    finally:
        conn.close()


@router.post("/users")
def users_create(
    body: CreateUserRequest,
    request: Request,
    current_user: dict = Depends(require_permission("users.write")),
):
    if not USERNAME_RE.fullmatch(body.username):
        raise HTTPException(status_code=400, detail="Invalid username (3-32 chars [A-Za-z0-9_])")
    if len(body.password) < PASSWORD_MIN_LEN:
        raise HTTPException(status_code=400, detail=f"Password too short (min {PASSWORD_MIN_LEN})")
    if body.role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"role must be one of {VALID_ROLES}")

    ip, ua = _request_meta(request)
    now = _now_iso()
    conn = db.get_conn()
    try:
        existing = conn.execute(
            "SELECT id FROM user WHERE username = ?", (body.username,)
        ).fetchone()
        if existing is not None:
            raise HTTPException(status_code=409, detail="Username already exists")

        cur = conn.execute(
            "INSERT INTO user (username, password_hash, role, created_at, created_by) "
            "VALUES (?, ?, ?, ?, ?)",
            (body.username, hash_password(body.password), body.role, now,
             current_user["user_id"]),
        )
        new_id = cur.lastrowid
        log_audit(
            conn,
            actor_user_id=current_user["user_id"],
            actor_username=current_user["username"],
            action="user.create",
            target=f"user:{new_id}",
            status="success",
            detail=f"role={body.role} username={body.username}",
            ip=ip, ua=ua,
        )
        row = conn.execute(
            "SELECT id, username, role, created_at, created_by, "
            "disabled_at, last_login_at FROM user WHERE id = ?",
            (new_id,),
        ).fetchone()
        return _user_row_to_dict(row)
    finally:
        conn.close()


@router.patch("/users/{user_id}")
def users_patch(
    user_id: int,
    body: PatchUserRequest,
    request: Request,
    current_user: dict = Depends(require_permission("users.write")),
):
    ip, ua = _request_meta(request)
    conn = db.get_conn()
    try:
        row = conn.execute(
            "SELECT id, username, role, disabled_at FROM user WHERE id = ?",
            (user_id,),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="User not found")

        is_self = user_id == current_user["user_id"]

        # Self-protection: can't demote yourself out of admin, can't disable self.
        if body.role is not None:
            if body.role not in VALID_ROLES:
                raise HTTPException(status_code=400, detail=f"role must be one of {VALID_ROLES}")
            if is_self and body.role != "admin":
                raise HTTPException(status_code=400, detail="Cannot demote yourself")
        if body.disabled is True and is_self:
            raise HTTPException(status_code=400, detail="Cannot disable yourself")

        if body.password is not None and len(body.password) < PASSWORD_MIN_LEN:
            raise HTTPException(
                status_code=400, detail=f"Password too short (min {PASSWORD_MIN_LEN})"
            )

        now = _now_iso()

        if body.role is not None and body.role != row["role"]:
            conn.execute(
                "UPDATE user SET role = ? WHERE id = ?",
                (body.role, user_id),
            )
            log_audit(
                conn,
                actor_user_id=current_user["user_id"],
                actor_username=current_user["username"],
                action="user.role.change",
                target=f"user:{user_id}",
                status="success",
                detail=f"{row['role']}->{body.role}",
                ip=ip, ua=ua,
            )

        if body.password is not None:
            conn.execute(
                "UPDATE user SET password_hash = ? WHERE id = ?",
                (hash_password(body.password), user_id),
            )
            log_audit(
                conn,
                actor_user_id=current_user["user_id"],
                actor_username=current_user["username"],
                action="user.password.change",
                target=f"user:{user_id}",
                status="success",
                detail=None,
                ip=ip, ua=ua,
            )

        if body.disabled is True and row["disabled_at"] is None:
            conn.execute(
                "UPDATE user SET disabled_at = ? WHERE id = ?",
                (now, user_id),
            )
            conn.execute(
                "UPDATE session SET revoked_at = ? "
                "WHERE user_id = ? AND revoked_at IS NULL",
                (now, user_id),
            )
            log_audit(
                conn,
                actor_user_id=current_user["user_id"],
                actor_username=current_user["username"],
                action="user.disable",
                target=f"user:{user_id}",
                status="success",
                detail=None,
                ip=ip, ua=ua,
            )
        elif body.disabled is False and row["disabled_at"] is not None:
            conn.execute(
                "UPDATE user SET disabled_at = NULL WHERE id = ?",
                (user_id,),
            )
            log_audit(
                conn,
                actor_user_id=current_user["user_id"],
                actor_username=current_user["username"],
                action="user.enable",
                target=f"user:{user_id}",
                status="success",
                detail=None,
                ip=ip, ua=ua,
            )

        updated = conn.execute(
            "SELECT id, username, role, created_at, created_by, "
            "disabled_at, last_login_at FROM user WHERE id = ?",
            (user_id,),
        ).fetchone()
        return _user_row_to_dict(updated)
    finally:
        conn.close()


# ── Audit log read ──────────────────────────────────────────────
@router.get("/audit")
def audit_list(
    limit: int = Query(default=100, ge=1, le=500),
    since: Optional[str] = Query(default=None),
    action: Optional[str] = Query(default=None),
    actor: Optional[str] = Query(default=None),
    status_: Optional[str] = Query(default=None, alias="status"),
    _: dict = Depends(require_permission("audit.read")),
):
    where = []
    params: list = []
    if since is not None:
        where.append("ts >= ?")
        params.append(since)
    if action is not None:
        where.append("action LIKE ?")
        params.append(f"{action}%")
    if actor is not None:
        where.append("actor_username = ?")
        params.append(actor)
    if status_ is not None:
        if status_ not in ("success", "failure"):
            raise HTTPException(status_code=400, detail="status must be 'success' or 'failure'")
        where.append("status = ?")
        params.append(status_)

    sql = (
        "SELECT id, ts, actor_user_id, actor_username, action, target, "
        "       status, detail, ip_address, user_agent "
        "FROM audit_log "
    )
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY ts DESC, id DESC LIMIT ?"
    params.append(limit)

    conn = db.get_conn()
    try:
        rows = conn.execute(sql, tuple(params)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
