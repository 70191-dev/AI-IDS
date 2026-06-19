"""Two-role permission matrix and FastAPI dependency factory.

Roles are intentionally only 'admin' and 'analyst' — see
_project/HARD_CONSTRAINTS.md ("Two roles only").
"""

from fastapi import Depends, HTTPException, Request, status

from src.utils.db import get_conn
from src.auth.tokens import validate_token
from src.auth.audit import log_audit


PERMISSIONS: dict[str, set[str]] = {
    "admin": {
        "users.read", "users.write", "audit.read",
        "capture.control", "replay.control",
        "mitigation.request", "mitigation.approve",
        "view.dashboard",
    },
    "analyst": {
        "view.dashboard",
        "mitigation.request",
    },
}


def has_permission(role: str, permission: str) -> bool:
    return permission in PERMISSIONS.get(role, set())


def _extract_bearer(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    if not header:
        return None
    parts = header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip() or None


def require_permission(permission: str):
    """Return a FastAPI dependency that enforces `permission`.

    On success, returns the authenticated user dict
    ({user_id, username, role, session_id}) so handlers can use it via
    `current_user = Depends(require_permission(...))`.

    401 -> missing/invalid token (no audit row; no actor known).
    403 -> valid token but role lacks permission. Writes audit_log
           row with action='permission.denied'.
    """

    def dependency(request: Request) -> dict:
        ip = request.client.host if request.client else None
        ua = request.headers.get("user-agent")
        endpoint = f"endpoint:{request.url.path}"

        token = _extract_bearer(request)
        if token is None:
            conn = get_conn()
            try:
                log_audit(
                    conn,
                    actor_user_id=None,
                    actor_username=None,
                    action="auth.failed",
                    target=endpoint,
                    status="failure",
                    detail="401 missing bearer token",
                    ip=ip,
                    ua=ua,
                )
            finally:
                conn.close()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        conn = get_conn()
        try:
            user = validate_token(conn, token)
            if user is None:
                log_audit(
                    conn,
                    actor_user_id=None,
                    actor_username=None,
                    action="auth.failed",
                    target=endpoint,
                    status="failure",
                    detail="401 invalid or expired token",
                    ip=ip,
                    ua=ua,
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or expired token",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            if not has_permission(user["role"], permission):
                log_audit(
                    conn,
                    actor_user_id=user["user_id"],
                    actor_username=user["username"],
                    action="permission.denied",
                    target=endpoint,
                    status="failure",
                    detail=f"required permission: {permission}",
                    ip=ip,
                    ua=ua,
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient permissions",
                )

            return user
        finally:
            conn.close()

    return dependency
