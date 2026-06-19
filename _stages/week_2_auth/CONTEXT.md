# Week 2 Stage Brief — Two-role auth on Streamlit

## Goal

Add admin + analyst roles to the existing Streamlit dashboard with
SQLite-backed users, sessions, and an audit log. This closes the
Phase 1 viva question about user management without violating
HARD_CONSTRAINTS.md.

## Inputs to read before starting

| Source | Why |
|---|---|
| _project/HARD_CONSTRAINTS.md | Boundary check before any code |
| _project/4_WEEK_PLAN.md (§ Week 2) | Full week 2 in-scope / out-of-scope |
| CURRENT_STATE.md § 7 (DB schema) | Existing tables, do not break |
| CURRENT_STATE.md § 4 (API endpoints) | Existing routes, wrap with RBAC |
| src/serve/app.py | Where new auth/users/audit endpoints land |
| src/utils/db.py | Where new tables get DDL'd (idempotent) |
| dashboard/app.py | Where login + role-aware UI gating lands |

## Deliverables

1. SQLite tables: user, session, audit_log — idempotent CREATE in db.py
2. src/auth/ package: passwords.py, tokens.py, dependencies.py,
   audit.py, rbac.py
3. Endpoints: /auth/login, /auth/logout, /auth/me, /users CRUD,
   /audit query
4. require_permission(...) dependency wired onto all existing
   mutating endpoints
5. tools/bootstrap_admin.py CLI
6. dashboard/auth_ui.py login flow
7. Role-aware sidebar in dashboard/app.py
8. dashboard/pages/users.py (admin only)
9. dashboard/pages/audit.py (admin only)

## Token / session model

- Opaque 32-byte URL-safe random tokens, stored in session table,
  NOT JWT
- 8-hour expiry
- Stored in Streamlit's app.storage.user (or st.session_state)
- Sent on every API call as Authorization: Bearer <token>
- Server validates against session table on every request
- /auth/logout sets session.revoked_at

## Two roles only

| Capability | admin | analyst |
|---|---|---|
| View alerts / stats / dashboard | ✓ | ✓ |
| Manage users | ✓ | ✗ |
| View audit log | ✓ | ✗ |
| Start/stop capture, replay | ✓ | ✗ |
| Request mitigation (Week 3) | ✓ | ✓ |
| Approve mitigation (Week 3) | ✓ | ✗ |

## Acceptance criteria

Fresh DB → bootstrap_admin creates admin → admin logs in → creates
analyst → analyst logs in in second browser → analyst sees fewer
sidebar items → analyst curls /users directly → 403 → admin views
audit log and sees: admin's login, analyst's creation, analyst's
login, the 403 attempt.

## Out of scope

Mitigation workflow (Week 3), 2FA, password reset, email
verification, OAuth, anything from the "do not introduce" list in
HARD_CONSTRAINTS.md.

## Notes

- The /predict endpoint stays UN-authed because the capture and
  replay processes POST to it via M2M. For Week 2, restrict /predict
  by binding to 127.0.0.1 only and documenting. If real M2M auth is
  needed later we add an X-Agent-Key header in Week 3 alongside the
  agent registration story — out of scope this week.
- Use streamlit-authenticator if and only if it cleanly supports
  server-side token validation against our /auth/me. Otherwise roll
  a minimal custom flow against our own endpoints. Add nothing to
  requirements.txt without justification in CHANGES.md.
