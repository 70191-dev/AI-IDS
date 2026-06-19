# Phase 2 — 4-Week Plan

Phase 2 turns the validated Phase 1 detection pipeline into a
defendable multi-user SOC tool with real mitigation.

## Week 1 — Real-attack validation (DONE)

Goal: prove the IDS detects real attacks, not just replay traffic.

Outcome: ~552 detections (run 1) and ~298 detections (run 2) across
slowhttptest, medusa SSH brute-force, and nikto web scan, run from a
Kali VM against the Windows IDS host on VMware host-only network.

Key finding: the model detects session-based attacks well (slowhttptest
~100%, medusa ~75%, nikto partial). Scan/flood tools (nmap -sS,
hping3 --flood) produce degenerate 2-packet flows that the model does
not recognize. This is a documented architectural limitation, not a
defect.

Artifacts: lab/attack_log.csv, lab/ATTACK_VALIDATION.md (the
centerpiece writeup, generated end of Week 1).

## Week 2 — Two-role auth on Streamlit (ACTIVE)

Goal: add admin + analyst roles to the existing Streamlit dashboard.
Single-machine, SQLite-backed. Closes the Phase 1 viva question
"how do you manage users?"

In-scope:
- New SQLite tables (idempotent migration): user, session, audit_log
- src/auth/ package: passwords (bcrypt via passlib), tokens (opaque
  32-byte session tokens stored in DB, NOT JWT), dependencies
  (FastAPI get_current_user), audit logger
- New endpoints under /auth: POST /auth/login, POST /auth/logout,
  GET /auth/me
- New endpoints under /users (admin only): GET /users, POST /users,
  PATCH /users/{id}
- New endpoint GET /audit (admin only) for the audit log viewer
- RBAC via src/auth/rbac.py — two-role permission matrix
- Wire require_permission(...) onto every existing mutating endpoint
- Streamlit login screen (dashboard/auth_ui.py)
- Role-aware sidebar in dashboard/app.py
- dashboard/pages/users.py (admin only)
- dashboard/pages/audit.py (admin only)
- tools/bootstrap_admin.py — one-time CLI to create first admin

Out-of-scope this week:
- Mitigation request/approve flow (that is Week 3)
- Real firewall blocking (that is Week 3)
- Any frontend tech other than Streamlit
- Multi-user concurrency stress testing
- Password reset flows
- Email verification

Acceptance: fresh DB → bootstrap_admin creates admin user → admin
logs in via dashboard → admin creates analyst user → analyst logs in
in second browser → analyst sees fewer sidebar items than admin →
analyst direct-curls /users and gets 403 → admin sees full audit log
including the 403 attempt.

## Week 3 — Mitigation workflow

Goal: analyst requests block, admin approves, netsh executes, Kali
attack visibly stalls.

In-scope:
- New SQLite tables: mitigation_request, mitigation_action
- src/mitigation/firewall.py — netsh wrapper, is_admin check, IP
  validation, public-only by default, JSON ledger at
  data/blocked_ips.json
- New endpoints: POST /mitigation/requests (analyst),
  GET /mitigation/requests, POST /mitigation/requests/{id}/approve
  (admin), POST /mitigation/requests/{id}/deny, GET /mitigation/blocked,
  POST /mitigation/unblock (admin)
- Two-person rule: analyst cannot approve own request within 5 seconds
- Dashboard: "Request Block" button on Attack-labeled alert rows
  (analyst+); Mitigation page with Pending Requests panel for admin
  (Approve / Deny inline); Active Blocks panel with Unblock buttons
- Audit log captures the full chain: alert → request → decision →
  execution

Out-of-scope: auto-block on detection (always human-in-loop).

Acceptance: with admin/root, run slowhttptest from Kali → alerts
appear → analyst clicks Request Block → admin approves → netsh rule
added → slowhttptest connections stall on Kali side → audit log
shows alert ID + request ID + approver + netsh stdout. Unblock works
symmetrically.

## Week 4 — Polish + defense

Goal: presentable for viva.

In-scope:
- README rewrite (current one is stale, references non-existent files)
- RECONCILIATION_PHASE2.md — side-by-side: Phase 1 proposal claims vs
  Phase 2 reality, Phase 1 viva questions vs Phase 2 answers
- FUTURE_WORK.md — endpoint agent design, multi-machine deployment
  story, aggregator extension for scan/flood detection — all
  designed-on-paper so the panel sees we understood the bigger
  architecture and chose detection-first
- defense/DEMO_SCRIPT.md — exact 5-minute live-attack demo path
- defense/QA_BANK.md — 25+ anticipated questions with prepared answers
- Smoke test in tests/ that boots the API in-process and asserts
  rows land in all relevant tables
- Buffer days for things that always break before defense

Out-of-scope: new features beyond Weeks 1-3, code-signing, public
demo deployments.

Acceptance: clean repo, all docs honest and accurate, demo rehearsed
3+ times, defense rehearsal video archived as insurance.
