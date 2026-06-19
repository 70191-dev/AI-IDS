# AI-Driven Intrusion Detection and Threat Mitigation System for Secure Networks

> Final Year Project — BSCS, University of Lahore (Fall 2022–2026)
> Project ID: Fall-2025-104
> Supervisor: Dr. Nadeem Iqbal, Department of CS&IT

## Overview

This system captures live network traffic on a Windows host, classifies
each flow with a Random Forest model trained on CIC-IDS2017, and surfaces
attack alerts in a two-role SOC dashboard. Detections are persisted to
SQLite, every privileged action is recorded in an append-only audit log
(no UPDATE or DELETE statements against the `audit_log` table exist in
the codebase),
and confirmed attacks can be mitigated through a human-in-the-loop
workflow: an analyst requests a block on an attacker IP, an admin
reviews and approves, and the host firewall is updated via
`netsh advfirewall`. The entire stack runs on a single Windows machine
with no cloud services and no third-party telemetry.

Built and defended as an academic FYP; production deployment would
require the extensions documented in `FUTURE_WORK.md`.

## Architecture

```
                           +-----------------------------+
                           |  Streamlit SOC Console      |
                           |  (dashboard/app.py)         |
                           |  - login + RBAC gate        |
                           |  - alerts table, charts     |
                           |  - Request Block expander   |
   browser <----- :8501 ---|  - pages/Users, Audit,      |
                           |    Mitigation               |
                           +--------------+--------------+
                                          |
                                          v
                           +-----------------------------+
                           |  FastAPI (src/serve/app.py) |
   uvicorn ::8000 -------- |  /predict  /alerts  /stats  |
                           |  /auth/*   /users/*         |
                           |  /capture/* /replay/*       |
                           |  /mitigation/*  /audit      |
                           +--------------+--------------+
              +----------------+----------+-----------+----------------+
              v                v                      v                v
     +----------------+  +-----------+        +---------------+  +------------+
     | scapy live     |  | RF binary |        | SQLite (one   |  | netsh      |
     | capture (Npcap)|  | + RF multi|        | file)         |  | advfirewall|
     | replay loop    |  | (models/) |        |               |  | (Windows)  |
     +----------------+  +-----------+        +---------------+  +------------+
                                                     |
                                +--------------------+----------------------+----------------------+
                                |                    |                      |                      |
                          ERD tables           Auth tables            Mitigation tables      Security tables
                          (Phase 1)            (Week 2)               (Week 3)               (Week 4)
                          - traffic_flow       - user                 - mitigation_request   - login_attempts
                          - detection_result   - session              - mitigation_action
                          - alert              - audit_log
                          - mitigation_record
```

## Tech Stack

- Python 3.12
- FastAPI + uvicorn (REST API on :8000)
- Streamlit (SOC dashboard on :8501)
- SQLite (single-file DB at `data/ids.db`)
- scikit-learn (Random Forest, two-stage binary + multi-class)
- scapy (live packet capture; requires Npcap on Windows)
- bcrypt + passlib (password hashing, cost factor 12)
- Windows `netsh advfirewall` (mitigation enforcement)
- Plotly + streamlit-autorefresh (dashboard charts and tick)

## Quick Start

> **NOTE:** Mitigation enforcement requires (a) the API process to be
> running elevated **and** (b) no third-party kernel-mode AV active on
> the host. See **Known Limitations** below.

1. **Clone the repo.**
2. **Install Npcap.** Download from <https://npcap.com> and install in
   "WinPcap API-compatible mode". Required for live packet capture.
3. **Run `START.bat` as administrator** (right-click → Run as
   administrator — elevation is needed for both packet capture and
   `netsh` rule edits). On the first run, START.bat creates a virtual
   environment under `.venv\`, installs dependencies from
   `env\requirements.txt`, generates training data, and trains the
   binary and multi-class models. This first-time pass takes ~3
   minutes. Subsequent runs skip straight to launching the services.
4. **Bootstrap the initial admin.** Open a second elevated PowerShell
   window in the repo root and run:
   ```
   .venv\Scripts\python.exe tools\bootstrap_admin.py --username admin1
   ```
   You will be prompted for a password (minimum 12 characters). The
   script refuses to create a second admin once one exists.
5. **Open the dashboard** at <http://localhost:8501> and sign in as the
   admin you just created. The FastAPI docs are at
   <http://localhost:8000/docs>.

To stop everything, close the START.bat console window.

## Features

### Detection

Two-stage Random Forest. The binary head decides Benign vs Attack at the
F1-optimal threshold (currently `0.3858`, persisted to
`models/threshold.txt`). For flows labelled Attack, the multi-class head
assigns one of eight categories (Benign, DoS, DDoS, Port Scan, Brute
Force, Web Attack, Bot, Infiltration). Both models train from CIC-IDS2017
features via `src/data/prep_cic2017.py` and the 50-feature
`UNIFIED_FEATURES` schema. Live packet capture and CSV replay are both
supported through the same `/predict` endpoint.

### Two-role RBAC

Two roles only: `admin` and `analyst`. Sessions are SQLite-backed with
opaque 32-byte bearer tokens and an 8-hour TTL. Passwords are hashed
with bcrypt at cost factor 12. Self-demote and self-disable are blocked
at the API layer; disabling a user atomically revokes their active
sessions. Bearer tokens are opaque random bytes — not a signed token
format. There is no OAuth and no SSO. See
`_project/HARD_CONSTRAINTS.md` for the deliberate scope of the auth model.

### Audit log

Every privileged action (login, logout, user create/disable, capture
start/stop, replay start/stop, mitigation request/approve/deny/execute)
and every 401/403 lands in the `audit_log` table with actor, target,
status, IP, and user-agent. The dashboard exposes an admin-only Audit
Log page with prefix-filter and CSV export.

### Human-in-loop mitigation

An analyst clicks **Request Block** on an attack-labelled row in the
alerts table. The request lands in `mitigation_request` with status
`pending`. An admin reviews the request on the Mitigation page and
either approves or denies. A 5-second two-person guard prevents an
admin from approving a request they created themselves (it returns 403
and logs the attempt). On approval, `src/mitigation/firewall.py`
invokes `netsh advfirewall firewall add rule` to block the source IP
inbound on the host firewall, writes the result to `mitigation_action`,
and records every step in the audit log. Failed netsh executions are
surfaced in a dedicated "Recent Failed Executions" table on the
Mitigation page rather than being silently swallowed.

### Demo dashboard

Real-time alerts table, score distribution chart, top-source-prefix bar
chart, alerts-over-time. The capture-interface dropdown shows friendly
labels (e.g. `Wi-Fi — Intel(R) Wi-Fi 6 AX201 160MHz`) instead of raw
NPF GUIDs. The Request Block dropdown excludes the local host's own
IPs (resolved via `socket.gethostname`) so an operator cannot
accidentally self-block, and deduplicates by source IP so a high-volume
single attacker collapses to one selectable row.

## Project Structure

```
ai_ids_complete/
├── START.bat                      Double-click (admin) to run everything
├── launch.py                      Supervisor: uvicorn + Streamlit
├── README.md                      This file
├── CHANGES.md                     Dated change log
├── CURRENT_STATE.md               Architecture snapshot
├── RECONCILIATION_PHASE2.md       Phase 1 claims → Phase 2 reality
├── FUTURE_WORK.md                 Deferred-extension roadmap
├── src/
│   ├── auth/                      passwords, tokens, audit, RBAC
│   ├── capture/                   live_capture (FlowAggregator, frozen)
│   ├── data/                      prep_cic2017, mock_data
│   ├── mitigation/                firewall (netsh wrapper)
│   ├── models/                    train.py
│   ├── serve/                     app.py, auth_routes.py, mitigation_routes.py
│   └── utils/                     db.py, helpers.py
├── dashboard/
│   ├── app.py                     Main SOC console
│   ├── auth_ui.py                 Login + api_request helper
│   └── pages/                     1_Users, 2_Audit_Log, 3_Mitigation
├── models/                        Trained .joblib + threshold.txt (frozen)
├── data/                          ids.db, blocked_ips.json, cic_profiles.json
├── tools/                         bootstrap_admin, dev_up, diagnose_*, replay_*
├── tests/                         test_firewall, test_mitigation_routes, test_smoke
├── lab/                           ATTACK_VALIDATION, ATTACK_PROFILES, attack_log
├── defense/                       DEMO_SCRIPT, QA_BANK
├── env/requirements.txt
├── _project/                      HARD_CONSTRAINTS, 4_WEEK_PLAN, etc.
└── _stages/                       Per-week stage briefs
```

## Demo

A scripted 5-minute live attack walkthrough (Kali slowhttptest against
the Windows host, end-to-end through detection → request → approve →
netsh block → unblock → audit) is in `defense/DEMO_SCRIPT.md`, which
also carries the pre-demo checklist and the backup-video fallback
procedure. The backup video that procedure points to
(`defense/demo_backup.mp4`) is recorded during dress rehearsal and is
not committed to the repo.

Two further defense companions accompany this README:
`RECONCILIATION_PHASE2.md` maps each Phase 1 proposal claim (FRs,
non-functional requirements, use cases, scope) to its Phase 2
implementation, and `defense/QA_BANK.md` holds anticipated panel
questions with prepared, evidence-cited answers. The deferred-extension
roadmap is in `FUTURE_WORK.md`.

## Known Limitations

- **Third-party kernel-mode AV co-existence.** Avast, Kaspersky, ESET
  and Norton install WFP callouts and/or NDIS lightweight filters that
  sit below Windows Defender Firewall in the packet processing stack.
  While such filters are active, AI-IDS-issued netsh block rules are
  created correctly but bypassed on the AV-bound path. Disable AV
  shields ("until restart") or configure an exclusion before relying
  on enforcement. Diagnosed during Week 3 with
  `tools/diagnose_round2.ps1`; documented in `CHANGES.md`
  (2026-05-25 closeout entry) and `FUTURE_WORK.md` §7.

- **Scan and flood detection.** Tools like `nmap -sS` and
  `hping3 --flood` produce 2-packet singleton flows that fall outside
  the CIC-IDS2017 training distribution; the binary head's
  precision drops on these. Per-flow aggregation is a Phase 1 design
  choice preserved through Phase 2 (see `_project/HARD_CONSTRAINTS.md`).
  Cross-flow correlation for scan/flood detection is documented as a
  designed-on-paper extension in `FUTURE_WORK.md` §2.

- **Multi-class drift on novel attacks.** The binary head remains
  reliable in live conditions; the multi-class head tends to collapse
  out-of-distribution attacks toward `DoS` (e.g. `nikto` reconnaissance
  is labelled `DoS`). Drift behaviour is characterised in
  `lab/ATTACK_VALIDATION.md`. Mitigation triggers off the binary label,
  not the multi-class label, so this is a labelling-fidelity issue,
  not a missed-detection issue.

- **Unblock recovery quirk.** After `netsh advfirewall firewall delete
  rule` succeeds, Windows occasionally holds in-kernel filter state
  for the previously-blocked remote. Restarting the target listener
  (or `Restart-Service mpssvc` on Pro/Enterprise SKUs) clears it.
  Environmental, not an AI-IDS defect; see `FUTURE_WORK.md` §7.

- **Single-machine deployment.** No endpoint agent, no multi-host
  fleet support. Sketched in `FUTURE_WORK.md` §1 as a designed-on-paper
  extension.

- **Encrypted-channel attack validation.** Not in scope for Phase 2.
  Sketched in `FUTURE_WORK.md` §4.

Full extension roadmap in `FUTURE_WORK.md`.

## Tests

The test suite covers per-component invariants and end-to-end wiring.
Run with:

```
pytest tests/
```

The smoke test (`tests/test_smoke.py`) boots the FastAPI app in-process
via `TestClient` and exercises the full chain — auth → `/predict` →
mitigation request → admin approval → mocked `netsh` execution → audit
log — then verifies the nine core ERD/auth/mitigation tables are
present. (The schema in `src/utils/db.py` defines ten tables in total:
four Phase 1 ERD + three Week 2 auth + two Week 3 mitigation + one
Week 4 security table, `login_attempts`, added by W4-Sub4d and not in
the smoke test's expected set.) It runs in roughly 13 seconds and
needs no admin elevation, no network interface, no Kali VM, and no AV
changes. It is the safety net for refactors: if it passes, the wiring
is intact.

Existing test coverage:

- `tests/test_firewall.py` — 6 tests on the netsh wrapper
  (`src/mitigation/firewall.py`)
- `tests/test_mitigation_routes.py` — 12 tests on the mitigation
  endpoints, RBAC, and the two-person rule
- `tests/test_smoke.py` — 3 tests on end-to-end app wiring
- `tests/test_login_lockout.py` — 3 tests on login timing
  equalization and per-user lockout

Total: 24 tests; the full suite runs in ~24 seconds.

## Team

- **Muhammad Usman Tariq** (SAP 70139691)
- **Muhammad Mousa Khan** (SAP 70140245)
- **Supervisor:** Dr. Nadeem Iqbal, Department of CS&IT, The University
  of Lahore

## Academic Use

This project was developed as a Final Year Project at the University of
Lahore. Code and documentation are provided for academic and
educational reference. The CIC-IDS2017 dataset is used under its
public-research license. Third-party libraries retain their respective
open-source licenses.
