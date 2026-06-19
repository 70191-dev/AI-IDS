# AI-IDS — Master Project Context

> **AI-Driven Intrusion Detection and Threat Mitigation System for Secure Networks**
> Final Year Project, BSCS — University of Lahore. Project ID **Fall-2025-104**.
> Single comprehensive, code-grounded reference for the implementation as it
> exists in this repository. Every factual claim below is traceable to a file
> in the tree; inferences are explicitly labelled **(inferred)**.

**Generated:** 2026-05-31 · **Backend version (from `src/serve/app.py`):** `2.2.0`
**Project stage (from `_stages/CURRENT_STAGE.md`):** Week 4 — Polish + defense (ACTIVE)

---

## Table of Contents

1. [Project Summary](#1-project-summary)
2. [Scope](#2-scope)
3. [Architecture](#3-architecture)
4. [Tech Stack](#4-tech-stack)
5. [Directory & File Map](#5-directory--file-map)
6. [Functional & Non-Functional Requirements](#6-functional--non-functional-requirements)
7. [Module Reference](#7-module-reference)
8. [API Reference](#8-api-reference)
9. [Database Schema](#9-database-schema)
10. [ML Model](#10-ml-model)
11. [Auth & RBAC](#11-auth--rbac)
12. [Mitigation](#12-mitigation)
13. [AI Incident Report (LLM)](#13-ai-incident-report-llm)
14. [Dashboard](#14-dashboard)
15. [Setup & Run (from zero)](#15-setup--run-from-zero)
16. [Configuration](#16-configuration)
17. [Testing & Validation](#17-testing--validation)
18. [Limitations & Future Work](#18-limitations--future-work)
19. [Defense Reconciliation](#19-defense-reconciliation)
20. [Change Log Summary](#20-change-log-summary)

---

## 1. Project Summary

**What it is.** A standalone, Windows-based, fully-offline network Intrusion
Detection System (IDS) with human-in-the-loop threat mitigation. It captures
or replays network flows, classifies each flow with a two-stage Random Forest
model trained on CIC-IDS2017, raises severity-rated alerts, persists everything
to a single SQLite file, and lets a two-role SOC team (admin / analyst) request
and approve IP blocks that are enforced on the host via Windows Firewall
(`netsh advfirewall`). A Streamlit dashboard is the operator console, and a
local LLM (Ollama) can write plain-English incident reports on demand.

**The problem it solves.** Small/single-host environments that cannot run a
cloud SIEM still need (a) ML-based detection of malicious traffic, (b) an
auditable record of who saw and acted on each alert, and (c) a controlled way
to block attackers without a single operator unilaterally cutting connectivity.
AI-IDS delivers all three on one machine with no external dependencies.

**Intended users.** Two roles, defined in `src/auth/rbac.py`:
- **analyst** — monitors the dashboard and *requests* blocks.
- **admin** — everything an analyst can do, plus user management, audit-log
  access, capture/replay control, and *approval* of blocks.

**Current version.** The FastAPI application declares
`version="2.2.0"` and `title="AI-IDS Detection API"`
(`src/serve/app.py` lines 207–213); the module docstring labels it "v2.2".
`CHANGES.md` is titled "FYP Submission Pass" and its newest dated entry is
**2026-05-31** (report-panel reliability fixes).

**Team & supervision** (from `README.md` / `CLAUDE.md` / `AGENTS.md`):
Muhammad Usman Tariq (SAP 70139691) and Muhammad Mousa Khan (SAP 70140245),
supervised by Dr. Nadeem Iqbal, Department of CS&IT, The University of Lahore.
The project is described as "Phase 1 shipped and defended; Phase 2 built on top
of the preserved Phase 1 ML pipeline."

---

## 2. Scope

### In scope (implemented in this repo)
- Live packet capture (scapy + Npcap) **and** synthetic flow replay, both
  feeding the same `/predict` endpoint.
- Two-stage Random Forest classification: binary (Benign vs Attack) +
  multi-class (8 families).
- Severity rating, mitigation-recommendation lookup, CSV + SQLite persistence.
- Two-role RBAC, opaque server-side sessions, bcrypt password hashing,
  append-only audit log, per-user login lockout.
- Human-in-the-loop mitigation: request → approve (two-person rule) → `netsh`
  block → audit, plus unblock.
- Streamlit SOC dashboard (main console + Users / Audit Log / Mitigation pages),
  optionally hosted in a native desktop window via pywebview.
- Advisory, read-only AI incident reports via a local Ollama model.

### Explicitly out of scope
`_project/HARD_CONSTRAINTS.md` ("Stack — do not introduce") forbids, and the
codebase therefore omits:
- **Cloud / external services** — everything runs on loopback; no outbound calls.
- **PostgreSQL** — SQLite is the deliberate single-file store.
- **Docker / docker-compose** — listed as out of scope. *(A stale
  `docker/docker-compose.yml` still exists in the tree; see
  [§19 Defense Reconciliation](#19-defense-reconciliation) for this contradiction.)*
- **Frontend rewrites** (NiceGUI/React/Vue) — Streamlit stays.
- **OAuth, SSO, 2FA, email verification, password-reset flows.**
- **Endpoint agents / multi-machine / multi-tenant isolation** — single host only.
- **Redis / RabbitMQ / Celery; PyInstaller/installers.**
- **Linux mitigation (iptables)** — mitigation is Windows `netsh` only.
- **More than two roles** — "admin and analyst. No viewer, no auditor."

---

## 3. Architecture

### 3.1 Pipeline (capture → preprocess → classify → alert → mitigate → dashboard)

```
 packet on wire / synthetic flow
        │
        ▼
 [CAPTURE]   src/capture/live_capture.py  (scapy sniff, Npcap)   ──┐
             tools/replay_loop.py         (CIC-profile sampler)  ──┤  both POST /predict
        │                                                          │
        ▼                                                          │
 [PREPROCESS] FlowAggregator → 50 UNIFIED_FEATURES  (live)         │
             prep_cic2017.py → same schema           (offline train)
        │                                                          │
        ▼                                                          │
 [CLASSIFY]  POST /predict  (src/serve/app.py)  ◀───────────────────┘ loopback-only
             RF binary  →  score ≥ threshold ? Attack : Benign
             if Attack: RF multi-class → one of 8 families
        │
        ▼
 [ALERT]     helpers.get_severity(score) → Critical/High/Medium/Low
             helpers.get_mitigation(type,severity) → recommendation dict
        │
        ▼
 [PERSIST]   db.insert_flow_result(...) — ONE transaction:
             traffic_flow → detection_result → alert → mitigation_record
             (+ logs/alerts.csv backup, + in-memory recent_alerts deque)
        │
        ▼
 [DASHBOARD] Streamlit polls /alerts /stats /health every 4s
        │
        ▼
 [MITIGATE]  analyst POST /mitigation/requests  (pending)
             admin   POST /mitigation/requests/{id}/approve
                     → firewall.block_ip() → netsh advfirewall add rule
                     → mitigation_action row + audit_log chain
```

### 3.2 Runtime processes (all loopback / offline)

```
        ┌─────────────────────────────────────────────────────────────┐
        │  Windows host (single machine, no cloud)                     │
        │                                                              │
        │   ┌──────────────────────┐      ┌──────────────────────┐    │
        │   │ Streamlit SOC console │      │ desktop_app.py        │    │
        │   │ dashboard/app.py      │◀────▶│ pywebview window      │    │
        │   │ http://127.0.0.1:8501 │      │ (hosts :8501)         │    │
        │   └──────────┬───────────┘      └──────────────────────┘    │
        │              │ HTTP + Bearer token                           │
        │              ▼                                               │
        │   ┌──────────────────────────────────────────────┐          │
        │   │ FastAPI (uvicorn)  http://127.0.0.1:8000      │          │
        │   │ src/serve/app.py + auth/mitigation/report     │          │
        │   └───┬─────────────┬──────────────┬──────────────┘          │
        │       │             │              │                         │
        │       ▼             ▼              ▼                         │
        │  ┌─────────┐  ┌───────────┐  ┌──────────────┐                │
        │  │ RF .joblib│ │ SQLite    │  │ netsh        │                │
        │  │ models/  │  │ data/ids.db│  │ advfirewall  │                │
        │  └─────────┘  └───────────┘  └──────────────┘                │
        │                                                              │
        │   ┌──────────────────────────────────────────────┐          │
        │   │ Ollama (optional)  http://127.0.0.1:11434     │          │
        │   │ llama3.2:1b — advisory incident reports only  │          │
        │   └──────────────────────────────────────────────┘          │
        │                                                              │
        │   Traffic sources (loopback POST → /predict):                │
        │     • scapy live capture thread (in-process)                 │
        │     • tools/replay_loop.py (subprocess)                      │
        └─────────────────────────────────────────────────────────────┘
```

- **FastAPI :8000** — bound to `127.0.0.1` by `launch.py`. Hosts detection,
  auth, mitigation, report, and capture/replay control. `/predict` is
  additionally restricted to loopback callers in code.
- **Streamlit :8501** — the only browser-facing surface; CORS on the API is
  pinned to `http://localhost:8501` / `http://127.0.0.1:8501`.
- **Ollama :11434** — optional, advisory-only; if absent the report feature
  degrades to a 503 and nothing else is affected.

### 3.3 End-to-end data flow: one packet → displayed alert → approved block

1. A packet arrives on the capture interface. `FlowAggregator.add_packet`
   buckets it into a bidirectional 5-tuple flow
   (`src/capture/live_capture.py`).
2. After 5 s of inactivity (`FLOW_TIMEOUT`), the flush thread extracts the
   50-feature vector and POSTs `{flow_id:"live-…", features, src_ip, …}` to
   `http://127.0.0.1:8000/predict`.
3. `predict()` checks the caller is loopback, aligns features to
   `feature_names`, runs `model_binary.predict_proba` → `score`,
   compares to `THRESHOLD` (0.3858) → `label`. If Attack, `model_multi`
   assigns `attack_type` and `attack_confidence`.
4. `get_severity(score)` → severity; `get_mitigation(attack_type, severity)` →
   recommendation dict.
5. `db.insert_flow_result(...)` writes `traffic_flow` (+ `detection_result`,
   and for attacks `alert` + `mitigation_record`) in one transaction; the
   `alert.id` is returned. A CSV row and a `recent_alerts` deque entry are added.
6. The dashboard's 4 s `st_autorefresh` pulls `/alerts` and renders the row;
   attack rows are tinted red and carry the `alert_id`.
7. An **analyst** picks the attacker IP and clicks **Request Block** →
   `POST /mitigation/requests` → row in `mitigation_request` (status `pending`).
8. An **admin** opens the Mitigation page and clicks **Approve & Block** →
   `POST /mitigation/requests/{id}/approve`. The two-person rule (5 s) is
   checked, the request flips to `approved`, `firewall.block_ip()` runs
   `netsh advfirewall firewall add rule … action=block remoteip=<ip>`, a
   `mitigation_action` row records the netsh result, and every step is written
   to `audit_log`. The block also appears in `data/blocked_ips.json`
   (the netsh ledger) and on the dashboard's Active Blocks panel.

---

## 4. Tech Stack

**`env/requirements.txt` (verbatim):**

```
numpy
pandas
scikit-learn
joblib
fastapi
uvicorn
streamlit
streamlit-autorefresh
plotly
pyarrow
requests
scapy
matplotlib
passlib[bcrypt]==1.7.4
bcrypt==4.0.1
# pywebview: native desktop window wrapper for the SOC dashboard
pywebview==6.2.1
```

| Dependency | Role in this project |
|---|---|
| `numpy` | Numeric arrays; feature math in capture, replay, training, prep. |
| `pandas` | DataFrames for training data, feature alignment in `/predict`, dashboard tables. |
| `scikit-learn` | `RandomForestClassifier`, `Pipeline`, `RobustScaler`, metrics, threshold tuning. |
| `joblib` | Serialise/load the trained `.joblib` models. |
| `fastapi` | REST API framework (`src/serve/*`). |
| `uvicorn` | ASGI server hosting the FastAPI app on :8000. |
| `streamlit` | SOC dashboard + admin pages. |
| `streamlit-autorefresh` | 4 s auto-tick on the main dashboard. |
| `plotly` | Score histogram + top-source bar chart. |
| `pyarrow` | Parquet I/O for `data/processed/train.parquet`. |
| `requests` | HTTP client (capture→/predict, replay→/predict, dashboard→API, report→Ollama). |
| `scapy` | Live packet capture / interface enumeration (needs Npcap on Windows). |
| `matplotlib` | Optional training plots (`reports/threshold_tuning.png`, confusion matrix). |
| `passlib[bcrypt]==1.7.4` | `CryptContext` wrapper for password hashing. |
| `bcrypt==4.0.1` | Bcrypt backend (cost factor 12). |
| `pywebview==6.2.1` | Native OS window wrapping the Streamlit UI (`desktop_app.py`). |

**Other stack facts:**
- **Python:** `README.md` states **Python 3.12**; cached bytecode in the tree is
  `cpython-312`, consistent with 3.12. (`docker/docker-compose.yml` references
  `python:3.11-slim`, contradicting this — see [§19](#19-defense-reconciliation).)
- **OS:** Windows (mitigation uses `netsh advfirewall`; elevation probed via
  `ctypes.windll.shell32.IsUserAnAdmin`). Capture additionally needs **Npcap**.
- **Open-source / offline:** all dependencies are permissive OSS; CIC-IDS2017 is
  used under its public-research license (`README.md` "Academic Use"). No cloud,
  no telemetry.
- **Local LLM (runtime, not pip):** Ollama serving `llama3.2:1b` on
  `127.0.0.1:11434` (optional).

---

## 5. Directory & File Map

```
ai_ids_complete/
├── CLAUDE.md / AGENTS.md         Always-loaded project memory for AI assistants
├── README.md                     Human-facing overview, quick start, limitations
├── CHANGES.md                    Dated change log (FYP submission pass)
├── CURRENT_STATE.md              Architecture/state snapshot (large)
├── RECONCILIATION_PHASE2.md      Phase 1 proposal claim → Phase 2 reality map
├── FUTURE_WORK.md                Designed-on-paper extension roadmap (10 sections)
├── FYP_PHASE_2_FULL_CONTEXT.md   Pre-existing large context doc (~103 KB)
├── START.bat                     Admin-only entry point (venv→deps→train→launch)
├── launch.py                     Supervisor: uvicorn + Streamlit + desktop window
├── desktop_app.py                pywebview wrapper opening :8501 in a native window
├── sample_request.json           Example /predict body (flow_id "demo-001", 38 feats)
├── .gitignore                    Ignores .venv, models/*.joblib, data/ids.db, etc.
│
├── src/
│   ├── serve/
│   │   ├── app.py                FastAPI app: /health /predict /alerts /stats,
│   │   │                         capture & replay control, lifespan model load
│   │   ├── auth_routes.py        /auth/* /users/* /audit
│   │   ├── mitigation_routes.py  /mitigation/* (request/approve/deny/block/unblock)
│   │   └── report_routes.py      GET /report/{alert_id} (local-LLM incident report)
│   ├── auth/
│   │   ├── rbac.py               PERMISSIONS matrix + require_permission() dependency
│   │   ├── passwords.py          bcrypt CryptContext, timing-equalisation dummy hash
│   │   ├── tokens.py             opaque session tokens, validate/create/revoke
│   │   └── audit.py              log_audit() — single audit-log writer
│   ├── capture/
│   │   └── live_capture.py       FlowAggregator + scapy sniff + run_in_thread (FROZEN)
│   ├── data/
│   │   ├── prep_cic2017.py       CIC CSV → 50 UNIFIED_FEATURES parquet (FROZEN schema)
│   │   └── mock_data.py          Synthetic CIC-style data generator (FROZEN schema)
│   ├── mitigation/
│   │   └── firewall.py           netsh advfirewall wrapper (is_admin/validate/block/unblock)
│   ├── models/
│   │   └── train.py              Trains binary + multi-class RF (FROZEN — do not edit)
│   └── utils/
│       ├── db.py                 SQLite schema (10 tables) + insert_flow_result + reads
│       └── helpers.py            severity thresholds, MITIGATION_DB, CSV logger
│
├── dashboard/
│   ├── app.py                    Main SOC console (Live State, alerts, request-block, AI report)
│   ├── auth_ui.py                Login flow + bearer-aware api_request() wrapper
│   └── pages/
│       ├── 1_Users.py            Admin: user CRUD, role change, disable/enable
│       ├── 2_Audit_Log.py        Admin: filter/export audit_log
│       └── 3_Mitigation.py       Admin: pending requests, active blocks, failures
│
├── models/
│   ├── rf_binary.joblib          Binary RF (also copied to rf.joblib)
│   ├── rf.joblib                 Backward-compat copy of binary
│   ├── rf_cic_binary.joblib      CIC-trained binary (PRIMARY loaded by API)
│   ├── rf_multi.joblib           Multi-class RF
│   ├── rf_cic_multi.joblib       CIC-trained multi-class (PRIMARY loaded by API)
│   ├── model_meta.json           feature_names, class_names, class maps, threshold, metrics
│   └── threshold.txt             0.385841 (F1-optimal binary threshold)
│
├── data/
│   ├── ids.db                    SQLite store (gitignored; created at runtime)
│   ├── blocked_ips.json          netsh block/unblock ledger (firewall.py)
│   ├── cic_profiles.json         Per-class CIC feature distributions (replay sampler)
│   ├── processed/
│   │   ├── train.parquet         Training data (418,481 rows, 50 features)
│   │   ├── class_map.json        {Benign:0 … Web Attack:7}
│   │   └── data_info.json        Source=CIC-IDS2017, class distribution, balancing config
│   └── downloads/MachineLearningCSV/MachineLearningCVE/*.csv   Raw CIC-IDS2017 CSVs
│
├── evaluation/
│   ├── metrics.json              Binary/multi metrics + threshold (from train.py)
│   └── evaluation_report.txt     Human-readable metrics + confusion matrices
│
├── tools/
│   ├── replay_loop.py            Mixed benign/attack replay (used by /replay/start)
│   ├── replay_attack.py          Attack-only replay, per-type detection check
│   ├── replay_dos.py             DoS-focused replay helper
│   ├── extract_cic_profiles.py   Builds data/cic_profiles.json from train.parquet
│   ├── bootstrap_admin.py        One-time CLI to create the first admin user
│   ├── dev_up.bat / dev_up.ps1   Dev launcher (auto-start capture on a NIC)
│   └── diagnose_firewall_block.ps1 / diagnose_round2.ps1   netsh/AV diagnostics
│
├── tests/
│   ├── test_firewall.py          6 tests on the netsh wrapper
│   ├── test_mitigation_routes.py 12 tests on mitigation endpoints + two-person rule
│   ├── test_smoke.py             3 tests: end-to-end auth→predict→mitigation→audit
│   └── test_login_lockout.py     3 tests: timing equalisation + per-user lockout
│
├── lab/
│   ├── ATTACK_VALIDATION.md      Week-1 Kali validation writeup (recall numbers)
│   ├── ATTACK_PROFILES.md        Planned attack tool profiles
│   └── attack_log.csv            Attack windows (start/end ts) used for SQL queries
│
├── defense/
│   ├── DEMO_SCRIPT.md            5-minute live demo runbook
│   └── QA_BANK.md                Anticipated panel Q&A with citations
│
├── env/requirements.txt          Dependency list (see §4)
├── docker/docker-compose.yml     OUT OF SCOPE / stale (binds 0.0.0.0; see §19)
├── .streamlit/config.toml        Streamlit theme (dark) + port 8501
├── _project/                     HARD_CONSTRAINTS, 4_WEEK_PLAN, HOW_TO_WORK_HERE, RESUME
├── _stages/                      CURRENT_STAGE.md + per-week CONTEXT briefs
├── logs/                         alerts.csv, fastapi.log, replay.log (runtime)
└── reports/                      training plots (runtime)
```

*Note:* the repo also contains many `*.bak*` backups and root-level ad-hoc
diagnostic scripts (`check_*.py`, `inspect_db.py`, `verify_ips.py`), plus WFP
capture artifacts (`wfp_*.xml`, `wfp_capture.etl.cab`) produced during the
Week-3 AV/firewall diagnosis. These are developer scratch artifacts, not part
of the runtime path. **(inferred from filenames/content)**

---

## 6. Functional & Non-Functional Requirements

Mapped to the implementing modules (proposal FR IDs from
`RECONCILIATION_PHASE2.md`):

| FR | Requirement | Implemented by |
|---|---|---|
| **FR_01** | Capture live network traffic from a chosen interface | `src/capture/live_capture.py` (`FlowAggregator`, `scapy_capture`, `run_in_thread`); control endpoints `GET /capture/interfaces`, `POST /capture/start`/`stop`, `GET /capture/status` in `src/serve/app.py`. |
| **FR_02** | Preprocess traffic & extract features | Live: `FlowAggregator._extract_features` → 50 features. Offline: `src/data/prep_cic2017.py` (CIC CSV → `UNIFIED_FEATURES`), `src/data/mock_data.py` (synthetic). |
| **FR_03** | Classify as benign/malicious with ML | `POST /predict` in `src/serve/app.py`: binary `predict_proba` ≥ threshold → label; multi-class head → family. Models trained by `src/models/train.py`. |
| **FR_04** | Generate alerts, logs, severity, mitigation info | `helpers.get_severity` / `helpers.get_mitigation`; persistence `db.insert_flow_result` (traffic_flow→detection_result→alert→mitigation_record); CSV backup `helpers.log_alert`; audit via `src/auth/audit.py`. |
| **FR_05** | View alerts/logs/mitigation via GUI | `dashboard/app.py` + `dashboard/pages/*`; reads `/alerts`, `/stats`, `/health`, `/mitigation/*`, `/audit`. |
| **Auth/RBAC/Audit** (Phase 2) | Login, roles, permission gating, audit trail | `src/auth/{rbac,passwords,tokens,audit}.py`, `src/serve/auth_routes.py`, `tools/bootstrap_admin.py`. |
| **Mitigation/Blocking** (Phase 2) | Request→approve→`netsh` block + unblock | `src/serve/mitigation_routes.py` + `src/mitigation/firewall.py` + `dashboard/pages/3_Mitigation.py`. |
| **AI report** (Phase 2) | Plain-English incident report | `src/llm/report.py` + `src/serve/report_routes.py` + dashboard report fragment. |

**Non-functional requirements** (from `RECONCILIATION_PHASE2.md` §2, grounded
against code):
- **Offline / standalone** — all services bind loopback; no outbound calls
  except to local Ollama. SQLite single file at `data/ids.db`.
- **Near-real-time** — capture flush every 3 s, flow timeout 5 s; dashboard
  ticks every 4 s; `/predict` is a single RF inference. (Doc claims `/predict`
  < ~20 ms warm; not independently benchmarked here.)
- **Simple GUI** — Streamlit, two-role gated, friendly NIC labels, dedup.
- **Modular** — clear `src/{auth,capture,data,mitigation,models,serve,utils}`
  boundaries; additive-only schema/API rules in `HARD_CONSTRAINTS.md`.
- **Open-source** — see [§4](#4-tech-stack).

---

## 7. Module Reference

### `src/serve/app.py` — FastAPI core + traffic-source control
- **Project-root discovery + model loading.** `load_threshold()` (env →
  `model_meta.json` → `threshold.txt` → 0.5); `load_model(primary, *fallbacks)`.
  The `lifespan` async context loads the binary model
  (`rf_cic_binary.joblib` → `rf_binary.joblib` → `rf.joblib`), the multi-class
  model (`rf_cic_multi.joblib` → `rf_multi.joblib`), reads `model_meta.json`
  (`feature_names`, `class_names`, `reverse_class_map`, `data_source`), calls
  `db.init_db()`, and hydrates the `recent_alerts` deque (maxlen 1000) from SQL.
- **Schemas (Pydantic):** `Flow{flow_id, features:dict, src_ip?, dst_ip?,
  src_port?, dst_port?, protocol?}`, `PredictionResult{flow_id, score, label,
  label_text, attack_type, attack_confidence, severity, mitigation, timestamp}`,
  `CaptureStartReq{iface?}`, `ReplayStartReq{rate=5.0, attack_ratio=0.45}`.
- **Helpers:** `build_feature_df(features)` (zero-fills missing features, scrubs
  inf/NaN), `_infer_source_mode(flow_id)` (`live-`→live, `demo-`→manual, else
  replay), `_normalize_npf_iface(name)` (pads bare-GUID NIC names to
  `\Device\NPF_…`), `_audit_action(...)` (success audit for capture/replay).
- **Capture/replay state** is held in module dicts guarded by
  `_capture_lock` / `_replay_lock`; replay is launched as a subprocess running
  `tools/replay_loop.py`.
- `LOOPBACK_HOSTS = {"127.0.0.1","::1","localhost"}` gate for `/predict`.

### `src/serve/auth_routes.py` — auth, users, audit-read
- Constants: `USERNAME_RE = ^[A-Za-z0-9_]{3,32}$`, `PASSWORD_MIN_LEN = 12`,
  `VALID_ROLES = ("admin","analyst")`, `LOGIN_LOCKOUT_THRESHOLD = 5`,
  `LOGIN_LOCKOUT_MINUTES = 15`.
- `auth_login` enforces lockout (in SQLite UTC), verifies bcrypt, equalises
  timing on the missing/disabled-user path, opportunistically rehashes, records
  `last_login_at`, creates a session, and audits success/failure.
- `users_create` / `users_patch` enforce validation + self-protection (no
  self-demote, no self-disable; disabling revokes the user's sessions).
- `audit_list` supports `limit`, `since`, `action` (prefix), `actor`, `status`.

### `src/serve/mitigation_routes.py` — request/approve/deny/block/unblock
- `TWO_PERSON_RULE_SECONDS = 5`, `MAX_REASON_LEN = 500`.
- `_allow_private_for_lab()` reads `MITIGATION_ALLOW_PRIVATE` (default reject
  private ranges). `_now_iso()` emits UTC `…Z` microsecond timestamps matching
  the firewall ledger. `_parse_iso_z()` parses both timestamp shapes.
- Endpoints create requests (reject duplicate pending per IP), approve (enforce
  two-person rule, then `firewall.block_ip`), deny, list blocked (enriched from
  DB), unblock, list netsh failures, and an admin-only `_diag/elevation` probe.
  A netsh failure on approve does **not** roll back the approval (honest audit).

### `src/serve/report_routes.py` — AI incident report
- `GET /report/{alert_id}` (gated `view.dashboard`): read-only join over
  `alert`/`detection_result`/`traffic_flow`/`mitigation_record`; falls back to
  `get_mitigation()` recommendations if the stored row is sparse; calls
  `report.generate_report(...)`; returns `ReportResponse{report, model,
  alert_id}` or `503` on `ReportUnavailable`.

### `src/auth/rbac.py` — permission matrix + dependency factory
- `PERMISSIONS` dict (see [§11](#11-auth--rbac)); `has_permission(role, perm)`;
  `_extract_bearer(request)`; `require_permission(perm)` returns a FastAPI
  dependency that 401s on missing/invalid token (audited `auth.failed`) and
  403s on insufficient role (audited `permission.denied`), else returns
  `{user_id, username, role, session_id}`.

### `src/auth/passwords.py` — hashing
- `BCRYPT_ROUNDS = 12`; `pwd_context = CryptContext(schemes=["bcrypt"],
  deprecated="auto", bcrypt__rounds=12)`. `hash_password`, `verify_password`,
  `needs_rehash`, and `verify_dummy_for_timing()` (constant-time defence against
  username enumeration).

### `src/auth/tokens.py` — opaque sessions
- `SESSION_TTL_HOURS = 8`; `generate_token()` = `secrets.token_urlsafe(32)`
  (not JWT). `create_session`, `validate_token` (joins session→user; rejects
  revoked/disabled/expired and bumps `last_seen_at`), `revoke_token`,
  `cleanup_expired_sessions`.

### `src/auth/audit.py` — `log_audit(conn, *, actor_user_id, actor_username,
action, target, status, detail, ip, ua)` — the single writer for `audit_log`;
validates `status ∈ {success, failure}`.

### `src/capture/live_capture.py` — FROZEN per HARD_CONSTRAINTS
- `FLOW_TIMEOUT = 5.0`, `FLUSH_INTERVAL = 3.0`. `FlowAggregator` keys flows by
  bidirectional 5-tuple, tracks fwd/bwd packets/lengths/IATs/flags, and
  `_extract_features` emits all 50 `UNIFIED_FEATURES` (38 base + 12
  schema-parity; `active_std`/`idle_std` use the `mean*0.5` fill that
  `prep_cic2017.py` uses; `init_win_bytes_*` approximated at 8192).
  `scapy_capture` uses `sniff(..., stop_filter=…)`. `run_in_thread(iface,
  api_url)` probes `conf.L2listen` so `PermissionError` surfaces synchronously,
  then runs sniff + flush threads under a supervisor.

### `src/data/prep_cic2017.py` — FROZEN schema
- Maps 78 CIC columns → 50 snake_case `UNIFIED_FEATURES` (`CIC_COLUMN_MAP`),
  `map_family()` collapses raw labels into the 8 families, balances classes
  (`MAX_PER_CLASS = 100_000`, `MIN_PER_CLASS = 500`; oversampling adds 1 %
  Gaussian noise), derives any missing features, writes `train.parquet`,
  `class_map.json`, `data_info.json`.

### `src/data/mock_data.py` — FROZEN schema
- Per-class distribution specs (`CLASS_PROFILES`) sampled into the same 50
  features + 3 % label noise; writes `train.parquet` + `class_map.json`. Used
  by `START.bat`/`train.py` when no real CIC data is present.

### `src/models/train.py` — FROZEN (do not edit)
- Two-stage trainer. Binary: `Pipeline(RobustScaler, RandomForest(n_estimators=
  500 CIC/400, max_depth=30/25, min_samples_leaf=3, class_weight=
  balanced_subsample, random_state=42))`. Multi: `n_estimators=600/500,
  max_depth=35/30, min_samples_leaf=2`. `find_optimal_threshold` maximises F1 on
  the PR curve → `threshold.txt`. Writes both generic and `rf_cic_*` model
  copies, `model_meta.json`, `evaluation/metrics.json`,
  `evaluation/evaluation_report.txt`, and plots.

### `src/mitigation/firewall.py` — netsh wrapper (stdlib only)
- `RULE_NAME_PREFIX = "AI-IDS Block"`, ledger `data/blocked_ips.json`,
  `NETSH_TIMEOUT_SECONDS = 10`. `is_admin()` via `IsUserAnAdmin`;
  `validate_ip(ip, *, allow_private=False)` rejects unspecified/loopback/
  link-local/multicast/reserved/private; `block_ip`/`unblock_ip` shell out to
  `netsh advfirewall firewall add|delete rule` (idempotent; never raise — return
  a result dict); `list_blocked_ips()` reads the ledger.

### `src/utils/db.py` — SQLite layer
- `get_conn()` (FK on, WAL, Row factory), `init_db()` (idempotent
  `SCHEMA_DDL`), `insert_flow_result(...)` (one transaction across 2–4 ERD
  tables), `fetch_recent_alerts`, `fetch_stats`, `table_counts`. DB path
  overridable via `IDS_DB_PATH`.

### `src/utils/helpers.py` — severity + recommendations + CSV
- `SEVERITY_THRESHOLDS` (Critical 0.95 / High 0.80 / Medium 0.60 / Low 0.40),
  `get_severity(score)`, `MITIGATION_DB` (per-family recommendation playbooks by
  severity) + `GENERIC_MITIGATION`, `get_mitigation(attack_type, severity)`,
  `log_alert(...)` (CSV backup with 5 MB rotation).

### `dashboard/` — see [§14](#14-dashboard).

---

## 8. API Reference

All endpoints are mounted on the single FastAPI app (`src/serve/app.py`) and
served at `http://127.0.0.1:8000`. "Permission" is the argument to
`require_permission(...)`; endpoints with no permission listed are open
(read-only status) except `/predict`, which is **loopback-restricted in code**.

### Core router (`src/serve/app.py`)

| Method | Path | Auth/Perm | Purpose / notes |
|---|---|---|---|
| GET | `/health` | none | Status: model flags, `model_version`, `threshold`, `data_source`, `db_path`, `flows_processed` (= `detection_result` count), `classes`, `n_features`, `capture_running`, `replay_running`, `admin_elevated`. |
| POST | `/predict` | **loopback-only**, no token | Body `Flow`. Runs binary + multi-class, writes the ERD chain, returns `PredictionResult`. Non-loopback callers get **403**; model not loaded → **503**. |
| GET | `/alerts?limit=` | none | `{"alerts":[…]}` slice of the hot cache (limit default 100, ≤ 1000). |
| GET | `/stats` | none | Aggregates from SQL: totals, `attack_rate_pct`, `attack_types`, `severity_counts`, `uptime_since`, `threshold`. |
| GET | `/mitigation/{attack_type}/{severity}` | none | Recommendation lookup via `get_mitigation`. |
| GET | `/capture/interfaces` | none | `{interfaces:[{id,name,description}]}` from scapy. |
| POST | `/capture/start` | `capture.control` | Body `CaptureStartReq{iface?}`. 409 if running; 403 `admin_required` if not elevated; 500 `scapy_missing`. Audited. |
| POST | `/capture/stop` | `capture.control` | Stops the capture thread. Audited. |
| GET | `/capture/status` | none | `{running, iface, started_at, error}`. |
| POST | `/replay/start` | `replay.control` | Body `ReplayStartReq{rate=5.0, attack_ratio=0.45}`. Spawns `tools/replay_loop.py`. 409 if running. Audited. |
| POST | `/replay/stop` | `replay.control` | Terminates the replay subprocess. Audited. |
| GET | `/replay/status` | none | `{running, pid, rate, attack_ratio, started_at}`. |

### Auth router (`src/serve/auth_routes.py`)

| Method | Path | Perm | Purpose |
|---|---|---|---|
| POST | `/auth/login` | none | Body `{username,password}` → `{token, expires_at, username, role}`. 401 on failure/lockout (generic "Invalid credentials"). |
| POST | `/auth/logout` | `view.dashboard` | Revokes the bearer session. |
| GET | `/auth/me` | `view.dashboard` | `{user_id, username, role, session_id, permissions[]}`. |
| GET | `/users` | `users.read` | List users (id, username, role, created_at, created_by, disabled_at, last_login_at). |
| POST | `/users` | `users.write` | Create user `{username,password,role}`. 400 invalid, 409 duplicate. |
| PATCH | `/users/{user_id}` | `users.write` | Change role / reset password / disable+enable. Self-protection enforced. |
| GET | `/audit` | `audit.read` | Filterable audit log: `limit`(≤500), `since`, `action`(prefix), `actor`, `status`. Newest first. |

### Mitigation router (`src/serve/mitigation_routes.py`, prefix `/mitigation`)

| Method | Path | Perm | Purpose |
|---|---|---|---|
| POST | `/mitigation/requests` | `mitigation.request` | Create a block request `{alert_id, target_ip, reason?}`. 201; 404 alert missing; 400 bad IP; 409 duplicate pending. |
| GET | `/mitigation/requests?status=` | `view.dashboard` | List requests (joined to usernames), newest first. |
| POST | `/mitigation/requests/{id}/approve` | `mitigation.approve` | Two-person rule (5 s), flips to approved, runs `block_ip`, records `mitigation_action`. 200 (with `warning` if netsh failed), 403 two-person, 409 non-pending. |
| POST | `/mitigation/requests/{id}/deny` | `mitigation.approve` | Deny a pending request (no two-person rule). |
| GET | `/mitigation/blocked` | `view.dashboard` | Active blocks from the netsh ledger, enriched with approver username. |
| POST | `/mitigation/unblock` | `mitigation.approve` | Body `{ip, reason?}`. Requires a prior request for that IP (schema needs `request_id`); runs `unblock_ip`. |
| GET | `/mitigation/actions/failures?limit=` | `mitigation.approve` | Recent failed netsh actions (for the dashboard failures table). |
| GET | `/mitigation/_diag/elevation` | `mitigation.approve` | Read-only elevation probe (IsUserAnAdmin + TokenElevation). |

### Report router (`src/serve/report_routes.py`, prefix `/report`)

| Method | Path | Perm | Purpose |
|---|---|---|---|
| GET | `/report/{alert_id}` | `view.dashboard` | Generate a plain-text incident report via local Ollama. `{report, model, alert_id}`; 404 unknown alert; 503 if LLM unavailable. |

---

## 9. Database Schema

SQLite at `data/ids.db` (override with `IDS_DB_PATH`). Opened with
`PRAGMA foreign_keys=ON; journal_mode=WAL; synchronous=NORMAL`. **Ten tables**
(verbatim CREATE statements in `src/utils/db.py:SCHEMA_DDL`).

### Phase 1 ERD (4 tables)

**`traffic_flow`** — one row per `/predict`.
`id PK`, `ts TEXT NOT NULL`, `flow_id TEXT NOT NULL`, `src_ip`, `dst_ip`,
`src_port INT`, `dst_port INT`, `protocol INT`, `duration REAL`,
`source_mode TEXT NOT NULL CHECK(source_mode IN ('replay','live','manual'))`,
`raw_features_json TEXT NOT NULL`. Indexes on `ts`, `flow_id`, `src_ip`.

**`detection_result`** — one row per detection.
`id PK`, `flow_id INT NOT NULL → traffic_flow.id ON DELETE CASCADE`,
`score REAL`, `label INT`, `label_text TEXT`, `attack_type`,
`attack_confidence REAL`, `model_version`, `threshold REAL`,
`created_at TEXT`. Indexes on `created_at`, `flow_id`, `label`, `attack_type`.

**`alert`** — created only when `label == 1`.
`id PK`, `detection_id INT NOT NULL → detection_result.id ON DELETE CASCADE`,
`severity TEXT`, `status TEXT DEFAULT 'open'`, `created_at`. Indexes on
`created_at`, `detection_id`, `severity`.

**`mitigation_record`** — recommendation snapshot per alert.
`id PK`, `alert_id INT NOT NULL → alert.id ON DELETE CASCADE`, `attack_type`,
`severity`, `description`, `recommendations_json TEXT NOT NULL`, `created_at`.

### Week 2 auth (3 tables)

**`user`** — `id PK`, `username UNIQUE NOT NULL`, `password_hash NOT NULL`,
`role CHECK(role IN ('admin','analyst'))`, `created_at`, `created_by → user.id`,
`disabled_at`, `last_login_at`.

**`session`** — `id PK`, `token UNIQUE NOT NULL`, `user_id → user.id`,
`created_at`, `expires_at`, `revoked_at`, `last_seen_at`, `user_agent`,
`ip_address`.

**`audit_log`** — `id PK`, `ts NOT NULL`, `actor_user_id → user.id`,
`actor_username`, `action NOT NULL`, `target`,
`status CHECK(status IN ('success','failure'))`, `detail`, `ip_address`,
`user_agent`. (No UPDATE/DELETE on this table exist in the codebase →
append-only by convention.)

### Week 3 mitigation (2 tables)

**`mitigation_request`** — `id PK`, `alert_id → alert.id`, `target_ip NOT NULL`,
`reason`, `requested_by → user.id`, `requested_at`,
`status CHECK(status IN ('pending','approved','denied','expired','cancelled'))`,
`decided_by → user.id`, `decided_at`, `decision_note`.

**`mitigation_action`** — `id PK`, `request_id → mitigation_request.id NOT NULL`,
`action_type CHECK(action_type IN ('block','unblock'))`, `target_ip NOT NULL`,
`executed_by → user.id`, `executed_at`,
`status CHECK(status IN ('success','failure'))`, `netsh_stdout`, `netsh_stderr`,
`error_detail`.

### Week 4 security (1 table)

**`login_attempts`** — `username TEXT PK`, `failure_count INT DEFAULT 0`,
`locked_until TEXT`, `last_failure_at TEXT`.

### Text ERD

```
traffic_flow 1──< detection_result 1──< alert 1──< mitigation_record
                                          │
                                          └──< mitigation_request 1──< mitigation_action
user 1──< session
user 1──< audit_log (actor)
user 1──< mitigation_request (requested_by / decided_by)
user 1──< mitigation_action (executed_by)
login_attempts (keyed by username; standalone)
```

### One `/predict` across tables (single transaction)

`db.insert_flow_result()` opens `BEGIN`, inserts `traffic_flow` (features JSON,
IP/port metadata — explicit fields from live capture win over the
`flow_id`-prefix fallback), then `detection_result`. **If `label == 1`** it also
inserts `alert` (status `open`) and `mitigation_record` (recommendations JSON),
then `COMMIT`. Any exception → `ROLLBACK`. Returns
`{flow_pk, detection_pk, alert_pk, mitigation_pk}` (last two `None` for benign).
The smoke test verifies the **nine core** ERD/auth/mitigation tables exist; the
schema defines ten total (the Week-4 `login_attempts` is not in that set).

---

## 10. ML Model

- **Dataset:** CIC-IDS2017 (`data/downloads/MachineLearningCSV/MachineLearningCVE/*.csv`
  → `prep_cic2017.py`). `data_info.json`/`metrics.json` record **418,481**
  balanced training rows. Class distribution after balancing: Benign 100,000,
  DDoS 100,000, DoS 100,000, Port Scan 100,000, Brute Force 15,342, Bot 1,966,
  Web Attack 673, Infiltration 500 (`max_per_class=100,000`, `min_per_class=500`).
- **Feature schema:** **50** `UNIFIED_FEATURES` (snake_case), listed verbatim in
  `model_meta.json` and `prep_cic2017.py:UNIFIED_FEATURES` — flow duration,
  fwd/bwd packet counts & lengths, IAT mean/std, TCP flag counts, destination
  port, window bytes, rate features, subflow features, active/idle stats, etc.
  **No IP address is a model input** (IPs are persisted for forensics only).
- **Two-stage design** (`/predict` in `app.py`):
  1. **Binary head** (`rf_cic_binary.joblib`) → `score = predict_proba[:,1]`;
     `label = int(score ≥ THRESHOLD)`.
  2. **Multi-class head** (`rf_cic_multi.joblib`), only if `label == 1` →
     `attack_type` via `reverse_class_map` and `attack_confidence = max(proba)`.
     If the argmax is "Benign", the code walks down to the next non-Benign class.
  - Classes (index→name): `0 Benign, 1 Bot, 2 Brute Force, 3 DDoS, 4 DoS,
    5 Infiltration, 6 Port Scan, 7 Web Attack`.
- **Threshold:** read with priority **env `THRESHOLD` → `model_meta.json`
  `threshold` → `models/threshold.txt` → 0.5** (`load_threshold()` in app.py).
  `threshold.txt` = `0.385841`; `model_meta.json` = `0.38584062950485853`. Chosen
  by `find_optimal_threshold` (max-F1 point on the PR curve) in `train.py`.
- **Training** (`train.py`): single stratified 80/20 split; both heads are
  `Pipeline(RobustScaler → RandomForestClassifier(class_weight="balanced_subsample",
  random_state=42, n_jobs=-1))`. Binary CIC params `n_estimators=500,
  max_depth=30, min_samples_leaf=3`; multi-class CIC `n_estimators=600,
  max_depth=35, min_samples_leaf=2`. `trained_at = 2026-02-13T15:21:26`.
- **Metadata** (`model_meta.json`): feature_names, class_names, class_map,
  reverse_class_map, data_source `"CIC-IDS2017"`, threshold, and headline metrics.
- **Reported metrics** (`evaluation/metrics.json` + `evaluation_report.txt`,
  83,697-sample validation split):
  - Binary: accuracy **0.9986**, F1 **0.9991**, precision 0.999, recall 0.9992,
    AUC-ROC 0.9999, AP 1.0. Confusion: TN 19,936 / FP 64 / FN 51 / TP 63,646.
  - Multi-class: accuracy **0.9962**, F1-macro **0.9291**, F1-weighted 0.9969.
    Per-class F1 — Infiltration 1.0, DDoS 0.9997, Port Scan 0.9997, DoS 0.9994,
    Benign 0.9977, Bot 0.9862, Brute Force 0.9616, **Web Attack 0.4884**.
- **Honest strengths / limitations:**
  - **Strength:** session-based, multi-packet flows (slow-DoS, SSH brute force,
    web probing) — strong binary detection; offline metrics near-perfect.
  - **Limitation 1 (Web Attack family fidelity):** Web Attack F1 ≈ 0.49 due to
    class scarcity (673 raw rows, oversampled with 1 % noise) and feature overlap
    with DoS. Binary detection is unaffected.
  - **Limitation 2 (scan/flood):** `nmap -sS`, `hping3 --flood` create 2-packet
    singleton flows that are out-of-distribution for the per-flow aggregator;
    live validation recorded **zero detections across 6,585 such flows** (see
    [§17](#17-testing--validation)). Documented as a deliberate scope boundary.
  - **Limitation 3 (multi-class drift live):** in live runs the multi-class head
    collapses out-of-distribution attacks toward `DoS` (e.g. nikto labelled
    `DoS`); mitigation triggers on the **binary** label, so this is a labelling,
    not a missed-detection, issue.

---

## 11. Auth & RBAC

**Roles:** exactly two — `admin` and `analyst` (`user.role` CHECK constraint).

**Permission matrix** — verbatim from `src/auth/rbac.py`:

```python
PERMISSIONS = {
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
```

| Permission | admin | analyst | Gates |
|---|:---:|:---:|---|
| `view.dashboard` | ✅ | ✅ | `/auth/me`, `/auth/logout`, `/mitigation/requests` (GET), `/mitigation/blocked`, `/report/{id}` |
| `mitigation.request` | ✅ | ✅ | `POST /mitigation/requests` |
| `mitigation.approve` | ✅ | — | approve / deny / unblock / failures / `_diag/elevation` |
| `users.read` | ✅ | — | `GET /users` |
| `users.write` | ✅ | — | `POST /users`, `PATCH /users/{id}` |
| `audit.read` | ✅ | — | `GET /audit` |
| `capture.control` | ✅ | — | `/capture/start`, `/capture/stop` |
| `replay.control` | ✅ | — | `/replay/start`, `/replay/stop` |

**Login / session / token flow:**
1. `POST /auth/login` → lockout check (5 failures = 15-min lock, in SQLite UTC),
   bcrypt verify (timing-equalised dummy on missing/disabled user), success
   clears the failure counter, updates `last_login_at`, and
   `tokens.create_session()` issues an opaque `secrets.token_urlsafe(32)` token
   with an **8-hour TTL** stored in `session`.
2. Client sends `Authorization: Bearer <token>`. `require_permission`
   →`validate_token` joins `session`→`user`, rejecting revoked, disabled, or
   expired sessions (and bumping `last_seen_at`).
3. `POST /auth/logout` revokes the session row.

**Password hashing:** bcrypt via passlib, **cost factor 12**
(`BCRYPT_ROUNDS = 12`); opportunistic rehash on login if the cost moves; min
password length 12; username `^[A-Za-z0-9_]{3,32}$`.

**Audit logging:** every login (success/failure/locked), logout, user
create/role-change/password-change/disable/enable, capture/replay toggle,
mitigation request/approve/deny/block/unblock, and **every 401/403**
(`auth.failed`, `permission.denied`) is written via `log_audit()`. The
`audit_log` table has no UPDATE/DELETE path in code (append-only by convention;
**not** cryptographically tamper-evident — explicitly stated in `CHANGES.md`
W4-Sub4d / `README.md`).

**Bootstrap:** `tools/bootstrap_admin.py --username <name> [--password <pw>]`
creates the first admin (role `admin`, `created_by=NULL`) and an audit row
`bootstrap_admin`; it refuses to create a second admin if one exists.

---

## 12. Mitigation

**Workflow (request → approve → block), two-person rule:**
1. **Analyst** selects an attacker IP from an attack-labelled alert and
   `POST /mitigation/requests {alert_id, target_ip, reason?}`. The endpoint
   verifies the alert exists, validates the IP (`firewall.validate_ip`,
   respecting `MITIGATION_ALLOW_PRIVATE`), and rejects a duplicate pending
   request for the same IP (409). Row lands in `mitigation_request` as `pending`.
2. **Admin** opens the Mitigation page and approves
   (`POST /mitigation/requests/{id}/approve`). **Two-person rule:** if the
   approver is the requester *and* less than **5 seconds** have elapsed since
   creation, the call is rejected **403** and audited as a failure (this is a
   behavioural control — admins do hold `mitigation.approve`). Denying your own
   request is always allowed.
3. On approval the request flips to `approved` and
   `firewall.block_ip(target_ip, allow_private=…)` runs
   `netsh advfirewall firewall add rule name="AI-IDS Block <ip>" dir=in
   action=block remoteip=<ip>` (requires the API process to be **elevated**;
   idempotent if the rule already exists). The result is written to
   `mitigation_action` and every step to `audit_log`. **A netsh failure does
   not roll back the approval** — the response carries a `warning` and the
   failure surfaces in `/mitigation/actions/failures`.

**IP validation:** by default `validate_ip` rejects unspecified, loopback,
link-local, multicast, reserved, and private (RFC1918/ULA) addresses. The
DEV/LAB override `MITIGATION_ALLOW_PRIVATE=true` (set by `START.bat`) permits
private IPs so the demo can block the Kali attacker `192.168.142.128`.
`HARD_CONSTRAINTS.md` requires the production default to reject private ranges.

**Unblock:** `POST /mitigation/unblock {ip, reason?}` runs
`netsh … delete rule`. Because `mitigation_action.request_id` is NOT NULL, an
unblock requires a prior `mitigation_request` row for that IP (most recent
approved, else most recent of any status); ad-hoc unblocks must use `netsh`
directly.

**Ledger:** `data/blocked_ips.json` records every block/unblock with a
UTC `…Z` timestamp; `list_blocked_ips()` returns IPs whose latest action is a
block. `GET /mitigation/blocked` enriches these with the approving username.

**Dashboard surface:** `dashboard/pages/3_Mitigation.py` shows pending requests
(Approve & Block / Deny), an Active Blocks banner + table (with Unblock), and a
**Recent Failed Executions** table for netsh failures (the symptom when the API
is not elevated). `GET /mitigation/_diag/elevation` is a read-only probe that
reports `IsUserAnAdmin` and `GetTokenInformation(TokenElevation)`.

---

## 13. AI Incident Report (LLM)

- **Module:** `src/llm/report.py`; **route:** `GET /report/{alert_id}` in
  `src/serve/report_routes.py` (read-only, gated `view.dashboard`).
- **Endpoint / models:** `OLLAMA_URL` default `http://127.0.0.1:11434`.
  In code, **both** `OLLAMA_MODEL` and `OLLAMA_FALLBACK_MODEL` default to
  `llama3.2:1b`; `OLLAMA_TIMEOUT` defaults to **120 s**. `generate_report` calls
  the primary model, then the fallback, raising `ReportUnavailable` if both
  fail. `_call_model` POSTs `/api/generate` with `stream:false`,
  `keep_alive:"30m"`, `temperature:0.2`.
  > **Note / discrepancy:** the task brief and `CHANGES.md` describe
  > `qwen2.5:3b` as a primary/fallback. The **code defaults do not reference
  > qwen2.5:3b** — both default to `llama3.2:1b` (overridable via env). See
  > [§19](#19-defense-reconciliation).
- **Prompt:** `_build_prompt` constrains the model to the supplied facts (alert
  id, attack type/description, severity, score, src IP, dst port, time) and the
  approved-playbook recommendations; output is plain-text with fixed sections
  (Summary, Incident Details, What Happened, Severity Justification, Recommended
  Actions, Evidence), under 320 words.
- **Advisory / read-only:** it reads existing alert rows only and **never**
  affects detection, scoring, mitigation, or the database.
- **Graceful degradation:** if Ollama is offline the route returns **503** and
  the dashboard shows an offline notice ("Start Ollama and ensure a model is
  pulled (`ollama pull llama3.2:1b`). The IDS is unaffected.").
- **Dashboard fragment:** `dashboard/app.py` `_report_panel` is an
  `@st.fragment` (so it reruns independently of the 4 s auto-refresh), uses an
  `on_click` callback to avoid the "first click does nothing" race, shows a
  spinner ("this can take 10–40 seconds"), renders the report in a keyless
  `text_area`, and offers a `.txt` download. **(Task notes ~20–30 s latency on
  modest hardware; the dashboard copy says 10–40 s.)**
- **Env vars:** `OLLAMA_URL`, `OLLAMA_MODEL`, `OLLAMA_FALLBACK_MODEL`,
  `OLLAMA_TIMEOUT`.

---

## 14. Dashboard

`dashboard/app.py` (main console) + `dashboard/auth_ui.py` (login + API client) +
three auto-discovered pages. Theme is a dark "SOC console" palette; the page
auto-refreshes every **4 s** via `st_autorefresh` (paused while a report is
generating).

**Login flow (`auth_ui.py`):** `require_login()` renders a themed login form,
POSTs `/auth/login`, fetches `/auth/me` for the permission list, and caches
`{token, username, role, permissions, expires_at, session_id, user_id}` in
`st.session_state["auth"]`. `api_request()` is a bearer-aware wrapper that
returns `(status_code, json)` and clears the session + reruns on a 401.
`logout_button()` revokes the server session.

**Main console panels (`app.py`):**
- **Header** — API online/offline chip, ADMIN-ELEVATED / NOT-ELEVATED chip,
  threshold + model-version chips, dataset/classes line, and a six-stage
  **CAPTURE → DETECT → REQUEST → APPROVE → BLOCK → AUDIT** flow strip whose
  stages light up from live state.
- **Sidebar — Traffic Source (role-gated)** — Replay Start/Stop (`replay.control`)
  and Live Capture Start/Stop with a friendly NIC dropdown (`capture.control`);
  structured `admin_required` / `scapy_missing` errors render as toasts.
- **Live State strip** — five cards: Live Capture, Replay, Flows Seen, Attacks
  Detected (+ rate), Active Blocks (+ pending count).
- **Recent Alerts** — hand-rolled HTML table (Time · Source IP · Attack Type ·
  Score chip · Severity chip · Alert ID · Flow ID); attack rows tinted red.
  Every user/network-controlled field is `html.escape`d (XSS fix C1).
- **Request Block expander** (`mitigation.request`) — deduplicates attack rows
  by source IP, excludes the host's own IPs (so the operator can't self-block),
  and POSTs `/mitigation/requests`.
- **AI incident report fragment** — see [§13](#13-ai-incident-report-llm).
- **Secondary context** — Plotly score-distribution histogram (with a dashed
  threshold line) and a Top-10 source-IP bar chart.

**Admin pages (`dashboard/pages/`)** — each calls `require_login()` then a hard
permission check ("Admin only" stop if missing; defense-in-depth, since the nav
entry is still visible):
- **1_Users.py** (`users.write`) — user table, create user, per-user role
  change / password reset / disable+enable.
- **2_Audit_Log.py** (`audit.read`) — filter (limit/since/action/actor/status),
  summary metrics, table, CSV export.
- **3_Mitigation.py** (`mitigation.approve`) — pending requests with
  Approve/Deny, Active Blocks banner + Unblock, Recent Failed Executions. No
  auto-refresh (actions are user-driven).

---

## 15. Setup & Run (from zero)

**Prerequisites:** Windows; Python 3.12 on PATH; **Npcap** (from
<https://npcap.com>, "WinPcap API-compatible mode") for live capture; optional
**Ollama** with `llama3.2:1b` pulled for AI reports. Run elevated (admin) — both
packet capture and `netsh` rule edits require it.

**One-shot launch (recommended):** right-click **`START.bat` → Run as
administrator**. `START.bat`:
1. Verifies elevation (`net session`); warns and exits if not admin.
2. Creates `.venv` if missing (`python -m venv .venv`).
3. Installs deps if the import probe fails
   (`.venv\Scripts\pip.exe install -r env\requirements.txt`).
4. If `models\model_meta.json` is missing, runs `src\data\mock_data.py` then
   `src\models\train.py` (≈3 min first run).
5. Sets `MITIGATION_ALLOW_PRIVATE=true` (DEV/LAB — lets the demo block the
   private-subnet Kali host) and runs `python launch.py`.

`launch.py` then: starts uvicorn on `127.0.0.1:8000` (log level warning, logs to
`logs/fastapi.log`), waits for `/health`, starts Streamlit **headless** on
`:8501` (`--theme.base dark`), and spawns `desktop_app.py` (pywebview native
window). Replay is **off by default** — start it from the sidebar.

**Bootstrap the first admin** (separate elevated shell, repo root):
```
.venv\Scripts\python.exe tools\bootstrap_admin.py --username admin1
```
(prompts for a ≥12-char password; refuses a second admin).

**Reach the UI:** the native window opens automatically; browser fallback
<http://localhost:8501>. FastAPI docs at <http://localhost:8000/docs>.

**First-run walkthrough:** sign in as `admin1` → (sidebar) **Start Replay** to
generate traffic → watch Recent Alerts + Live State populate → as analyst,
**Request Block** an attacker IP → as admin, open **Mitigation** → **Approve &
Block** → confirm the rule in **Active Blocks** and the chain in **Audit Log**.

**Manual launch (alternative):**
`.venv\Scripts\python.exe -m uvicorn src.serve.app:app --host 127.0.0.1 --port 8000`
then `.venv\Scripts\python.exe -m streamlit run dashboard/app.py --server.port 8501`.

**Troubleshooting (from code/README):**
- *Backend down / API OFFLINE chip* — check `logs/fastapi.log`; the dashboard
  falls back to `logs/alerts.csv` for cold-start display.
- *Capture "admin_required" toast* — the API isn't elevated; relaunch
  `START.bat` as administrator.
- *"scapy_missing"* — install scapy + Npcap.
- *Approve succeeds but no block appears* — the API isn't elevated, OR a
  third-party kernel-mode AV (Avast/Kaspersky/ESET/Norton) is intercepting below
  Defender Firewall; pause AV shields. See the Failed Executions table and
  `/mitigation/_diag/elevation`.
- *AI report 503* — Ollama isn't running / model not pulled; IDS is unaffected.
- *Reports previously needed two clicks / showed stale text* — fixed
  2026-05-31 (report fragment + on-click callback + keyless text area).

---

## 16. Configuration

All configuration is environment variables + a few hardcoded constants. There
is no `.env` file in the tree.

| Knob | Where read | Default | Effect |
|---|---|---|---|
| `THRESHOLD` | `app.py load_threshold()` | — (then `model_meta.json` → `threshold.txt` → 0.5) | Binary decision threshold override (highest priority). |
| `IDS_DB_PATH` | `src/utils/db.py` | `data/ids.db` | Redirect the SQLite file (tests use a tempfile). |
| `MITIGATION_ALLOW_PRIVATE` | `mitigation_routes._allow_private_for_lab()`, passed to `firewall` | `false` | `true` permits blocking private IPs (set by `START.bat` for the lab demo). |
| `OLLAMA_URL` | `src/llm/report.py` | `http://127.0.0.1:11434` | Local LLM endpoint. |
| `OLLAMA_MODEL` | `src/llm/report.py` | `llama3.2:1b` | Primary report model. |
| `OLLAMA_FALLBACK_MODEL` | `src/llm/report.py` | `llama3.2:1b` | Fallback report model. |
| `OLLAMA_TIMEOUT` | `src/llm/report.py` | `120` (seconds) | Per-call LLM timeout. |

**Threshold source priority:** env `THRESHOLD` → `model_meta.json:"threshold"`
→ `models/threshold.txt` → `0.5`.

**Ports (hardcoded):** API `127.0.0.1:8000`; Streamlit `8501`
(`.streamlit/config.toml` + `launch.py` flags); Ollama `127.0.0.1:11434`.
`launch.py` forces Streamlit `--server.headless true --theme.base dark`, which
overrides `.streamlit/config.toml` (`headless=false`) at runtime. **(inferred:
runtime flag precedence)**

**Other constants:** session TTL 8 h (`tokens.py`), bcrypt rounds 12
(`passwords.py`), login lockout 5/15 (`auth_routes.py`), two-person window 5 s
and max-reason 500 (`mitigation_routes.py`), netsh timeout 10 s + rule prefix
"AI-IDS Block" + ledger `data/blocked_ips.json` (`firewall.py`), CSV rotation at
5 MB (`helpers.py`), recent-alerts cache 1000 (`app.py`), capture flow-timeout
5 s / flush 3 s (`live_capture.py`), replay defaults rate 5.0 / attack-ratio
0.45 (`replay_loop.py`).

---

## 17. Testing & Validation

### Automated tests (`tests/`, run with `pytest tests/`)
- **`test_firewall.py`** — 6 tests (V1–V6): `validate_ip` rejects
  private/loopback/link-local by default and accepts public; `block_ip` refuses
  when not admin; happy-path argv-list netsh call; idempotency; unblock
  happy+idempotent; ledger round-trip (tmp path). All netsh calls mocked.
- **`test_mitigation_routes.py`** — 12 tests (V1–V12): happy path, two-person
  rule fires, deny-own allowed, duplicate-pending 409, private-IP gated by
  `MITIGATION_ALLOW_PRIVATE`, netsh failure does not revert approval, approve
  non-pending 409, RBAC gates (analyst can't approve/unblock; 401 without
  token), unblock-without-prior-request 400, unblock happy path, list ordering +
  username joins + filter, blocked-ledger enrichment. Uses a tempfile DB +
  router-only app.
- **`test_smoke.py`** — 3 tests: app boots + `/health` 200; nine core tables
  present; full chain auth → `/predict` (loopback satisfied by `TestClient`) →
  analyst request → admin approve (mocked `block_ip`) → audit-log assertions.
- **`test_login_lockout.py`** — 3 tests: dummy-verify on missing-user path,
  lockout after 5 failures, counter reset on success.
- **Totals (per `README.md`):** 24 tests; full suite ≈24 s; smoke ≈13 s.
  Needs no admin, no NIC, no Kali, no AV change.

### Kali VM lab (`lab/ATTACK_VALIDATION.md`, `lab/attack_log.csv`)
- **Topology:** Kali attacker `192.168.142.128` ↔ Windows IDS host
  `192.168.142.1` on **VMware VMnet8** (host-isolated; both VMs on the same
  physical machine; no external LAN). Windows host runs scapy live capture,
  FastAPI :8000, Streamlit :8501, `data/ids.db`.
  *(The Week-4 demo script references a different demo network, e.g.
  `192.168.1.16`; the validation lab is VMnet8 `192.168.142.0/24`.)*
- **Session-based tools used** (inside the training distribution):
  `slowhttptest` (DoS, slow-read; 200 held sockets), `medusa` (SSH brute force),
  `nikto` (~8,000 HTTP web-attack probes). Flow-level recall across two runs:
  slowhttptest 29–66 %, medusa SSH 67–100 %, nikto 29–84 %; every profile
  produced detections in both runs (percentages are conservative — benign
  background traffic is in the denominator).
- **Why scan/flood tools were not used for the headline result:** `nmap -sS`
  and `hping3 -S --flood` produce 2-packet **singleton flows** (fresh source
  port per probe, RST before handshake) that are out-of-distribution for the
  CIC-IDS2017 per-flow model; early rounds recorded **0 detections across 6,585
  such flows** (max score 0.291 vs threshold 0.386). This is an aggregator
  design boundary (per-flow keying, preserved from Phase 1), not a defect — the
  fix (coarser-key/cross-flow correlation) is deferred to `FUTURE_WORK.md` §2.
- **Provenance:** all recall numbers come from deterministic SQL over
  `data/ids.db` joined to the windows in `lab/attack_log.csv`; the model,
  threshold, schema, and `/predict` contract were unchanged during validation.

### Replay tools (synthetic validation, no Kali needed)
- `tools/replay_loop.py` — used by `POST /replay/start`; samples per-class CIC
  feature distributions (`data/cic_profiles.json`, built by
  `extract_cic_profiles.py`) and POSTs mixed benign/attack flows
  (`<src_ip>-<uuid8>` flow IDs; benign from private IPs, attacks from public IPs;
  20 % "aggressive" mode toward Q95).
- `tools/replay_attack.py` — attack-only replay with per-type detection-rate
  printout; `tools/replay_dos.py` — DoS-focused helper.

---

## 18. Limitations & Future Work

**Honest limitations (code/`README.md`/`lab/`):**
- **Scan/flood gap** — singleton-flow scans/floods undetected (per-flow
  aggregator; §17).
- **Web Attack multi-class fidelity** — F1 ≈ 0.49; live multi-class drifts
  toward `DoS` (binary detection + mitigation unaffected).
- **Single-host only** — no endpoint agent, no fleet.
- **Human-in-the-loop blocking** — no auto-block; every block needs analyst
  request + admin approval.
- **Windows-only mitigation** — `netsh advfirewall`; no Linux/iptables.
- **Third-party kernel-mode AV co-existence** — Avast/Kaspersky/ESET/Norton WFP
  callouts can bypass AI-IDS netsh rules on the AV-bound path; AV shields must be
  paused for enforcement (diagnosed Week 3).
- **In-kernel unblock recovery quirk** — after a successful delete, Windows may
  hold filter state; restart the listener or `Restart-Service mpssvc`.
- **LLM latency** — report generation ~10–40 s on modest hardware; advisory only.
- **No production false-positive rate measured** — named as first
  post-submission task.
- **Encrypted-channel attacks, adversarial evasion, long-run stability** — not
  validated.

**Future work (`FUTURE_WORK.md`, 10 sections — designed-on-paper only):**
1. Endpoint agent / multi-machine deployment.
2. Aggregator extension for scan/flood detection (cross-flow correlation).
3. Auto-block on high-confidence detection.
4. Encrypted-channel attack detection.
5. Cloud threat-intelligence integration.
6. Production-grade UI.
7. Hardening for third-party AV co-existence + unblock recovery.
8. Model retraining pipeline + multi-class drift monitoring.
9. Architectural roadmap.
10. Rationale for each deferral (the defense answer).

**Explicit out-of-scope:** cloud, PostgreSQL, Docker, OAuth/SSO/2FA, multi-device
— see [§2](#2-scope).

---

## 19. Defense Reconciliation

### Where the live implementation EXCEEDS earlier Phase-1 documentation
The Phase-1 proposal (per `RECONCILIATION_PHASE2.md`) asked for capture →
preprocess → binary classify → alert → view, on a desktop GUI. The delivered
system goes **beyond** that scope with:
- **Multi-class classification** — 8 attack families (proposal asked binary
  only). ✅+ — `train.py`, `model_meta.json`.
- **Severity tiers** — Critical/High/Medium/Low from the binary score
  (`helpers.SEVERITY_THRESHOLDS`).
- **Human-in-the-loop approved blocking** — full `mitigation_request` →
  `mitigation_action` workflow with a 5-second two-person rule and `netsh`
  enforcement (proposal envisaged passive recommendation strings).
- **Auth + RBAC + append-only audit log** — entirely new in Phase 2
  (`src/auth/*`, `audit_log`).
- **Relational persistence** — the Figure-4.2 ERD realised as SQLite with FK
  cascade + WAL (replacing flat CSV).
- **AI incident report** — local-LLM advisory reports (`src/llm/report.py`).
- **Week-4 security hardening** — CORS pinned, login lockout, timing
  equalisation, XSS escaping (`CHANGES.md` W4-Sub4d).

### Where code and existing project docs DISAGREE (align before the panel)
These are real mismatches found while reading the code; flagged so slides/report
can be corrected:

1. **Multi-class model filename.** `RECONCILIATION_PHASE2.md` (FR_03/UC_03)
   names `models/rf_multiclass.joblib`. **No such file exists.** The code
   (`app.py`) loads `rf_cic_multi.joblib` (primary) / `rf_multi.joblib`. Files
   present: `rf_binary`, `rf`, `rf_cic_binary`, `rf_multi`, `rf_cic_multi`.
2. **RBAC permission names.** The reconciliation doc cites `capture:start` /
   `capture:stop` (colon, two perms). The code uses a single dot-style permission
   **`capture.control`** (and `replay.control`) — see `rbac.py`.
3. **`/predict` response shape.** The doc says `/predict` returns
   `{label, score, multiclass_label}`. The actual `PredictionResult` is
   `{flow_id, score, label, label_text, attack_type, attack_confidence,
   severity, mitigation, timestamp}` — there is no `multiclass_label` key
   (`attack_type` carries the family).
4. **`src/models/inference.py`** is cited (UC_03) but **does not exist**;
   inference is inline in `app.py:predict()`.
5. **Capture API.** The doc says capture uses scapy `AsyncSniffer`; the frozen
   `live_capture.py` uses `sniff(..., stop_filter=…)` on a managed thread.
6. **LLM model naming.** The top of `CHANGES.md` (and this task's brief)
   describe `qwen2.5:3b` as the primary report model with `llama3.2:1b`
   fallback. The **code defaults both** `OLLAMA_MODEL` and
   `OLLAMA_FALLBACK_MODEL` to `llama3.2:1b` (`report.py`), and the route reports
   `model = llama3.2:1b`. Either pull/point env vars at qwen2.5:3b or correct
   the docs.
7. **Docker.** `HARD_CONSTRAINTS.md` forbids Docker, yet `docker/docker-compose.yml`
   exists; it uses `python:3.11-slim` (README says 3.12) and binds services to
   `0.0.0.0` (contradicting the loopback-only/offline design). Treat as stale —
   not the supported run path.
8. **Streamlit headless flag.** `.streamlit/config.toml` sets
   `[server] headless = false`, but `launch.py` starts Streamlit with
   `--server.headless true`; the desktop window is the intended primary UI.
9. **Severity vs threshold nuance** (worth pre-empting): severity is computed
   from the **binary** score only when `label==1` (score ≥ 0.386). Because
   `get_severity` returns "Low" for any score below 0.40, attack flows scoring
   0.386–0.40 are labelled severity **Low** — consistent with the live-validation
   scores (mostly 0.26–0.49), which is why most live alerts are Low/Medium.
   **(inferred from `helpers.get_severity` + `app.py` ordering.)**

---

## 20. Change Log Summary

From `CHANGES.md` (most recent first) and `_stages/CURRENT_STAGE.md`. Week
status: Week 1 DONE 2026-05-23, Week 2 DONE 2026-05-24, Week 3 DONE 2026-05-25,
Week 4 ACTIVE.

- **2026-05-31 — Report-panel reliability fixes** (`dashboard/app.py` only):
  moved the AI-report panel into an `@st.fragment`; restored the
  `report_generating` pause; fixed stale display (removed the keyed `text_area`);
  fixed "first click does nothing" via an `on_click` callback. Advisory-only;
  detection/scoring/mitigation/DB untouched.
- **(undated header) AI incident report (local LLM)** — added `src/llm/report.py`
  + `GET /report/{alert_id}` + dashboard report expander. Read-only, no new
  Python deps, graceful 503 if Ollama down.
- **2026-05-29 — Native desktop window** — new `desktop_app.py` (pywebview);
  `launch.py` orchestrates uvicorn → wait `/health` → headless Streamlit → detached
  window; added `pywebview==6.2.1` and `assets/`.
- **2026-05-28 — W4-Sub4f — defense-pass documentation fixes** — README table
  count 9→10 (`login_attempts`), QA_BANK Q31 (Web Attack F1), Q32 (adversarial
  bypass), Q7 framing. Docs only; 24 tests green.
- **2026-05-28 — W4-Sub4d — security review fixes (C1–C4)** — C1 XSS escape of
  `flow_id`; C2 CORS pinned to localhost:8501/127.0.0.1:8501; C3a login timing
  equalisation; C3b per-user `login_attempts` lockout (5/15); C4 audit-log
  wording ("append-only", not "immutable"). New `test_login_lockout.py` (24
  tests total).
- **2026-05-28 — demo-script sync** after the Streamlit SOC redesign (labels /
  flow-strip / audit action names). Docs only.
- **2026-05-27 — W4-Sub4a/b/c** — pytest smoke test; README sanity pass;
  QA_BANK Q26 + Week-4 CHANGES.
- **2026-05-26 — W4-Sub1/2/3** — README rewrite; `RECONCILIATION_PHASE2.md` +
  `FUTURE_WORK.md`; `defense/DEMO_SCRIPT.md` + `defense/QA_BANK.md`.
- **2026-05-25 — Week 3 closeout (mitigation)** — Sub-tasks 1–6: mitigation
  schema + module skeleton, netsh wrapper, endpoints + RBAC + audit, dashboard
  wiring, elevation diagnostic + failure UX, demo-readiness polish, Request-Block
  dedup by src_ip. Full chain verified end-to-end live against Kali; Avast-induced
  bypass diagnosed.
- **2026-05-24 — Week 2 closeout (auth)** — two-role auth on Streamlit; admin
  pages (Users / Audit Log); RBAC + sessions + audit.
- **2026-05-24 — Week 1 closeout (validation writeup)** — `ATTACK_VALIDATION.md`.
- **2026-05-23 — Week 1 closeout (real attack validation)** — Kali rounds;
  documented the scan/flood null result.
- **(submission-pass header) FR_01 + Figure-4.2 ERD** — wired live capture in as
  a togglable source; introduced the SQLite ERD (`traffic_flow → detection_result
  → alert → mitigation_record`) with single-transaction writes, hot-cache
  hydration, and `/stats` from SQL; extended `FlowAggregator` to the full 50
  features; added capture control endpoints; added `scapy` to requirements.

---

*End of `PROJECT_CONTEXT_FULL.md`. This document is descriptive (documentation
only); no code, model, data, or configuration was modified in producing it.*
