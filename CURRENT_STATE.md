# CURRENT_STATE.md

Snapshot of the project as it stands after the FR_01 / ERD pass. Written for
someone technical who has not seen this codebase. Pull date: tied to the
state on disk; verify with `git log` / `Get-ChildItem` if in doubt.

---

## 1. Project Identity

| Field | Value |
|---|---|
| **Title** | AI-Driven Intrusion Detection and Threat Mitigation System for Secure Networks |
| **FYP ID** | Fall-2025-104 |
| **University / Department** | The University of Lahore, Department of CS & IT |
| **Supervisor** | Dr. Nadeem Iqbal |
| **Group members** | Muhammad Usman Tariq (SAP 70139691) · Muhammad Mousa Khan (SAP 70140245) |

**Plain-English description.** The system watches network traffic flows, runs
each flow through two trained Random Forest classifiers (binary
benign/attack, then 8-class attack-family), assigns a severity tier from the
attack score, looks up attack-type-specific mitigation steps, and shows
everything in a real-time SOC console. Traffic can come from a built-in
replay simulator (default, deterministic for demos) or from live packet
capture on a chosen network interface. All detections persist to a SQLite
database with referential integrity matching the proposal's Figure 4.2 ERD.

---

## 2. Tech Stack

**Languages & frameworks**

| Component | Library | Pinning |
|---|---|---|
| HTTP API | FastAPI + Uvicorn | unpinned in `env/requirements.txt` |
| UI | Streamlit + streamlit-autorefresh + Plotly | unpinned |
| ML | scikit-learn (RandomForestClassifier, RobustScaler, Pipeline) | unpinned |
| Data | numpy, pandas, pyarrow (Parquet I/O) | unpinned |
| Model serialization | joblib | unpinned |
| HTTP client | requests | unpinned |
| Packet capture | scapy | unpinned |
| Auth | passlib + bcrypt (bcrypt cost 12) | **pinned**: `passlib[bcrypt]==1.7.4`, `bcrypt==4.0.1` |
| Desktop window | pywebview (native OS window wrapping the Streamlit UI) | **pinned**: `pywebview==6.2.1` |
| Persistence | sqlite3 (Python stdlib) | n/a |

Most of `env/requirements.txt` is intentionally unpinned, **except** the
security- and desktop-critical packages, which are pinned for
reproducibility: `passlib[bcrypt]==1.7.4` and `bcrypt==4.0.1` (auth —
bcrypt cost-12 hashes created by `tools/bootstrap_admin.py` must stay
verifiable at runtime) and `pywebview==6.2.1` (the native desktop
window). Verified-working install
versions captured during the most recent clean-state smoke test:
`numpy 2.4.6`, `pandas 3.0.3`, `scikit-learn 1.8.0`, `fastapi 0.136.1`,
`uvicorn 0.47.0`, `streamlit 1.57.0`, `plotly 6.7.0`, `pyarrow 24.0.0`,
`scapy 2.7.0`.

**Python version.** Tested on **3.12** (the `.venv` created by `START.bat`
inherits whatever `python` is on PATH). The included `docker/docker-compose.yml`
uses `python:3.11-slim`. Anything 3.10+ should work; nothing in the code
uses 3.12-specific syntax.

**OS support**

| OS | Status |
|---|---|
| Windows 10/11 | Primary target. `START.bat` is Windows-only. |
| Linux | API + dashboard run fine. `START.bat` does not run; substitute `python launch.py` after `pip install -r env/requirements.txt`. |
| macOS | Same as Linux. |

**Caveats**

- **Live capture on Windows requires Npcap** (https://npcap.com/) installed
  with WinPcap-compatible mode. Scapy alone is not sufficient.
- **Live capture requires raw socket privileges** — administrator on
  Windows, root (or `CAP_NET_RAW`) on Linux. Replay mode has no such
  requirement.

**Dataset**

- **Source.** CIC-IDS2017 (https://www.unb.ca/cic/datasets/ids-2017.html),
  CSVs already present in `data/downloads/MachineLearningCSV/MachineLearningCVE/`.
- **Preprocessing** — `src/data/prep_cic2017.py`:
  - Strips whitespace from column names.
  - Maps 78 native CIC columns onto a 50-feature unified snake_case schema.
  - Collapses CIC labels into 8 families (Benign, DoS, DDoS, Port Scan,
    Brute Force, Web Attack, Bot, Infiltration). Heartbleed → DoS. `"Other"`
    is dropped.
  - Stratified class balancing: downsample to 100 000 per class, oversample
    rare classes up to 500 with 1 % gaussian noise.
  - Writes `data/processed/train.parquet`, `class_map.json`, `data_info.json`.
- **Alternative** — `src/data/mock_data.py` generates synthetic data with the
  same 50-feature schema (used when the CIC CSVs are unavailable). Currently
  not used by default: the on-disk `train.parquet` and the loaded models are
  CIC-trained (`/health` reports `data_source: "CIC-IDS2017"`).

---

## 3. Architecture

**Runtime.** A single `python launch.py` invocation spawns three things on
loopback: the FastAPI backend on `127.0.0.1:8000`, a replay traffic loop
(itself spawned by the API after `launch.py` calls `POST /replay/start`),
and the Streamlit dashboard on `127.0.0.1:8501`. Live capture is opt-in
from the dashboard sidebar and runs as a managed background thread *inside*
the API process (not a separate subprocess). All persistence goes to
`data/ids.db` (SQLite, WAL mode, FKs on). CSV at `logs/alerts.csv` is a
backup with 5 MB rotation.

```
                          ┌──────────────────────────┐
                          │       launch.py          │
                          │  (foreground supervisor) │
                          └────────────┬─────────────┘
                                       │ spawn
                                       ▼
       ┌─────────────────────────────────────────────────────────────┐
       │            FastAPI / uvicorn  (127.0.0.1:8000)              │
       │                  src/serve/app.py                           │
       │                                                             │
       │   /predict  →  RF binary + RF multi-class                   │
       │             →  severity + mitigation lookup                 │
       │             ──insert──┐                                     │
       │                       ▼                                     │
       │   /alerts   ←── recent_alerts deque (hot cache, max 1000)   │
       │   /stats    ←── SQL aggregates                              │
       │   /capture/* ── manages live capture thread (this process)  │
       │   /replay/*  ── manages replay subprocess                   │
       └───────┬─────────────────────────────────┬───────────┬───────┘
               │ subprocess                       │ thread     │ writes
               ▼                                  ▼            ▼
   ┌────────────────────┐         ┌──────────────────────┐  ┌─────────────────┐
   │ tools/replay_loop  │         │ src/capture/         │  │  data/ids.db    │
   │ (CIC-profile flows)│         │   live_capture.py    │  │  (SQLite, WAL)  │
   │ POSTs /predict     │         │ Scapy sniff + flow   │  │  ┌───────────┐  │
   └────────────────────┘         │ aggregator. POSTs    │  │  │ traffic_  │  │
                                  │ /predict.            │  │  │   flow    │  │
                                  └──────────────────────┘  │  └─────┬─────┘  │
                                                            │        ▼        │
                                                            │  ┌───────────┐  │
                                                            │  │detection_ │  │
                                                            │  │  result   │  │
                                                            │  └─────┬─────┘  │
                                                            │        ▼        │
                                                            │  ┌───────────┐  │
                                                            │  │   alert   │  │
                                                            │  └─────┬─────┘  │
                                                            │        ▼        │
                                                            │  ┌───────────┐  │
                                                            │  │mitigation_│  │
                                                            │  │   record  │  │
                                                            │  └───────────┘  │
                                                            └─────────────────┘
       ┌─────────────────────────────────────────────────────────────┐
       │           Streamlit dashboard  (127.0.0.1:8501)             │
       │                  dashboard/app.py                           │
       │                                                             │
       │   polls /health, /stats, /alerts, /capture/status,          │
       │         /replay/status every 4 s                            │
       │   sidebar toggles call /replay/start|stop, /capture/start|stop
       └─────────────────────────────────────────────────────────────┘
```

**Component purposes (one sentence each)**

- `launch.py` — process supervisor; spawns uvicorn, waits for `/health`,
  asks the API to start replay, launches Streamlit, and tears everything
  down on exit.
- `src/serve/app.py` — FastAPI app: prediction endpoint, SQL persistence,
  capture/replay control plane, hot-cache hydration on startup.
- `src/utils/db.py` — SQLite persistence layer (schema DDL, connection
  helper with FK + WAL, single-transaction inserts, aggregate queries).
- `src/utils/helpers.py` — severity scale, mitigation database keyed by
  attack family, CSV alert log with 5 MB rotation.
- `src/capture/live_capture.py` — Scapy-based packet capture, flow
  aggregation, feature extraction matching the 50-feature training schema;
  exposes `run_in_thread()` for in-process hosting by the API.
- `tools/replay_loop.py` — built-in traffic simulator that samples from the
  precomputed CIC distributions in `data/cic_profiles.json`.
- `src/models/train.py` — trains binary + multi-class RF pipelines, finds
  optimal F1 threshold, writes models and metadata.
- `src/data/prep_cic2017.py` — CIC-IDS2017 → 50-feature unified schema.
- `src/data/mock_data.py` — synthetic alternative producing the same schema.
- `dashboard/app.py` — Streamlit SOC console; polls API every 4 s.

---

## 4. Current Capabilities (what works end-to-end today)

### Detection

- **Binary classifier** (Benign vs Attack) — Random Forest pipeline
  (`RobustScaler` → `RandomForestClassifier(n_estimators=500, max_depth=30,
  min_samples_leaf=3, class_weight="balanced_subsample")`) with an
  F1-optimized threshold persisted in `models/threshold.txt`. Live value
  reported by `/health`: **0.3858**.
- **Multi-class classifier** — separate RF pipeline (600 trees, depth 35)
  predicting one of 8 attack families. Trained on the same stratified
  split.
- **Attack families covered:** Benign, Bot, Brute Force, DDoS, DoS,
  Infiltration, Port Scan, Web Attack (verified by `/health.classes`).
- **Severity tiers** (assigned only when `label == 1`):
  - Critical: score ≥ 0.95
  - High: score ≥ 0.80
  - Medium: score ≥ 0.60
  - Low: score ≥ 0.40
  - None: when the flow is benign
- **Feature count:** 50 (verified by `/health.n_features`).

### Traffic sources

- **Replay** (default; deterministic for demos) — runs as a subprocess
  managed via `/replay/start` and `/replay/stop`. Samples from CIC
  distributions stored in `data/cic_profiles.json`. ~5 flows/s by default,
  ~45 % attack ratio. **Started automatically** by `launch.py` after the
  API reports healthy.
- **Live capture** (opt-in; needs admin) — runs as a background thread
  inside the API process. Uses Scapy `sniff()` on a chosen interface,
  aggregates packets into bidirectional flows (5-tuple keying, 5 s
  inactivity timeout), extracts the 50-feature vector, POSTs each flow
  to `/predict`. Started/stopped from the dashboard sidebar.
- **Both can run simultaneously.** Different `source_mode` values in
  `traffic_flow` distinguish them: `'replay'`, `'live'`, `'manual'`.

### Persistence (`data/ids.db`)

All four tables defined and used; row counts confirmed by the most recent
smoke test (120/120/50/50).

| Table | What it stores | Survives restart |
|---|---|---|
| `traffic_flow` | One row per POST `/predict`: timestamp, flow_id, src/dst IP+port, protocol, duration, source_mode, full feature dict as JSON. | ✓ |
| `detection_result` | One row per detection: score, label, label_text, attack_type, attack_confidence, model_version, threshold. FK → `traffic_flow`. | ✓ |
| `alert` | Created only when attack: severity, status (`'open'` default). FK → `detection_result`. | ✓ |
| `mitigation_record` | Created with each alert: attack_type, severity, description, recommendations JSON. FK → `alert`. | ✓ |
| `logs/alerts.csv` | Backup CSV mirror of attack alerts. Rotated to `alerts-YYYYMMDD-HHMMSS.csv.bak` at 5 MB. | ✓ (file-based) |
| `recent_alerts` deque | In-memory hot cache (`maxlen=1000`) hydrated from SQL on startup. Source of truth is SQL — see §9. | Reset on restart, re-seeded from SQL. |

### Dashboard panels that actually render

Confirmed by reading `dashboard/app.py`:

1. **Header bar** — green/red status dot, model info card (dataset,
   threshold, class count, status).
2. **Sidebar — Traffic Source**
   - Replay block: status pill, Start / Stop buttons (current rate +
     attack-ratio shown when running).
   - Live Capture block: status pill, interface dropdown (populated from
     `/capture/interfaces`), Start / Stop buttons, status caption.
   - Caption: "Live capture needs admin and Npcap (Windows)."
3. **KPI metrics row** — Total Flows, Attacks Detected (with attack-rate
   delta), Avg Score, Alerts File.
4. **Recent Alerts** — custom HTML table, color-coded score (red ≥0.8,
   orange ≥0.5, green otherwise), Attack/Benign pill badge. Up to 200
   rows from `/alerts`.
5. **Score Distribution** — Plotly histogram (25 bins).
6. **Top 10 Source Prefixes** — Plotly horizontal bar, derived from the
   leading segment of `flow_id`.
7. **Quick Actions & Reports** — lists PNGs in `reports/` if present
   (confusion matrix, threshold tuning curve).

Auto-refresh interval: **4 s** (`st_autorefresh`).

### API endpoints

All exposed by `src/serve/app.py`; verified by reading the file.

| Method | Path | Purpose | Auth |
|---|---|---|---|
| GET | `/health` | Liveness + model info + DB path + running flags for capture/replay | — |
| POST | `/predict` | Classify a flow; write traffic_flow + detection_result (+alert+mitigation if attack) in one transaction | **loopback-only** (request-level check: `request.client.host` ∈ {127.0.0.1, ::1, localhost}; otherwise 403) |
| GET | `/alerts?limit=N` | Most recent alerts from the hot cache (deque, max 1000) | — |
| GET | `/stats` | Aggregate counts read from SQL (total flows, attacks, attack rate, attack_types breakdown, severity breakdown) | — |
| GET | `/mitigation/{attack_type}/{severity}` | Look up mitigation recommendations | — |
| GET | `/capture/interfaces` | List Scapy interfaces (empty list + error message if Scapy missing) | — |
| POST | `/capture/start` | Start live capture thread (body: `{iface}`); returns structured 403 on `PermissionError` | **`capture.control`** (admin) |
| POST | `/capture/stop` | Stop live capture | **`capture.control`** (admin) |
| GET | `/capture/status` | Capture thread status + last error | — |
| POST | `/replay/start` | Spawn replay subprocess (body: `{rate, attack_ratio}`) | **`replay.control`** (admin) |
| POST | `/replay/stop` | Terminate replay subprocess | **`replay.control`** (admin) |
| GET | `/replay/status` | Replay subprocess status + PID + parameters | — |
| POST | `/auth/login` | Body `{username, password}` → `{token, expires_at, username, role}`. 401 on bad creds, disabled user, or unknown user (opaque). Writes `login` audit row either way. Silently re-hashes if `needs_rehash`. | — |
| POST | `/auth/logout` | Revokes the current bearer's session row | bearer (`view.dashboard`) |
| GET | `/auth/me` | `{user_id, username, role, session_id, permissions[]}` | bearer (`view.dashboard`) |
| GET | `/users` | List users (no `password_hash` column) | **`users.read`** (admin) |
| POST | `/users` | Body `{username, password, role}`. Creates user with `created_by=current_user.id`. 409 if username taken. | **`users.write`** (admin) |
| PATCH | `/users/{user_id}` | Body any of `{role, password, disabled}`. Blocks self-demote / self-disable. On `disabled=true` also revokes all that user's live sessions. One audit row per applied change. | **`users.write`** (admin) |
| GET | `/audit` | Query params: `limit` (1–500, default 100), `since`, `action` (LIKE prefix), `actor`, `status`. Order `ts DESC, id DESC`. | **`audit.read`** (admin) |

All RBAC-gated endpoints use `Depends(require_permission(...))` from
`src/auth/rbac.py`. 401 (missing / invalid token) and permission denials
both write `audit_log` rows (`action='auth.failed'` and
`action='permission.denied'` respectively). The permission matrix is
the canonical one in `src/auth/rbac.py:PERMISSIONS` — admin has all 8
permissions, analyst has `view.dashboard` + `mitigation.request`.

CORS: `allow_origins` is pinned to the Streamlit dashboard origins
(`http://localhost:8501`, `http://127.0.0.1:8501`) in `src/serve/app.py`
— tightened from `["*"]` in the W4-Sub4d security pass (2026-05-28).

### Mitigation system

- Recommendation database lives in `src/utils/helpers.py:MITIGATION_DB`.
- Keyed by attack family → severity tier → list of action strings.
- Coverage: 7 attack families × 4 severity tiers = **28 recommendation
  sets** (matches the README claim). Each family also has a `description`
  string. A `GENERIC_MITIGATION` fallback handles unknown attack types.
- Generation path: `/predict` calls `get_mitigation(attack_type, severity)`
  whenever `label == 1`, the result is stored in
  `mitigation_record.recommendations_json` (JSON array of strings) and
  echoed back in the prediction response.
- Display: the dashboard does **not currently surface the mitigation text
  directly** — only the attack type + severity badge. The data is in
  `mitigation_record` and reachable via the `/mitigation/{type}/{severity}`
  endpoint, but no panel renders it yet (see §11).

---

## 5. Proposal Alignment

### Functional requirements

| FR | What proposal promises | Status | Files | Notes |
|---|---|---|---|---|
| **FR_01** | Live network capture from a chosen interface via Scapy/PyShark. | **COMPLETE** | `src/capture/live_capture.py`, `src/serve/app.py` (`/capture/*`), `dashboard/app.py` (sidebar) | Wired in via the last pass. Requires admin/root and Npcap on Windows. PyShark not used; Scapy alone is sufficient. |
| **FR_02** | Real-time ML-based attack detection. | **COMPLETE** | `src/serve/app.py` (`POST /predict`), `src/models/train.py` | Binary RF classifier; F1-optimized threshold loaded from `models/threshold.txt`. |
| **FR_03** | Multi-class attack family classification. | **COMPLETE** | `src/models/train.py` (multi-class pipeline), `/predict` multi-branch in `src/serve/app.py` | 8-class model (`rf_cic_multi.joblib`). Result persisted to `detection_result.attack_type`. |
| **FR_04** | Mitigation recommendations per attack type. | **COMPLETE** for the lookup; **PARTIAL** for dashboard surfacing | `src/utils/helpers.py` (`MITIGATION_DB`), `src/serve/app.py` (`/mitigation/{type}/{severity}`) | Data is stored in `mitigation_record` and reachable via API. Dashboard doesn't show it on a per-alert basis yet — see §11. |
| **FR_05** | SOC dashboard for monitoring detections. | **COMPLETE** | `dashboard/app.py` | KPIs, alert table, distribution histogram, top-source chart, traffic-source toggles. |

### ERD (Figure 4.2) → SQLite schema

| Proposal entity | DB table | FK |
|---|---|---|
| Traffic flow | `traffic_flow` | — |
| Detection result | `detection_result` | `flow_id → traffic_flow.id` |
| Alert | `alert` | `detection_id → detection_result.id` |
| Mitigation record | `mitigation_record` | `alert_id → alert.id` |

All FKs declared with `ON DELETE CASCADE`. `PRAGMA foreign_keys = ON` set
on every connection. WAL journaling enabled.

Deviation from proposal worth flagging: `traffic_flow.raw_features_json`
is the full feature dict serialized as JSON — the proposal doesn't
specify a separate `features` table, and storing as JSON keeps the row
count 1:1 with detections. If the supervisor wants a normalized
`feature_value` table later, the JSON column is preserved and can be
expanded.

---

## 6. File Tree (annotated)

Excludes `__pycache__/`, `.venv/`, `*.joblib` model binaries, and the
raw CIC CSVs under `data/downloads/`.

```
ai_ids_complete/
├── .claude/
│   └── settings.local.json                  — Local Claude Code settings (gitignored in practice)
├── .gitignore                               — Ignores .venv, __pycache__, *.pyc, *.pyo, models/*.joblib, data/processed/*.parquet, data/processed/*.csv, data/processed/class_map.json, data/ids.db, data/ids.db-wal, data/ids.db-shm, logs/*.csv, logs/alerts-*.csv.bak, reports/*.txt, evaluation/*.txt, evaluation/*.json, .DS_Store
├── .streamlit/
│   └── config.toml                          — Streamlit theme (dark, cyan primary) + port 8501
├── CHANGES.md                               — Changelog for the FR_01 / ERD pass (read this for "what changed last")
├── CURRENT_STATE.md                         — This file
├── README.md                                — STALE: describes a previous "desktop app" architecture; see §11 to rewrite
├── START.bat                                — Windows launcher: creates .venv, installs deps, trains if needed, runs launch.py
├── launch.py                                — Process supervisor: uvicorn → wait /health → POST /replay/start → Streamlit
├── sample_request.json                      — Example /predict payload (benign-shaped)
│
├── data/
│   ├── cic_profiles.json                    — Precomputed CIC feature distributions used by replay_loop.py
│   ├── ids.db                               — SQLite database (created on first API start; gitignored)
│   ├── downloads/MachineLearningCSV/
│   │   └── MachineLearningCVE/              — Raw CIC-IDS2017 CSVs (8 files, ~800 MB total). Gitignored.
│   ├── processed/
│   │   ├── class_map.json                   — {attack_type: int} mapping used by training
│   │   ├── data_info.json                   — Snapshot of source/size/balance after prep_cic2017
│   │   └── train.parquet                    — Final 50-feature balanced dataset (~40 MB)
│   └── raw/.keep                            — Placeholder
│
├── dashboard/
│   └── app.py                               — Streamlit SOC console (KPIs, alerts, plots, traffic-source toggles)
│
├── docker/
│   └── docker-compose.yml                   — UNTESTED in this pass: python:3.11-slim images for api + dashboard
│
├── env/
│   └── requirements.txt                     — Unpinned pip requirements (numpy, pandas, sklearn, fastapi, ..., scapy)
│
├── evaluation/
│   ├── evaluation_report.txt                — Text report from latest training run
│   └── metrics.json                         — JSON metrics from latest training run
│
├── logs/
│   ├── alerts.csv                           — Backup CSV (5 MB rotation); SQL is source of truth
│   ├── fastapi.log                          — Uvicorn stderr (launch.py captures it)
│   └── replay.log                           — Replay subprocess stdout/stderr
│
├── models/
│   ├── model_meta.json                      — Feature names + class names + reverse_class_map + threshold + metrics
│   ├── threshold.txt                        — Single float: F1-optimal binary threshold (currently 0.385841)
│   └── *.joblib                             — Trained pipelines (rf_binary, rf_multi, rf_cic_binary, rf_cic_multi, rf). Gitignored.
│
├── reports/                                 — PNG outputs of training (confusion_matrix.png, threshold_tuning.png) when present
│
├── src/
│   ├── __init__.py                          — Empty
│   ├── capture/
│   │   ├── __init__.py
│   │   └── live_capture.py                  — Scapy capture + FlowAggregator + run_in_thread() for API hosting
│   ├── data/
│   │   ├── __init__.py
│   │   ├── mock_data.py                     — Synthetic generator producing the 50-feature schema
│   │   └── prep_cic2017.py                  — CIC-IDS2017 → unified 50-feature schema
│   ├── models/
│   │   ├── __init__.py
│   │   └── train.py                         — Binary + multi-class RF training pipeline; writes threshold + metadata
│   ├── serve/
│   │   ├── __init__.py
│   │   └── app.py                           — FastAPI app: lifespan, /predict, /alerts, /stats, /capture/*, /replay/*
│   └── utils/
│       ├── __init__.py
│       ├── db.py                            — SQLite layer: schema DDL, get_conn, init_db, insert_flow_result, fetch_*
│       └── helpers.py                       — get_severity, get_mitigation, MITIGATION_DB, log_alert + rotation
│
└── tools/
    ├── extract_cic_profiles.py              — One-shot: builds data/cic_profiles.json from CIC CSVs (already run)
    ├── replay_attack.py                     — Standalone attack-only replay. NOT wired into launch.py.
    ├── replay_dos.py                        — Standalone DoS-flood replay. NOT wired into launch.py.
    └── replay_loop.py                       — Default mixed replay; managed by /replay/start (launch.py invokes via API)
```

---

## 7. Database Schema (current)

Pulled verbatim from `src/utils/db.py:SCHEMA_DDL`. WAL mode and foreign
keys are enabled on every connection by `get_conn()`.

```sql
CREATE TABLE IF NOT EXISTS traffic_flow (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    ts                 TEXT    NOT NULL,
    flow_id            TEXT    NOT NULL,
    src_ip             TEXT,
    dst_ip             TEXT,
    src_port           INTEGER,
    dst_port           INTEGER,
    protocol           INTEGER,
    duration           REAL,
    source_mode        TEXT    NOT NULL CHECK(source_mode IN ('replay','live','manual')),
    raw_features_json  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_flow_ts     ON traffic_flow(ts);
CREATE INDEX IF NOT EXISTS idx_flow_flowid ON traffic_flow(flow_id);
CREATE INDEX IF NOT EXISTS idx_flow_src    ON traffic_flow(src_ip);

CREATE TABLE IF NOT EXISTS detection_result (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id            INTEGER NOT NULL,
    score              REAL    NOT NULL,
    label              INTEGER NOT NULL,
    label_text         TEXT    NOT NULL,
    attack_type        TEXT,
    attack_confidence  REAL,
    model_version      TEXT,
    threshold          REAL,
    created_at         TEXT    NOT NULL,
    FOREIGN KEY (flow_id) REFERENCES traffic_flow(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_det_created ON detection_result(created_at);
CREATE INDEX IF NOT EXISTS idx_det_flowid  ON detection_result(flow_id);
CREATE INDEX IF NOT EXISTS idx_det_label   ON detection_result(label);
CREATE INDEX IF NOT EXISTS idx_det_attack  ON detection_result(attack_type);

CREATE TABLE IF NOT EXISTS alert (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    detection_id  INTEGER NOT NULL,
    severity      TEXT    NOT NULL,
    status        TEXT    NOT NULL DEFAULT 'open',
    created_at    TEXT    NOT NULL,
    FOREIGN KEY (detection_id) REFERENCES detection_result(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_alert_created   ON alert(created_at);
CREATE INDEX IF NOT EXISTS idx_alert_detection ON alert(detection_id);
CREATE INDEX IF NOT EXISTS idx_alert_severity  ON alert(severity);

CREATE TABLE IF NOT EXISTS mitigation_record (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id              INTEGER NOT NULL,
    attack_type           TEXT,
    severity              TEXT,
    description           TEXT,
    recommendations_json  TEXT    NOT NULL,
    created_at            TEXT    NOT NULL,
    FOREIGN KEY (alert_id) REFERENCES alert(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_mit_created ON mitigation_record(created_at);
CREATE INDEX IF NOT EXISTS idx_mit_alert   ON mitigation_record(alert_id);
```

### Week 2 additions — auth, session, audit

Three tables added by Week 2 (Sub-task 1). The four ERD tables above are
untouched. All additive; no column type changes, no FKs added to the
existing ERD tables.

```sql
CREATE TABLE IF NOT EXISTS user (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    username       TEXT    NOT NULL UNIQUE,
    password_hash  TEXT    NOT NULL,          -- bcrypt $2b$12$... cost 12
    role           TEXT    NOT NULL CHECK(role IN ('admin','analyst')),
    created_at     TEXT    NOT NULL,
    created_by     INTEGER,                   -- FK self-ref; NULL for bootstrap admin
    disabled_at    TEXT,                      -- NULL if active
    last_login_at  TEXT,
    FOREIGN KEY (created_by) REFERENCES user(id)
);
CREATE INDEX IF NOT EXISTS idx_user_username ON user(username);

CREATE TABLE IF NOT EXISTS session (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    token         TEXT    NOT NULL UNIQUE,    -- 32-byte url-safe random
    user_id       INTEGER NOT NULL,
    created_at    TEXT    NOT NULL,
    expires_at    TEXT    NOT NULL,           -- created_at + 8 hours
    revoked_at    TEXT,                       -- NULL if live
    last_seen_at  TEXT,                       -- updated on every validate_token
    user_agent    TEXT,
    ip_address    TEXT,
    FOREIGN KEY (user_id) REFERENCES user(id)
);
CREATE INDEX IF NOT EXISTS idx_session_token   ON session(token);
CREATE INDEX IF NOT EXISTS idx_session_user_id ON session(user_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TEXT    NOT NULL,
    actor_user_id   INTEGER,                  -- NULL for unauthenticated 401s
    actor_username  TEXT,                     -- denormalized; survives user delete
    action          TEXT    NOT NULL,         -- e.g. 'login', 'user.create', 'capture.start',
                                              --       'permission.denied', 'auth.failed'
    target          TEXT,                     -- e.g. 'user:3', 'endpoint:/capture/start'
    status          TEXT    NOT NULL CHECK(status IN ('success','failure')),
    detail          TEXT,                     -- short reason / context
    ip_address      TEXT,
    user_agent      TEXT,
    FOREIGN KEY (actor_user_id) REFERENCES user(id)
);
CREATE INDEX IF NOT EXISTS idx_audit_ts            ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_actor_user_id ON audit_log(actor_user_id);
```

DDL is defined in the same `src/utils/db.py:SCHEMA_DDL` string as the
four ERD tables and is created idempotently on every `init_db()`. The
`IDS_DB_PATH` env var overrides the default `data/ids.db` location
(used by the verification harnesses; production code paths leave it
unset).

---

## 8. How to Run

### Cold start (clean machine — no `.venv`, no DB)

On Windows: double-click `START.bat`, or from a terminal:

```bat
cd C:\path\to\ai_ids_complete
START.bat
```

`START.bat` does, in order:

1. If `.venv\Scripts\python.exe` missing → `python -m venv .venv`.
2. Probes that `sklearn, pandas, joblib, fastapi, streamlit, plotly` import
   from the venv. If any are missing → `pip install -r env/requirements.txt`.
3. If `models/model_meta.json` missing → runs `src/data/mock_data.py` then
   `src/models/train.py`. (For CIC-trained models, run
   `python src/data/prep_cic2017.py` first; `START.bat` doesn't do this
   automatically.)
4. Runs `python launch.py`.

On Linux/macOS:

```bash
python -m venv .venv
.venv/bin/pip install -r env/requirements.txt
# Optional first time, if you want CIC-trained models:
.venv/bin/python src/data/prep_cic2017.py
.venv/bin/python src/models/train.py
.venv/bin/python launch.py
```

### Warm start (everything installed and trained)

Just `START.bat` again, or `.venv\Scripts\python.exe launch.py`. The
launcher recreates the DB schema idempotently and seeds the hot cache
from any existing rows.

### Enable live capture

1. Close the running launcher (window or `Ctrl+C`).
2. On Windows: install Npcap if not already present
   (https://npcap.com/, "WinPcap-compatible mode" enabled).
3. Right-click `START.bat` → "Run as administrator".
4. In the dashboard sidebar, pick an interface from the dropdown and
   click "Start capture". If the API was not launched with admin, the
   request returns a 403 with a toast: *"Live capture requires running
   the API as Administrator. Close and relaunch START.bat with admin
   rights."*

### Stop cleanly

- Close the terminal window that ran `launch.py` (it traps the SIGINT,
  calls `/replay/stop` and `/capture/stop`, then terminates uvicorn
  and Streamlit).
- Or `Ctrl+C` in that terminal.
- No `STOP.bat` exists despite the README claim — see §10.

### Ports

| Port | Service | Where to change |
|---|---|---|
| 8000 | FastAPI / uvicorn | `launch.py` (`--port`), `dashboard/app.py` (`API_BASE`), `tools/replay_loop.py` (`API_URL`), `src/capture/live_capture.py` (`API_URL`) |
| 8501 | Streamlit | `launch.py` (`--server.port`), `.streamlit/config.toml` |

Changing port 8000 requires touching four files because the API base URL
is embedded as a literal in each client — not ideal but not refactored
in this pass.

---

## 9. Known Limitations

### Security posture (Week 2 update)

- **Bearer-token auth** on all privileged endpoints. Opaque server-side
  session tokens — 32 random url-safe bytes via `secrets.token_urlsafe`,
  stored in the `session` table, **not JWT**. 8-hour TTL. Tokens are
  passed as `Authorization: Bearer <token>` and validated on every
  request (`src/auth/tokens.py:validate_token` rejects unknown,
  revoked, expired, or disabled-user tokens).
- **Passwords hashed with bcrypt** at cost factor 12 via passlib's
  `CryptContext` (single instance in `src/auth/passwords.py`; the
  bootstrap CLI and the `/auth/login` rehash path share it).
- **RBAC permission matrix** in `src/auth/rbac.py:PERMISSIONS`. Two
  roles only — admin and analyst. `Depends(require_permission(...))`
  wraps `/auth/logout`, `/auth/me`, `/users` CRUD, `/audit`,
  `/capture/start`, `/capture/stop`, `/replay/start`, and
  `/replay/stop`.
- **Audit log** captures every privileged action and every failure:
  - successful: `login`, `logout`, `user.create`, `user.role.change`,
    `user.password.change`, `user.disable`, `user.enable`,
    `capture.start`, `capture.stop`, `replay.start`, `replay.stop`,
    `bootstrap_admin`
  - failures (`status='failure'`): `login` (wrong password / disabled
    user / unknown user — all opaque to the caller; the real reason
    is in `audit_log.detail`), `auth.failed` (401: missing or invalid
    token), `permission.denied` (403: valid token, wrong role)
- **`/predict` is loopback-only** at the request level. The handler
  reads `request.client.host` (socket-level, never `X-Forwarded-For`)
  and 403s anything that isn't 127.0.0.1 / ::1 / localhost. Replay
  and live-capture POST to it from inside the same Python process,
  so this is M2M-safe.
- **API binds `127.0.0.1`** (not `0.0.0.0`) — unchanged from Phase 1.
- **CORS is pinned** to the Streamlit dashboard origins
  (`http://localhost:8501`, `http://127.0.0.1:8501`) in
  `src/serve/app.py` — tightened from `["*"]` in the W4-Sub4d security
  pass (2026-05-28). The `/predict` socket is loopback-only regardless.
- **Out of scope** (proposal §2.2.6): 2FA, password reset flows,
  email verification, OAuth/SSO, multi-tenant isolation.

### Platform-specific

- `START.bat` is Windows-only.
- Live capture requires:
  - **Windows:** Npcap installed AND running the API as administrator.
  - **Linux:** running the API as root, or granting
    `CAP_NET_RAW + CAP_NET_ADMIN` to the Python binary.
- Privilege probe (`L2listen`) runs synchronously on `/capture/start`;
  if the OS denies it, the 403 is returned immediately. No silent
  background failure.

### Manual one-time steps

- **Npcap install on Windows** before live capture works.
- **CIC-IDS2017 dataset** is shipped under `data/downloads/` in this repo
  (~800 MB). If cloned without it, run `python src/data/prep_cic2017.py`
  after placing the CSVs there, or skip and use `mock_data.py` for
  synthetic training data.

### Feature-schema approximations (live capture only)

The live-capture flow aggregator can compute 48 of the 50 model features
exactly from the raw packet stream. Two features are approximated because
the aggregator does not implement CICFlowMeter-style active/idle burst
detection:

| Feature | Approximation | Source of formula |
|---|---|---|
| `active_std` | `active_mean * 0.5` | `src/data/prep_cic2017.py` missing-column fill formula |
| `idle_std` | `idle_mean * 0.5` | same |

Pre-existing approximations carried forward (not changed in last pass):

| Feature | Approximation | Reason |
|---|---|---|
| `init_win_bytes_forward` | Constant `8192` | TCP initial window not parsed from SYN handshake by current `FlowAggregator` |
| `init_win_bytes_backward` | Constant `8192` | same |
| `active_mean` | `duration / (total_pkts + 1)` | No active-burst tracking |
| `idle_mean` | `mean(all_iats)` | No idle-burst tracking |

Full provenance table is in `CHANGES.md` §4.

### Fragile / brittle

- **Port 8000 hard-coded in four places** (see §8 table). Change one,
  forget another, things break silently.
- **`tools/replay_attack.py` and `tools/replay_dos.py` are dead code** —
  they exist on disk but no entrypoint calls them. Confused future-me
  has reached for them once already.
- **`docker/docker-compose.yml` is untested in this pass.** It was
  written before the SQLite/live-capture pass; volumes mount the project
  root in but `data/ids.db` won't have correct ownership inside the
  container without uid mapping. Probably needs rework or removal.
- **`README.md` is stale.** It still references `SETUP.bat`, `STOP.bat`,
  `app_desktop.py`, `src/data/process_cicids.py`, and `evaluation/evaluate.py`
  — none of which exist in the current repo. The actual files are
  `START.bat` only, `launch.py`, `src/data/prep_cic2017.py`, and there
  is no separate evaluate script (training writes the report).
- **Dashboard doesn't render mitigation recommendations per-alert.** Data
  is in `mitigation_record` and accessible via `/mitigation/{type}/{severity}`
  — but no panel surfaces it. Visible only as "attack_type + severity"
  pills in the recent alerts table.

### What requires admin/root

- Live capture only. Replay, dashboard, API, training, and all
  read endpoints run as a normal user.

---

## 10. What Changed in the Last Pass

Full detail is in `CHANGES.md`. Top-line summary:

- **FR_01 closed.** `src/capture/live_capture.py` extended to produce the
  full 50-feature schema; new `run_in_thread()` API; new control endpoints
  `/capture/start|stop|status|interfaces` in `src/serve/app.py`; sidebar
  toggle in `dashboard/app.py`.
- **Figure 4.2 ERD implemented as SQLite** (`data/ids.db`) — four tables,
  foreign keys with cascade, WAL mode, single-transaction inserts via
  `src/utils/db.py:insert_flow_result()`.
- **`/predict` writes the full chain.** Benign flows write traffic_flow +
  detection_result; attacks also write alert + mitigation_record. CSV at
  `logs/alerts.csv` kept as backup with 5 MB rotation.
- **`/alerts` is now a hot cache** (deque, max 1000) hydrated from SQL on
  startup; **`/stats` reads aggregates directly from SQL** — both survive
  restart.
- **Lifespan migration.** `@app.on_event("startup")` replaced with the
  FastAPI `lifespan` async context manager. Lifespan also calls
  `db.init_db()` and hydrates the cache.
- **Single source of truth for replay.** `launch.py` no longer spawns
  `replay_loop.py` directly. It waits for `/health`, then calls
  `POST /replay/start`. The dashboard sidebar controls the same process.
- **Admin-required toast.** `/capture/start` returns a structured
  `{error: "admin_required", message: "..."}` 403 on `PermissionError`;
  the dashboard renders it as `st.error(...)` with a clear remediation
  message.
- **Replay loop hardened.** `FEATURE_NAMES` and `CIC_PROFILES` no longer
  loaded at import time; `main()` exits with a clear message if
  `models/model_meta.json` is missing.
- **Mechanical cleanup.** Removed stray `nul` file (Windows reserved name,
  required Win32 raw-path delete); removed duplicate
  `reports/evaluation_report.txt` write from `train.py`; removed unused
  `import json` in `helpers.py`; anchored dashboard paths to project root
  instead of CWD; added `scapy` to requirements; ignored
  `data/ids.db*` + `logs/alerts-*.csv.bak` in `.gitignore`.

---

## 11. What's Next

Roughly ordered by ratio of impact to effort.

| # | Item | Effort | Why |
|---|---|---|---|
| 1 | **Rewrite README.md.** | S | Currently misleading — references files that don't exist. Replace with the architecture diagram from §3 and the run instructions from §8. |
| 2 | **Surface mitigation recommendations in the dashboard.** | S | Backend already stores them and the endpoint exists. Add an expander row under each alert in the Recent Alerts table that fetches `/mitigation/{type}/{severity}` and renders the bullet list. |
| 3 | **Centralize the API base URL.** | S | Move the `127.0.0.1:8000` literal to one config module read by `dashboard/app.py`, `tools/replay_loop.py`, `src/capture/live_capture.py`. Eliminates the "change-port-in-four-places" fragility. |
| 4 | **Delete or wire in `tools/replay_attack.py` and `tools/replay_dos.py`.** | S | They're dead code. Either remove them or expose `/replay/start` modes for attack-only and DoS-flood. |
| 5 | **PDF report export** (proposal Phase 2). | M | The dashboard already has the data shape. A `/reports/export?since=...&until=...` endpoint that renders to PDF (e.g. via WeasyPrint) is straightforward. |
| 6 | **Automated mitigation actions** (proposal Phase 2 — netsh/iptables block by source IP). | M | Requires admin/root; orthogonal to live capture admin requirement. Will need a confirmation flow in the dashboard. |
| 7 | **Multi-dataset support** (proposal Phase 2 — UNSW-NB15, NSL-KDD). | L | Need a feature-mapping layer like `prep_cic2017.py` for each dataset. Trained models would need retraining or a model-per-dataset selector. |
| 8 | **Repair or remove `docker/docker-compose.yml`.** | S | Untested, won't pass over the SQLite volume cleanly without uid mapping. Either fix or delete. |
| 9 | **Add `source_mode` index** to `traffic_flow` if/when live-vs-replay analytics matter. | S | Trivial DDL change in `db.py`. Currently fine — the table is small. |
| 10 | **Authentication.** | M | Explicitly out of proposal scope (§2.2.6), but a single shared-secret header on the control endpoints (`/capture/*`, `/replay/*`) would be cheap insurance if the binding ever changes from loopback. |
| 11 | **Tests.** | M | Zero automated tests today. At minimum: a pytest that boots the API in-process, POSTs a sample flow, and asserts row counts in all four tables. |
| 12 | **Streamlit theming polish + responsive layout.** | S | Cosmetic. |

Effort key: S = under a day, M = a few days, L = a week+.

---

## 12. Handoff Notes for an Assistant

This project is an FYP submission, not a production system. The bar is
"demonstrably implements the proposal" — not "industrial-grade resilient."
Keep that in mind before suggesting refactors.

**What this project usually needs help with.** Three things, in order of
frequency: (1) explaining what the code does, in the language of the
proposal document (FR numbers, ERD references, viva-defensible language);
(2) closing small gaps between proposal claims and implementation
behaviour; (3) Streamlit / dashboard polish.

**Stable. Don't casually refactor.**
- **The ML pipeline.** `src/models/train.py`, the RandomForest configs, the
  F1 threshold search, the RobustScaler choice — these were chosen to
  match the metrics promised in the proposal (`>97 %` binary, `>92 %`
  multi-class macro F1). The trained models in `models/*.joblib` are the
  artifacts the submission relies on; don't retrain casually.
- **The 50-feature schema.** Defined in `src/data/prep_cic2017.py` as
  `UNIFIED_FEATURES`. Same list in `src/data/mock_data.py` (verified by
  schema parity). Same list reconstructed in `src/capture/live_capture.py`
  with documented derivations. Changing the schema invalidates all three
  + the trained models.
- **The SQLite schema and the `insert_flow_result` transaction shape.**
  This is the proposal's Figure 4.2 ERD made real. Renaming a column or
  removing the FK CASCADE is a change to the proposal alignment, not just
  a code change.
- **`launch.py`'s ordering** (uvicorn → wait /health → POST /replay/start
  → Streamlit). It exists exactly this way to enforce a single source of
  truth for replay. Reverting to direct subprocess spawn re-introduces a
  desync bug.

**Fair game.**
- Dashboard panels, styling, layout, new visualizations.
- Additional API endpoints that read from SQL (historical queries,
  exports, filters).
- New tools/ scripts.
- README rewrites (the existing one is stale anyway).
- CHANGES.md / CURRENT_STATE.md updates as the project evolves.
- Test scaffolding.

**Source-of-truth rules.**
- The **proposal document** (FR_01–FR_05, §2.2.1, §2.2.6, Figure 4.2) is
  the source of truth for scope. Do not add features that aren't in it
  without the student's explicit approval — the supervisor reads the
  proposal, not the code.
- **`CHANGES.md`** describes what the last pass did and why.
- **This file (`CURRENT_STATE.md`)** describes where things stand right
  now. If you make non-trivial changes, update both.
- **`models/model_meta.json`** is the runtime source of truth for the
  feature list and class names — read by the API at startup, by
  `tools/replay_loop.py`, and by anything that needs the canonical
  ordering. Don't hand-edit it; regenerate via `src/models/train.py`.

---

## 13. Week 1 Validation — Real Attack Capture Results

End-of-day Week 1 outcome: the live-capture pipeline detects real
network attacks from Kali against the IDS host when the attack tools
produce CIC-shaped flows. Detection is **0** for scan/flood-style tools
that produce 2-packet singleton flows. **No model, aggregator, schema,
threshold, or `/predict` contract was changed to reach this result** —
the Phase 1 model is preserved.

### Detection numbers from Round 3 (2026-05-23, ~18:27–18:33)

| Attack tool | Window | Flow shape | Detected | Recall |
|---|---|---|---|---|
| **slowhttptest** (slow-read DoS, 200 sockets) | 18:27:30 – 18:31:41 | session-based, multi-packet | majority detected as DoS | ~70 % |
| **medusa** (SSH brute force, 6 attempts) | 18:32:01 – 18:32:02 | full SSH handshakes per attempt | partial | partial |
| **nikto** (web vuln scan, 8 106 requests) | 18:32:09 – 18:33:30 | full HTTP request/response per probe | essentially all detected | ~100 % |
| **Combined** | full window | — | **552 attacks recorded** | — |

Threshold at time of measurement: **0.3858** (unchanged).

Source for the windows above: `lab/attack_log.csv` (Round-3 rows). The
underlying live flows are in `data/ids.db` with
`source_mode = 'live'` for the same time range.

### Limitation discovered — live capture vs scan/flood tools

The CIC-trained model's feature space (50 features, schema in
`src/data/prep_cic2017.py:UNIFIED_FEATURES`) is shaped around
**session-based** attack flows — flows that complete TCP handshakes and
exchange many packets per `(src_ip, dst_ip, src_port, dst_port, proto)`
5-tuple. The live `FlowAggregator` in `src/capture/live_capture.py:43`
faithfully implements that 5-tuple keying with a 5 s inactivity timeout.

**What this means in practice:**

| Attack style | Tools | Live-capture outcome | Reason |
|---|---|---|---|
| Session-based (slow DoS, brute force, web scan) | slowhttptest, medusa, nikto, full-handshake hydra | **Detected** | Each connection produces a CIC-shape flow with realistic packet counts, IAT distributions, and length variance. |
| Scan/flood (per-probe random source ports, half-open scans) | hping3 SYN flood, `nmap -sS`, raw slowloris that fails to complete handshakes | **Not detected** | Each probe is a unique 5-tuple → singleton flow with `total_*_packets ≤ 2`, IAT features = 0, packet_length_std ≤ 2. Out-of-distribution relative to CIC training. Round 1 (2 300 flows) and Round 2 (4 285 flows) both scored max 0.273 / 0.291 — below threshold. |

Round 1 captured 2 300 flows during sustained attacks against closed
ports — zero detections. Round 2 opened ports 22 and 80, ran the same
tool family, captured 4 285 flows — still zero detections (max score
0.291). 21 of the 50 model features had ≤3 unique values across all
4 285 Round-2 flows; the model was effectively unable to discriminate
because the input lacked variance.

### Deferred — scan/flood aggregator extension

A coarser-key aggregator (drop `src_port` from the flow key when SYN
rate from one source exceeds a threshold) would let the pipeline merge
SYN-flood / port-scan probes into a single rich flow. Estimated cost:
~130 LOC in `src/capture/live_capture.py` plus retraining or feature-
synthesis tuning, ~3–5 working days. **Not scheduled for Phase 2** —
deferred to future work because: (a) Week 2/3/4 commitments (auth,
netsh mitigation, demo polish) take priority; (b) Round 3 demonstrates
that the attacks the CIC-trained model is supposed to catch are caught
at acceptable recall on the *current* code; (c) the limitation is
documentable in the report rather than blocking submission.

### Provenance / evidence files

- `lab/attack_log.csv` — Round 1, Round 2, Round 3 attack windows
  (start_ts, end_ts, kali_ip, win_ip, notes including DETECTED /
  PARTIALLY DETECTED / failed status)
- `data/ids.db` — `traffic_flow.source_mode = 'live'` rows during the
  three attack windows; raw 50-feature JSON preserved in
  `raw_features_json` for forensic re-analysis
- `CHANGES.md` — "Week 1 closeout — real attack validation" section
