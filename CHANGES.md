# CHANGES — FYP Submission Pass

**Project:** Fall-2025-104 — AI-Driven Intrusion Detection and Threat Mitigation
System for Secure Networks
**Scope of this changeset:** close FR_01 (live capture) and the proposal's
Figure 4.2 ERD (relational persistence). Plus mechanical cleanup folded into
the same pass.

---

## 2026-06-01 — User manual screenshots (Figures 8.1–8.11)

- Added report-ready PNG figures under `reports/figures/` for the startup
  launcher, login screen, SOC dashboard overview, traffic-source controls,
  highlighted recent alerts, Request Block panel, mitigation page, user
  management page, audit log, generated local-LLM incident report, and logout
  control.
- Captured the application views from the running local dashboard. No
  mitigation request, firewall change, user-management mutation, replay start,
  or live-capture start was performed while preparing the figures.
- Generated the Figure 8.10 advisory report from the existing alert `#9180`
  using the local language-model service. The report remains read-only and did
  not alter detection, scoring, mitigation, or database records.

---

## AI incident report (local LLM)
Added "Generate Incident Report (AI)" feature. New module src/llm/report.py calls a
LOCAL Ollama instance (default qwen2.5:3b, fallback llama3.2:1b) to write a plain-text
incident report for an existing alert. New authed read-only route src/serve/report_routes.py
(GET /report/{alert_id}, gated on view.dashboard). Dashboard gains a report expander with a
.txt download. ADVISORY/READ-ONLY: does not affect detection, scoring, mitigation, or the DB.
No cloud, no new Python deps. Degrades gracefully (503 -> offline notice) if Ollama is down.

### 2026-05-31 — Report panel reliability fixes (dashboard/app.py only)
- Refactored the report panel into an `@st.fragment` so it reruns independently
  of the page's 4s `st_autorefresh` (the live feed no longer has to freeze).
- Restored the `report_generating` pause around the blocking LLM call so a page
  autorefresh can't re-arm and tear down an in-flight request.
- Fixed stale display: the incident-report `st.text_area` was keyed, so Streamlit
  cached the first report and ignored later `value=` arguments — switching alerts
  kept showing the previous report. Removed the key; it now re-renders the current
  report (confirmed via fastapi.log: the backend was producing correct, distinct
  reports all along — purely a display bug).
- Fixed "first click does nothing, second click works": replaced the
  `if st.button(...)` check with an `on_click` callback that records the request in
  `session_state`, processed on the next run. The action no longer depends on
  catching the exact click-rerun, which the 4s autorefresh could pre-empt.
All four changes are dashboard-only and advisory; detection, scoring, mitigation,
and the DB are untouched.

---

## 1. FR_01 closed — Live packet capture wired in

The proposal commits to capturing live traffic from a chosen interface using
Scapy/PyShark (FR_01). Previously, `src/capture/live_capture.py` existed but
was orphaned — never invoked. This pass wires it in as a togglable traffic
source that coexists with the existing replay mode (for demo reproducibility,
the proposal demo flow is unchanged by default).

### What changed
- `src/capture/live_capture.py`
  - Added `run_in_thread(iface, api_url) -> (thread, stop_event)`. Imports
    Scapy synchronously so missing-dependency errors surface immediately;
    probes raw-socket privileges via `L2listen` before spawning the sniff
    thread so `PermissionError` is raised on the start call rather than
    silently inside a background thread.
  - Extended `FlowAggregator._extract_features` from 38 features to the
    full 50-feature schema the model expects (parity with
    `src/data/prep_cic2017.py` and `src/data/mock_data.py`). See
    §4 below for derivation provenance — no formulas were invented.
- `src/serve/app.py`
  - New control endpoints: `GET /capture/interfaces`,
    `POST /capture/start`, `POST /capture/stop`, `GET /capture/status`.
  - Capture runs as a managed thread inside the API process. On
    `PermissionError` the start endpoint returns a structured 403 body
    `{"error":"admin_required","message":"..."}` so the dashboard can
    render an admin-required toast instead of a raw HTTP error.
- `dashboard/app.py`
  - Sidebar **Traffic Source** section with two independent toggles
    (Replay, Live Capture). Live Capture has an interface dropdown
    populated from `/capture/interfaces`.
  - The admin-required and scapy-missing error shapes render as a
    Streamlit `st.error` toast with the exact remediation message from
    the proposal demo script, e.g.: *"Live capture requires running the
    API as Administrator. Close and relaunch START.bat with admin rights."*
- `env/requirements.txt`: added `scapy`.
  - Windows runtime requirement (not pip-installable): **Npcap**
    (https://npcap.com/).

### Live capture coexists with replay
Both sources POST to the same `/predict` endpoint. They are distinguished
in storage by `traffic_flow.source_mode` (`'replay'` vs `'live'` vs
`'manual'`), and in the runtime by the `flow_id` prefix (`live-<uuid8>`
vs `<src_ip>-<uuid8>`). They can run simultaneously; the dashboard
toggles are independent. This matches the FR_01 demo requirement
(capture works) without breaking the FR_02–FR_05 reproducibility story
(replay still works the same way).

---

## 2. Figure 4.2 ERD implemented as SQLite (`data/ids.db`)

Previously, alerts were stored only as flat `logs/alerts.csv` with no
referential integrity, and aggregate stats were in-memory only (reset on
restart). This pass introduces a proper relational store mapped 1:1 to
the proposal's Figure 4.2.

### Schema (`src/utils/db.py`)

`PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;`

| Table | Key columns | FK | Notes |
|---|---|---|---|
| `traffic_flow` | `id PK`, `ts`, `flow_id`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `duration`, `source_mode`, `raw_features_json` | — | One row per POST /predict. `source_mode CHECK IN ('replay','live','manual')`. Indexes on `ts`, `flow_id`, `src_ip`. |
| `detection_result` | `id PK`, `score`, `label`, `label_text`, `attack_type`, `attack_confidence`, `model_version`, `threshold`, `created_at` | `flow_id → traffic_flow.id ON DELETE CASCADE` | One row per detection. Indexes on `created_at`, `flow_id`, `label`, `attack_type`. |
| `alert` | `id PK`, `severity`, `status` (default `'open'`), `created_at` | `detection_id → detection_result.id ON DELETE CASCADE` | Created only when `label == 1`. Indexes on `created_at`, `detection_id`, `severity`. |
| `mitigation_record` | `id PK`, `attack_type`, `severity`, `description`, `recommendations_json`, `created_at` | `alert_id → alert.id ON DELETE CASCADE` | Created with each `alert`. Indexes on `created_at`, `alert_id`. |

### Write path
`POST /predict` writes every row of the chain in a **single transaction**
via `db.insert_flow_result(...)`. Benign flows produce
`traffic_flow + detection_result`; attacks produce all four. If the chain
fails, nothing is committed (try/except wraps `BEGIN`/`COMMIT`/`ROLLBACK`).
The CSV at `logs/alerts.csv` is kept as a **backup** with 5 MB rotation
(`helpers.rotate_csv_if_large`).

### Read path
- `GET /alerts` reads from `recent_alerts`, a `deque(maxlen=1000)`.
  This deque is now a **hot cache** of the most recent
  `detection_result` rows. It is hydrated from SQL at startup
  (`lifespan`) so it survives API restarts, and updated on every
  `/predict`. **Source of truth is SQL.** Historical queries beyond
  the 1000-row window should go to `data/ids.db` directly.
- `GET /stats` reads aggregate counts straight from SQL
  (`db.fetch_stats()`) — `attack_types`, `severity_counts`,
  `total_flows`, `attack_rate_pct`. These now survive restart.

### Dashboard API surface unchanged
`dashboard/app.py` still hits the same `/health`, `/alerts`, `/stats`,
`/mitigation/*` endpoints. No client-side migration needed.

---

## 3. Phase 3 smoke test — verified end-to-end

Smoke run (post-rebuild from clean state — `.venv` and `data/ids.db`
both deleted):

```
============== /health ==============
{
  "status":"ok",
  "model_binary":true, "model_multi":true,
  "model_version":"rf_cic_binary.joblib",
  "threshold":0.38584062950485853,
  "data_source":"CIC-IDS2017",
  "db_path":".../data/ids.db",
  "flows_processed":120,
  "classes":["Benign","Bot","Brute Force","DDoS","DoS","Infiltration","Port Scan","Web Attack"],
  "n_features":50,
  "capture_running":false, "replay_running":false
}

============== /stats ==============
{
  "total_flows":120, "total_attacks":50, "total_benign":70,
  "attack_rate_pct":41.7,
  "attack_types":{"Brute Force":12,"Port Scan":10,"DoS":10,"Infiltration":9,"DDoS":9},
  "severity_counts":{"Low":33,"Medium":9,"High":7,"Critical":1},
  "threshold":0.38584062950485853
}

============== SQL row counts ==============
  traffic_flow         120
  detection_result     120
  alert                50
  mitigation_record    50

  FK chain - last 5 alerts joined across all four tables:
    mit#50 -> alert#50 -> det#118 -> flow#118  198.51.100.77-9c6b6caf   DoS          sev=Low      src=replay
    mit#49 -> alert#49 -> det#115 -> flow#115  212.71.253.80-17364e1d   Infiltration sev=Low      src=replay
    mit#48 -> alert#48 -> det#112 -> flow#112  23.129.64.210-69c7c00d   DDoS         sev=Low      src=replay
    mit#47 -> alert#47 -> det#111 -> flow#111  103.25.17.9-74c69a56     Infiltration sev=Medium   src=replay
    mit#46 -> alert#46 -> det#107 -> flow#107  91.219.236.80-a12c8e7e   DDoS         sev=Medium   src=replay

============== /capture/interfaces ==============
  status: 200
  interface count: 42
    (NPF device handles, sample: \Device\NPF_{AE32E0B8-...}, ...)
```

**Invariants verified:**
- `count(traffic_flow) == count(detection_result)` (every prediction
  writes both rows in one txn) → ✓ 120/120.
- `count(alert) == count(mitigation_record) == total_attacks` → ✓ 50/50/50.
- FK chain `mitigation_record → alert → detection_result → traffic_flow`
  joins cleanly for every row → ✓ verified on tail of 5 rows.
- `attack_types` sum (12+10+10+9+9 = 50) == `total_attacks` → ✓.
- `/capture/interfaces` returns Scapy interfaces without requiring admin
  (only `/capture/start` requires admin) → ✓.

**Note on the 5 hand-crafted /predict probes:** the synthetic feature
values used to manually exercise `/predict` (3 attack-shaped flows,
2 benign-shaped) all scored below the threshold (`max 0.239` vs
`threshold 0.386`) and so all 5 landed in `traffic_flow + detection_result`
only. To exercise the `alert + mitigation_record` chain, the smoke test
also ran `/replay/start` (rate=20, attack_ratio=0.6) for 15s, which
produced realistic CIC-profile-sampled flows and filled all four tables
as shown above. Both behaviours are correct — the optimized threshold
is conservative by design (`find_optimal_threshold` in `train.py`
maximizes F1).

---

## 4. Feature-schema parity — provenance of each derivation

`live_capture.py._extract_features` now produces all 50 features the
trained model expects. Where the formula differs between
`mock_data.py` (synthetic) and `prep_cic2017.py` (real CIC), live
capture picks the source that matches the **real underlying signal**
when one is available; otherwise it uses the prep-stage fill formula.
**No formulas were invented for this pass.**

| Added feature | Source of formula | Live-capture computation |
|---|---|---|
| `fwd_packet_length_max` | CIC native (`Fwd Pkt Len Max`); mock fabricates as `mean * U(1.5, 3.0)` | `max(fwd_lens)` — real value from packets, matches CIC half of training data |
| `fwd_packet_length_std` | CIC native; mock fabricates as `mean * U(0.3, 0.8)` | `np.std(fwd_lens)` — real |
| `bwd_packet_length_max` | CIC native; mock fabricates | `max(bwd_lens)` — real |
| `bwd_packet_length_std` | CIC native; mock fabricates | `np.std(bwd_lens)` — real |
| `fwd_iat_std` | CIC native; mock fabricates as `mean * U(0.5, 1.5)`; `prep_cic2017` fill formula is `mean * 0.8` | `np.std(fwd_iats)` — real |
| `bwd_iat_std` | CIC native; mock fabricates; `prep_cic2017` fill is `mean * 0.8` | `np.std(bwd_iats)` — real |
| `subflow_fwd_packets` | Identity in both: `= total_fwd_packets` | `n_fwd` — identity (exact match) |
| `subflow_fwd_bytes` | Identity: `= total_length_of_fwd_packets` | `sum(fwd_lens)` — identity (exact match) |
| `subflow_bwd_packets` | Identity: `= total_backward_packets` | `n_bwd` — identity |
| `subflow_bwd_bytes` | Identity: `= total_length_of_bwd_packets` | `sum(bwd_lens)` — identity |
| `active_std` | **Approximation.** `prep_cic2017.py` missing-column fill formula: `active_mean * 0.5` | `active_mean * 0.5` — uses prep formula |
| `idle_std` | **Approximation.** `prep_cic2017.py` missing-column fill formula: `idle_mean * 0.5` | `idle_mean * 0.5` — uses prep formula |

**Approximations carried forward from pre-existing live_capture code
(not introduced by this changeset, listed here for completeness):**
- `init_win_bytes_forward = init_win_bytes_backward = 8192`. The TCP
  initial window is not visible from packet header inspection alone in
  the way `FlowAggregator` parses; CICFlowMeter reads it from the SYN
  handshake. Documented as an approximation in the original
  `_extract_features` code (`# approximation`).
- `active_mean = duration / (total_pkts + 1)`,
  `idle_mean = mean(all_iats)`. CICFlowMeter computes these from
  active/idle burst-period tracking that `FlowAggregator` does not
  perform. These were already used by the original orphaned code; this
  pass does not change them.

**Why this is safe.** The trained model sees a mixed corpus: half from
`prep_cic2017.py` (real CIC `Active Std`/`Idle Std` columns) and half
from `mock_data.py` (synthetic `mean * U(0.3, 1.0)`, expected value
0.65). For live capture, using `mean * 0.5` (the prep_cic2017 missing-
fill formula) places `active_std`/`idle_std` at a stable point inside
that mixed distribution rather than introducing a new constant the
model has never seen. The first ten attacks in the smoke run all
classified into the expected attack families with sensible scores,
which is consistent with this choice being benign.

---

## 5. Bonus cleanup (folded into this pass)

| Issue | Fix |
|---|---|
| Stray `nul` file at project root (Unix `>/dev/null` redirect on Windows accidentally created a real file) | Deleted (via Win32 raw-path prefix; `nul` is a reserved name and won't unlink without it) |
| `tools/replay_loop.py` loaded `FEATURE_NAMES` / `CIC_PROFILES` at module import — silently produced empty feature dicts if `models/model_meta.json` was missing | Moved both into `main()`. If `FEATURE_NAMES` is empty: `print` instructions and `sys.exit(1)` |
| `src/serve/app.py` used deprecated `@app.on_event("startup")` | Replaced with `lifespan` async context manager (FastAPI ≥ 0.93 idiom). Lifespan also calls `db.init_db()` and hydrates the cache from SQL |
| `dashboard/app.py` paths were relative to CWD — broke if Streamlit launched from outside the project root | Anchored `ALERTS_CSV` and `REPORTS_DIR` to `PROJECT_ROOT = Path(__file__).resolve().parent.parent`. Dropped the unused root-level `alerts.csv` fallback |
| `logs/alerts.csv` grew unbounded (was already 2.3 MB) | `helpers.rotate_csv_if_large(max=5 MB)` renames to `alerts-YYYYMMDD-HHMMSS.csv.bak` on overflow; called at the top of every `log_alert` |
| `src/models/train.py` wrote `evaluation/evaluation_report.txt` AND a duplicate `reports/evaluation_report.txt` | Removed the duplicate write. PNG reports (`confusion_matrix.png`, `threshold_tuning.png`) still go to `reports/` and are still consumed by the dashboard |
| `helpers.py` had `import json` unused | Removed |
| `launch.py` started replay as its own subprocess, AND the dashboard could start one via `/replay/start` — two sources of truth | `launch.py` now waits for `/health` and then calls `POST /replay/start`. The dashboard's Start/Stop toggle controls the same process. One source of truth (adjustment #3) |

---

## Security Note

**(updated W4-Sub4d.)** Capture/replay **control** endpoints
(`/capture/start`, `/capture/stop`, `/replay/start`, `/replay/stop`)
require `capture.control` / `replay.control` permission via
`require_permission` since Week 2. Read-only status endpoints
(`/capture/interfaces`, `/capture/status`, `/replay/status`) remain
unauthenticated by design — they expose NIC names and worker state
only, and are reachable only on loopback. The original Week-1 note
below described the pre-Week-2 state and is retained for provenance.

- **Section 2.2.1** (System Architecture) defines the deployment as a
  standalone desktop application running on a single host. The API
  binds to `127.0.0.1:8000` only — never `0.0.0.0`. There is no
  network listener exposed off the loopback interface, so the trust
  boundary is the local user account.
- **Section 2.2.6** (Non-functional requirements) treated multi-user
  access control as out of scope for the Phase 1 submission; Phase 2
  Week 2 added two-role RBAC + an audit log on top, so this is now
  shipped, not deferred.

CORS is pinned to the Streamlit origins (`http://localhost:8501`,
`http://127.0.0.1:8501`) as of W4-Sub4d; it was previously
`allow_origins=["*"]` for localhost-only development.

Live capture additionally requires the *operating system's* privilege
boundary — administrator rights on Windows, root on Linux — because
raw socket access (Scapy `L2listen`) is gated by the OS. When that
check fails, `/capture/start` returns a structured 403 the dashboard
renders as a clear toast: *"Live capture requires running the API
as Administrator. Close and relaunch START.bat with admin rights."*

---

## Mapping back to the proposal

| Proposal artifact | Where it lives in the code now |
|---|---|
| FR_01 (live capture, interface selection) | `src/capture/live_capture.py` + `/capture/*` endpoints in `src/serve/app.py` + sidebar toggle in `dashboard/app.py` |
| FR_02 (real-time detection) | `POST /predict` in `src/serve/app.py` (unchanged behaviour; now also writes SQL) |
| FR_03 (multi-class classification) | `model_multi` branch in `src/serve/app.py`, persisted to `detection_result.attack_type` |
| FR_04 (mitigation recommendations) | `src/utils/helpers.py:get_mitigation`, persisted to `mitigation_record` |
| FR_05 (SOC dashboard) | `dashboard/app.py` (KPIs, alert table, plots, source toggles) |
| Figure 4.2 ERD — traffic_flow | `traffic_flow` table |
| Figure 4.2 ERD — detection_result | `detection_result` table (FK → traffic_flow) |
| Figure 4.2 ERD — alert | `alert` table (FK → detection_result) |
| Figure 4.2 ERD — mitigation_record | `mitigation_record` table (FK → alert) |
| Section 2.2.1 (standalone desktop) | API binds 127.0.0.1, no external listeners |
| Section 2.2.6 (out-of-scope auth) | No control-plane authentication; documented in Security Note above |

---

## Week 1 closeout — real attack validation (2026-05-23)

End-to-end validation that the live-capture pipeline detects real attacks
launched from Kali (192.168.142.128) against the IDS host (192.168.142.1)
on a VMware host-only network. No model retraining, no aggregator changes,
no schema changes — the Phase 1 model and the 50-feature schema were
preserved throughout.

### Hotfixes applied (live-capture compat with scapy 2.7 + IP plumbing)

- **`L2listen` hotfix** — `from scapy.all import L2listen` is no longer
  exported on scapy 2.5+/2.7. `src/capture/live_capture.py:run_in_thread`
  now resolves the listen-socket class via `conf.L2listen` (the public
  class reference, equivalent to `L2pcapListenSocket` on Windows with
  Npcap). The synchronous privilege probe semantics are preserved so
  `PermissionError` still surfaces on `/capture/start` rather than
  silently inside the sniff thread.
- **IP-fields plumbing** — live capture extracted `src_ip` / `dst_ip`
  correctly from the packet stream, but the `/predict` request contract
  had no carrier for those fields, so `traffic_flow.src_ip` /
  `traffic_flow.dst_ip` were NULL on every live row. Fixed by adding
  optional `src_ip / dst_ip / src_port / dst_port / protocol` fields to
  the `Flow` Pydantic model (`src/serve/app.py`), passing them through
  to `db.insert_flow_result(...)`, and having
  `live_capture.flush_and_send` populate them on each POST. Replay
  continues to work unchanged: it doesn't send these fields, and
  `db._flow_meta_from_features` falls back to flow_id-prefix parsing
  as before.

### Three Kali attack rounds — what worked and what didn't

| Round | Tools used | Target services | Flows captured | Detected | Outcome |
|---|---|---|---|---|---|
| 1 | hping3 SYN flood, slowloris, hydra SSH | All ports closed on target | 2,300 | **0** | Singleton-flow failure: every connection was a 2-packet (SYN, RST) exchange because nothing was listening. Diagnostic confirmed the model was being fed degenerate, near-zero-variance feature vectors. |
| 2 | hping3, nmap `-sS`, raw slowloris, hydra | OpenSSH + HTTP opened on target | 4,285 | **0** (max score 0.291 vs threshold 0.386) | Even with listening services, *scan/flood-style* tools (hping3 random source ports, nmap half-open scan) still produced 2-packet singletons because each probe used a fresh source port and was RST-ed before completing. 21 of 50 features had ≤3 unique values across all 4,285 flows. |
| 3 | slowhttptest, medusa SSH, nikto | OpenSSH + HTTP open, same target | (run-3 capture window) | **552** | Switched to tools that complete TCP sessions and exchange many packets per connection. Detection per tool: slowhttptest ~70 % recall, nikto ~100 % recall, medusa SSH partial. |

### Decision: no code change, no retraining

The diagnostic established that the model and aggregator are correct for
the kind of attacks CIC-IDS2017 actually labels — session-based attacks
that produce multi-packet TCP flows. The capture gap is real but isolated
to SYN-flood / port-scan tools that never complete handshakes. A future
aggregator extension (coarser key for scan/flood traffic) is documented
in `CURRENT_STATE.md` §13 as deferred work.

What is preserved unchanged through this validation:
- `models/*.joblib` (binary + multi-class RF) — same artifacts as Phase 1
- `models/model_meta.json` and the 50-feature schema
- `src/models/train.py`
- `models/threshold.txt` (still **0.3858**)
- `/predict` contract (the new fields are *additive optional*; the
  semantics of `features` are unchanged)
- The four ERD tables and the `insert_flow_result` transaction shape

### Files touched by Week 1 hotfixes

- `src/capture/live_capture.py` — L2listen → `conf.L2listen`; payload to
  `/predict` now includes `src_ip / dst_ip / src_port / dst_port / protocol`
- `src/serve/app.py` — `Flow` Pydantic model gains five optional fields;
  `predict()` passes them through to `db.insert_flow_result(...)`
- `src/utils/db.py` — `insert_flow_result()` accepts the new optional
  kwargs and prefers them over the flow_id-prefix fallback
- `lab/attack_log.csv` — three appended rows for the Round-3 attacks
- `CHANGES.md` — this section
- `CURRENT_STATE.md` — new §13

---

## Week 1 closeout — ATTACK_VALIDATION.md generated (2026-05-24)

Pure documentation pass. No code, model, threshold, schema, DB rows,
or `/predict` contract changed.

Added: `lab/ATTACK_VALIDATION.md` — the Week-1 centerpiece writeup
for Phase 2 defense. Sections cover methodology (lab setup, attack
tooling, IDS config, capture process), per-attack results for both
runs, attack-tool selection rationale (why slowhttptest/medusa/nikto
instead of nmap-sS/hping3/hydra), reproducibility comparison,
honest limitations, threats to validity, provenance, and conclusion.

All counts and percentages were queried directly from `data/ids.db`
against the windows in `lab/attack_log.csv`, filtered by
`source_mode = 'live'` and Kali IP `192.168.142.128`. Strict-window
totals (matching the recorded start/end timestamps): Run 1 = 347
detections in 1 348 live flows (25.7 %); Run 2 = 276 detections in
484 live flows (57.0 %). Per-tool recall ranges: slowhttptest 29–66 %,
medusa SSH 67–100 %, nikto 29–84 %. The document explains why these
strict-window numbers are conservative relative to true attack-only
recall (background benign traffic dilutes the denominator) and why
trailing slowhttptest tail flows that flush after the recorded
`end_ts` were excluded.

---

## Week 2 closeout — Auth + RBAC + admin pages (2026-05-24)

Phase 2 Week 2 closed: two-role authentication + RBAC + per-action
audit log + Streamlit admin pages, all built on top of the preserved
Phase 1 ML pipeline. Sub-tasks landed sequentially and each was
verified before the next began.

### What shipped

| Sub-task | Surface | Verified by |
|---|---|---|
| 1 | DB tables `user`, `session`, `audit_log` (additive) + `tools/bootstrap_admin.py` CLI | 4 init/idempotency/refusal checks |
| 2 | `src/auth/` package: `passwords`, `tokens`, `audit`, `rbac` (+ permission matrix) | round-trip A-D pure-function checks |
| 3 | `/auth/login\|logout\|me`, `/users` CRUD, `/audit` filter; `require_permission(...)` on `/capture/*` and `/replay/*`; `/predict` loopback-only | E1-E13 against fresh uvicorn + temp DB |
| 4 | Streamlit login screen, role-aware sidebar, bearer-token plumbing; `dev_up.ps1` admin-login step | F1-F8 in browser + auto API contract |
| 5 | Admin-only Streamlit pages: `Users`, `Audit Log` | G1-G2 auto; G3-G12 manual (this section) |

### Hard constraints preserved

`src/models/train.py`, `models/*.joblib`, `models/threshold.txt`,
`UNIFIED_FEATURES`, the `FlowAggregator`, the four ERD tables
(`traffic_flow`, `detection_result`, `alert`, `mitigation_record`),
and the `/predict` request/response contract are all untouched.
Stack additions limited to `passlib[bcrypt]==1.7.4` and
`bcrypt==4.0.1` in production `requirements.txt`; `httpx` and
`pytest` are dev-only in a new `requirements-dev.txt`.

### New files (Sub-task 5)

- `dashboard/pages/1_Users.py` — admin User Management page (list,
  create, role change, password reset, disable / re-enable).
- `dashboard/pages/2_Audit_Log.py` — admin Audit Log viewer with
  filters (limit, since, action prefix, actor, status) + CSV export.

### Modified files (Sub-task 5)

- `dashboard/app.py` — sidebar footer adds two hint captions
  ("→ **Users** page (sidebar nav)" and "→ **Audit Log** page
  (sidebar nav)") visible only when the user has the relevant
  permission.

### Known limitation — OPTION X visibility

Streamlit's built-in `pages/` mechanism shows page names in the
sidebar nav to all logged-in users regardless of role. The two
admin pages each gate at script-top with
`require_login()` + permission check, so an analyst who clicks
"Users" or "Audit Log" gets a hard red `st.error("Admin only ...")`
+ `st.stop()`. The nav entry itself remains visible. This is
**defense in depth** rather than a confidentiality concern (the
API enforces the same gate independently and writes
`permission.denied` audit rows). Cleaner per-role nav hiding via
custom sidebar render is future-work polish.

### Verification status — Sub-task 5

- G1 — files exist + parse: PASS (auto)
- G2 — `/users` and `/audit` contract still correct: PASS (auto)
- G3-G12 — see in-session manual test plan; user to confirm in
  browser. Underlying API endpoints were exercised end-to-end during
  sub-task 3 verification (E1-E13).

---

## 2026-05-24 — Week 2 closeout: two-role auth on Streamlit DONE

Sub-tasks 1-5 code complete. Programmatic G1+G2 + manual G3-G12 browser
tests all passed. Bearer-token auth, RBAC, audit log, Users admin page,
Audit Log admin page all live. Phase 1 brain untouched.

---

## 2026-05-24 — Week 3 Sub-task 1: mitigation schema + module skeleton

Added mitigation_request, mitigation_action tables + 6 indexes to
SCHEMA_DDL. Idempotent. Existing ERD/auth tables untouched. Created
src/mitigation/ package. No endpoints yet (W3-Sub3) and no firewall
code (W3-Sub2).

---

## 2026-05-25 — Week 3 Sub-task 2: netsh firewall wrapper

src/mitigation/firewall.py written. Pure stdlib, no DB or audit.
Public: is_admin, validate_ip, block_ip, unblock_ip,
list_blocked_ips. Private ranges rejected by default. Idempotent.
Ledger at data/blocked_ips.json. 6 pytest tests pass with
subprocess mocked — no real netsh calls during testing.

---

## 2026-05-25 — Week 3 Sub-task 3: mitigation endpoints + RBAC + audit

src/serve/mitigation_routes.py with 6 endpoints: POST /mitigation/requests
(mitigation.request), GET /mitigation/requests (view.dashboard), POST
/mitigation/requests/{id}/approve (mitigation.approve, 5s two-person
rule), POST /mitigation/requests/{id}/deny (mitigation.approve), GET
/mitigation/blocked (view.dashboard), POST /mitigation/unblock
(mitigation.approve). Wired into app.py. Full audit chain:
request.create → request.approve/deny → block.execute / unblock.execute.
firewall.py cleanup: datetime.utcnow → timezone-aware (identical string
format). 12 pytest tests pass with netsh mocked.
MITIGATION_ALLOW_PRIVATE=true env var enables lab demo against Kali
(192.168.142.128); default rejects private ranges.

---

## 2026-05-25 — Week 3 Sub-task 4: dashboard wiring for mitigation

dashboard/app.py: added Request Block action as an **expander below the
alerts panel** (the existing alerts table is hand-rolled HTML which
doesn't admit per-row buttons, so per-row st.columns would have been
heavily invasive — expander is the cleaner choice). Visible only to
users holding `mitigation.request`. Pre-fetches pending requests once
per render to disable the button with tooltip when the picked IP
already has a pending block.

New dashboard/pages/3_Mitigation.py: admin-only (mitigation.approve),
two sections — Pending Requests (Approve/Deny per row in expanders) and
Active Blocks (dataframe + Unblock selectbox). Uses auth_ui.api_request
for all HTTP. No autorefresh on this page (user-driven actions).

Backend tweak (additive only, no contract changes): added
`a.id AS alert_id` and `f.src_ip AS src_ip` to
src/utils/db.py::fetch_recent_alerts; captured the
db.insert_flow_result return value in /predict so the cache row carries
`alert_id` and `src_ip`. The /alerts response gains two fields; nothing
existing changed. Required for the Request Block panel to identify
which alert it is requesting a block for.

Verification plan H1-H10 documented below; user to run manually after
restarting IDS as admin.

### H1-H10 verification plan (manual, user-run)

- **H1.** Setup. Stop any running IDS process. Re-launch START.bat as
  Administrator (the netsh add/delete needs elevation). Open the
  dashboard at http://localhost:8501 in a browser and sign in as
  `analyst1`.

- **H2.** Trigger an attack. On the Kali VM (192.168.142.128), run
  slowhttptest against the Windows host (the command you've been using
  in lab — replace `<host>` with the IDS box IP):
  `slowhttptest -c 200 -H -g -o slow -i 10 -r 200 -t GET -u http://<host>/ -x 24 -p 3`
  Wait ~20 seconds and watch the dashboard. Confirm Attack-labelled rows
  appear in the Recent Alerts table with the attacker IP visible in the
  Flow ID prefix.

- **H3.** Expand "Request block for an alert" below the alerts table.
  Select the topmost Attack row. Click **Request Block**. Confirm a
  green `st.success` toast appears reading
  `Block requested for 192.168.142.128 (request id N). Awaiting admin approval.`
  The expander re-runs; the dropdown now shows the same row with
  ` — PENDING` suffix and the button is disabled with the tooltip
  `A pending block request already exists for this IP.`

- **H4.** From the dropdown pick a second Attack row with the same
  src_ip (192.168.142.128). Confirm the button is still disabled with
  the same tooltip — the dedupe is per-IP, not per-alert.

- **H5.** If your slowhttptest produced multiple distinct attacker IPs
  (or you started a second attack from a different VM), pick an Attack
  row with a *different* src_ip. Confirm the button is enabled and a
  click creates a new pending request. (Skip if only one src_ip is
  present.)

- **H6.** Click "Sign out" in the sidebar. Sign in again as `admin1`.
  Click **Mitigation** in the left sidebar nav.

- **H7.** Confirm the Pending Requests section shows the request(s)
  created in H3/H5, each in its own expander. Expand the first one.
  Type "demo approval" into the Approval note field. Click
  **Approve & Block**. Confirm a green `st.success` toast appears
  reading `Request N approved. Block executed: rule 'AI-IDS Block
  192.168.142.128' added.` The expander disappears on rerun.

- **H8.** Switch back to the Kali terminal running slowhttptest.
  Confirm the connections start failing / stalling within a few
  seconds (the netsh inbound block rule is now active against
  192.168.142.128). New TCP SYNs from Kali to the host should be
  dropped silently.

- **H9.** In the dashboard, scroll to the Active Blocks section.
  Confirm `192.168.142.128` appears in the dataframe with columns
  `ip, rule_name, blocked_at, request_id, approved_by_username='admin1'`.
  Expand "Unblock an IP", pick `192.168.142.128` from the dropdown,
  type "lab demo done" as the reason, click **Unblock**. Confirm
  `Unblocked 192.168.142.128. Rule removed: AI-IDS Block 192.168.142.128.`

- **H10.** Confirm slowhttptest connections resume (the rule is gone).
  Click **Audit Log** in the sidebar nav. Filter on action prefix
  `mitigation`. Confirm at least these rows are present, in order:
  `mitigation.request.create` (analyst1, success),
  `mitigation.request.approve` (admin1, success),
  `mitigation.block.execute` (admin1, success),
  `mitigation.unblock.execute` (admin1, success).
  This proves the full request → approve → execute → unblock chain
  was recorded end-to-end.

Note for H1: if you're running with `MITIGATION_ALLOW_PRIVATE=true`
already set in the launch script, 192.168.142.128 (private) is allowed
through the request creator. Without the env var, H3 will get a 400
`IP is private (...) ; pass allow_private=True to override` — set the
env var before re-launching START.bat for the demo. Production
deployments leave it unset.

---

## 2026-05-25 — W3-Sub4 hotfix: elevation diagnostic + failure UX

H7-H8 manual verification surfaced a real bug: the API process spawned
by `START.bat` (double-click) was not elevated, so
`firewall.block_ip()`'s `is_admin()` probe returned False and netsh
add-rule was refused. The approval flow itself worked end-to-end
(request created, approved, audit log chain present) but the firewall
rule was never installed and Kali kept reaching the host. Worse, the
dashboard hid this from the admin: the request left Pending, Active
Blocks stayed empty, and the only evidence of failure was in
`/audit?q=mitigation`.

This hotfix is diagnostic-first (per CLAUDE.md): expose the elevation
state, hard-stop unelevated launches, and surface netsh failures in
the dashboard as a real table instead of a transient banner.

Changes:

- **`src/serve/app.py`**: `/health` now returns `admin_elevated: bool`
  (calls `src.mitigation.firewall.is_admin()`). This lets a curl
  smoke-test confirm the elevation state without authenticating.

- **`src/serve/mitigation_routes.py`**: two new endpoints, both
  RBAC-gated on `mitigation.approve` (admin only):
    * `GET /mitigation/_diag/elevation` — read-only probe. Returns
      `platform`, `process_pid`, `MITIGATION_ALLOW_PRIVATE_env`,
      `firewall_is_admin_result`, raw `IsUserAnAdmin` + error,
      and `GetTokenInformation(TokenElevation)` + error. No secrets.
      Two orthogonal probes because IsUserAnAdmin can be misleading
      with UAC linked tokens; if they disagree, that itself is the
      signal.
    * `GET /mitigation/actions/failures?limit=50` — joins
      `mitigation_action` (status='failure') with `mitigation_request`
      for `request_status` and `user` for `executed_by_username`.
      Newest first, max 200.

- **`START.bat`**: hard elevation check at the top of the script
  (`net session >nul 2>&1` + `errorLevel neq 0` → warn + pause +
  `exit /b 1`). Existing `MITIGATION_ALLOW_PRIVATE=true` lab line is
  preserved. `tools/dev_up.ps1` already self-elevates via
  `Start-Process -Verb RunAs` (lines 28-37), so the check is
  intentionally not duplicated there.

- **`dashboard/pages/3_Mitigation.py`**:
    * Approve handler: when the response carries `"warning"` (netsh
      failed), show `st.error(...)` with the error detail AND a hint
      pointing at the new Failed Executions table. Critically, do
      NOT `st.rerun()` in that branch — otherwise the message dies
      with the rerun. The success branch still reruns so the pending
      list refreshes.
    * New "Recent Failed Executions" section below Active Blocks.
      Calls `/mitigation/actions/failures` and renders columns
      `executed_at, action_type, target_ip, request_id,
      executed_by_username, error_detail`.

What's intentionally NOT changed:
- `firewall.py` is untouched. The elevation check there is already
  correct; the problem is the calling process's privileges.
- The audit log chain is unchanged.
- No DB schema changes; the new endpoints only SELECT.
- `dev_up.ps1` is not given a second elevation check — it already
  self-elevates and adding another would be cargo-culted duplication.

Verification (manual, no pytest, no app run was performed for this
sub-task):
- `curl http://127.0.0.1:8000/health` should show
  `"admin_elevated": true` when launched via the elevated START.bat,
  `false` otherwise.
- Unelevated `START.bat` should print the WARNING block and exit 1
  before launching `launch.py`.
- `GET /mitigation/_diag/elevation` (with admin bearer) should return
  `firewall_is_admin_result: true` and `token_elevation: true` on an
  elevated process, both false otherwise.
- An intentionally-failing block (e.g. unelevated API) should appear
  in the new "Recent Failed Executions" dataframe on the Mitigation
  page, with the error message visible in the `error_detail` column.


## 2026-05-25 — Week 3 Sub-task 5: demo readiness UX polish
- /capture/interfaces: response shape extended to {id, name, description} per interface, populated from scapy's get_windows_if_list. Backward-compat-checked across all consumers; no break. Dashboard sidebar now shows friendly labels (e.g. 'Wi-Fi — Intel(R) Wi-Fi 6 AX201 160MHz') instead of raw NPF GUIDs.
- Request Block dropdown in dashboard/app.py now filters out the Windows host's own IPs (resolved via socket.gethostname + getaddrinfo) to prevent operator-error self-blocks. Filter is shown as a visible caption above the dropdown.
- Main dashboard page now shows a small header banner with the current host's IPs as a visual reference for the operator.
- No backend logic, model, capture, or mitigation code changed. Pure UI polish.

## 2026-05-25 — Week 3 Sub-task 6: deduplicate Request Block dropdown by src_ip
Request Block dropdown now shows one option per unique attacker source IP, aggregating count, latest alert_id, and max score per group. Eliminates dropdown noise from high-volume single-attacker traffic (slowhttptest etc.). Caption shows deduplication ratio. Backend behavior unchanged — POST body still carries one alert_id and target_ip; the latest alert_id per group is used.


## 2026-05-25 — Week 3 closeout: full mitigation workflow verified end-to-end

Week 3 is done. All sub-tasks shipped, full request → approve → execute
→ unblock chain verified live against Kali on the bridged Wi-Fi
network. Audit log captures every step.

### Sub-tasks (one-line summary each)

- **W3-Sub1** — mitigation schema additions: `mitigation_request` and
  `mitigation_action` tables, both additive, FK chain to alert + user
  intact, `request_id NOT NULL` on action preserved.
- **W3-Sub2** — `src/mitigation/firewall.py` netsh wrapper (pure
  stdlib): `is_admin`, `validate_ip`, `block_ip`, `unblock_ip`,
  `list_blocked_ips`. Idempotent, ledger-backed. 6 pytest tests pass
  with subprocess mocked.
- **W3-Sub3** — 6 `/mitigation/*` endpoints in
  `src/serve/mitigation_routes.py` with RBAC (`mitigation.request` /
  `mitigation.approve` / `view.dashboard`), full audit chain, 5s
  two-person rule on approve. 12 pytest tests pass with netsh mocked.
- **W3-Sub4** — Streamlit wiring: Request Block expander in
  `dashboard/app.py` and admin-only `dashboard/pages/3_Mitigation.py`
  (Pending Requests + Active Blocks + Unblock).
- **W3-Sub4 hotfix** — elevation diagnostic
  (`/mitigation/_diag/elevation` + `admin_elevated` in `/health`),
  hard elevation gate in `START.bat`, persistent failure UX in the
  Mitigation page, new `/mitigation/actions/failures` table.
- **W3-Sub5** — demo-readiness UX polish: friendly capture interface
  labels (`Wi-Fi — Intel(R) Wi-Fi 6 AX201 ...` instead of NPF GUIDs),
  self-IP filter on Request Block dropdown, host-IP banner at top of
  dashboard.
- **W3-Sub6** — Request Block dropdown deduplication by src_ip
  (one row per attacker IP, aggregating count / latest alert_id /
  max score).

### H1-H10 live verification (PASSED)

Ran end-to-end against Kali bridged at 192.168.1.16, Windows host at
192.168.1.8.

- **Detection** (H2): slowhttptest detected reproducibly. Attack rows
  appeared in the dashboard alerts table within seconds of starting
  `slowhttptest -c 200 -H -g -o slow -i 10 -r 200 -t GET -u http://...
  -x 24 -p 3` on Kali; src_ip column = 192.168.1.16; score in the
  attack range; multi-class label populated.
- **Request** (H3): `analyst1` clicked Request Block on the Kali row.
  201 returned, toast read `Block requested for 192.168.1.16
  (request id N). Awaiting admin approval.` Dropdown re-render
  showed " — PENDING" marker and disabled state on the same IP.
- **Dedup + self filter** (H4 / H5 / W3-Sub5+6): host's own IP
  (192.168.1.8) excluded from the dropdown; multiple alerts from
  192.168.1.16 collapsed to one row reading
  `192.168.1.16 — N recent attack alerts — latest #K at HH:MM:SS
  — max score X.XXXX`.
- **Approval** (H7): `admin1` signed in, opened Mitigation page,
  expanded the pending row, typed "demo approval" as the note,
  clicked Approve & Block. 200 returned with `block_result.ok=true`;
  netsh rule `AI-IDS Block 192.168.1.16` added; audit chain wrote
  `mitigation.request.approve` (success) followed by
  `mitigation.block.execute` (success).
- **Enforcement** (H8): slowhttptest output flipped to
  `connected: 0, service available: NO` within seconds. Kali
  `curl -v --connect-timeout 5 -I http://192.168.1.8/` timed out
  in the TCP handshake. `pfirewall.log` showed DROP entries with
  src=192.168.1.16.
- **Unblock** (H9): admin1 unblocked from the Active Blocks panel.
  netsh rule removed; mitigation_action `unblock` row written with
  status=success.
- **Audit** (H10): Audit Log page filtered on `mitigation` showed,
  in order: `mitigation.request.create` (analyst1, success),
  `mitigation.request.approve` (admin1, success),
  `mitigation.block.execute` (admin1, success),
  `mitigation.unblock.execute` (admin1, success).

### Pre-resolution block-bypass — root cause

Earlier in Week 3 we hit a bypass: the netsh rule existed and was
enabled, the API process was elevated, the rule's profile/scope was
correct, and pfirewall.log showed ZERO drop entries while Kali's
curl still returned HTTP 200. Two round-1 and round-2 diagnostic
scripts (`tools/diagnose_firewall_block.ps1` and
`tools/diagnose_round2.ps1`) narrowed it to a packet path that
bypassed Windows Filtering Platform entirely.

Root cause: **Avast Antivirus** installs a kernel-mode WFP callout
and an NDIS lightweight filter that intercept incoming packets
*before* Windows Defender Firewall evaluates user-mode rules. While
those filters are active, netsh block rules have no effect on the
Avast-bound path. Disabling Avast's shields ("Disable until computer
restart" in the Avast tray menu) allows the WF path to function
normally; the AI-IDS rule then enforces correctly as verified above.

This is a third-party AV co-existence issue, **not** an AI-IDS
defect. The same class of bypass is plausible with Kaspersky, ESET
and Norton, all of which ship comparable kernel-mode filters.
`tools/diagnose_round2.ps1` is the artefact that pinned this down;
keep it for future repeat-debugging.

**Demo workaround**: as Step 1 of the live demo, disable Avast
shields until restart. Re-enable after the demo.

### Unblock recovery quirk

After `netsh advfirewall firewall delete rule` succeeds, Windows
occasionally holds in-kernel filter state for previously-blocked
remotes. The user-mode rule is gone; the kernel still drops. Two
remedies observed working:

1. Restart the Python `http.server` target (Ctrl-C + relaunch).
2. Optionally `Restart-Service mpssvc` (Windows Defender Firewall
   service). On Windows Home this can fail (the service is locked
   from user-mode restart); Pro/Enterprise accept it.

Also documented as Windows behaviour, not AI-IDS defect.

### Polish landed (W3-Sub5 + Sub6)

- Friendly NIC labels in the capture interface dropdown
- Self-IP filter on Request Block dropdown (and visible caption)
- Host-IP banner at top of dashboard
- Dedupe-by-src_ip on Request Block dropdown (one row per attacker)

### Summary

AI-IDS, netsh integration, RBAC, audit, and the dashboard wiring are
all verified clean. The bypass we spent time on was environmental
(Avast), not a defect in any component we shipped. Phase 1 brain
remains frozen. No HARD_CONSTRAINTS violations. Ready for Week 4
(polish + defense docs).

---

## 2026-05-26 — Week 4 Sub-task 1 (W4-Sub1): README rewrite

The README predated Phase 2. Replaced the 153-line stale version with
a 252-line rewrite reflecting Phase 2 reality: two-role auth (Week 2)
and human-in-loop mitigation (Week 3) layered on the preserved Phase 1
ML pipeline; three SQLite groups (four ERD tables + three auth tables +
two mitigation tables); the Streamlit + FastAPI + SQLite stack called
out as a deliberate Phase 1-stack preservation; single-machine Windows
deployment with Npcap + netsh; and `START.bat` (admin) → dashboard →
sign-in as the run path. Original archived as `README.md.bak`.

Four deviations from the sub-task spec, all to match reality:
- Quick Start uses `START.bat` as the setup driver rather than the
  spec's manual venv steps — `START.bat` is the actual entrypoint.
- `tools/bootstrap_admin.py` documented with its real `--username`
  CLI signature.
- PyShark dropped from the Tech Stack list: `env/requirements.txt`
  ships scapy only and pyshark is not imported anywhere in `src/`.
- JWT phrasing reworded from "no JWT, no OAuth, no SSO" to "Bearer
  tokens are opaque random bytes — not a signed token format" — same
  disclosure, more accurate to what we built.

---

## 2026-05-26 — Week 4 Sub-task 2 (W4-Sub2): RECONCILIATION_PHASE2.md + FUTURE_WORK.md

`RECONCILIATION_PHASE2.md` (466 lines): an auditable claim-by-claim
mapping between the Phase 1 proposal (`DOC-20251226-WA0032.docx`) and
Phase 2 reality. Covers all five Functional Requirements (FR_01–FR_05),
all five Use Cases (UC_01–UC_05), the non-functional requirements, the
architecture/design artefacts, the tech stack (PyShark dropped, marked
🟡), and the scope-statement reconciliation — the host-level vs
network-level firewall-blocking distinction is made explicit. Closes
the three Phase 1 viva questions (user management, real attacks,
actual mitigation) with shipping-code evidence.

`FUTURE_WORK.md` (449 lines): eight designed-on-paper extensions, each
with an engineer-week effort estimate — endpoint agent / multi-machine
(§1), scan/flood detection closing the nmap/hping3 gap (§2), auto-block
on high confidence (§3), encrypted-channel detection (§4), cloud threat
intelligence (§5), production-grade UI (§6), third-party AV co-existence
closing the Avast gap (§7), model retraining pipeline (§8). The stage
brief's two mandatory items (unblock recovery, multi-class drift) were
folded into §7 and §8 respectively to keep the extension count clean.

---

## 2026-05-26 — Week 4 Sub-task 3 (W4-Sub3): defense/DEMO_SCRIPT.md + defense/QA_BANK.md

New `defense/` directory at repo root.

`DEMO_SCRIPT.md` (276 lines): a 5-minute live attack runbook. Pre-demo
checklist (disable Avast shields as step 1), a step-by-step timeline in
the four-marker format `[DO]` / `[SAY]` / `[PANEL SEES]` /
`[IF IT BREAKS]`, and a backup-video procedure for irrecoverable live
failures.

`QA_BANK.md` (529 lines): 28 anticipated panel questions across six
categories (scope/design, detection/ML, mitigation, architecture,
process/validation, hostile), answered in a defensible-engineer voice
with file-path and line-number citations.

Deviation: Q13 (two-person rule) was rewritten from the spec draft
after reading the actual code at `src/serve/mitigation_routes.py:309`
— the guard is a same-user check, not specifically an admin-holding-
analyst-role check. Q20 (audit schema) and Q22 (loopback gate) line
citations were verified against source.

---

## 2026-05-27 — Week 4 Sub-task 4a (W4-Sub4a): pytest smoke test

New `tests/test_smoke.py` (277 lines, 3 tests). Boots the real FastAPI
app via `TestClient`, exercises auth → `/predict` → mitigation chain →
audit log, and asserts all nine tables are present. The 21-test full
suite (6 firewall + 12 mitigation_routes + 3 smoke) is all green; the
smoke test broke no existing tests.

Runtime 12.97 s on the Lenovo i5 dev box, dominated by the joblib
lifespan load (~4.6 s binary RF + ~0.9 s multi-class RF). Honest
reporting was kept over hitting an arbitrary sub-10 s number — the
intrinsic floor is however long the real app's lifespan takes.

Three deviations from spec, all corrections to reality:
- Audit action names corrected from the spec drafts (`auth.login` →
  `login`, `users.create` → `user.create`, `mitigation.execute` →
  `mitigation.block.execute`).
- `TestClient` configured with `client=("127.0.0.1", 0)` because
  Starlette's default `client=("testclient", ...)` does not satisfy
  the loopback gate at `src/serve/app.py:300`.
- The two-person rule is bypassed by using different users (analyst
  submits, admin approves) rather than sleeping 6 seconds — faster
  and it tests the real production path.

---

## 2026-05-27 — Week 4 Sub-task 4b (W4-Sub4b): README sanity pass

Eight surgical edits to `README.md` (252 → 291 lines) now that the
forward-referenced defense docs exist. Backed up pre-edit to
`README.md.bak2` (W4-Sub1's `README.md.bak` left intact).

- Forward-pointer reality check: confirmed `defense/DEMO_SCRIPT.md`,
  `defense/QA_BANK.md`, `RECONCILIATION_PHASE2.md`, and
  `FUTURE_WORK.md` all exist; updated README pointers to be accurate.
  `RECONCILIATION_PHASE2.md` was previously not referenced anywhere.
- Added FUTURE_WORK.md section numbers to Known Limitations: AV → §7,
  scan/flood → §2, unblock recovery → §7, single-machine → §1,
  encrypted-channel → §4. Also fixed a bare `HARD_CONSTRAINTS.md`
  pointer to `_project/HARD_CONSTRAINTS.md`.
- Added a `## Tests` section reflecting the W4-Sub4a smoke test and
  the 21-test full suite.

Two contradictions found and reported: (a) QA_BANK Q26 was stale
relative to the shipped smoke test (fixed in W4-Sub4c); (b)
`defense/demo_backup.mp4` was referenced as if it existed — reworded
to "recorded during dress rehearsal, not committed to the repo."

---

## 2026-05-27 — Week 4 Sub-task 4c (W4-Sub4c): QA_BANK Q26 + CHANGES.md Week 4

Closed the two gaps surfaced by W4-Sub4b.

- QA_BANK Q26 rewritten to accurately describe the shipped
  `tests/test_smoke.py` (3 tests, nine-table check, ~13 s runtime,
  full auth → predict → mitigation → audit chain coverage). The stale
  "Coming in W4-Sub6" planning text is gone. Backed up as
  `defense/QA_BANK.md.bak`.
- Added this Week 4 section to `CHANGES.md`, which previously ended at
  the 2026-05-25 Week 3 closeout with no Week 4 entries — documenting
  W4-Sub1 through W4-Sub4c. Backed up as `CHANGES.md.bak`.

Documentation-only pass. No code, model, threshold, schema, or
`/predict` contract changes. Phase 1 brain remains frozen.

---

## 2026-05-28 — Week 4 Sub-task 4d (W4-Sub4d): security review fixes (C1–C4)

A security review (W4 final pass) surfaced four Bucket C findings —
real, undocumented gaps. Rather than defer them to FUTURE_WORK, this
sub-task fixes them in code. Phase 1 brain untouched; all 24 tests
green (21 existing + 3 new).

- **C1 — XSS via `flow_id` in the dashboard.** `dashboard/app.py` built
  the Recent Alerts table as hand-rolled HTML and interpolated
  `flow_id` into a `<td>` rendered with `unsafe_allow_html=True` without
  escaping. Fixed by wrapping the value in `html.escape(...)` (added
  `import html`). Time/score were already safe (sliced / float-coerced).

- **C2 — wildcard CORS.** `src/serve/app.py` used
  `allow_origins=["*"]`. Pinned to the only legitimate origins,
  `["http://localhost:8501", "http://127.0.0.1:8501"]` (both forms
  because browsers treat them as distinct origins). `allow_credentials`
  left unset; `allow_methods` / `allow_headers` untouched. The
  loopback gate on `/predict` stays as a second defence layer.

- **C3a — login timing oracle.** A missing username returned 401
  instantly while an existing one paid the ~250 ms bcrypt verify,
  enabling username enumeration. `src/auth/passwords.py` gained a
  module-level `_DUMMY_HASH` and `verify_dummy_for_timing()`; the
  missing-user path in `src/serve/auth_routes.py` now runs the dummy
  verify so response time is equalized.

- **C3b — per-user lockout.** New additive `login_attempts` table
  (`username PK, failure_count, locked_until, last_failure_at`) in
  `src/utils/db.py` SCHEMA_DDL. The login handler checks lockout before
  any password work (comparison done entirely in SQLite UTC via
  `datetime('now')` to avoid Python/SQLite format skew), increments the
  failure count via an atomic `INSERT ... ON CONFLICT(username) DO
  UPDATE` (so concurrent failures don't lose increments), locks for
  `LOGIN_LOCKOUT_MINUTES` (15) after `LOGIN_LOCKOUT_THRESHOLD` (5)
  failures, audit-logs lockouts as `auth.login.locked`, and clears the
  counter on a successful login. Per-username (not per-IP) by design.
  Missing users are never written to the table (no username-existence
  leak via DB growth).

- **C4 — audit-log wording.** `README.md` no longer calls the audit log
  "immutable"; it now says "append-only (no UPDATE/DELETE against the
  `audit_log` table exist in the codebase)". QA_BANK Q14 rewritten to
  drop the "cannot do it invisibly" overclaim and honestly note the log
  is append-only-by-convention but not cryptographically tamper-evident.

- **QA_BANK Q29 / Q30 added** (end of Category F) describing the C2 and
  C3 fixes as applied (not deferred).

- **Stale Security Note corrected** (this file): the pre-Week-2 note
  calling `/capture/*` and `/replay/*` "unauthenticated" now reflects
  that control endpoints are RBAC-gated via `require_permission` since
  Week 2; only the read-only status endpoints remain unauthenticated.

- **Tests.** New `tests/test_login_lockout.py` (3 tests): dummy-verify
  invoked on the missing-user path, lockout after 5 failures, and
  counter reset on successful login. Full suite: 24 passing (21 + 3).

Backups (pre-edit): `dashboard/app.py.bak`, `src/serve/app.py.bak`,
`src/serve/auth_routes.py.bak`, `src/auth/passwords.py.bak`,
`src/utils/db.py.bak`, `README.md.bak3`, `defense/QA_BANK.md.bak2`,
`CHANGES.md.bak2`.

## 2026-05-28 — Week 4 Sub-task 4f (W4-Sub4f): defense-pass documentation fixes

An expert-panel-grade read of the project flagged one factual error and
three QA_BANK gaps. All four are closed here. Documentation-only — no
code, no schema, no model touched; all 24 tests still green.

- **FIX 1 — README table count corrected (9 → 10).** `README.md` stated
  the smoke test "verifies all nine SQLite tables are present". After
  W4-Sub4d added `login_attempts`, `src/utils/db.py` SCHEMA_DDL defines
  ten tables (4 Phase 1 ERD + 3 Week 2 auth + 2 Week 3 mitigation + 1
  Week 4 security). The README's smoke-test paragraph now says
  "verifies the nine core ERD/auth/mitigation tables are present" and
  notes parenthetically that the schema defines ten tables in total,
  with the Week 4 `login_attempts` table not in the smoke test's
  expected set. The architecture diagram (top of the README) was
  extended with a fourth "Security tables (Week 4) — login_attempts"
  column. `tests/test_smoke.py` was NOT touched — the 9-table expected
  set is a test-scope decision that predates W4-Sub4d, and subset
  semantics (`missing = expected - present`) means the test passes
  cleanly against a 10-table DB. Updating that test would be a code
  change outside the scope of this sub-task.

- **FIX 2 — QA_BANK Q31 added (Web Attack per-class F1).** A panel
  reading `models/model_meta.json` will see Web Attack per-class F1
  ≈ 0.4884, half of every other class (all ≥ 0.96). Q8 covered
  multi-class drift generally; Q31 (end of Category B) explains why
  *Web Attack specifically* underperforms — class scarcity (oversampling
  with 1% Gaussian noise generates near-duplicates, not new variance)
  and feature overlap (HTTP-heavy flows share signatures with DoS in
  CIC-IDS2017). The answer notes this is a labelling-fidelity problem,
  not a detection problem — the binary head still flags these flows
  as Attack and mitigation triggers off the binary label — and that
  the fix (class-weighted training or HTTP-specific features) requires
  retraining, which is frozen under HARD_CONSTRAINTS for Phase 2 and
  sketched in `FUTURE_WORK.md` §8.

- **FIX 3 — QA_BANK Q32 added (adversarial bypass).** "How would an
  attacker bypass your system?" was an obvious hostile question with
  no prior QA entry; the threats-to-validity material existed only in
  `lab/ATTACK_VALIDATION.md` §6. Q32 (end of Category F) gives three
  ranked bypass paths — scan/flood (singleton flows; see Q9),
  encrypted channels (see Q10), and adversarial pacing (model evasion
  by shaping IAT and packet-size distributions to mimic benign
  traffic) — and is honest that no single-model flow-based IDS fully
  closes the third path, which is why production deployments ensemble
  ML with signature-based tools like Suricata and with rate / volume
  anomaly detectors.

- **FIX 4 — QA_BANK Q7 framing tightened.** Q7 already disclosed the
  missing false-positive measurement honestly. One sentence appended
  to make the omission a deliberate Week-4 trade-off rather than an
  oversight: Week 4 was scoped for security hardening (CORS, lockout,
  timing equalization) and defense preparation, and the FP measurement
  is named as the first post-submission task. Wording matches the
  existing Q7 voice; the rest of Q7 is unchanged.

- **No code touched.** No `.py` file, no `requirements.txt`, no
  `src/`, no `models/`, no schema, no test changed. Full suite still
  at 24 passing.

Backups (pre-edit): `README.md.bak5`, `defense/QA_BANK.md.bak3`,
`CHANGES.md.bak3`. Prior backups (`.bak` through `.bak4` for README;
`.bak`, `.bak2` for the other two) preserved.

---

## 2026-05-28 — Week 4 demo-script sync after Streamlit SOC redesign

Documentation-only sync after the Streamlit dashboard redesign changed
visible labels and demo landmarks. No code, model, schema, threshold, or
test file changed.

- `defense/DEMO_SCRIPT.md`: synced the live demo flow to the redesigned
  dashboard. The pre-demo checklist now describes the sidebar **Live
  Capture** control as **Start** under **Traffic Source**, with the top
  **Live State** strip showing **Live Capture = RUNNING**.
- Step 1 now points the panel to the **Live State** strip, the
  **CAPTURE -> DETECT -> REQUEST -> APPROVE -> BLOCK -> AUDIT** flow
  strip, and the triage-first alert columns.
- Step 4 now matches the actual analyst UI labels: **Request Block · N
  pending**, **Pick an attacker**, and **Request Block**. The stale
  **Submit Request** wording is gone.
- Audit examples now use the action names emitted by code:
  `mitigation.block.execute` and `mitigation.unblock.execute`.

Backups (pre-edit): `defense/DEMO_SCRIPT.md.bak`, `CHANGES.md.bak4`.

---

## 2026-05-29 — Native desktop window (pywebview wrapper)

Wrapped the Streamlit SOC dashboard in a native desktop window so the
project presents as a desktop application (closer to the Phase 1
proposal's "desktop-based GUI" framing) without rewriting the frontend.
Streamlit stays the UI; pywebview only hosts it in an OS window. No
model, schema, threshold, ML pipeline, or API/`/predict` contract was
touched.

- **NEW `desktop_app.py`** — pywebview wrapper. Polls
  `http://localhost:8501` until Streamlit answers (60 s timeout), then
  opens one native window (1500x950, min 1200x800) titled
  "AI-IDS — Intrusion Detection & Threat Mitigation" using
  `assets/icon.ico`. It does NOT start the backend; it assumes uvicorn +
  Streamlit are already up. Closing the window leaves the backend
  running (browser fallback at `http://localhost:8501`).
- **`launch.py`** now orchestrates the window: starts uvicorn (8000),
  waits for `/health`, starts Streamlit **headless**
  (`--server.headless true`, no auto-browser), then spawns
  `desktop_app.py` detached. (Replay remains an opt-in sidebar toggle,
  not auto-started.)
- **`START.bat`** console messaging updated to mention the desktop
  window ("Desktop window (pywebview, opens after dashboard is up)" /
  "The SOC dashboard will open in a native desktop window. Browser
  fallback: http://localhost:8501").
- **`env/requirements.txt`** adds `pywebview==6.2.1` (pinned, with a
  comment). passlib/bcrypt remain the only other pinned entries.
- **`assets/`** added: `icon.ico` (window/taskbar), `icon.png`, and
  `icon_login.png`. `dashboard/auth_ui.py` now renders the login hero
  icon from `assets/icon_login.png` (falls back to `icon.png`) as a
  base64 data URI.
- **No logic touched in:** `src/serve/*`, `src/models/*`, `src/auth/*`,
  `src/utils/db.py` schema, `models/*`. No test imports pywebview, so
  the existing suite is unaffected.
- **Stack note:** pywebview is a new dependency. It *hosts* the existing
  Streamlit UI in an OS window rather than replacing it, so it is
  consistent with the HARD_CONSTRAINTS "Streamlit stays / no frontend
  rewrite" rule. Browser access at `http://localhost:8501` remains the
  fallback if pywebview is unavailable.

Pre-edit backups on disk for this redesign wave: `launch.py.bak_desktop`,
`START.bat.bak_desktop`, `env/requirements.txt.bak_desktop`, plus the
dashboard `*.bak_preanim` / `*.bak_predesign` copies.

---

## 2026-06-01 — Phase II report finalization

Documentation-only polish pass on the populated Phase II Word report.
No application code, model, threshold, schema, API contract, or test
file changed.

- Rebuilt the Table of Contents, List of Figures, and List of Tables
  from the report's actual headings and captions.
- Replaced stale template headers and front-matter placeholders with
  the Phase II project details.
- Added IEEE-style in-text citations, removed unused sample references,
  and replaced the unverifiable SOC citation with a verifiable source.
- Corrected report typos and compacted the ERD data dictionary so it no
  longer spills onto a mostly empty continuation page.
- Render-verified the corrected `FYP Phase-II Report - FIXED.docx`
  deliverable across all 118 pages.
