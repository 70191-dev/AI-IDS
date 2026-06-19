# Phase 1 → Phase 2 Reconciliation

> Auditable mapping between the Phase 1 proposal (DOC-20251226-WA0032.docx,
> the FYP SRS submitted Dec 2025) and the system delivered at Phase 2
> closeout (May 2026). Each row is verifiable against the source document
> and the current codebase.

## How to read this document

This document exists because the Phase 1 viva surfaced three explicit
gaps in the proposal-as-delivered: user management was absent, real
attack validation had not been performed, and "threat mitigation" had
only ever meant "show an alert." Phase 2 was scoped to close those
three gaps without disturbing the Phase 1 detection brain. This
document is the per-claim audit trail that proves each gap was
closed.

The reconciliation uses four status markers throughout. **✅ shipped
as proposed** means the Phase 2 implementation realises the proposal
claim with no material deviation. **🟡 shipped with documented
deviation** means an intentional gap or substitution exists and is
explained inline. **🟥 deferred to future work** means the proposal
claim was not implemented; the rationale and the eventual path live
in `FUTURE_WORK.md`. **➕ shipped beyond proposal** means Phase 2
delivered capability not present in the original scope.

Source-of-truth conventions: Phase 1 claims are quoted verbatim from
`DOC-20251226-WA0032.docx` with chapter and figure references where
they appear in the source. Phase 2 reality is cited by file path
relative to the repository root and, where helpful, by a dated
`CHANGES.md` entry recording when the work landed. Diagrams from the
docx are referenced by figure number only — they are not reproduced
here.

## 1. Functional Requirements (FR_01 – FR_05)

### FR_01 — Capture network traffic

**Phase 1 proposal claim** (Chapter 2.3.1, Table FR_01 Description):

> "The system shall capture live network packets from the selected
> network interface for monitoring and analysis."

Input: raw network interface. Output: raw network traffic data.
Requirements: active network interface, packet capture permission.
Basic flow: user selects network interface → system starts packet
capture → packets are collected in real time.

**Phase 2 delivered:** Live packet capture is implemented in
`src/capture/live_capture.py` using scapy's `AsyncSniffer` backed
by Npcap on Windows. The capture surface is exposed through
`POST /capture/start` and `POST /capture/stop` on the FastAPI app
(`src/serve/app.py`), gated by the `capture:start` and
`capture:stop` RBAC permissions. The interface list is exposed via
`GET /capture/interfaces`, which since W3-Sub5 returns
`{id, name, description}` triples by joining scapy's
`get_windows_if_list()` against the NPF GUID. The dashboard
selectbox displays friendly NIC labels rather than raw GUIDs.

**Status:** ✅

**Notes:** The Phase 1 expectation of "user selects network
interface → system starts packet capture" is satisfied through the
Streamlit Capture controls (`dashboard/app.py`) backed by the
RBAC-gated endpoints above. Elevation is required on Windows;
`START.bat` enforces this at launch (W3-Sub4).

### FR_02 — Preprocess network traffic

**Phase 1 proposal claim** (Chapter 2.3.1, Table FR_02 Description):

> "The system shall preprocess capture network traffic and extract
> relevant features required for machine learning analysis."

Basic flow: captured packets are cleaned → features are extracted →
data is prepared for classification.

**Phase 2 delivered:** Preprocessing happens in two places. (a) The
`FlowAggregator` inside `src/capture/live_capture.py` accumulates
packets into bidirectional flows keyed by 5-tuple and emits the
50-feature `UNIFIED_FEATURES` schema when a flow times out or hits a
packet-count threshold. The aggregator is HARD_CONSTRAINTS-frozen
(see `_project/HARD_CONSTRAINTS.md`) and was preserved unchanged
through Phase 2. (b) Offline preprocessing of CIC-IDS2017 raw CSVs
into the same `UNIFIED_FEATURES` schema is done by
`src/data/prep_cic2017.py`.

**Status:** ✅

**Notes:** The feature schema (50 fields, listed in
`prep_cic2017.py:UNIFIED_FEATURES`) is the Phase 1 brain and was
deliberately frozen. No Phase 2 sub-task touched it.

### FR_03 — Classify network traffic

**Phase 1 proposal claim** (Chapter 2.3.1, Table FR_03 Description):

> "The system shall classify network traffic as normal or malicious
> using trained machine learning models."

Input: processed traffic data. Output: classification results
(normal / intrusion). Requirements: trained machine learning model.
Basic flow: system loads trained model → inputs processed data →
generates classification result.

**Phase 2 delivered:** Two-stage Random Forest. The binary head
(`models/rf_binary.joblib`) decides Benign vs Attack at the
F1-optimal threshold persisted in `models/threshold.txt` (currently
`0.3858`). For flows the binary head labels Attack, the multi-class
head (`models/rf_multiclass.joblib`) assigns one of eight categories
(Benign, DoS, DDoS, Port Scan, Brute Force, Web Attack, Bot,
Infiltration). The classification surface is `POST /predict` on the
FastAPI app, which accepts a 50-feature dict and returns
`{label, score, multiclass_label}`. Training code in
`src/models/train.py` is HARD_CONSTRAINTS-frozen.

**Status:** ✅ (matches proposal), and ➕ in one respect: the
proposal asked only for binary classification; Phase 2 ships a
multi-class head as well, trained from the same dataset.

**Notes:** Live attack validation in Week 1 (see
`lab/ATTACK_VALIDATION.md` and CHANGES.md 2026-05-23 entry) found
that session-style attacks (slowhttptest, medusa, nikto) are
detected at 25–57% recall reproducibly across two runs. Singleton-
flow attacks (`nmap -sS`, `hping3 --flood`) fall outside the
per-flow training distribution and are not detected; this limitation
is documented and the architectural fix is sketched in
`FUTURE_WORK.md`.

### FR_04 — Generate alerts, logs, and mitigation information

**Phase 1 proposal claim** (Chapter 2.3.1, Table FR_04 Description):

> "The system shall generate alerts and maintain logs when malicious
> network activity is detected. the system shall also provide basic
> threat mitigation support by assigning severity levels and
> presenting response recommendations to assist users in handling
> detected threats."

Input: classification results. Output: alerts, logs, threat severity
level, mitigation recommendations.

**Phase 2 delivered:** Every prediction lands a row in three SQLite
tables: `traffic_flow` (the 50-feature input), `detection_result`
(label + score + multiclass_label), and `alert` (only if the binary
score is above threshold). The alert row carries the human-readable
severity bucket and the `src_ip` of the attacker. Beyond the original
"alert + log" scope, Phase 2 added an immutable `audit_log` table
(every privileged action: login, capture start/stop, mitigation
request/approve/deny/execute, plus every 401/403). The audit log is
visible to admins via `dashboard/pages/2_Audit_Log.py` with
prefix-filter and CSV export.

The "response recommendations" piece in the proposal — originally
intended as static suggestion strings — was upgraded in Phase 2 to a
full human-in-loop mitigation workflow (see FR_05 note and Section 6
below).

**Status:** ➕ (delivered beyond proposal scope).

**Notes:** Phase 1 envisaged passive recommendations ("you should
investigate this"). Phase 2 delivers an actionable workflow that
both records the alert and surfaces a Request Block control on the
attack-labelled row.

### FR_05 — View alerts, logs, and mitigation information

**Phase 1 proposal claim** (Chapter 2.3.1, Table FR_05 Description):

> "the system shall allow users to view detected intrusion alerts,
> historical traffic logs, and associated threat mitigation
> recommendations through a graphical user interface."

Input: stored alerts, log records, and mitigation data. Output:
visual display of alerts, severity levels, and mitigation
recommendations. Requirements: graphical user interface.

**Phase 2 delivered:** The Streamlit SOC dashboard
(`dashboard/app.py` plus the three pages under `dashboard/pages/`)
serves this requirement. Recent Alerts table with sortable columns,
score distribution chart, top-source-prefix bar chart, alerts-over-
time graph, capture controls, Request Block expander, and three
admin/analyst-gated subpages: Users, Audit Log, Mitigation. Auto-
refresh via `streamlit-autorefresh`.

**Status:** 🟡 — content matches but the GUI substrate differs.

**Notes:** Phase 1 specified a "desktop-based graphical user
interface (GUI)" (Chapter 2.2, Technologies used, paragraph 0201).
Phase 2 delivers a Streamlit web dashboard accessed via browser at
`http://localhost:8501`. Operationally this preserves the single-
machine constraint (no cloud, no external service) — the Streamlit
server runs on localhost only — and the workflow remains identical.
The substitution is justified in Section 5 of this document and is
covered by `_project/HARD_CONSTRAINTS.md` ("Streamlit stays").

## 2. Non-functional Requirements

The Phase 1 proposal lists seven non-functional requirements in
Chapter 2.3.2. Each is reconciled below.

| Requirement | Phase 1 claim (1 line) | Phase 2 reality (1 line) | Status |
|---|---|---|---|
| Usability | Simple GUI usable without advanced cybersec expertise. | Streamlit dashboard, two-role gating, friendly NIC labels, host banner, dropdown dedup. | ✅ |
| Reliability | Continuous operation through unexpected input without crashing or data loss. | uvicorn + Streamlit auto-restart via `launch.py` supervisor; SQLite WAL; failure rows persisted to `mitigation_action`. | ✅ |
| Performance | Process and classify in near real time. | `/predict` < ~20 ms warm on Win11; capture-to-alert under one second end-to-end on the demo host. | ✅ |
| Design constraints | Standalone desktop application, no cloud / external servers. | Single Windows host, no outbound calls, SQLite single-file DB at `data/ids.db`. | ✅ |
| Portability | Deployable on standard desktop environments. | Windows-only by design (netsh + Npcap); a documented constraint of the mitigation backend. | 🟡 |
| Maintainability | Modular design supporting future ML / mitigation updates. | Clear module boundaries (`src/auth`, `src/capture`, `src/mitigation`, `src/serve`); additive-only schema rules in HARD_CONSTRAINTS. | ✅ |
| License agreement | Open-source / academic licenses for all components. | All dependencies in `env/requirements.txt` carry permissive open-source licenses; CIC-IDS2017 used under its public-research license. | ✅ |

The portability row is marked 🟡 because Phase 2 deliberately scoped
mitigation enforcement to Windows-only via `netsh advfirewall`. A
Linux iptables branch was explicitly excluded by HARD_CONSTRAINTS. A
multi-platform mitigation backend is documented in
`FUTURE_WORK.md`.

## 3. Use Cases (UC_01 – UC_05)

Each use case from Chapter 3 of the proposal maps cleanly to a
Phase 2 implementation surface. The table below lists the primary
actor as stated in the docx and the on-disk surface that realises
the use case.

| UC ID | Use case name (docx) | Primary actor | Implementation surface |
|---|---|---|---|
| UC_01 | Capture network traffic | user | `dashboard/app.py` Capture controls → `POST /capture/start` → `src/capture/live_capture.py:AsyncSniffer` |
| UC_02 | Preprocess network traffic | system | `src/capture/live_capture.py:FlowAggregator` (live) and `src/data/prep_cic2017.py` (offline) |
| UC_03 | Classify network traffic | System | `POST /predict` → `src/models/inference.py` → RF binary + multiclass joblibs |
| UC_04 | Generate alerts, logs, and mitigation information | system | `src/serve/app.py` write-path: `traffic_flow` + `detection_result` + `alert` rows; `audit_log` rows for privileged actions |
| UC_05 | View alerts, logs, and mitigation information | user | `dashboard/app.py` (alerts + charts) + `dashboard/pages/2_Audit_Log.py` + `dashboard/pages/3_Mitigation.py` |

The alternate flows specified in each UC are honoured in code: an
unavailable interface returns a `400` from `/capture/start`,
malformed feature dicts return a `422` from `/predict`, an absent
model file is caught at app startup, and an empty alerts table is
handled by the dashboard's "no rows yet" copy.

## 4. Architecture and Design Artefacts

The Phase 1 proposal includes ten figures across Chapter 4 (system
architecture, ERD, two DFD levels, class diagram, activity diagrams,
sequence diagrams, collaboration diagram, state transition diagram,
component diagram, deployment diagram). These are not reproduced
here; they are referenced by docx figure number, and the Phase 2
implementation surface that realises them is cited from the
codebase.

| Artefact | Phase 1 doc section | Phase 2 status | Note |
|---|---|---|---|
| Architecture diagram | docx Fig 4.1 | ➕ Phase 2 extended beyond original | Added FastAPI service, auth + mitigation subsystems; see `README.md` ASCII diagram and `CURRENT_STATE.md`. |
| ERD | docx Fig 4.2 | ➕ Phase 2 extended beyond original | Four original tables preserved (`traffic_flow`, `detection_result`, `alert`, `mitigation_record`); five new (`user`, `session`, `audit_log`, `mitigation_request`, `mitigation_action`). Additive-only per HARD_CONSTRAINTS. |
| DFD L0 | docx Fig 4.3.1 | ✅ Phase 2 implementation matches | External actor (user) → System → External output (alerts/dashboard). |
| DFD L1 | docx Fig 4.3.2 | ➕ Phase 2 extended beyond original | Added auth process and mitigation-execution process branches. |
| Class diagram | docx Fig 4.4 | ➕ Phase 2 extended beyond original | Added Pydantic models for auth (`User`, `Session`), mitigation (`MitigationRequest`, `MitigationAction`), audit. |
| Activity diagrams (4.5.1 – 4.5.5) | docx Fig 4.5.x | ✅ Phase 2 implementation matches | One activity flow per FR; all five still reflected by the codebase. |
| Sequence diagrams (4.6.1 – 4.6.5) | docx Fig 4.6.x | ✅ Phase 2 implementation matches | Sequence per FR preserved; mitigation introduces a new sequence covered in `defense/DEMO_SCRIPT.md` (W4-Sub3). |
| Collaboration diagram | docx Fig 4.7 | ✅ Phase 2 implementation matches | Object collaboration patterns preserved. |
| State transition diagram | docx Fig 4.8 | ✅ Phase 2 implementation matches | Capture session states (idle / running / stopped) preserved. |
| Component diagram | docx Fig 4.9 | ➕ Phase 2 extended beyond original | Added auth and mitigation components; underlying capture/preprocess/classify/alert/dashboard chain preserved. |
| Deployment diagram | docx Fig 4.10 | ✅ Phase 2 implementation matches | Standalone single-host deployment preserved exactly. |

## 5. Technology Stack

The proposal's technology section (Chapter 2.2, paragraphs 0198–0201)
lists specific tools. Each is reconciled below.

| Component | Phase 1 proposed | Phase 2 delivered | Status | Note |
|---|---|---|---|---|
| Programming language | Python | Python 3.12 | ✅ | |
| ML library | Scikit-learn | scikit-learn (Random Forest, two-stage) | ✅ | |
| Packet capture | Scapy and PyShark | scapy only | 🟡 | See PyShark note below. |
| UI framework | desktop-based graphical user interface (GUI) | Streamlit web dashboard served on localhost | 🟡 | See UI substitution note below. |
| Storage | local file-based storage | SQLite (single file at `data/ids.db`) | ✅ | File-based local storage; matches in spirit and in operational footprint. |
| Backend / API | (not specified in Phase 1) | FastAPI + uvicorn (REST, OpenAPI docs at `/docs`) | ➕ | New service layer that enables RBAC enforcement and the mitigation workflow. |
| Auth | (not specified in Phase 1) | bcrypt (cost 12) + passlib + opaque 32-byte bearer tokens, 8-hour session TTL | ➕ | Wholly new in Phase 2; closes viva question Q1. |
| Mitigation enforcement | (not specified — proposal explicitly excluded enforcement) | Windows `netsh advfirewall firewall add rule` via `src/mitigation/firewall.py` | ➕ | Wholly new in Phase 2; closes viva question Q3. |
| Dashboard charts | (not specified) | Plotly + streamlit-autorefresh | ✅ | |

**PyShark note (🟡 packet capture).** The proposal lists "Scapy and
PyShark" as the packet-capture stack. Phase 2 ships scapy only and
does not install PyShark. Two reasons. (1) scapy's `AsyncSniffer`
plus the in-process `FlowAggregator` already covers every capture
path the system needs; PyShark would only have provided redundant
coverage. (2) PyShark wraps `tshark.exe` and therefore requires
Wireshark to be on the deployment PATH, which adds a second
installer and a second moving part to every demo. Dropping PyShark
removed deployment friction without removing capability. Recorded
in CHANGES.md under the Week 1 hotfixes entry (2026-05-23).

**UI substitution note (🟡 UI framework).** The proposal specifies
a "desktop-based graphical user interface (GUI)" (paragraph 0201).
Phase 2 delivers a Streamlit web dashboard served on localhost. The
substitution is intentional and preserves every operational
property the proposal cared about: single-machine deployment, no
cloud dependency, no external service, an interface accessible from
the user's own machine. What changes is the delivery surface —
browser vs native window. The trade-off favours portability (any
modern browser renders it identically), iteration speed (Streamlit
hot-reload during the FYP timeline), and the ability to demonstrate
the system to a panel on any laptop. `_project/HARD_CONSTRAINTS.md`
records that the Streamlit choice is deliberately preserved for the
remainder of Phase 2 and is not to be rewritten.

## 6. Scope Statement Reconciliation

The proposal's Chapter 2.1.2 (Scope) and Chapter 2.2.6 (Apportioning
of requirements) make specific scope claims. They are quoted and
reconciled below.

**Quote from Chapter 2.1.2 (paragraph 0327):**

> "The system does not perform automatic enforcement actions such
> as packet blocking, traffic filtering, or intrusion prevention at
> the network level. Instead, it supports threat mitigation by
> assisting users in identifying, understanding, and responding to
> detected threats through informed decision support."

**Phase 2 reconciliation.** Phase 2 added a human-in-loop mitigation
workflow: an analyst requests a block on an attack-labelled flow,
an admin reviews and either approves or denies, and on approval the
host firewall is updated via `netsh advfirewall`. This is **not**
automatic enforcement. The decision to block remains with a human
admin; the system never blocks without an approval row in
`mitigation_request`; a 5-second two-person guard prevents the same
human from creating and approving a request. The proposal's
no-automatic-enforcement principle is therefore honoured —
Phase 2 sits one explicit step on the "informed decision support"
side of an automated IPS.

It is also worth distinguishing "network-level" from "host-level"
enforcement. The proposal's exclusion is at the **network level**
(router / switch / inline appliance). Phase 2 blocks at the
**host-level** firewall (the Windows host running AI-IDS), which is
a strictly narrower capability: it stops traffic to and from the
monitoring host, not traffic between unrelated devices on the
segment. The narrowing matters: the proposal's stated worry was
about an unattended system disrupting an organisation's network;
host-level blocking under human approval cannot do that.

**Quote from Chapter 2.2.6 (paragraph 0415):**

> "Advanced features such as automatic intrusion prevention,
> network-level traffic blocking, cloud-based analytics, and
> multi-device monitoring are considered out of scope for the
> current version and may be implemented in future versions."

**Phase 2 status of each item:**

- **Automatic intrusion prevention.** Still out of scope by design.
  Human-in-loop preserved. 🟥 (documented; see Section 7 Q3.)
- **Network-level traffic blocking.** Still out of scope.
  Host-level blocking is a strictly narrower replacement, not the
  proposal's excluded capability. 🟡 (host-level added; network-
  level still deferred to `FUTURE_WORK.md`.)
- **Cloud-based analytics.** Still out of scope. No cloud calls of
  any kind are made by the system. 🟥 (deferred; sketched in
  `FUTURE_WORK.md` Section 5.)
- **Multi-device monitoring.** Still out of scope. Single-machine
  deployment is preserved. 🟥 (deferred; endpoint-agent design in
  `FUTURE_WORK.md` Section 1.)

## 7. Phase 1 Viva Findings → Phase 2 Response

The Phase 1 viva surfaced three explicit questions. Each is closed
below.

### Q1: User management

**Asked:** "How would you manage users? Anyone can use this
dashboard?"

**Phase 2 answer.** Week 2 added two-role RBAC (admin / analyst),
SQLite-backed sessions with opaque 32-byte bearer tokens (8-hour
TTL), bcrypt password hashing (cost factor 12), per-action
permission checks via `Depends(require_permission(...))`, and an
immutable audit log covering every privileged action. Three new
tables: `user`, `session`, `audit_log`. The initial admin is
created by `tools/bootstrap_admin.py`, which refuses to run a
second time once an admin exists.

**Evidence.** `src/auth/passwords.py`, `src/auth/sessions.py`,
`src/auth/audit.py`, `src/auth/rbac.py`, `src/serve/auth_routes.py`,
`dashboard/pages/1_Users.py`, `dashboard/pages/2_Audit_Log.py`,
`tools/bootstrap_admin.py`, CHANGES.md entries dated 2026-05-24.

### Q2: Real attacks vs replay

**Asked:** "What about real attacks vs replay traffic?"

**Phase 2 answer.** Week 1 ran the system live against a Kali
attacker VM and characterised what it actually catches in the
field. Session-style attacks (slowhttptest, medusa SSH brute-force,
nikto reconnaissance) are detected at 25–57% recall reproducibly
across two runs. Singleton-flow attacks (`nmap -sS`, `hping3
--flood`) fall outside the per-flow CIC-IDS2017 training
distribution and are not detected; the architectural cause
(per-flow `FlowAggregator` does not see scan / flood patterns) is
documented along with the eventual design fix.

**Evidence.** `lab/ATTACK_VALIDATION.md`, `lab/attack_log.csv`,
`lab/ATTACK_PROFILES.md`, CHANGES.md entry dated 2026-05-23 ("Week
1 closeout — real attack validation"), `FUTURE_WORK.md` Section 2
for the scan / flood extension sketch.

### Q3: Actual mitigation

**Asked:** "What about actually mitigating threats? You only detect."

**Phase 2 answer.** Week 3 added a human-in-loop mitigation
workflow. An analyst clicks Request Block on an attack-labelled row,
an admin reviews and either approves or denies, and on approval the
host firewall is updated via `netsh advfirewall firewall add rule`.
A 5-second two-person guard prevents an admin from approving a
request they created themselves. Failed netsh executions surface on
a "Recent Failed Executions" table on the Mitigation page rather
than being silently swallowed. The full chain (request → approve →
execute) was verified live against Kali slowhttptest on 2026-05-25.

**Evidence.** `src/mitigation/firewall.py`,
`src/serve/mitigation_routes.py`, `dashboard/pages/3_Mitigation.py`,
`tests/test_firewall.py`, `tests/test_mitigation_routes.py`,
CHANGES.md entries dated 2026-05-25 (W3 Sub-tasks 1–6 + closeout).

## 8. Documented Deviations Summary

Every 🟡 row from the document, on one line each, with the section
that explains it.

- **FR_05 (View alerts) — UI substrate.** Streamlit web dashboard
  on localhost in place of native desktop GUI. See Section 5,
  "UI substitution note."
- **Non-functional Portability.** Mitigation enforcement is
  Windows-only (netsh). See Section 2.
- **Tech Stack — Packet capture.** scapy only; PyShark dropped.
  See Section 5, "PyShark note."
- **Tech Stack — UI framework.** Streamlit web rather than desktop
  GUI. See Section 5, "UI substitution note."
- **Scope — Network-level traffic blocking.** Phase 2 ships
  host-level blocking; network-level (router / switch / inline
  appliance) remains out of scope. See Section 6.

## 9. Summary

Of the five Functional Requirements proposed in Phase 1, four
(FR_01 – FR_04) ship as proposed or beyond; FR_05 ships with one
documented UI-substrate deviation (Streamlit web vs desktop GUI)
that preserves every operational property the proposal cared about.
All five Use Cases are realised end-to-end in the codebase. All
seven Non-functional Requirements ship as proposed, with one
deliberate narrowing (Portability scoped to Windows for the
mitigation backend).

The three viva questions are all closed with shipping code and live
evidence: Q1 (user management) closed by Week 2's two-role RBAC +
audit; Q2 (real attacks) closed by Week 1's live Kali validation
documented in `lab/ATTACK_VALIDATION.md`; Q3 (actual mitigation)
closed by Week 3's human-in-loop workflow verified live on
2026-05-25.

The out-of-scope items the proposal listed (automatic intrusion
prevention, network-level traffic blocking, cloud-based analytics,
multi-device monitoring) are honestly preserved as out-of-scope.
Each has a designed-on-paper extension in `FUTURE_WORK.md` so that
the path from FYP-scope SOC tool to production-grade SOC platform
is documented, not hand-waved.
