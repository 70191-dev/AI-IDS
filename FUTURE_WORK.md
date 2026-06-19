# Future Work — Designed-on-Paper Extensions

> Roadmap of extensions beyond the Phase 2 scope. Each item is
> described in enough architectural detail to defend the design
> decision to defer it, not implement it.

## How to read this document

This document records work we deliberately did not do. "Designed-
on-paper" matters: it shows we considered each extension, sized it
against the FYP timeline, and chose detection-first delivery on
purpose. When the panel asks "how would you actually do X?", the
answer is the corresponding section below.

Each entry uses five subsections: **Context** (why deferred),
**Design Sketch** (architecture), **Integration Points** (with
explicit `NEW:` / `REUSE:` / `ADDITIVE:` markers), **Risks / Open
Questions**, and **Estimated Effort** (engineer-weeks; one
engineer, full-time, with testing and basic hardening).

## 1. Endpoint Agent / Multi-Machine Deployment

**Context.** Phase 2 monitors traffic on a single Windows host —
the same machine that runs AI-IDS. The Phase 1 proposal explicitly
listed multi-device monitoring as out of scope (Chapter 2.2.6).
A production SOC needs visibility across many endpoints, not the
single bastion host. The single-machine constraint was the right
call for an FYP because it removed an entire class of distributed-
system problems from the deliverable, but it caps the system at
"the laptop is the network."

**Design Sketch.** Lightweight endpoint agent on each monitored
host, packaged as a standalone Python service that reuses the
existing `FlowAggregator`. The agent extracts the 50-feature
`UNIFIED_FEATURES` vector locally and ships **feature dicts only**
(never raw packets) to a central AI-IDS instance over mTLS —
payloads never leave the host, and a feature dict is ~1.5 KB
versus ~MB per flow of packet data. The central instance receives
the dicts at `/predict`, runs the existing two-stage RF, and tags
each endpoint as a separate stream (`endpoint_id` column joins
flows back to origin). On admin approval, central fans the block
command to the originating agent which issues netsh locally and
reports the result row back. Heartbeat every 30 s; agent missing
> 90 s → admin sees a "stale endpoint" warning. Enrolment uses a
short-lived bootstrap token; agent self-rotates a per-host mTLS
cert on first heartbeat.

**Integration Points:**
- NEW: `agents/win_agent.py`, `agents/linux_agent.py`, packaging
- NEW: `src/auth/enrolment.py` for bootstrap tokens and mTLS cert
  issuance
- NEW endpoints: `/agents/enroll`, `/agents/heartbeat`,
  `/agents/{id}/block`, `/agents/{id}/health`
- REUSE: `src/capture/live_capture.py:FlowAggregator` — extract to
  shared library so agent and central use the identical code
- REUSE: `src/serve/app.py:/predict` — agents post here unchanged
- ADDITIVE schema: `endpoint` table, `endpoint_id` FK on
  `traffic_flow` and `mitigation_request`

**Risks / Open Questions.** mTLS cert lifecycle on unattended
endpoints (rotation, revocation, mass re-enrol after CA
compromise). Network partition handling — should the agent cache
flows locally if central is unreachable, and how much? Cross-
platform mitigation: netsh / iptables / pf abstractions turn one
shell-out into a per-OS backend.

**Estimated Effort.** ~6–8 engineer-weeks for an MVP that covers
Windows + Linux endpoints, mTLS enrolment, heartbeat, central
fan-out, and basic block fan-out. Doubled with production
hardening (HA central, cert auto-rotation, agent self-update).

## 2. Aggregator Extension for Scan/Flood Detection

**Context.** Week 1 documented that `nmap -sS` and `hping3 --flood`
produce singleton or near-singleton flows that the per-flow
`FlowAggregator` cannot accumulate enough features for the binary
RF to classify. Root cause is architectural, not training-data:
CIC-IDS2017 includes Port Scan flows but the per-flow aggregator
emits flows on timeout or packet-count threshold, and a 2-packet
SYN-then-RST scan never accumulates statistical features that
match the trained distribution. This is the known and documented
limitation under "Scan and flood detection" in `README.md`.

**Design Sketch.** Add a parallel **burst aggregator** that
runs alongside the existing `FlowAggregator` and operates on a
strictly orthogonal feature set. Sliding-window counters per
`src_ip` over 5 s and 30 s windows. Two derived metrics: distinct
`dst_port` count (port-scan signal) and distinct `dst_ip` count
(host-sweep signal), plus per-window SYN-rate. When a counter
crosses a per-metric threshold, emit a synthetic "burst" event
with its own feature schema (separate from
`UNIFIED_FEATURES`, never reused). The burst event is classified
by a lightweight rule-based head first (simple thresholds), and
later by an optional small classifier trained on the port-scan
slice of CIC-IDS2017. Burst events join the existing alerts table
with a distinguishing `event_kind = 'burst'`.

**Integration Points:**
- NEW: `src/capture/burst_aggregator.py` (parallel to
  `live_capture.py:FlowAggregator`)
- ADDITIVE: `burst_features.py` with its own schema (cannot reuse
  `UNIFIED_FEATURES` — different problem class)
- NEW: rule-based classifier in `src/models/burst_rules.py`;
  optional ML head later
- REUSE: existing `alert` table with an additive `event_kind`
  column; existing mitigation workflow takes burst events
  unchanged

**Risks / Open Questions.** False-positive rate on legitimate
multi-port services (load balancers, internal scanners,
monitoring agents). Thresholds need per-deployment tuning —
operator-facing config surface required. Distributed scan
(attacker spreading source IPs) needs a different window
strategy; not in the MVP. ML route is constrained by training-
data scarcity: CIC-IDS2017 has port scans from only one source.

**Estimated Effort.** ~3–4 engineer-weeks for rule-based burst
detection wired into the existing alert path. +2 weeks if a
trained ML head is added.

## 3. Auto-Block on High-Confidence Detection

**Context.** Phase 2 is human-in-loop by design: analyst requests,
admin approves, then netsh runs. This was the deliberate response
to viva Q3 and the cleanest answer to the proposal's
"no automatic enforcement" line. A production deployment may
want a narrow exception for very high-confidence detections —
e.g., when the binary head returns > 0.95 and the multi-class
head agrees on a non-Benign category — to reduce time-to-block
from minutes to seconds. The default policy stays human-in-loop;
auto-block is an opt-in narrow override.

**Design Sketch.** Configurable policy table.
`auto_block_policy(threshold, multiclass_required, cooldown_seconds,
auto_unblock_hours, scope, enabled)`. Decision happens at the
`/predict` response site: if the policy is enabled and both
predicates match, the response triggers an immediate netsh block
on a dedicated code path that audit-logs the action with
`action = 'mitigation.auto_block'` (distinct from
`'mitigation.execute'`) so the audit trail makes the bypass
explicit. Auto-unblock fires from a periodic cleanup job. An
admin can override per-IP via an allowlist (whitelist of IPs that
can never be auto-blocked) and per-policy via the dashboard.
Cooldown prevents the same `src_ip` from being re-blocked within
N seconds of an existing block, which avoids netsh thrash on
flapping detections.

**Integration Points:**
- ADDITIVE schema: `auto_block_policy` and
  `auto_block_allowlist` tables
- NEW endpoint: `/mitigation/policy` (CRUD, admin-only)
- ADDITIVE to the `/predict` response path: post-classification
  hook that consults policy and fires netsh; reuses
  `src/mitigation/firewall.py` unchanged
- ADDITIVE to audit log: distinct `action` value

**Risks / Open Questions.** False-positive blast radius — a
single mis-classification at score 0.96 blocks a legitimate user
before any human sees it. Threshold tuning is per-deployment, not
per-product. Allowlist drift: the list grows and quietly becomes
the de-facto policy. Audit-trail integrity: auto-block needs the
same write-then-execute discipline as human-approved blocks.

**Estimated Effort.** ~2–3 engineer-weeks for the policy table,
the predict-path hook, the allowlist UI, and the auto-unblock
cleanup job.

## 4. Encrypted-Channel Attack Detection

**Context.** Phase 2 detection was validated against plaintext
HTTP / SSH attacks. CIC-IDS2017 contains some encrypted flows but
the live validation used cleartext for ease of observation. A
production-grade SOC needs to detect attacks ridden on TLS — both
because legitimate user traffic is now overwhelmingly encrypted
and because attackers know that.

**Design Sketch.** Two complementary approaches that can ship
independently. **(a) Metadata-only features** — TLS handshake
fingerprinting (JA3 / JA3S), certificate anomalies (self-signed,
unusual issuer, very short validity), flow-timing patterns, SNI
inspection. No payload decryption. Implemented as a feature
extraction stage that runs before the existing classifier; the
features feed a separate model trained on an encrypted-traffic
dataset, not CIC-IDS2017. **(b) TLS termination at a monitored
proxy** — appropriate only for environments where corporate
policy already allows it (corporate proxy in monitored
enterprise). Out of scope for the open product; documented for
deployments that have it.

**Integration Points:**
- NEW: `src/capture/tls_features.py` (parse ClientHello, derive
  JA3, extract SNI and cert fingerprints)
- ADDITIVE: feature set independent of the 50-feature
  `UNIFIED_FEATURES`
- NEW model head trained on an encrypted-traffic dataset (e.g.
  CIRA-CIC-DoHBrw-2020 for DNS-over-HTTPS) — separate joblib,
  separate threshold file, separate routing in `inference.py`
- REUSE: alert table and mitigation workflow

**Risks / Open Questions.** Legality and policy of TLS
termination — out of scope for the open product. JA3 fingerprint
databases go stale as libraries (Chrome, curl, Go's `net/http`)
rotate ClientHello defaults. Encrypted-traffic datasets are
narrower and noisier than CIC-IDS2017; the model head will need
ongoing maintenance.

**Estimated Effort.** ~4–6 engineer-weeks for metadata-only JA3
+ cert anomaly detection with a trained classifier head.

## 5. Cloud-Based Threat Intelligence Integration

**Context.** Phase 2 is fully offline by design — no outbound
calls, no telemetry, no cloud dependency. This is faithful to
the proposal's standalone-system stance and is a hard
HARD_CONSTRAINTS rule. Threat intelligence (known-malicious IPs,
attack signatures, IOCs from feeds like AlienVault OTX,
AbuseIPDB, MISP) would augment detection, but introducing
cloud calls is a deliberate trade-off. The right shape is
*optional, defaulting to off*.

**Design Sketch.** Scheduled pull (every 6 h) from a configured
TI feed. Local cache at `data/ti_cache.json`. A pre-
classification IP-lookup happens at the start of `/predict`: if
the source IP appears in the TI list, the binary score is
adjusted (configurable boost, never a hard override — the model
still gets the final word) and the detection row is tagged with
`ti_match = '<feed_name>:<reason>'`. The cache stays local; the
feed pull is the only outbound call, and it can be disabled
entirely. Configuration knob: full-offline default preserved;
operator must opt in to enable TI fetch.

**Integration Points:**
- NEW: `src/ti/fetcher.py` and `src/ti/cache.py`
- HOOK: pre-classification path in `src/serve/app.py:/predict`
- ADDITIVE column: `ti_match` on `detection_result`
- ADDITIVE config: `ti.enabled`, `ti.feed_url`, `ti.fetch_interval`

**Risks / Open Questions.** TI feed reliability and accuracy —
public feeds carry noisy false positives, and an IP that was
malicious last week may belong to a benign tenant today.
Privacy: even a read-only TI lookup leaks "this host saw
traffic from this IP" to the feed provider if the lookup is
online; mitigate by caching the full IOC list locally and doing
lookups offline against the cache. Two-way TI (push our IoCs
back to the feed) is a separate, larger problem.

**Estimated Effort.** ~2 engineer-weeks for read-only cached TI
with the configurable hook. ~4 weeks if two-way contribution is
in scope.

## 6. Production-Grade UI

**Context.** Phase 2 uses Streamlit — deliberate, recorded in
`HARD_CONSTRAINTS.md`, and defensibly sufficient for the FYP
scope (it shipped auth + RBAC + audit + mitigation UI inside
four weeks). Production SOC operators expect more: Splunk /
Elastic Security / Wazuh-dashboard-class keyboard shortcuts,
customisable layouts, sub-second websocket push updates, saved
views, multi-monitor layouts. Streamlit isn't that and wasn't
trying to be.

**Design Sketch.** React or Vue SPA over the existing FastAPI
backend. Backend changes are minimal: add `/ws/alerts` websocket
pushing alert rows on insert (replaces polling). SPA owns
frontend state — filter chips, saved views, layout. The
Streamlit dashboard stays in-tree as "minimal mode" for low-
resource demos. Two frontends sounds doubled but the backend
doesn't fork; Streamlit becomes the lab-bench tool, SPA is the
production target.

**Integration Points:**
- REUSE: the entire FastAPI layer (`src/serve/*`), every
  endpoint, every Pydantic model
- NEW: `frontend/` (React or Vue, build with Vite, deployed as
  static assets)
- ADDITIVE: `/ws/alerts` websocket endpoint
- Backwards-compat: Streamlit dashboard still serves at :8501
  unchanged

**Risks / Open Questions.** Maintaining two frontends costs more
than maintaining one — every UI change has to be considered in
both, even if Streamlit only gets a subset. Hire-ability concern
for a small team: who maintains the React SPA after the FYP
team graduates? Build / deploy complexity: Streamlit is one
Python process; the SPA adds a Node build chain.

**Estimated Effort.** ~8–12 engineer-weeks for feature-parity
SPA covering alerts, capture controls, users, audit log,
mitigation. The websocket push refactor is the smallest piece;
the SPA itself is most of the time.

## 7. Hardening for Third-Party AV Co-Existence and Unblock Recovery

**Context.** Week 3 documented two related Windows-specific edge
cases affecting netsh-based mitigation. **(a) Third-party kernel-
mode AV.** Avast (confirmed via `tools/diagnose_round2.ps1`) and
any AV with a kernel-mode WFP callout or NDIS lightweight filter
(Kaspersky / ESET / Norton are the obvious candidates) sits
*above* Windows Defender Firewall in the packet stack; while
active, AI-IDS netsh rules are correctly created but bypassed.
Week 3 demo workaround: disable AV shields "until restart." **(b)
In-kernel unblock recovery.** After `netsh advfirewall firewall
delete rule` succeeds, Windows occasionally holds in-kernel
filter state for the previously-blocked remote (user-mode rule
gone, kernel still drops). Restart the target listener — or, on
Pro/Enterprise SKUs, `Restart-Service mpssvc` (Home denies it).

**Design Sketch.** Three complementary paths. **(a) AV-exclusion
documentation.** Per-vendor guides (Avast, Kaspersky, ESET,
Norton) for whitelisting AI-IDS netsh rules so the AV callout
passes blocked packets to the user-mode firewall. Docs-only.
**(b) Direct WFP API integration.** Replace netsh with a WFP
caller via `pywin32` + WFP COM interfaces; sits at the kernel-
mode filter layer and bypasses the bypassing AV. Policy-
selectable backend (existing netsh stays default; WFP is the
heavyweight option for AV-co-existence). **(c) Unblock recovery
worker.** Background routine triggered after unblock that probes
connectivity to the formerly-blocked host and clears stale
kernel state if the probe stays denied for > 30 s. Optional;
default off. (d) Vendor partnership — out of scope for FYP.

**Integration Points:**
- (a) is documentation only — extend `defense/DEMO_SCRIPT.md`
  with vendor exclusion steps
- (b) NEW: `src/mitigation/wfp.py` as alternative to
  `firewall.py`; ADDITIVE `mitigation_backend` config field
  (`netsh` / `wfp`)
- (c) NEW: `src/mitigation/unblock_worker.py` background task

**Risks / Open Questions.** WFP API complexity — the surface is
C-level COM and requires careful resource management; getting
this wrong leaks kernel handles. Filter driver code-signing
requirements: WHQL certification is not free and not fast. The
unblock-recovery worker needs to be careful not to mask a
genuine block that the operator still wants.

**Estimated Effort.** (a) ~1 engineer-week. (b) ~6–10 engineer-
weeks plus certification cost. (c) ~1 engineer-week.

## 8. Model Retraining Pipeline and Multi-Class Drift Monitoring

**Context.** Phase 2 uses a frozen Random Forest trained on
CIC-IDS2017 (data collected in 2017). Attack patterns evolve;
the multi-class head already exhibits documented drift on novel
attacks (`nikto` reconnaissance gets labelled `DoS` rather than
its own category — `lab/ATTACK_VALIDATION.md`). Mitigation
triggers off the binary label, not the multi-class label, so
drift is currently a labelling-fidelity issue rather than a
missed-detection issue — but it is a labelling issue that will
get worse. A production system needs a labelled-feedback loop,
a periodic retrain, and drift monitoring on the live class
distribution.

**Design Sketch.** Three components. **(a) Operator labelling.**
Admin labels selected production flows from the dashboard via a
new page; labelled rows persist in `training_feedback` table
joined to the original `traffic_flow` row. **(b) Retrain
pipeline.** Manual-trigger or weekly cron retrain via
`tools/retrain.py`; regenerates `models/rf_binary.joblib`,
`models/rf_multiclass.joblib`, `models/threshold.txt`. New
model runs in **shadow mode** (predictions logged, not
actioned) for N flows before promotion; admin sees a side-by-
side comparison on a Training page. Promotion is one-click;
rollback keeps the last three models in `models/archive/` for
one-click reversion. **(c) Drift monitor.** Rolling histogram
of multi-class predictions over 24-hour windows; an alert fires
when the Wasserstein distance between consecutive windows
exceeds a threshold. The drift alert lands in the existing
alerts table with a distinct `event_kind = 'drift'`.

**Integration Points:**
- ADDITIVE schema: `training_feedback`, `model_version`,
  `drift_window` tables
- NEW: `dashboard/pages/4_Training.py` (admin-only) for
  labelling UI and shadow-vs-prod comparison
- NEW: `tools/retrain.py` for the offline retrain
- REUSE / unfreeze: `src/models/train.py` would need to be
  unfrozen post-FYP (currently HARD_CONSTRAINTS-protected)
- NEW: `src/models/drift_monitor.py` periodic worker

**Risks / Open Questions.** Labelling burden — analyst time is
the scarcest SOC resource, and asking for thousands of labels
hits reality fast. Active-learning helps (label only what the
model is uncertain about) but introduces its own bias. Drift
detection has false positives too: a real distributional shift
(application rollout, holiday traffic) looks identical to
attacker novelty. Training-data poisoning: attacker-influenced
flows being labelled by a compromised or miscued analyst would
degrade the next model.

**Estimated Effort.** ~5–7 engineer-weeks for labelling UI +
retrain pipeline + shadow-mode A/B. +2 weeks for the drift
monitor and its alert path.

## 9. Architectural Roadmap

Extensions interact. Some are independent and can ship alone;
others naturally follow on. The ASCII roadmap below maps the
dependency relationships.

```
                +----------------------+
                |  Phase 2 SHIPPED     |
                |  (FastAPI + RF + UI) |
                +----------+-----------+
                           |
   +---------+----+---+----+-+--------+---------+
   v         v        v      v        v         v
  1.Agent  2.Burst  3.Auto  6.SPA   7.AV/WFP   (independent
  (fleet)  (scan/   block   UI       hardening  shippable
           flood)                               in any order)
   |         |        |
   +----+----+----+---+
        v
   4. Encrypted-channel detection
        |
        v
   5. Threat-intel integration (optional augmentation)
        |
        v
   8. Retrain pipeline + drift monitor
   (most valuable once 1, 2, or 4 produce fresh labelled data)
```

Extensions 1, 6, and 7 are independent and can ship in any
order. Extensions 4 and 5 are independent of each other but
both naturally precede 8 because 8's value scales with the
volume and diversity of labelled flows feeding it.

## 10. Why we deferred each of these (the defense answer)

FYP scope is bounded by two hard limits: a four-week Phase 2
budget after Phase 1, and the panel's expectation that each
delivered piece is real working code with live evidence behind
it. Each extension above is real engineering work, scoped at 2–
12 engineer-weeks. Trying to ship any one of them during Phase 2
would have meant cutting Week 1 (real attack validation, closing
viva Q2), Week 2 (auth, closing viva Q1), or Week 3 (mitigation
workflow, closing viva Q3). The three viva questions took
priority because they were the panel's explicit feedback;
everything else had to wait.

The Phase 2 deliverable is a defensible, honest-about-its-limits
system: detection live-validated, RBAC enforced, audit-logged,
human-approved mitigation verified end-to-end against Kali. The
eight extensions in this document sketch the credible "next
quarter" roadmap from FYP-scope SOC tool to production-grade SOC
platform — each with integration points, effort estimates, and
risks called out in the open.
