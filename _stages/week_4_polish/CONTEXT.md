# Week 4 Stage Brief — Polish + defense

Week 3 closed on 2026-05-25 with the full mitigation chain verified
live against Kali. Week 4 is defense readiness: docs, demo polish,
QA prep, smoke coverage. **No new features.** Anything that smells
like a feature beyond what Weeks 1-3 already shipped is out of scope.

## Goal

Walk into the panel defense with:

- A README that matches what the code actually does (the current
  one is stale from before Phase 2).
- A reconciliation doc that lets the panel compare Phase 1 claims
  against Phase 2 reality, side by side.
- A future-work doc that pre-empts the obvious panel questions
  about scope.
- A scripted, rehearsed 5-minute live demo with no surprises.
- A Q&A bank covering the questions we actually expect.
- A smoke test that boots the API in-process and proves the data
  path still lands rows in every table we claim it does.

## Deliverables

### 1. README rewrite

The current README predates Phase 2. Rewrite to reflect:
- Phase 2 = auth (Week 2) + mitigation (Week 3) on top of the
  Phase 1 ML pipeline.
- Two-role RBAC (admin / analyst), no other roles.
- SQLite, Streamlit, FastAPI stack — call out that this is
  deliberate (Phase 1 stack preserved, see HARD_CONSTRAINTS).
- Single-machine deployment, Windows host with Npcap + netsh.
- How to run: START.bat (admin) → dashboard → sign in. Reference
  the elevation gate.
- **Environmental caveat block**: third-party kernel-mode AV
  must be paused for netsh enforcement to work. Avast confirmed;
  others likely. Cite CHANGES.md "Week 3 closeout".
- Pointers to defense/DEMO_SCRIPT.md and defense/QA_BANK.md.

### 2. RECONCILIATION_PHASE2.md

Side-by-side table. Left column = Phase 1 defense claims (pulled
from the Phase 1 report / proposal). Right column = Phase 2
reality.

Cover at minimum:
- Detection (binary + multi-class) — claim vs delivered model.
- Persistence (SQLite ERD) — claim vs the four tables (plus the
  new auth + mitigation additions).
- Live capture + replay — Phase 1 plan vs Phase 2 implementation
  (Npcap, /capture/start, RBAC-gated).
- Mitigation — Phase 1 "we will block attackers" vs Phase 2
  "approval-flow with two-person rule + audit + netsh + the AV
  caveat".
- Auth / RBAC / audit — wholly new in Phase 2.
- UI — Streamlit dashboard scope change.

Every row should cite the source file and the CHANGES.md date
where the Phase 2 reality landed.

### 3. FUTURE_WORK.md

Must include all five:

- **Third-party AV co-existence as a deployment caveat.** Cite the
  Avast finding. List the broader class of kernel-mode AV /
  endpoint protection that introduces the same path. Suggest
  mitigations: deploy alongside Defender-only hosts, or coordinate
  with the AV vendor via an exclusion. This is the FIRST item.
- **In-kernel unblock recovery.** Document the observed "rule
  deleted, kernel still drops" quirk. Note the
  Python-server-restart and `Restart-Service mpssvc` remedies.
- **Endpoint agent for multi-machine deployment.** Sketch what a
  light agent on each host would look like (registration, heartbeat,
  forwarding flows to central API, receiving block commands).
- **Aggregator extension for scan / flood detection.** The current
  FlowAggregator is per-flow-tuple. Scan / flood detection wants
  cross-flow correlation (one source touching many ports / many
  destinations in a window). Sketch the data structure and where
  it would live.
- **Multi-class drift monitoring.** Production-time drift in attack
  class distribution would silently hurt the multi-class head.
  Sketch a comparison of class-distribution histograms over rolling
  windows + an alert threshold.

Out of scope for Week 4 itself — just document; don't build.

### 4. defense/DEMO_SCRIPT.md

Tight 5-minute walkthrough.

- **Step 0** (off-stage): START.bat elevated, AI-IDS up,
  dashboard open in browser, signed in as analyst1 in one window
  and admin1 in another.
- **Step 1**: disable Avast shields "until restart" — show the
  tray menu in passing. Explain in one sentence why
  (kernel-mode AV / WFP precedence).
- **Step 2**: verify Kali IP (`ip a` on Kali, `192.168.1.16` or
  whatever the demo network gives), Windows IP from the
  dashboard host banner.
- **Step 3**: trigger slowhttptest. Watch attack rows appear in
  Recent Alerts.
- **Step 4**: analyst1 clicks Request Block on the
  deduplicated Kali row. Show the pending state + caption.
- **Step 5**: switch to admin1 window. Approve & Block. Show
  netsh rule appearing in Active Blocks.
- **Step 6**: switch back to Kali terminal. slowhttptest shows
  `connected: 0, service available: NO`. curl times out.
- **Step 7**: admin1 unblocks. (Mention the kernel-state quirk
  proactively if the panel sees a stale block — restart Python
  http.server if needed.)
- **Step 8**: show the Audit Log filtered on `mitigation`. Read
  out the chain.

Time budget: 5 minutes ± 30s. Rehearse three times.

Include a runbook section with the **exact commands** for Kali
(slowhttptest, curl) and Windows (re-enable Avast).

### 5. defense/QA_BANK.md

25+ anticipated panel questions with prepared answers (1-3
sentences each, plus citations to code / CHANGES.md / future-work).

Must include AT LEAST these five:

- "Why doesn't your block work with Avast on?" → kernel-mode AV
  filter precedence above WFP; documented; demo workaround;
  enterprise solution = coordinate with AV exclusion or deploy
  on Defender-only hosts.
- "What about scan / flood detection?" → out of scope (per-flow
  FlowAggregator preserved from Phase 1). Sketch in
  FUTURE_WORK.md.
- "Why Streamlit instead of a professional UI?" → Phase 1 stack
  preservation; HARD_CONSTRAINTS deliberately forbids a rewrite.
  Streamlit was sufficient to deliver auth + RBAC + audit +
  mitigation UI inside the FYP timeline.
- "Two-person rule rationale?" → defensible audit trail; matches
  real-world SOC controls for destructive actions; 5-second
  window enforces minimum human attention between create + approve.
- "What would multi-machine deployment look like?" → endpoint
  agent sketch from FUTURE_WORK.md.

Other strong candidates to draft:
- Why SQLite and not Postgres?
- How do you ensure model freshness?
- What's the detection latency end-to-end?
- How do you prevent privilege escalation in the dashboard?
- Why netsh instead of Windows Firewall API directly?
- What happens if the API dies mid-approval?
- How do you prevent replay of bearer tokens?
- Why only IPv4 today?
- Adversarial robustness of the model?
- Can a malicious analyst flood request creation?
- Audit log integrity — can it be tampered?
- Two roles only — why not viewer / auditor?
- How do you back up the SQLite DB?
- What's the false-positive rate in production-like traffic?
- Why is private-IP blocking off by default?
- How would you add an exclusion list?
- What if Kali used a spoofed source IP?
- What does the threat model assume about insider access?
- How big does the data get?
- Why aren't you using deep learning?

### 6. Smoke test (tests/)

One pytest file. Boots the FastAPI app in-process (TestClient,
slim app like the mitigation test pattern), hits /predict with
a known-attack feature dict, asserts:
- a row landed in `traffic_flow`
- a row landed in `detection_result`
- a row landed in `alert`
- a row landed in `mitigation_record` (if score >= threshold)

Lightweight. Does NOT exercise auth, RBAC, mitigation flow — we
have dedicated tests for those. Goal: catch regressions in the
core data path without booting the whole app.

## Schedule

Work backwards from the defense date. Reserve:

- **2 buffer days** for surprises (panel scheduling change,
  laptop dies, demo network flaps, etc.).
- **3 dress rehearsals** of the live demo, end-to-end, with
  someone playing panel.

If anything overruns, cut from QA_BANK (drop down to the 5
mandatory + 10 best of the rest) before cutting from the
rehearsals.

## Out of scope (do not start)

- New endpoints, new tables, new dashboard pages.
- Any change to the Phase 1 brain (models/, train.py,
  prep_cic2017.py).
- Any change to firewall.py or mitigation_routes.py beyond
  trivial doc edits.
- Multi-machine, agent build, Docker, installers, OAuth, SSO.
- Anything in HARD_CONSTRAINTS.md "Stack — do not introduce".

If a deliverable above would require violating HARD_CONSTRAINTS,
**stop and ask** before doing anything.
