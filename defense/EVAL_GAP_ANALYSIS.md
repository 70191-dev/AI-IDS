# Phase-II Evaluation Readiness — Gap Analysis

> **Read-only assessment.** Generated 2026-06-19 for the Phase-II evaluation on
> **July 1–2, 2026** (~12 days out). This file is the only artifact produced;
> no code, model, schema, doc, or git state was changed. Git was inspected with
> read-only commands only.
>
> **Honesty stance:** marks are awarded by a human evaluator against the two
> forms below, not by the repo. Where this report says ✅ it means *well-
> positioned to score high if presented well*, not *guaranteed full marks*.
> Where the project genuinely lacks something, it is marked ❌ even if the
> architecture deliberately excludes it — the evaluator scores against the
> form, not against our design intent.

---

## 1. Forms summary (totals + scoring notes, verbatim)

### Form A — `FYP-Phase-II Evaluation Form.docx`

Header (verbatim): **THE UNIVERSITY OF LAHORE / Faculty of Information
Technology / Department of Computer Science & IT / BSCS Final Project
Evaluation Report.**

Metadata fields (all blank, to be filled by evaluator): Project ID, Project
Title, Supervised By, Evaluation Date, Evaluated By, Group Members (3 student
rows — note our team has **only 2** students, so Student 3 stays blank).

**Group Evaluation — "GROUP Assessment attribute (A)", Marks out of 5 each,
`TOTAL (A) OUT OF 50`:**

1. Requirement Analysis
2. Design
3. Implementation / Technical Complexity
4. Testing & Deployment
5. Quality Of Software
6. GUI & User-Friendliness
7. Required Diagrams / Architecture Diagram
8. Quality Of Document (Writing & Formatting)
9. User Manual
10. Project Demonstration (Software Execution)

(10 × 5 = 50; this section is internally consistent.)

**Individual Student Assessment — scoring note reproduced VERBATIM (note the
internal inconsistency, preserved exactly):**

> INDIVIDUAL STUDENT ASSESMENT
> Note: Please give marks out of 20 for each Assessment Attribute
> (1-2 = poor; 2-4 = average; 4-5= very good)

Attributes (scored per student): Presentation · Coding · Documentation ·
Contribution in project design (use cases, class diagram, architectural design
etc.) · Overall project knowledge. Row label: **`Total Marks /50`** per student.

> ⚠️ **The scoring note is self-contradictory and should be clarified with the
> evaluator/supervisor.** It says *"marks out of 20 for each"* (5 attributes ×
> 20 = 100, not 50), the band guide *"4-5 = very good"* implies *out of 5*, and
> the row total is **/50** (which across 5 attributes implies *out of 10 each*).
> Three mutually inconsistent scales. Most likely intent: Group (50) +
> Individual (50) = the final **"Student X (Marks out of 100)"** boxes at the
> bottom. Do not assume — confirm on the day.

Final boxes: **Student 1 / Student 2 / Student 3 (Marks out of 100)** and
*Signature of Evaluator*.

**Form A effective total:** Group **/50** (shared) + Individual **/50** per
student → **/100 per student**.

### Form B — `FYP Phase-II Deployment Score Form.docx`

Title (verbatim): **FINAL DEPLOYMENT SCORE.** Five attributes, 5 marks each.
Total row reads, verbatim (with an encoding artifact preserved): **`TOTAL OUT
OF � 25 -`** (the `�` is a corrupted character in the source file — treat as
"TOTAL OUT OF 25").

Each criterion's description is reproduced verbatim:

1. **Live Deployment & Access** — *"The project must be accessible through a
   working public URL with no downtime during evaluation."* `____/5`
2. **Proper hosting setup (cloud/server/platform)** — *"The system should be
   hosted on a reliable cloud/server platform with correct environment
   configuration."* `____/5`
3. **Domain & SSL correctly configured** — *"The deployed project must use a
   valid domain and secure HTTPS (SSL/TLS) without certificate errors."* `____/5`
4. **Resource optimization (API, DB, memory, compute)** — *"The system should
   efficiently use server, database, API, and memory resources without
   unnecessary overhead."* `____/5`
5. **Git repository quality & meaningful commits** — *"The project must maintain
   a clean Git repository with structured commits reflecting real development
   progress."* `____/5`

> 🔴 **Structural warning (the single most important finding in this report).**
> Form B is written for a **cloud-hosted public web application**. AI-IDS is, by
> deliberate design and by `_project/HARD_CONSTRAINTS.md`, the opposite: a
> **single-machine, loopback-only (`127.0.0.1`), fully-offline Windows desktop
> security tool** that sniffs a local NIC (scapy/Npcap) and edits the *host*
> firewall (`netsh advfirewall`). Items 1–3 (public URL, cloud hosting, domain +
> SSL = **15 of 25 marks**) are not "missing features" — they are *architecturally
> excluded* and partly *forbidden by HARD_CONSTRAINTS* (no cloud, no Docker,
> loopback-only, CORS pinned to localhost). A packet-capture + host-firewall IDS
> physically cannot do its job on a cloud VM behind a public URL. **This must be
> raised with the supervisor before eval day** (see §3, must-do #1).

---

## 2. Criterion-by-criterion gap analysis

### Form A — Group Evaluation (/50)

| # | Criterion | Form | Marks | Status | Evidence | Gap / risk |
|---|---|---|---|---|---|---|
| A1 | Requirement Analysis | A-Group | 5 | ✅ | `RECONCILIATION_PHASE2.md` (FR_01–FR_05, UC_01–UC_05, 7 NFRs mapped claim-by-claim to code); `PROJECT_CONTEXT_FULL.md` §6; Phase-II report. | Reconciliation doc has internal code/doc mismatches (see A5) a sharp panelist could catch; cheap to fix. |
| A2 | Design | A-Group | 5 | ✅ | Figure-4.2 ERD realised as 10 SQLite tables (`src/utils/db.py`); proposal Figs 4.1–4.10 (arch, ERD, DFD L0/L1, class, activity ×5, sequence ×5, collaboration, state, component, deployment) per `RECONCILIATION_PHASE2.md` §4; README ASCII architecture. | Most design artefacts are Phase-1; Phase-2 additions (auth/mitigation) are additive and documented. Solid. |
| A3 | Implementation / Technical Complexity | A-Group | 5 | ✅ | Two-stage RF + FastAPI + RBAC + opaque-token sessions + append-only audit + 2-person-rule netsh mitigation + login lockout + live capture + local-LLM reports (`src/` tree; `PROJECT_CONTEXT_FULL.md` §7). | Genuinely high complexity. Strongest criterion on this form. |
| A4 | Testing **& Deployment** | A-Group | 5 | ⚠️ | Testing strong: 24 pytest tests (`tests/`), in-process smoke test, live Kali validation (`lab/ATTACK_VALIDATION.md`). | **"Deployment" half is weak.** No hosting, no CI, **not even a git repo** (see B5). If evaluator reads "Deployment" as hosted/accessible (as Form B does), this loses marks. `START.bat` one-click local run is the only deployment story. |
| A5 | Quality Of Software | A-Group | 5 | ⚠️→✅ | Additive-only schema/API discipline (`HARD_CONSTRAINTS.md`); Week-4 security hardening — CORS pin, XSS escape, login lockout, timing equalization (`CHANGES.md` W4-Sub4d); graceful degradation; transactional writes. | Repo hygiene drags it: many `*.bak*` files, root-level scratch scripts (`check_*.py`, `inspect_db.py`, `wfp_*.xml`), a **stale `docker/docker-compose.yml`** that binds `0.0.0.0` and contradicts the design, and doc/code mismatches (`rf_multiclass.joblib` named but absent; `src/models/inference.py` cited but absent; `/predict` response shape; `qwen2.5:3b` vs actual `llama3.2:1b`) — all catalogued in `PROJECT_CONTEXT_FULL.md` §19. A panelist browsing the tree sees clutter. |
| A6 | GUI & User-Friendliness | A-Group | 5 | ✅ | Streamlit SOC console: role-aware sidebar, friendly NIC labels, src-IP dedup, self-block filter, host-IP banner, CAPTURE→…→AUDIT flow strip, native pywebview desktop window, login hero; screenshots Figs 8.1–8.11 (`reports/figures/`). | "Why Streamlit not a pro UI?" is pre-answered (`QA_BANK.md`; `FUTURE_WORK.md` §6). Admin-page nav visible to all roles (defense-in-depth, gated server-side). Minor. |
| A7 | Required Diagrams / Architecture Diagram | A-Group | 5 | ✅ | Proposal Figs 4.1–4.10 (`RECONCILIATION_PHASE2.md` §4); README ASCII diagram; Phase-II report List of Figures (`CHANGES.md` 2026-06-01). | None material. |
| A8 | Quality Of Document (Writing & Formatting) | A-Group | 5 | ✅ | `FYP Phase-II Report - FIXED.docx` (118 pages, render-verified, rebuilt TOC / List of Figures / List of Tables, IEEE citations — `CHANGES.md` 2026-06-01); extensive markdown corpus. | Two near-identical report `.docx` (FIXED + CORRECTED) — submit the right one only. |
| A9 | User Manual | A-Group | 5 | ✅ | Figs 8.1–8.11 walkthrough (`reports/figures/`: startup, login, dashboard, traffic controls, alerts, request-block, mitigation, users, audit, AI report, logout) + README Quick Start + first-run walkthrough (`PROJECT_CONTEXT_FULL.md` §15). | Confirm the report's Chapter 8 binds these figures into a labelled "User Manual" section; if it's only loose figures, tighten it. |
| A10 | Project Demonstration (Software Execution) | A-Group | 5 | ⚠️ | Full chain verified live H1–H10 against Kali on 2026-05-25 (`CHANGES.md`); polished `defense/DEMO_SCRIPT.md` with [DO]/[SAY]/[PANEL SEES]/[IF IT BREAKS] + backup-video fallback. | **Fragile dependencies:** requires Avast shields OFF (else netsh block silently bypassed), a Kali VM on the same subnet, admin elevation, DHCP-stable IPs, a target `http.server`, and session-based attacks only (scan/flood won't detect). Multi-class shows "DoS" labels (drift). If the eval room can't reproduce the lab, the live demo can't run — backup video becomes load-bearing. |

### Form A — Individual Student Assessment (/50 each, per student)

| # | Criterion | Form | Marks | Status | Evidence | Gap / risk |
|---|---|---|---|---|---|---|
| A-I1 | Presentation | A-Indiv | (see note) | ⚠️ not repo-assessable | `defense/DEMO_SCRIPT.md`, `defense/QA_BANK.md` (32 Qs) | Depends on each student on the day; material is strong. |
| A-I2 | Coding | A-Indiv | (see note) | ⚠️ not repo-assessable | Substantial real codebase exists | Both students must be able to speak to code they wrote; evaluator probes individually. |
| A-I3 | Documentation | A-Indiv | (see note) | ✅ material strong | Report + README + reconciliation + future-work + QA bank | — |
| A-I4 | Contribution in project design (use cases, class diagram, architectural design) | A-Indiv | (see note) | ⚠️ not repo-assessable | Design artefacts exist (A2/A7) | Each student should own specific diagrams/use-cases to claim. |
| A-I5 | Overall project knowledge | A-Indiv | (see note) | ⚠️ not repo-assessable | `QA_BANK.md` 32 prepared Q&A with citations | Rehearse the hostile questions (scan/flood, Avast bypass, FP rate, drift). |

> Individual marks are a viva judgement of each student, not a property of the
> repo — this report can only confirm the **supporting material is strong**. The
> "/50 vs out-of-20" note ambiguity (above) affects how these are tallied.

### Form B — Deployment Score (/25)

| # | Criterion | Form | Marks | Status | Evidence | Gap / risk |
|---|---|---|---|---|---|---|
| B1 | Live Deployment & Access (public URL, no downtime) | B-Deploy | 5 | ❌ | API binds `127.0.0.1:8000`, Streamlit `localhost:8501`; CORS pinned to localhost; loopback-only `/predict` (`PROJECT_CONTEXT_FULL.md` §3; `HARD_CONSTRAINTS.md`). | **No public URL exists and the design forbids one.** Full 5 at risk. |
| B2 | Proper hosting setup (cloud/server/platform) | B-Deploy | 5 | ❌ | Single Windows host, no cloud/server; `HARD_CONSTRAINTS.md` forbids Docker & cloud. | A stale `docker/docker-compose.yml` exists but is explicitly out-of-scope, binds `0.0.0.0`, uses `python:3.11-slim` (contradicts 3.12), and is **not** the supported run path. Full 5 at risk. |
| B3 | Domain & SSL correctly configured (HTTPS, valid cert) | B-Deploy | 5 | ❌ | HTTP only, localhost only, no domain, no TLS anywhere in the stack. | Full 5 at risk. |
| B4 | Resource optimization (API, DB, memory, compute) | B-Deploy | 5 | ⚠️ | **Real efficiency story exists:** SQLite WAL + targeted indexes; one RF inference per `/predict`; `recent_alerts` deque capped at 1000 (hot cache hydrated from SQL once); CSV rotation at 5 MB; single-transaction ERD writes; models loaded once at lifespan; headless Streamlit (`PROJECT_CONTEXT_FULL.md` §7/§16). | Framed for a single host, not "server" resources. No load test / profiling / memory numbers; the `/predict <~20 ms warm` claim is **unbenchmarked** (`RECONCILIATION_PHASE2.md` §2 flags this). With a talking track + one quick measurement, **~2–4/5 is defensible**. |
| B5 | Git repository quality & meaningful commits | B-Deploy | 5 | ❌ | `git status` / `git remote -v` / `git log` → **"fatal: not a git repository"**; no `.git` dir; **0 commits; no remote**. A `.gitignore` (321 B) exists (intent) but `git init` was never run. | The week-by-week `CHANGES.md` is rich real history — but **none of it is in git**. Full 5 at risk, **but this is the most recoverable item** (see §3 must-do #2). |

---

## 3. Suggestions / action plan

Ordered by **(marks at risk ÷ effort)**. Effort: **S** ≤ a few hours · **M** ≈
a day · **L** ≈ multi-day. Items that conflict with `HARD_CONSTRAINTS.md` are
flagged 🔒 — those are **your decision and the supervisor's**, not mine to make.

### MUST-DO BEFORE EVAL

**M1 — Clarify with the supervisor whether Form B applies to a desktop/security
project at all.** *(Serves B1+B2+B3 = 15 marks, and clarifies A4. Effort: S —
one conversation.)* This is the highest leverage action in the whole report.
Form B assumes a cloud web app; AI-IDS is an offline host-level IDS that *cannot*
run behind a public URL and still capture packets / netsh-block. Ask explicitly:
(a) does this rubric apply to our project type; (b) is there an alternative
deployment expectation for desktop/security FYPs; (c) are we expected to expose
the dashboard via a tunnel for the eval window? **15 marks hinge on the answer
and you have ~12 days.** Get it in writing/email.

**M2 — Initialize Git, make structured commits, push to a remote.** *(Serves B5
= 5 marks. Effort: S–M.)* Currently **not a repo at all**. Concretely: `git
init` (the `.gitignore` already exists and correctly ignores `.venv`,
`*.joblib`, `data/ids.db`); stage in **logical, well-messaged commits grouped by
the weeks/features already narrated in `CHANGES.md`** (Phase-1 base → FR_01+ERD →
Week-1 validation → Week-2 auth → Week-3 mitigation → Week-4 hardening/defense);
push to a private (or public) GitHub so `git remote -v` and `git log --oneline`
show real structure. **Honest caveat:** commit timestamps will be recent, not
historical — the form rewards "real development progress," so if asked, say the
history was reconstructed from the dated `CHANGES.md` log at submission time.
Still far better than zero. *(This is a git/repo action, not a HARD_CONSTRAINTS
code change — but get the user's go-ahead before any commit/push, per the
read-only mandate of this task.)*

**M3 — Build a "resource optimization" talking track + one real measurement.**
*(Serves B4 up to ~3 marks + reinforces A5/A3. Effort: S.)* Write a short note
(or a slide) citing the concrete efficiencies in B4 above, and capture **one**
defensible number — e.g. warm `/predict` latency from a quick local timing loop,
plus the process RSS — so "resource optimization" is evidenced, not asserted.
Don't retrain or touch the model; this is measurement + narrative only.

**M4 — Dress-rehearse the live demo 3× and confirm the backup video actually
exists.** *(Serves A10 = 5 marks + A-I1 Presentation. Effort: S–M.)* The script
is excellent but the demo is fragile. Verify on the real eval-day machine/network:
Avast shields off, admin elevation (`/health → admin_elevated:true`), Kali IP,
target `http.server`, capture RUNNING. **`DEMO_SCRIPT.md` references
`defense/demo_backup.mp4` as "recorded during dress rehearsal, not committed" —
make sure that recording genuinely exists** before eval day; right now it's a
promise, not a file.

**M5 — (🔒 decision-gated) Front the dashboard on a public HTTPS URL for the
eval window.** *(Serves B1+B2+B3 up to 15 marks. Effort: M.)* If M1 confirms Form
B is non-negotiable, the **least-invasive** option is a tunnel (Cloudflare
Tunnel / ngrok) exposing the *read-only Streamlit dashboard* over a provided
HTTPS domain with a trusted cert, while capture + netsh mitigation stay on the
local host. This yields a public URL (B1), a hosting/platform story (B2 partial),
and domain+SSL (B3). **🔒 It conflicts with the loopback-only / offline /
CORS-pinned HARD_CONSTRAINTS** and partially misrepresents the offline design, so
it needs your explicit decision *and* supervisor blessing. A heavier alternative
— deploy a capture-disabled "viewer" build to a cloud VM against a seeded
`ids.db` purely to satisfy the rubric (Effort L) — buys the same marks with more
work and more misrepresentation risk; I'd prefer the tunnel if you go this route
at all. **Do not do either without sign-off.**

### NICE-TO-HAVE (do if time after must-dos)

**N1 — Repo hygiene pass.** *(Serves A5, fraction of 5. Effort: S.)* Before a
panelist browses the tree: relocate/aside the `*.bak*` clutter, root-level
scratch scripts, and WFP capture artifacts; delete or clearly mark the stale
`docker/docker-compose.yml` (it contradicts the offline design). **Suggestion
only — don't delete anything you might still want; I changed nothing.**

**N2 — Fix the doc/code mismatches.** *(Serves A1/A5/A8 credibility. Effort: S.)*
Correct in `RECONCILIATION_PHASE2.md`: `rf_multiclass.joblib` → actual
`rf_cic_multi.joblib`; remove the `src/models/inference.py` reference (inference
is inline in `app.py`); fix the `/predict` response shape; `AsyncSniffer` →
`sniff(..., stop_filter=…)`; `qwen2.5:3b` → `llama3.2:1b`. These are catalogued
in `PROJECT_CONTEXT_FULL.md` §19. Cheap insurance against a cross-checking panel.

**N3 — Measure a production-like false-positive rate.** *(Serves A3/A10 and the
`QA_BANK` Q7 honesty. Effort: M.)* Already named as the "first post-submission
task"; even a rough replay-based FP number strengthens the detection story.

**N4 — Consolidate a standalone `USER_MANUAL.md`** binding Figs 8.1–8.11 with
captions, if the report's Chapter 8 isn't self-contained. *(Serves A9. Effort: S.)*

---

## 4. Honest bottom line

### Form A — Evaluation Form

**Group (/50): realistic best case ≈ 43–47/50.** Eight of ten criteria (A1–A3,
A5–A9) are genuine ✅ — this is a real, complex, well-documented system and it
shows. The two soft spots are **A4 (Testing & *Deployment*)** and **A10 (live
demo fragility)**, both ⚠️. **Depends on:** the live demo executing in the eval
environment (or a *real* backup video existing), the evaluator not reading the
"Deployment" in A4 strictly against the cloud rubric, and repo clutter not
denting A5. **Floor ≈ 36–38/50** if the demo fails *and* "Deployment" is judged
harshly.

**Individual (/50 each): not assessable from the repo — realistically ≈ 40–46/50
per student with good viva prep.** The QA bank and docs are strong; outcomes
hinge on each student articulating their own contribution and fielding hostile
questions. **Confirm the contradictory "out of 20 / 4-5 / /50" scoring scale
with the evaluator** so the tally isn't a surprise.

### Form B — Deployment Score Form (/25)

**This is the at-risk form.** It is the wrong rubric for this project, and that
is the headline.

- **No action: realistic ≈ 2–4/25.** Only B4 (resource optimization) earns
  partial credit; B1, B2, B3, B5 score at/near zero.
- **After must-dos M2 + M3 (Git initialized + resource talking track):
  ≈ 7–10/25.** B5 recovers most of its 5, B4 firms up to 2–4.
- **After M5 (🔒 public HTTPS exposure, with sign-off): up to ≈ 17–22/25** — but
  only by relaxing HARD_CONSTRAINTS and partially misrepresenting an offline
  tool, which is a decision you and the supervisor must own.

**Everything on Form B ultimately depends on M1.** If the supervisor confirms the
deployment rubric doesn't apply to a desktop/security project (or substitutes an
alternative), the structural 15-mark hole closes by reinterpretation. If it *does*
apply as written, the realistic ceiling without changing what the project
fundamentally *is* — capture-disabled-cloud-viewer hacks aside — is low, and
**M2 (Git) is the one clean, honest 5 marks on the table.** Do M1 and M2 first,
this week.

---

*End of analysis. Read-only: this file is the only artifact created; no other
file, no model, no schema, no git state was modified.*
