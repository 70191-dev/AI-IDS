# Resume Pointer

Single source of truth for "where am I in this project" when picking
up a cold session. Update whenever the active week / sub-task / last
meaningful action changes.

## Active

- **Active week:** Week 4 — Polish + defense
- **Active sub-task:** Week 4 kickoff (README rewrite is first)
- **Stage brief:** _stages/week_4_polish/CONTEXT.md

## Last action

Week 3 closed on 2026-05-25. Full mitigation chain verified live
with Kali (slowhttptest detected → analyst1 Request Block →
admin1 Approve & Block → netsh rule installed → Kali curl times
out → admin1 Unblock → audit log clean). UX polished for demo:
friendly capture labels, self-IP filter, host banner, dropdown
dedup. See CHANGES.md "Week 3 closeout" entry.

## Open issues (environmental, not AI-IDS defects)

- **Third-party kernel-mode AV co-existence.** AI-IDS cannot
  enforce blocks while a kernel-mode AV filter (Avast confirmed;
  Kaspersky / ESET / Norton likely behave the same) is active on
  the host. The AV's WFP callout / NDIS lightweight filter sits
  *above* Windows Filtering Platform and short-circuits packets
  before user-mode firewall rules evaluate. Demo workaround:
  disable AV shields "until restart" before the live demo;
  re-enable after. Documented in CHANGES.md and to be reflected
  in defense/DEMO_SCRIPT.md (Step 1) and FUTURE_WORK.md
  (deployment caveats).

- **Unblock recovery quirk.** After `netsh advfirewall firewall
  delete rule` succeeds, Windows occasionally holds in-kernel
  filter state for the previously-blocked remote. The user-mode
  rule is gone; the kernel still drops. Fix: restart the Python
  http.server target. Optional: `Restart-Service mpssvc` (works
  on Pro/Enterprise; may be denied on Home).

Both items are documented as **environmental** limitations of the
host OS / installed software, not defects in any AI-IDS component.

## Where the rules live

- Hard constraints: `_project/HARD_CONSTRAINTS.md`
- 4-week plan: `_project/4_WEEK_PLAN.md`
- Working norms: `_project/HOW_TO_WORK_HERE.md`
- Current architecture: `CURRENT_STATE.md`
- Change log: `CHANGES.md`
