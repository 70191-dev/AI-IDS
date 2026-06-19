# How to work in this project

## Session start

1. Read _stages/CURRENT_STAGE.md — which week are we in?
2. Read that week's _stages/week_N_*/CONTEXT.md
3. Skim _project/HARD_CONSTRAINTS.md
4. Acknowledge in 1-2 lines what you read, then await the user's task

## During work

- One task at a time. Finish before moving to the next.
- /compact at natural task boundaries (after a fix lands, after a
  diagnostic completes).
- Show diffs, not full files, when reporting changes.
- If a task fails, write a read-only diagnostic FIRST, then propose
  a fix based on what the diagnostic found. Don't guess-fix.

## After non-trivial work

- Update CHANGES.md: add a dated section at the bottom describing
  what changed and why
- Update CURRENT_STATE.md ONLY if the architecture or state of the
  system actually changed (new tables, new endpoints, new files
  worth knowing about). Don't update for tiny tweaks.

## Constraint checking

Before ANY code change, ask yourself:
- Does this touch anything in HARD_CONSTRAINTS.md? If yes, stop and
  ask the user.
- Does this require adding a stack component not in HARD_CONSTRAINTS
  "do not introduce" list? If yes, stop and ask.

## Output format for the user

When reporting work:
- One-line summary first
- Then a small table of files added/modified/deleted
- Then any diffs the user should see
- Then any test or smoke-check output
- Then "Stopping" or "Ready for next task"

Avoid walls of explanation unless the user asked for it.
