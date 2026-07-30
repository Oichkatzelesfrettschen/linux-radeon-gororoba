# Reconstruction coding assistant contract

The assigned commit is one exact prefix transition. The trusted plan checker
emits the only approved commit order. The migration oracle and effect
assignments define the allowed source result.

## Standing prompt

```text
You are reconstructing source history, not redesigning the driver.

Read AGENTS.md, MIGRATION_INPUT.toml, docs/reconstruction-roadmap.md,
the applicable reconstruction commit plan, and the assigned plan row before
editing.

Implement exactly one Reconstruction-id.

Use the migration oracle, approved effect assignments, effect bundle, and
expected prefix identity as the source of truth. Do not apply the chronological
patch series. Do not include an effect assigned to another commit. Do not invent
cleanup, rename parameters, change defaults, change comments, alter output
schemas, or refactor structure.

Before editing, print:
1. Reconstruction-id
2. required source dependencies
3. ordering and evidence dependencies
4. legacy effect atoms
5. files and symbols allowed to change
6. required kernel lanes
7. expected future profile and side-effect class
8. explicit non-goals

After editing:
1. show git diff --stat
2. show every changed symbol
3. run git diff --check
4. run the reconstruction-plan checker from the trusted control checkout
5. compare the driver subtree to the expected prefix tree
6. compare the source manifest to the expected prefix manifest
7. build every kernel lane declared by the plan
8. confirm no generated header or mkregtable is tracked
9. confirm the worktree is clean after committing
10. report the exact resulting driver tree object

Stop immediately when:
- a required effect is ambiguous;
- an edit requires a file or symbol absent from the plan;
- the oracle and assigned effects disagree;
- either required module build fails;
- a new warning appears;
- the current commit would include another plan ID;
- the expected prefix cannot be produced from the assigned effect bundle;
- a behavior improvement is tempting but not required for equivalence.

Do not continue by guessing. Record the mismatch as a finding.

Follow the exact topological sequence emitted by
scripts/check_reconstruction_plan.py. B01 through B08 build on 6.18. B09
through B14 and every M commit build on 6.18 and 7.1.
```

## Task response

```text
Task
  Reconstruction-id:
  Commit subject:

Inputs
  Source head:
  Migration input:
  Legacy effects:
  Source dependencies:
  Ordering dependencies:
  Evidence dependencies:

Allowed change surface
  Files:
  Symbols:
  Generated inputs:

Implementation
  Mechanism:
  Failure contract:
  Lifecycle:
  Locking:
  Hardware side effects:
  Default state:

Validation
  Trusted plan checker:
  Expected driver tree:
  Expected manifest:
  7.1 module build:
  6.18 module build:
  Warnings:
  Worktree status:
  Driver tree object:

Excluded work
  Explicitly deferred corrections:
```

The response reports evidence rather than substituting a plausible summary for
the exact prefix checks.
