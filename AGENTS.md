# linux-radeon-gororoba Agent and Developer Reference

## Instruction source

`AGENTS.md` is the root instruction file and owns the rules for this
repository. `CLAUDE.md` is a tracked repository-relative symbolic link to `AGENTS.md`, so Claude Code reads this same body and the rules live in one place.

## Contributor essentials

- Create a branch before the first edit and stage paths by name: an uncommitted edit has no owner. Every change lands through a branch and a pull request.
- Write a commit subject as a component prefix plus the mechanism; write the body in one to five sentences naming the invariant, the change, and the evidence. One final-safe mechanism per commit; formatting apart from logic; each commit builds and bisects.
- Write prose in direct, declarative, present-tense American English, emoji-free; meaningful symbols stay. Write ` -- ` where an em or en dash would go.
- Name durable artifacts by mechanism or content, never by chronology, actor, or process label.
- Bind a claim to a named source at the highest available evidence rank: silicon evidence, then register documents, then kernel source, then the packaging series, then retained findings, then commentary. Keep known, hypothesized, and speculative marked, and keep build, runtime, and silicon evidence apart.
- Keep secrets, hostnames, and absolute local paths out of tracked files, commits, and logs.
- Commits and PRs carry no AI attribution trailer; `Co-authored-by:` names human co-authors only. A patch sent to another project follows that project's disclosure policy, which the owner decides per submission.
- A hazardous path opens on the exact token its declaration names as armed; a selector whose zero or `-1` is meaningful takes a separate arming variable.
- Run the Validation checks before pushing, calibrate a new verdict script on a known-good and a known-bad input, and report an unrun check as `not run` with the reason.

## What this repository owns

Modified Radeon kernel source, the upstream base mapping, source generators,
register policy tables, source tests, and RAD-06. Arch and CachyOS packaging
lives in `radeon-custom`; hardware verdicts live in `steinmarder-r300`.

## Hard rules specific to source ownership

- A tracked file is source. Build products stay untracked, and
  `source-closure.toml` names the excluded classes. A generated
  `*_reg_safe.h` or a built `mkregtable` never lands in a commit.
- A register permission change is expressed in its `reg_srcs/` input, never by
  editing a generated bitmap. The generator is the only writer of those headers.
- Upstream files keep their SPDX identifiers and copyright headers verbatim
  through movement and refactoring.
- `UPSTREAM_BASE.toml` identifies the base by peeled commit and subtree tree
  object. A tag name alone is a mutable reference and does not identify a base.
- A change to the imported subtree states whether it is an upstream backport, a
  version-compat adaptation, an RS48X mechanism, or a Palm mechanism, and
  `docs/base-delta-map.tsv` carries that classification.

## Evidence scope in guards

Execution scope and evidence scope are distinct, and a guard states which it
uses. Retained hardware evidence in this lane comes from `1002:5974` on one
machine, so a `CHIP_RS480` guard executes on four device IDs while its evidence
covers one.

Three levels stay distinct in code and prose. `CHIP_RS480` names the family and
is the correct subject of an `rdev->family` guard. `RS485M (1002:5974)` names the
mobile target part every retained hardware claim binds to, reached through
`rdev->pdev->device`, distinguished from desktop RS482 (`1002:5975`). `RS485M`
also names the platform chipset from DMI and the `1002:5950` host bridge.

`policy/rs4xx-guard-scope.tsv` records, for each fork-added guard, the mechanism,
the current guard, the device IDs it executes on, the device IDs its evidence
covers, and the scope decision. A guard broader than its evidence is recorded
rather than silently narrowed, because narrowing changes behavior.

## Comment vocabulary

A source comment spends vocabulary its reader holds: the reader is a kernel
maintainer arriving with this tree and nothing else. A symbol grepped from the
tree carries its own definition (`gpu_parked`, `exclusive_lock`,
`TTM_PL_VRAM`, `dma_resv`), and an established term of the field stays a term
(`critical section`, `buffer object`, `fence`, `page table entry`).

A frame borrowed from another field or a compression coined for this project
gives way to its mechanism: `absorbing state` becomes reset recovery has failed
and the device stays parked until reboot, `imported BO` becomes a buffer object
created for a dma-buf import, and `new object lifetime` becomes allocates a
buffer object. Those frames keep their home in findings, commit bodies, and
`policy/`-adjacent prose that defines them; this rule governs source comments,
`policy/` table values, and identifiers.

## History shape

Source history encodes final mechanisms rather than experiment chronology. One
final-safe mechanism per commit, and legacy patches map many-to-one where a
later patch completed or corrected the same mechanism.
The packaging repository's `docs/legacy-patch-mechanism-map.tsv` preserves the
historical numbering that retained evidence cites, and
`docs/legacy-patch-transitions.tsv` there bonds each legacy patch to the tree
mutation it produces.

A hunk's landing site is verified against the function or declaration it was
meant to change rather than inferred from the final tree matching, because
compile success establishes compilable code and not intended placement.
`docs/legacy-patch-context-drift.tsv` in the packaging repository preserves each
drift finding.

Reconstruction commits are preserved on merge. A squash merge would destroy the
legacy-to-source mapping.

## Equivalence contract

The migration proof is two statements rather than raw equality against the
legacy payload:

```text
source_export == normalized_source_reference
generate(source_export) == legacy_generated_outputs
```

Correction and equivalence are separate commits. The legacy-equivalent state is
tagged first, and deliberate corrections land after it, so one commit is never
asked to both reproduce and change a legacy fact.

## Validation

- A clean checkout builds every generated header from source, and a full module
  build links `radeon.ko` with `modpost` complete and zero warnings.
- Two kernel targets are required: the 6.18 LTS line and current mainline.
  The version-compat class is itself a source delta, so a change touching it
  builds against both.
- A change touching `radeon_gem.c`, `radeon_prime.c`, or the park path in
  `radeon_device.c` runs `scripts/check_parked_admission_guards.py`, and
  `--selftest` alongside it. A compile test cannot see a parked refusal break:
  deleting the guard, moving it after the allocation it precedes, reading
  `needs_reset` rather than the latching `gpu_parked`, or returning 0 all
  compile clean and all readmit the traffic the guard stops. The selftest run
  proves the fixtures still discriminate, so a green tree result means the
  guards hold rather than that the patterns stopped matching.
- Hardware verdict language stays out of this repository. A source change earns
  `compile-verified` at most; promotion requires a retained bundle in
  `steinmarder-r300`.
