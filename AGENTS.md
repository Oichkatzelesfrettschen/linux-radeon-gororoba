# linux-radeon-gororoba Agent and Developer Reference

## Instruction source

`AGENTS.md` is the root instruction file and owns the rules for this
repository. `CLAUDE.md` loads it and adds tool-specific notes only.

The doctrine in `radeon-custom/AGENTS.md` governs the shared subjects: voice,
evidence rank, durable names, comment shape, hazard gates, AI disclosure, and
the prose rules. This file states what differs because this repository holds
kernel source rather than a patch series and a package.

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
is the correct subject of an `rdev->family` guard. `RS482 (1002:5974)` names the
part every retained hardware claim binds to, reached through
`rdev->pdev->device`. `RS485M` names the platform chipset from DMI and the
`1002:5950` host bridge, and it stays out of GPU register and reset claims.

`policy/rs4xx-guard-scope.tsv` records, for each fork-added guard, the mechanism,
the current guard, the device IDs it executes on, the device IDs its evidence
covers, and the scope decision. A guard broader than its evidence is recorded
rather than silently narrowed, because narrowing changes behavior.

## History shape

Source history encodes final mechanisms rather than experiment chronology. One
final-safe mechanism per commit, and legacy patches map many-to-one where a
later patch completed or corrected the same mechanism.
`docs/legacy-patch-effect-map.tsv` preserves the historical numbering that
retained evidence cites.

The legacy series applies with fuzz on eight patches, so a hunk's landing site
is verified against the function or declaration it was meant to change rather
than inferred from the final tree matching. Compile success establishes
compilable code and not intended placement.

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
- Both kernel targets are load-bearing: the 6.18 LTS line and current mainline.
  The version-compat class is itself a source delta, so a change touching it
  builds against both.
- A verdict-producing script calibrates on known-good and known-bad inputs
  before it is trusted.
- Hardware verdict language stays out of this repository. A source change earns
  `compile-verified` at most; promotion requires a retained bundle in
  `steinmarder-r300`.
