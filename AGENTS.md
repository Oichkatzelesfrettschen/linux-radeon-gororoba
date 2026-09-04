# linux-radeon-gororoba Agent and Developer Reference

## Instruction source

`AGENTS.md` is the root instruction file and owns the rules for this
repository. `CLAUDE.md` is a tracked repository-relative symbolic link to `AGENTS.md`, so Claude Code reads this same body and the rules live in one place.

Every load-bearing rule for source commits is stated in this file, so a
commit's governing rules are pinned by the commit that carries them rather
than by another repository's `main`. The shared doctrine summarized here:
prose is direct, declarative, indicative present tense in American English and
emoji-free, with no dash constructions in project-authored text; durable
names come from mechanism or content, never chronology, actors, or process
labels; a load-bearing claim binds to a named source at the highest available
evidence rank (silicon evidence, then register documents, then kernel source,
then the packaging series, then retained findings, then commentary); known,
hypothesized, and speculative stay marked; commits carry a component prefix,
a one-to-five-sentence mechanism body, and an `Assisted-by:` trailer naming
AI tools, with `Co-authored-by:` reserved for human co-authors; hazardous
paths open only on the exact token their declaration names as armed; and
every change lands through a branch and a pull request. `radeon-custom/AGENTS.md`
remains an informative companion for packaging-side detail.

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

## Comment vocabulary

A source comment spends only vocabulary its reader already holds. The reader is
a kernel maintainer arriving with this tree and nothing else, so a term that
resolves through a project glossary names nothing and the mechanism replaces it.

Three sources supply admissible terms. A symbol grepped from the tree carries
its own definition: `gpu_parked`, `exclusive_lock`, `TTM_PL_VRAM`, `dma_resv`.
An established term of art in the surrounding field stays a term: `critical
section`, `buffer object`, `fence`, `page table entry`. Plain mechanism English
carries the rest.

Two constructions fail. An analytical frame borrowed from another field prices
in that field's vocabulary, so `absorbing state` becomes the mechanism it
describes: reset recovery has failed and the device stays parked until reboot.
A compression coined for this project reads as standard and is not, so
`imported BO` becomes `a buffer object created for a dma-buf import` and `new
object lifetime` becomes `allocates a buffer object`.

Those frames keep their home in findings, commit bodies, and
`policy/`-adjacent prose that defines them. This rule governs source comments,
`policy/` table values, and identifiers.

## History shape

Source history encodes final mechanisms rather than experiment chronology. One
final-safe mechanism per commit, and legacy patches map many-to-one where a
later patch completed or corrected the same mechanism.
The packaging repository's `docs/legacy-patch-mechanism-map.tsv` preserves the
historical numbering that retained evidence cites, and
`docs/legacy-patch-transitions.tsv` there bonds each legacy patch to the tree
mutation it produces.

At pkgrel 90 the legacy series applied with fuzz on eight patches; the
pkgrel-91 correction in `radeon-custom` regenerated them, and the pkgrel-92
series applies under exact context with both engines producing identical
trees, `docs/legacy-patch-context-drift.tsv` there preserving each drift
finding. A hunk's landing site is still verified against the function or
declaration it was meant to change rather than inferred from the final tree
matching, because compile success establishes compilable code and not
intended placement.

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

## Claude Code notes

These notes came from the retired standalone `CLAUDE.md` loader and hold the Claude Code specifics that a tool-generic guide leaves out. A rule that applies to every agent lives in the sections above.

### Loading rule

`radeon-custom/AGENTS.md` carries the shared doctrine this repository inherits.
Load it before editing when the task touches voice, evidence rank, durable
names, comment shape, or the prose rules.

### Claude Code operating notes

Inspect the real tree before editing. `UPSTREAM_BASE.toml` identifies the base
by peeled commit and subtree tree object, and upstream source at that object is
authority over any summary of it.

A tracked file is source. Before adding a file, check `source-closure.toml`:
generated headers and built host programs stay untracked.

Inspect the diff before every commit. A hunk touching an imported upstream file
states which delta class it belongs to.

Commit trailers use `Assisted-by:` naming the tools used. The harness default
`Co-Authored-By:` trailer does not apply here.

### Response shape

Responses report changed mechanism, evidence used, validation run, checks not
run and why, and remaining risk, in emoji-free mechanism prose.
