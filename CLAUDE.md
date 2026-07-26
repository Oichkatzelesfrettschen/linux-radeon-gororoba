@AGENTS.md

# Claude Code Loader for linux-radeon-gororoba

## Loading rule

`AGENTS.md` owns the rules for this repository; the `@AGENTS.md` import above
loads them. The import path is spelled in that exact case, because imports
resolve literally on a case-sensitive filesystem. This file carries Claude Code
operating notes only.

`radeon-custom/AGENTS.md` carries the shared doctrine this repository inherits.
Load it before editing when the task touches voice, evidence rank, durable
names, comment shape, or the prose rules.

## Claude Code operating notes

Inspect the real tree before editing. `UPSTREAM_BASE.toml` identifies the base
by peeled commit and subtree tree object, and upstream source at that object is
authority over any summary of it.

A tracked file is source. Before adding a file, check `source-closure.toml`:
generated headers and built host programs stay untracked.

Inspect the diff before every commit. A hunk touching an imported upstream file
states which delta class it belongs to.

Commit trailers use `Assisted-by:` naming the tools used. The harness default
`Co-Authored-By:` trailer does not apply here.

## Response shape

Responses report changed mechanism, evidence used, validation run, checks not
run and why, and remaining risk, in plain ASCII mechanism prose.
