# Source-history reconstruction roadmap

This ledger records the state of the legacy-to-native migration: which gates
have closed, with the artifact that proves each closure, and which remain,
with the artifact each will produce. Statuses use the repository's evidence
classes; a closed item names its proof, and an open item names its gate.

## Closed

- Upstream base pinned by peeled commit and subtree tree object:
  `UPSTREAM_BASE.toml` (v6.18 base and the v7.1 mainline target).
- Driver subtree imported from the pinned base with a committed pristine
  manifest and import calibration in CI: `docs/legacy-base-source-manifest.tsv`.
- Base-delta classification of every divergence from the upstream base:
  `radeon-custom docs/base-delta-map.tsv`, closure-checked in CI.
- Per-hunk provenance with recorded search universe and
  confirmed/likely/unproven labels: radeon-custom Step 5 artifacts.
- Legacy series corrected to exact-context application. pkgrel 90 applied
  with fuzz on eight patches; pkgrel 91 regenerated them; pkgrel 92
  regenerated the two zero-context hunks (0027, 0038) after the transition
  walk exposed engine-divergent placement. Both engines now produce
  identical trees. Findings: `radeon-custom docs/legacy-patch-context-drift.tsv`.
- Payload and oracle manifests versioned by revision:
  `legacy-payload-0.3-90-default-fuzz-manifest.tsv` and the
  `migration-oracle-0.3-91-exact-context-*` pair in radeon-custom.
- Git-tree bonded per-patch transition ledger, dual-engine, identical-tree
  requirement on both-accept, final tree byte-identical to the migration
  oracle: `radeon-custom docs/legacy-patch-transitions.tsv`, reproduced in
  that repository's CI.
- Per-effect-atom mechanism map, one row per (patch, file), 124 rows, 16
  candidate mechanism buckets: `radeon-custom docs/legacy-patch-mechanism-map.tsv`.
- Migration input frozen by packaging commit and content hashes:
  `MIGRATION_INPUT.toml`, completeness- and base-agreement-checked in CI.
- Governing rules made self-contained in this repository's `AGENTS.md`, so a
  source commit's rules are pinned by the commit that carries them.
- Module build gate against the retained 6.18 root:
  `scripts/build_radeon_module.sh` plus the `module-build` CI job, calibrated
  and passing on 6.18.38-2-cachyos-lts.

## Open, in dependency order

1. Mechanism-bucket ratification. The 16 groups in the mechanism map are
   review buckets, not approved commit boundaries; each bucket is judged on
   mechanism identity rather than patch-number adjacency, and the coarse
   `depends_on` edges tighten during the same review. Output: an approved
   commit-boundary column or companion table. This is the one open Step 6
   judgment and it gates every mechanism commit below.
2. Mainline build target. `scripts/build_radeon_module.sh` gains a 7.1 root
   alongside 6.18; both targets are load-bearing because the version-compat
   class is itself a source delta. Output: a second module-build lane.
3. Per-commit reconstruction CI. Every reconstruction commit builds against
   7.1; a commit touching the version-compat class also builds against 6.18.
   Output: a workflow that walks the PR's commit range.
4. Base reconstruction commits: the two exact upstream backports preserving
   their original authors, the six version-compat adaptations grouped by API
   transition, the Palm bounded reset, the RS48X safe-register exposure, the
   source-form SMX_DC_CTL0 change, and the unproven-authorship helpers
   carrying `Authorship-status: unproven`. Ends at the 212-entry checkpoint:
   `source_export == normalized_source_reference` and
   `generate(source_export) == legacy_generated_outputs`.
5. Final-safe mechanism commits from the ratified buckets, one mechanism per
   commit, many-to-one from legacy patches. Ends at the 213-entry checkpoint
   under the same two-statement equivalence contract.
6. Annotated tag `radeon-unified-0.3-pkgrel91-source-equivalent` on the
   equivalence checkpoint. Corrections stay on the far side of the tag, so
   one commit never both reproduces and changes a legacy fact.
7. Post-tag corrections, each its own reviewed change: the RS485/0x5975
   comment correction, the guard-scope audit against
   `policy/rs4xx-guard-scope.tsv`, structural refactoring, and RAD-06
   source changes.

## Open, outside the tag ordering

- Attended audit of the retained `r300-kmsg-snapshot` sudo grant on the
  target host: executable root-owned, unwritable by the runner, accepting no
  arbitrary command or output path, environment-sanitizing, and the sole
  noninteractive entry in `sudo -l -U eirikr`. Attended sessions run inside
  ssh with tmux.
- radeon-custom compile-check script passes optimization flags through
  `KCFLAGS`; the current command-line `EXTRA_CFLAGS` is inert on 6.18 Kbuild.
  Lands with the script's next functional change.
- radeon-custom task tracker item 9, the stale RAD-06 cross-check draft
  gate, closes or converts during RAD-06's post-tag work.
- `options radeon lockup_timeout=0` stays the shipped default until an
  attended RS482 run demonstrates GPU recovery rather than host survival.
