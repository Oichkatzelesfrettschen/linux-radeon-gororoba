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
- Mechanism-bucket ratification closed with 24 approved native boundaries:
  `docs/reconstruction-commit-plan.tsv`.
- Every one of the 124 legacy effect atoms has one approved allocation:
  `docs/reconstruction-effect-assignments.tsv`.
- Patch 0031 writes and restores SCLK control around a plain read. M11 owns its
  three effect atoms with the other force-clock operations. M10 defines its
  first-read file operations before registration, and M09 contains only its
  direct indexed probe interfaces.
- M18 through M20 install latent parked containment before M21 activates
  parking. M22 then introduces reset recovery probes with the established
  parked refusal on every hardware path. This ordering keeps each prefix
  declared and buildable without a temporary unguarded interface.
- Every approved base and mechanism prefix has an exact driver tree and source
  manifest: `migration/expected-prefixes/`.
- Prefix composition and plan policy are calibrated and enforced:
  `scripts/check_reconstruction_plan.py` and
  `scripts/materialize_reconstruction_prefixes.py`.
- Per-commit reconstruction validation executes plans, checkers, build
  harnesses, and policy from the protected base SHA:
  `.github/workflows/reconstruction-history.yml`.
- A repository-scoped read-only deploy key materializes the pinned private
  packaging input in a credential-bearing setup job. Source builds receive
  only the sanitized, hash-verified oracle artifact.
- B14 and M24 regenerate every safe-register target from source. The ten
  outputs shipped by the legacy payload must match its pinned size and
  SHA-256 identities: `scripts/check_generated_register_outputs.py`.
- B01 through B14 preserve the approved authorship and kernel-lane contracts.
  B14 closes the exact 212-entry base checkpoint with driver tree
  `11598d3db07ac5d230ea0e3b8d42668fe80fd270`.
- Migration input frozen by packaging commit and content hashes:
  `MIGRATION_INPUT.toml`, completeness- and base-agreement-checked in CI.
- Governing rules made self-contained in this repository's `AGENTS.md`, so a
  source commit's rules are pinned by the commit that carries them.
- The 6.18 module-build gate passes. The retained 7.1 root carries a complete
  file, directory, and symlink manifest plus separate host-policy and
  package-signature provenance checks. B09 activates the 7.1 source lane after
  its compatibility frontier exists.

## Open, in dependency order

1. Final-safe mechanism commits follow the exact checker-emitted sequence.
   Each commit is one mechanism and one expected prefix. M24 closes the
   213-entry checkpoint.
2. The reconstruction branch merges into protected `main`. Post-merge source,
   generated-output, and dual-kernel checks verify the merge commit. The signed
   annotated tag `radeon-unified-0.3-pkgrel91-source-equivalent` then names that
   green merge commit.
3. Post-tag corrections, each its own reviewed change: the RS485/0x5975
   comment correction, the guard-scope audit against
   `policy/rs4xx-guard-scope.tsv`, structural refactoring, and RAD-06
   source changes.

## Open, outside the tag ordering

- Attended audit of the retained `r300-kmsg-snapshot` sudo grant on the
  target host: executable root-owned, unwritable by the runner, accepting no
  arbitrary command or output path, environment-sanitizing, and the sole
  noninteractive entry in `sudo -l -U eirikr`. Attended sessions run inside
  ssh with tmux.
- radeon-custom packaging commit `c49eacd8c7857045150705489dc03901efd2a92d`
  closes the external-module flag transition to `KCFLAGS`.
- radeon-custom task tracker item 9, the stale RAD-06 cross-check draft
  gate, closes or converts during RAD-06's post-tag work.
- `options radeon lockup_timeout=0` stays the shipped default until an
  attended RS482 run demonstrates GPU recovery rather than host survival.
