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
- The 24 mechanism commits follow the checker-emitted sequence and pass both
  kernel lanes at every prefix. M24 source commit
  `552b6976cf85a7421cfba3faa6dfffa3a5bce934` closes the exact 213-entry
  checkpoint with driver tree
  `b0f40a1970f57d00b690890120ad1ba8fd1e474c`. Trusted history run
  `30541547484` carries the per-commit logs.
- Protected-main merge commit
  `9079be562eebd184da9cf891fbc6a72d5ac0d9f3` retains the M24 driver tree.
  Equivalence-source run `30546146534` passes the 6.18 and 7.1 module lanes.
  The source manifest matches the migration oracle at SHA-256
  `71ae424fc8af1828200ec98e9233b646c6483c11ecfb778d91ec64ef6bf9f5dc`,
  and all ten legacy generated outputs match the frozen proof.
- Post-tag documentation merge
  `c999a1dcfcc2cb7e4a5794d450c435e00fbe7fff` retains the M24 driver tree.
  Closure-documentation run `30547154024` passes the same four source-static
  job classes.
- SSH-signed annotated tag
  `radeon-unified-0.3-pkgrel91-source-equivalent` has tag object
  `81a2510e34d1d62f5486683bcd6e240db8223b7d` and peels to the protected-main
  merge commit. `docs/source-equivalence-attestation.toml` records the signer
  identity and a repository-local verification command.
- Migration input frozen by packaging commit and content hashes:
  `MIGRATION_INPUT.toml`, completeness- and base-agreement-checked in CI.
- Governing rules made self-contained in this repository's `AGENTS.md`, so a
  source commit's rules are pinned by the commit that carries them.
- The 6.18 module-build gate passes. The retained 7.1 root carries a complete
  file, directory, and symlink manifest plus separate host-policy and
  package-signature provenance checks. B09 activates the 7.1 source lane after
  its compatibility frontier exists.
- The CHIP_RS480 device comment names the four PCI IDs without assigning a
  chipset name to 1002:5975. `policy/rs4xx-guard-scope.tsv` records the
  execution and evidence scope of every reconstructed mechanism without
  narrowing its guard.
- The source-owned build-feature policy classifies every B and M mechanism by
  its maximum executable side effect: `policy/build-features.toml`. Runtime
  dependencies are profile-monotone, evidence dependencies remain distinct,
  and `scripts/check_build_features.py` calibrates every rejection class.
- B11 splits after the equivalence tag: bounded Palm reset and default refusal
  remain production correctness, while `palm_pci_reset_unsafe` joins the
  root-only per-device B12 reset trigger under `palm-reset-dev`. The trigger
  registers through the DRM primary minor, executes only on `CHIP_PALM`, and
  holds the Radeon exclusive writer lock across the reset body.
- The no-flag build selects `prod`. Development builds select the monotone
  `observe-dev`, `probe-dev`, and `mutate-dev` source projections. `all-dev`
  remains an alias for the mutation-capable ceiling. Module metadata binds the
  source commit, profile, feature-policy digest, and upstream base.
  `policy/all-dev-interface-manifest.tsv` preserves all 19 development
  capabilities through an exact inventory of 17 module parameters, 32 debugfs
  files, and their source and generator markers. The module build gate verifies
  exact parameter, debugfs, linked-symbol, and generated-table projections.
  Production and all-development builds pass on 6.18 and 7.1. The intermediate
  development projections pass on 7.1.
- Development builds default to runtime profile `off`. The read-only
  `profile_dev` load-time parameter selects `observe-dev`, `probe-dev`, or
  `mutate-dev` up to the compiled ceiling. Registration and command-policy
  selection follow the resolved per-device profile. Operation-specific gates
  remain authoritative. The first mutation-capable operation that passes its
  final gate logs once per device and adds `TAINT_USER`.

## Open, after the equivalence tag

- Production and development packaging must select deterministic build
  profiles and preserve distinct package identities.
- RAD-06 source changes remain separate reviewed work.

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
