# linux-radeon-gororoba

Private upstream-derived Radeon subtree mirror carrying the modified kernel
source for the RS480/RS482/RS485 and Palm/Wrestler lanes.

This repository holds `drivers/gpu/drm/radeon/` from an identified upstream
Linux commit plus the project's changes to it. It is a standalone mirror rather
than a member of a GitHub fork network, and it carries the driver subtree rather
than a full Linux kernel tree. `UPSTREAM_BASE.toml` records the exact upstream
commit and subtree tree object, and the upstream repository remains the history
source for blame and commit archaeology.

## Repository boundary

<!-- markdownlint-disable MD013 -->

| Repository | Authority |
| --- | --- |
| `linux-radeon-gororoba` | Modified Radeon kernel source, upstream base mapping, source generators, register policy tables, source tests, RAD-06 |
| `radeon-custom` | Arch and CachyOS PKGBUILD, DKMS glue, compiler policy, initramfs and modprobe policy, hazard preflight, source pin, package verification |
| `steinmarder-r300` | Target-silicon probes, retained result bundles, falsifiers, hardware verdicts |
| `mesa-26-gororoba` | r300g and r3v userspace behavior |

<!-- markdownlint-enable MD013 -->

Packaging targets Arch and CachyOS alone.

## Source, package, and loaded deployment authority

`linux-radeon-gororoba` is the canonical modified source authority from
`radeon-unified-0.3-pkgrel91-source-equivalent` onward. `radeon-custom` owns
the source pin, package, DKMS lifecycle, and deployment policy.

The active `radeon-custom` recipe is 0.8.9-2. It pins the signed
`radeon-unified-0.8.9-profiled-source` tag object
`3bf1c5b3cc4b5247d99f737189a5739d70faacb0`, peeled source commit
`164167950d0f749468474536dd76045fddedc8b7`, driver tree
`a50c8ce2bc6c7645c7fe658470f67dbe2e93c31f`, and policy tree
`572a400c7aafe735805bb17c279503280ada573f`. Its package gates build and
verify the split package set, and its target kernel gate compiles the verified
production package on RS482. The repository carries no 0.8.9-2 signed release
attestation or loaded module identity, so 0.8.9-2 remains package and target
compile evidence rather than loaded deployment authority.

The live RS482 target records installed production and board policy package
version 0.7-1. The retained read only identity bundle joins PCI `1002:5974` to
the loaded `radeon` module, installed DKMS file, package version, and source
pin. It does not bind the installed files to the signed release archive bytes.
The loaded module carries srcversion `A7F72BE636B52D7EED42415`, GNU build ID
`a5f1ae7e6e040b20c53278d2978ea7a17a29b696`, compressed module SHA256
`6d058f68aefab94350e96a9e376e3ff577512cd4d4919b627e85b678ca1b0301`,
source commit `293a4ae3fe82cd03585ef3157e82b0b59b641b47`, and driver tree
`d57a22ad5356637d7075cb2aba83e22af71f7bfb`. The module exposes the `prod`
profile and zero development parameters. Steinmarder retains this evidence at
`src/re/r300/results/cachyos-vostro1000-rs482-radeon-unified-0.7-1-production-identity/`.

The identity capture observes successful boot ring and indirect buffer tests.
It runs no controlled graphics workload and establishes no conformance, reset,
register, performance, or silicon safety verdict. The retained 0.6-1 parked
device bundle remains the last parked behavior silicon verdict. The signed
0.6-1, 0.5-1, and 0.4-3 package sets remain rollback authorities, and the
0.3-96 legacy equivalent acceptance remains the deeper retained baseline.
Source commits after the 0.8 pin remain unshipped until `radeon-custom`
advances its source pin and records a new release and loaded module identity.

## Deployment identity preflight

`scripts/radeon_deployment_preflight.sh` qualifies an attended RS482 evidence
directory before a hardware run:

```sh
sh scripts/radeon_deployment_preflight.sh SOURCE_TREE EVIDENCE_DIR
```

A `CLEAR` verdict requires a clean source tree. The source commit, Radeon
subtree, build feature policy digest, and upstream base must equal the metadata
inside the installed module. The installed module srcversion must equal the
running module srcversion, and its vermagic must name the running kernel. The
RS482 device, module parameters, current boot journal, process wait channels,
fresh evidence directory, and active off host logging route must also be
observable and clear. An unavailable fact, malformed identity, mismatch, prior
attempt, reset, lockup, parked signature, or Radeon fence waiter produces
`BLOCKED`.

The mutation calibration verifies the verdict boundary offline:

```sh
sh scripts/radeon_deployment_preflight.sh --self-test
```

The preflight reads host state and proves deployment identity and collection
readiness. It does not load the module, submit GPU work, prove runtime
reachability, or establish a silicon verdict. Retained hardware results and
their promotion rules remain in `steinmarder-r300`.

The retained parked-device silicon verdict covers the older 0.6-1 module. An
attended RS482 park latched `gpu_parked`; fresh native GEM creates, USERPTR
creation, and foreign PRIME import each returned -EIO with `radeon_bo_create`
counting zero, CS submission returned -EBUSY through the separate
`!accel_working` refusal before parser entry, and `WAIT_IDLE` returned -EIO.
The verdict lives in steinmarder-r300 as bundle
`cachyos_vostro1000_rs482_parked_entry_contract_matrix_20260805T055406Z`.
The 0.7-1 source now preserves the dumb-create errno and adds a direct
`gpu_parked` CS refusal with -EIO before parser initialization. Both corrections
are source- and package-verified. The live 0.7 deployment identity does not
promote them to retained target behavior; 0.6-1 remains the last retained parked
silicon verdict. The warm reboot failure also remains open: the measured parked
host required physical power-cycle recovery.

## Source closure

`source-closure.toml` declares what the closure carries. Two classes stay out
because they are build products rather than source: the ten `*_reg_safe.h`
headers, which the build generates from `reg_srcs/` through `mkregtable`, and a
prebuilt `mkregtable` executable the legacy snapshot shipped beside its own
source. `reg_srcs/evergreen` returns as source, carrying the `SMX_DC_CTL0`
acceptance the legacy tree expressed only as a bit inside a generated header.

A clean checkout therefore builds every generated header from source, and no
tracked file is a build output.

## Radeon driver source map

`steinmarder-r300` owns the source-intelligence capture at
`tools/source-analysis/`. The instrument exports a named commit of this
repository through Git, applies the tracked source closure, and seals a bundle
carrying Git object proofs, GNU Global definitions and references, ctags, a
portable cscope cross reference, GNU cflow indexes and partitioned call trees,
declared and extracted callback bindings, contextual path witnesses, complexity
and coefficient vectors, optional preprocessed kernel lanes, and a complete
SHA-256 ledger. That repository owns retained result bundles and their seal
contract, so it owns the instrument that produces them and the narrative
contract that bounds their claims.

The capture reads this repository and never writes to it. It takes the checkout
as an explicit root, so a source commit here is measured rather than assumed:

```sh
make source-analysis-selftest RADEON_SOURCE_REPOSITORY=<this checkout>
```

`steinmarder-r300 tools/source-analysis/source-analysis-provenance.tsv` pins
each migrated file to its commit here by source and landed SHA-256.

## Build profiles

The no-flag build selects `prod`. Development builds form one monotone profile
order: `observe-dev`, `probe-dev`, and `mutate-dev`. The `--all-dev` flag is an
alias for `--mutate-dev`.

```sh
sh scripts/build_radeon_module.sh --self-test
sh scripts/build_radeon_module.sh \
  --prod \
  --kernel-build-root "$KERNEL_BUILD_ROOT"
sh scripts/build_radeon_module.sh \
  --observe-dev \
  --kernel-build-root "$KERNEL_BUILD_ROOT"
sh scripts/build_radeon_module.sh \
  --probe-dev \
  --kernel-build-root "$KERNEL_BUILD_ROOT"
sh scripts/build_radeon_module.sh \
  --mutate-dev \
  --kernel-build-root "$KERNEL_BUILD_ROOT"
sh scripts/build_radeon_module.sh \
  --all-dev \
  --kernel-build-root "$KERNEL_BUILD_ROOT"
```

The retained declared build identities are `6.18.38-2-cachyos-lts` and
`7.1.4-1-cachyos`. At source commit
`df6f5cf10024ee20cc5db66e5c891f9207f24f7a`, the exact-root matrix passed
`prod`, `observe-dev`, `probe-dev`, and `mutate-dev` with zero warnings on both
roots. The 6.18 root used the signed Clang and LLD 22.1.6 package set in
`ci/kernel-toolchains/clang-lld-22.1.6.sha256`; the 7.1 root used the signed
22.1.8 set. The built Radeon driver tree was
`bc05af9ebe11efd046b99359fd063f38a6b1e2ce`. This proves bounded compilation,
link, metadata, and interface projection. It does not prove module loading,
runtime reachability, or hardware behavior.

The temporary build tree carries `radeon_build_profile.h` and
`radeon-build-profile.toml`. The linked module records the source commit,
resolved profile, build-feature policy digest, and upstream base. The harness
verifies those fields, the exact module parameter and debugfs projection, the
linked development symbols, and the generated safe-register tables before
reporting success. Production builds omit every development interface.

Development builds default to runtime profile `off`. The load-time, read-only
parameter `profile_dev` accepts `off`, `observe-dev`, `probe-dev`, or
`mutate-dev`. A selection above the compiled profile rejects module loading,
and `all-dev` remains a build alias rather than a runtime value. Runtime
selection controls development interface registration and command-policy
selection. Operation-specific tokens, selectors, family checks, and
parked-state refusals remain independent gates. The first mutation-capable
operation that passes its final gate logs once per device and adds
`TAINT_USER`. Compiling a development profile and selecting a runtime profile
do not taint the kernel.

## Equivalence contract

The migration proof is not raw equality against the legacy payload, because the
legacy payload contains artifacts this repository declines to carry. It is two
statements:

```text
source_export == normalized_source_reference
generate(source_export) == legacy_generated_outputs
```

The normalized reference is the legacy tree with the exclusions and the
restoration above applied. The generated-output half proves the removals lose
nothing: rebuilding `mkregtable` from source and regenerating every header
reproduces what the legacy tree shipped.

## Identity terminology

`CHIP_RS480` names the family constant and covers `1002:5954`, `1002:5955`,
`1002:5974`, and `1002:5975`. `RS482 (1002:5974)` names the part every retained
hardware claim binds to. `RS485M` names the platform chipset of the target
machine, sourced from DMI and the `1002:5950` host bridge, and it stays out of
GPU register and reset claims.

## Hardware and memory path contracts

The active RS4xx hardware and memory source model has four finite owners:

* `policy/rs4xx-hardware-transition-contract.tsv` covers the eight-state
  admission model and the exact initialization, suspend, resume, reset, and
  unload transition owners. Its narrative is
  `docs/rs4xx-failed-reset-hardware-containment.md`.

* `policy/rs4xx-gart-memory-path.tsv` covers GART, TTM, BO mapping, PTE
  publication, userptr ownership, CPU mappings, move rollback, BO lifetime
  accounting, the six-owner TTM finalization veto, and teardown. Its narrative
  is `docs/rs4xx-gart-bo-lifecycle-contract.md`.
* `policy/radeon-cs-reservation-fence-contract.tsv` covers command admission,
  BO reservations, dependency import, IB scheduling, r300 fence commands, and
  reservation-fence publication. Its narrative is
  `docs/radeon-cs-reservation-fence-contract.md`.
* `policy/rs4xx-vram-gtt-capacity-contract.tsv` covers aperture admission,
  GART metadata cost, allocator capacity, BO placement and movement, pin
  accounting, usage counters, and fragmentation observations. Its exact
  four-selector matrix, exclusion ledger, coefficient ledger, source-lineage
  ledger, and narrative live beside it in `policy/` and
  `docs/rs4xx-vram-gtt-capacity-contract.md`.

The firmware parser adds a separate bounded input owner.
`docs/radeon-combios-bounded-rom-contract.md` defines BIOS acquisition extent,
first PCI image admission, COMBIOS table preflight, bounded ATOM interpretation,
and exact offline RS482 ROM replay. It changes driver C behavior by refusing an
invalid firmware span before hardware driving commands execute. The capacity
authority at commit `6667d7561617debdc62cf99c62fb47bd67f95043` remains a
source policy intake and does not claim a driver C behavior change.

All four ledgers separate source status from runtime and silicon status. The
transition contract proves finite source ordering, not scheduler interleavings
or target survival. Reservation fences and emitted cache commands prove
software and ring order, not cached-GTT payload visibility. GTT size is virtual
aperture capacity rather than proved physical backing, and a source-supported
selector is not a performance result. Exact RS482 payload, allocation-pressure,
and replay verdicts remain owned by Steinmarder, while Vostro owns K8, HT, DRAM,
address domain, PAT, MTRR, and event-scoped aperture observations.

`policy/rs4xx-ttm-retention-authority.toml` pins the Linux 6.18 and 7.1 TTM,
GEM, PRIME, and AGP cleanup sources. It binds complete BO, detached translation
table, page-accounting, resource-release, and imported-SG ownership claims to
their exact upstream bytes. `policy/pci-runtime-resume-rollback-authority.toml`
pins the matching PCI and runtime-PM sources. The transition and GART lifecycle
checkers verify these authority hashes before accepting their derived source
contracts.

## License

The imported files carry their upstream SPDX identifiers and copyright headers
verbatim. `COPYING` carries the GPL-2.0 text those identifiers reference.
