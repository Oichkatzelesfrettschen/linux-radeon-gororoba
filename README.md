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

The active `radeon-custom` recipe is 0.8-1. It pins the signed
`radeon-unified-0.8-profiled-source` tag object
`c3745d24ea7481ec56c5c0b1aa397be4b8788b72`, peeled source commit
`2433cbd69cd99d1dd002447bb4d481ed66141562`, and driver tree
`e3432f8dda41e2fcb93fad23a0f3825541c15e93`. Its package gates build and
verify the split package set, and its target kernel gate compiles the verified
production package on RS482. The repository carries no 0.8-1 signed release
attestation or loaded module identity, so 0.8-1 remains package and target
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

`scripts/capture_radeon_driver_source_map.py` exports a named commit through
Git, applies the tracked source closure, and writes a sealed deterministic
source intelligence bundle outside the repository. The bundle retains all 222
source inputs, the complete C and header denominator, Git object proofs, GNU
Global definitions and references with stable database dumps, ctags, the
portable cscope cross reference, GNU cflow indexes, partitioned cflow trees,
declared and extracted callback bindings, bounded queries, contextual path
witnesses, complexity measurements, coefficient vectors, linked profile
modules, canonical profile symbol deltas, command metadata, analyzer
diagnostics, and a complete SHA-256 ledger. The directory remains an ordinary
mutable filesystem object. The verifier detects changes through an independently
derived file denominator, the ledger, and offline artifact replay.

The optional kernel roots add preprocessed views for every declared kernel and
profile lane. Each root requires a matching toolchain bin directory. The
parent LLVM prefix has a tracked manifest for all 7,174 descendants, including
355 directories, 6,792 regular files, 27 symlinks, and the 295 entry Clang
resource tree. Before execution, the capture verifies the exact path set,
content identities, symlink resolution, ownership, effective writability,
special mode bits, and extended attributes. The 19 row semantic execution
closure then binds all nine LLVM commands, eight local libraries, and two
support targets to that finite tree.

Kbuild runs through `/usr/bin/make`, an absolute `LLVM` bin prefix,
`/usr/bin/sh`, and `PATH=/usr/bin:/bin`. The capture retains that command and
environment denominator, compiles the module, emits the selected translation
units, and normalizes temporary, toolchain, and kernel root paths. A second
tree scan compares against the same in-memory entries admitted before the
build. This contract identifies the LLVM prefix. It does not trace every host
helper process that Kbuild starts.

```sh
source_commit=$(git rev-parse HEAD)
output="/var/tmp/linux-radeon-gororoba-source-intelligence/radeon-driver-lifecycle-admission-reset-source-map/${source_commit}"
python3 scripts/capture_radeon_driver_source_map.py \
  --treeish "$source_commit" \
  --output "$output" \
  --kernel-build-root /opt/gororoba/kernel-builds/6.18.38-2-cachyos-lts \
  --kernel-build-root /opt/gororoba/kernel-builds/7.1.4-1-cachyos \
  --kernel-toolchain-bin \
    6.18.38-2-cachyos-lts=/opt/gororoba/toolchains/llvm-22.1.6/usr/bin \
  --kernel-toolchain-bin \
    7.1.4-1-cachyos=/opt/gororoba/toolchains/llvm-22.1.8/usr/bin
python3 scripts/capture_radeon_driver_source_map.py \
  --verify "$output" \
  --require-all-kernel-lanes
```

The union of `radeon-driver-lexical-map.tsv`,
`radeon-driver-declared-bindings.tsv`, and `analysis/call-candidates.tsv` is a
candidate research graph. It never proves runtime reachability, build-profile
inclusion, preprocessor activation, callback invocation, framework ordering,
hardware behavior, or completeness of indirect bindings. Preprocessed views
resolve named build lanes without changing that boundary. Contextual path
witnesses preserve ordered source edges, required conditions, and typed
callback or debugfs event joins without collapsing registration time into later
dispatch. `analysis/hazard-guard-identifier-census.tsv` remains a lexical
census. The mutation calibrated semantic checkers own their declared primary
source contracts. The reset checkers pin exact lexical intervals, reject a
finite opaque control set, and assume other intervening calls return. They do
not prove a compiler control flow graph, included header macro state, or
runtime execution.

`docs/radeon-driver-source-intelligence.md` defines the artifact architecture,
the complete reference attestation, the four retained path witnesses, the
coefficient derivations, the trust boundaries, and the next verification gates.

Two captures compare through normalized tables rather than analyzer database
bytes:

```sh
python3 scripts/capture_radeon_driver_source_map.py \
  --compare "$left_capture" "$right_capture" \
  --output "$comparison_output"
```

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

## Memory path contracts

The active RS4xx memory-path source model has two finite owners:

* `policy/rs4xx-gart-memory-path.tsv` covers GART, TTM, BO mapping, PTE
  publication, userptr ownership, CPU mappings, and teardown. Its narrative is
  `docs/rs4xx-gart-bo-lifecycle-contract.md`.
* `policy/radeon-cs-reservation-fence-contract.tsv` covers command admission,
  BO reservations, dependency import, IB scheduling, r300 fence commands, and
  reservation-fence publication. Its narrative is
  `docs/radeon-cs-reservation-fence-contract.md`.

Both ledgers separate source status from runtime and silicon status. In
particular, reservation fences and emitted cache commands prove software and
ring order, not cached-GTT payload visibility. Exact RS482 payload and replay
verdicts remain owned by Steinmarder, while Vostro owns K8, HT, DRAM, address
domain, PAT, MTRR, and event-scoped aperture observations.

## License

The imported files carry their upstream SPDX identifiers and copyright headers
verbatim. `COPYING` carries the GPL-2.0 text those identifiers reference.
