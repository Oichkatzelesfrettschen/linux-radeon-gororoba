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

## Transitional authority

`linux-radeon-gororoba` is the canonical modified-source authority from
`radeon-unified-0.3-pkgrel91-source-equivalent` onward.

`radeon-custom` has completed the signed source-pin cutover and remains the
deployment and packaging authority. Its active 0.7-1 packages pin this
repository's signed profiled-source checkpoint (tag
`radeon-unified-0.7-profiled-source`, tag object
7f500d682aad600ca443c7f26e913b6b4034c834, peeled source commit
293a4ae3fe82cd03585ef3157e82b0b59b641b47, and driver tree
d57a22ad5356637d7075cb2aba83e22af71f7bfb) across split production capability,
development capability, and RS482 board policy. The package attestation records
signed artifacts and successful dual-kernel DKMS lifecycles. That attestation
itself records target contact, installation, module load, and hardware operation
as NOT RUN for 0.7-1. A later read-only live cross-check establishes deployment
identity only. The bound PCI device resolves to `/sys/module/radeon`, and the
loaded module `srcversion` `A7F72BE636B52D7EED42415` matches the on-disk DKMS
0.7 module. The on-disk metadata pins source commit
`293a4ae3fe82cd03585ef3157e82b0b59b641b47` and driver tree
`d57a22ad5356637d7075cb2aba83e22af71f7bfb`. This cross-check does not amend the
attestation or establish retained behavioral acceptance. Later repository
commits may supersede source mechanisms without superseding the signed
deployment pin; they remain unshipped until radeon-custom records a new source
pin, package attestation, and module lifecycle. The retained 0.6-1 parked-device
bundle remains the last retained parked-behavior silicon verdict; it is not a
general current runtime authority. The signed 0.5-1 and 0.4-3 sets remain deeper
rollback authorities, and the 0.3-96 legacy-equivalent acceptance remains the
deeper retained baseline.

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
`286d8fbc56c8017bfe6e00a29771ddc2f3040654`, the exact-root matrix passed
`prod`, `observe-dev`, `probe-dev`, and `mutate-dev` with zero warnings on both
roots. The 6.18 root used the signed Clang and LLD 22.1.6 package set in
`ci/kernel-toolchains/clang-lld-22.1.6.sha256`; the 7.1 root used the signed
22.1.8 set. The built Radeon driver tree was
`ef45f03a970fdb84b8975ba3fec96b2bfe625324`. This proves bounded compilation,
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

The active RS4xx memory-path source model has three finite owners:

* `policy/rs4xx-gart-memory-path.tsv` covers GART, TTM, BO mapping, PTE
  publication, userptr ownership, CPU mappings, and teardown. Its narrative is
  `docs/rs4xx-gart-bo-lifecycle-contract.md`.
* `policy/radeon-cs-reservation-fence-contract.tsv` covers command admission,
  BO reservations, dependency import, IB scheduling, r300 fence commands, and
  reservation-fence publication. Its narrative is
  `docs/radeon-cs-reservation-fence-contract.md`.
* `policy/rs4xx-vram-gtt-capacity-contract.tsv` covers aperture admission,
  GART metadata cost, VRAM and GTT allocator capacity, BO placement, movement,
  pin accounting, usage counters, and fragmentation observations. Its exact
  four-state RS482 matrix and exclusions live beside it, and its narrative is
  `docs/rs4xx-vram-gtt-capacity-contract.md`.

All three ledgers separate source status from runtime and silicon status. In
particular, reservation fences and emitted cache commands prove software and
ring order, not cached-GTT payload visibility. GTT size is virtual aperture
capacity rather than proved physical backing, and a source-supported size is
not a performance result. Exact RS482 payload, allocation-pressure, and replay
verdicts remain owned by Steinmarder, while Vostro owns K8, HT, DRAM, address
domain, PAT, MTRR, and event-scoped aperture observations.

## License

The imported files carry their upstream SPDX identifiers and copyright headers
verbatim. `COPYING` carries the GPL-2.0 text those identifiers reference.
