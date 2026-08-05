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

| Repository | Authority |
| --- | --- |
| `linux-radeon-gororoba` | Modified Radeon kernel source, upstream base mapping, source generators, register policy tables, source tests, RAD-06 |
| `radeon-custom` | Arch and CachyOS PKGBUILD, DKMS glue, compiler policy, initramfs and modprobe policy, hazard preflight, source pin, package verification |
| `steinmarder-r300` | Target-silicon probes, retained result bundles, falsifiers, hardware verdicts |
| `mesa-26-gororoba` | r300g and r3v userspace behavior |

Packaging targets Arch and CachyOS alone.

## Transitional authority

`linux-radeon-gororoba` is the canonical modified-source authority from
`radeon-unified-0.3-pkgrel91-source-equivalent` onward.

`radeon-custom` has completed the signed source-pin cutover and remains the
deployment and packaging authority. Its active 0.6-1 packages pin this
repository's signed profiled-source checkpoint (tag
`radeon-unified-0.6-profiled-source`, object
7a011a561c38258180e1f3083a0e5d8e74f5c1dd, driver tree
84b3c5c0282bf37236f2c4fda80eb17048bdd1ed) across split production capability,
development capability, and RS482 board policy. The signed 0.6-1 production
and board-policy packages are installed and runtime-accepted on the RS482
target across a reboot, with the loaded module srcversion
EA8E3BBBBA9E5580BDA7553 bonded to source commit
7a8dfb50cc4861ebd2c33a2d96cd19f961443c8e. The signed 0.5-1 and 0.4-3 sets
are the rollback authorities, the `0.6-1 -> 0.5-1 -> 0.6-1` rollback path is
executed against the exact signed archives, and the 0.3-96 legacy-equivalent
acceptance remains the deeper retained baseline.

The parked-device entry contract this tree carries is hardware-pass on
RS482: an attended park latched `gpu_parked`, after which fresh native GEM
creates, USERPTR creation, and foreign PRIME import each returned -EIO with
`radeon_bo_create` counting zero, CS submission returned -EBUSY before
parser entry, and `WAIT_IDLE` returned -EIO, retained as steinmarder-r300
bundle `cachyos_vostro1000_rs482_parked_entry_contract_matrix_20260805T055406Z`.
Two open items ride that verdict: `radeon_mode_dumb_create` masks the parked
-EIO to -ENOMEM at the ioctl boundary, and an orderly warm reboot failed to
reclaim the parked host, so a park costs physical power-cycle recovery
capability.

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

## License

The imported files carry their upstream SPDX identifiers and copyright headers
verbatim. `COPYING` carries the GPL-2.0 text those identifiers reference.
