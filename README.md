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

`radeon-custom` remains the deployment and packaging authority until its
source-pin cutover. Deployments continue to consume `radeon-custom` until that
cutover is validated.

## Source closure

`source-closure.toml` declares what the closure carries. Two classes stay out
because they are build products rather than source: the ten `*_reg_safe.h`
headers, which the build generates from `reg_srcs/` through `mkregtable`, and a
prebuilt `mkregtable` executable the legacy snapshot shipped beside its own
source. `reg_srcs/evergreen` returns as source, carrying the `SMX_DC_CTL0`
acceptance the legacy tree expressed only as a bit inside a generated header.

A clean checkout therefore builds every generated header from source, and no
tracked file is a build output.

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
