# Development interface surface audit

The development surface is 38 fork-added debugfs nodes and 28 module
parameters, compiled only into development profiles and registered under the
per-device DRM debugfs root. This audit records, per node, the mode, the
profile tier, the gates that stand between an open file descriptor and MMIO,
and the mutation marker; it then records the hardening rows that remain open.
Symbols were verified against `drivers/gpu/drm/radeon/radeon_rs4xx_dev.c`,
`radeon_dev.c`, and `radeon_evergreen_dev.c` (`git grep -n debugfs_create_file`
and per-function body extraction).

`policy/dev-interface-registration-contract.tsv` binds the Palm reset node to
the DRM primary minor, its managed debugfs tree, mode 0200, runtime and
compiled mutate profiles, exact `CHIP_PALM` execution, and the external
evidence boundary. `scripts/check_all_dev_interfaces.py` calibrates this
contract against comment-stripped, brace-bounded function bodies. Its
mutations cover a global parent, early registration, missing family gates,
ignored hardware availability, early unlock, hardware access before the
family refusal, wrong mode, and wrong lifetime owner.

## Access-mode policy

Every node that touches hardware on read is root-only 0400. The two write
nodes are 0200 (`radeon_rs480_mc_flush`, `radeon_force_pci_reset_safe`).
`radeon_rs480_cp_me_ram_inject` is 0600 because its read reports the
last-injection software-state result buffer and never touches hardware; its
write is the armed path. The upstream radeon debugfs nodes
(`r100_rbbm_info`, `radeon_pm_info`, and peers) keep their upstream 0444
modes, because this policy governs the fork-added surface.

## Reader gate inventory

Every RS480 reader routes through `rs480_debugfs_refuse_if_parked` before any
register access, either directly in its show function or through the shared
`rs480_candidate_regs_emit` helper, so a parked GPU hard-returns a parked
notice with zero MMIO. The same guard reads `asic_suspended`, which
`radeon_suspend_kms` raises before powering the ASIC down and
`radeon_resume_kms` clears after restore, so a read during system suspend
reports the suspended state instead of reaching a powered-down engine. The
columns record the gates beyond that shared guard.

| Node | Mode | Tier | Gates beyond the parked guard | Mutation marker |
| --- | --- | --- | --- | --- |
| radeon_rs480_safe_regs | 0400 | observe-dev | curated safe list only | none |
| radeon_rs480_candidate_config_regs (+ alias radeon_rs480_candidate_regs) | 0400 | probe-dev | benign-at-rest list | none |
| radeon_rs480_candidate_gart_mc_regs | 0400 | probe-dev | benign-at-rest list | none |
| radeon_rs480_candidate_vap_regs | 0400 | probe-dev | rs480_hazard_readers_armed == 1 | none |
| radeon_rs480_candidate_ga_regs, _sc_regs, _gb_regs, _rb3d_regs, _zb_regs (+ legacy alias _z_regs), _firmware_read_regs, _vip_straggler_regs, _mc_benign_regs, _gart_status_regs | 0400 | probe-dev | benign-at-rest lists via rs480_candidate_regs_emit | none |
| radeon_rs480_uma_status, radeon_rs480_sclk_cntl, radeon_rs480_pll_regs | 0400 | observe-dev | fixed benign list | none |
| radeon_rs480_gart_page_table | 0400 | observe-dev | GART-ready check; decode only, no MMIO sweep | none |
| radeon_rs480_cp_me_ram_dump | 0400 | probe-dev | rs480_cp_me_ram_dump=1 in the seq start(); engine-idle contract | none |
| radeon_rs480_hazard_read | 0400 | probe-dev | rs480_hazard_readers_armed == 1 and rs480_hazard_index selection | none |
| radeon_rs480_frontier_probe, radeon_rs480_vertex_probe | 0400 | probe-dev | index selector (-1 sentinel) | none |
| radeon_rs480_cp_me_oracle | 0400 | probe-dev | exact token 0x4f524331; IGP live-fire excluded | none |
| radeon_rs480_force_clock_read, _force_clock_3d_read, _gated_read | 0400 | mutate-dev | index selector (-1 sentinel) | RS4xx force-clock read / force-clock 3D read / gated-state read |
| radeon_rs480_pll_write_probe | 0400 | mutate-dev | index selector (-1 sentinel) | RS4xx PLL write-path probe |
| radeon_rs480_cp_ib_scratch_oracle | 0400 | mutate-dev | rs480_cp_ib_scratch_oracle arm | RS4xx CP scratch oracle |
| radeon_rs480_reset_hang_probe | 0400 | mutate-dev | exact WD3A or WD3B token; admitted frontend state; forced request under reset writer lock; parked check and RBBM sample under reset read lock | RS4xx reset hang probe |
| radeon_rs480_vap_status_census | 0400 | mutate-dev | exact token 0x56415043 consumed by cmpxchg; single-census gate; pm-mutex clock lease; verified SCLK force and restore | RS4xx VAP status census |
| radeon_rs480_vap_status_burst_census | 0400 | mutate-dev | exact token 0x56415042 consumed by cmpxchg; single-census gate shared with the record census; pm-mutex clock lease; verified SCLK force and restore | RS4xx VAP status burst census |

## Writer gate inventory

| Node | Mode | Tier | Write contract | Mutation marker |
| --- | --- | --- | --- | --- |
| radeon_rs480_mc_flush | 0200 | mutate-dev | family check, exact command val == 1, radeon_dev_hardware_available (shutdown, suspended, parked), bounded 16-dword CP packet, nonseekable fd | RS4xx CP cache drain |
| radeon_rs480_cp_me_ram_inject | 0600 | mutate-dev | one operation per fd, token 0x494e4a31 plus literal ARM keyword, surplus-rejecting shared parser rs480_cp_me_inject_parse, address bound 0x100, radeon_dev_hardware_available, idle gate, restore validation before queue reenable, restore mismatch requests parked publication with the queue disabled | RS4xx CP-ME RAM injection |
| radeon_force_pci_reset_safe | 0200 | mutate-dev | DRM primary minor root, exact CHIP_PALM registration and write guards, exact command 1 via sysfs_streq, one operation per fd, exclusive_lock writer, radeon_dev_hardware_available, exact palm_pci_reset_unsafe Boolean, bounded PCI configuration reset | Palm PCI config reset |

Each write node opens through `nonseekable_open`, which clears `FMODE_LSEEK`
and `FMODE_PWRITE` on the descriptor, so lseek and pwrite fail at the VFS
layer and every trigger is a fresh open-write-close.

## Palm reset registration and execution boundary

The Palm reset path carries three independent family checks. Registration
requires a primary DRM minor, a live `minor->debugfs_root`, runtime
`mutate-dev`, and `rdev->family == CHIP_PALM`. The write handler repeats the
family check, takes `exclusive_lock` for writing, and checks hardware
availability before consuming the file position. The reset body repeats the
family check, asserts the writer lock, repeats hardware availability, requires
`palm_pci_reset_unsafe == 1`, and records the mutation immediately before the
first hardware write.

The driver table invokes one development dispatcher from `drm_driver`'s
`debugfs_init` callback. The dispatcher registers the RS4xx surface and the
Palm surface after DRM supplies the primary minor. `radeon_driver_load_kms`
contains no development debugfs registration. DRM core teardown removes the
per-device tree during unregister, so no global reset dentry retains a Radeon
device pointer.

The compiled `CHIP_PALM` PCI set is `1002:9802` through `1002:980a` in both
declared kernel targets. This repository carries migration source evidence and
no Palm silicon run. The source correction therefore earns compile verified
status only. A Palm hardware verdict requires a retained target bundle in the
Palm evidence lane.

The two shared-fops rows are inherited compatibility aliases, reproduced
byte-identically from the legacy packaging series
(`radeon-custom/patches/rs480/0004-rs480-candidate-regs-debugfs.patch`):
`radeon_rs480_candidate_regs` aliases the config cohort and
`radeon_rs480_candidate_z_regs` aliases the ZB cohort.

## Module parameter arming domains

The 17 parameters keep the three arming domains: booleans open at exactly 1
(`rs480_hazard_readers_armed`, `rs480_r400_us_cs`, `palm_pci_reset_unsafe`,
`rs480_safe_regs`, `rs480_candidate_regs`, `rs480_cp_me_ram_dump`), index
selectors use the -1 sentinel where any in-range nonnegative value selects
(`rs480_force_clock_index`, `rs480_force_clock_3d_index`,
`rs480_gated_read_index`, `rs480_pll_write_probe_index`,
`rs480_frontier_index`, `rs480_vertex_index`,
`rs480_hazard_index`), and exact-token gates require their named constant
(`rs480_cp_me_ram_inject`, `rs480_cp_me_oracle`,
`rs480_reset_hang_probe`, `rs480_cp_ib_scratch_oracle`).
`rs480_reset_mask` selects a mask where 0 is
the baseline. `profile_dev` is 0444 load-time-only; development arming binds
to one device through `radeon_dev_arm_holder`
(`policy/build-features.toml` `profile_model.development_arming`). The
registration root `radeon_rs480_re_debugfs_register` states the surface as an
unstable development ABI.

## Output schema versioning

Every fork-added readable node emits `schema rs480-dev v2` as its first
line: `rs480_debugfs_refuse_if_parked` emits it once per open for every
gate-routed reader (including the parked and suspended refusal notices),
and the GART page-table and CP-ME injection result readers emit it before
their own output. `RADEON_DEV_OUTPUT_SCHEMA_VERSION` in `radeon_dev.h` is
the one source of the version, `policy/build-features.toml`
`profile_model.output_schema_version` pins the value a probe runner may
accept, and `check_all_dev_interfaces.py` fails on drift between them.
The version increments whenever any node changes its emitted columns.

Three former row groups are closed in source: `rs480_debugfs_refuse_if_parked`
reads `asic_suspended` and refuses register access during system suspend; the
three write nodes open through `nonseekable_open`; and every write path admits
an exact command (`rs480_cp_me_inject_parse`, `sysfs_streq`, `val == 1`),
consumes its descriptor on admission where the operation touches hardware
once, and routes through `radeon_dev_asic_powered` or
`radeon_dev_hardware_available` immediately before final arm consumption.
