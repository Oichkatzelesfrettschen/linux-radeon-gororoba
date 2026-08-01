# Development interface surface audit

The development surface is 32 fork-added debugfs nodes and 18 module
parameters, compiled only into development profiles and registered under the
per-device DRM debugfs root. This audit records, per node, the mode, the
profile tier, the gates that stand between an open file descriptor and MMIO,
and the mutation marker; it then records the hardening rows that remain open.
Symbols were verified against `drivers/gpu/drm/radeon/radeon_rs4xx_dev.c`,
`radeon_dev.c`, and `radeon_evergreen_dev.c` (`git grep -n debugfs_create_file`
and per-function body extraction).

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
notice with zero MMIO. The columns record the gates beyond that shared guard.

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
| radeon_rs480_cp_ib_scratch_oracle | 0400 | mutate-dev | rs480_cp_ib_scratch_oracle arm | RS4xx CP scratch oracle |
| radeon_rs480_gpu_reset_recover_probe | 0400 | mutate-dev | exact arm token; engine-idle gate | RS4xx GPU reset recovery probe |
| radeon_rs480_reset_hang_probe | 0400 | mutate-dev | exact arm token; staged | RS4xx reset hang probe |

## Writer gate inventory

| Node | Mode | Tier | Write contract | Mutation marker |
| --- | --- | --- | --- | --- |
| radeon_rs480_mc_flush | 0200 | mutate-dev | family check, parked hard-return, bounded 16-dword CP packet | RS4xx CP cache drain |
| radeon_rs480_cp_me_ram_inject | 0600 | mutate-dev | ppos==0 one-shot, token 0x494e4a31 plus literal ARM keyword, sscanf exactness, address bound 0x100, idle gate, write-verify-restore | RS4xx CP-ME RAM injection |
| radeon_force_pci_reset_safe | 0200 | mutate-dev | Evergreen debugfs PCI reset path | Evergreen debugfs PCI reset |

The two shared-fops rows are inherited compatibility aliases, reproduced
byte-identically from the legacy packaging series
(`radeon-custom/patches/rs480/0004-rs480-candidate-regs-debugfs.patch`):
`radeon_rs480_candidate_regs` aliases the config cohort and
`radeon_rs480_candidate_z_regs` aliases the ZB cohort.

## Module parameter arming domains

The 18 parameters keep the three arming domains: booleans open at exactly 1
(`rs480_hazard_readers_armed`, `rs480_r400_us_cs`, `palm_pci_reset_unsafe`,
`rs480_safe_regs`, `rs480_candidate_regs`, `rs480_cp_me_ram_dump`), index
selectors use the -1 sentinel where any in-range nonnegative value selects
(`rs480_force_clock_index`, `rs480_force_clock_3d_index`,
`rs480_gated_read_index`, `rs480_frontier_index`, `rs480_vertex_index`,
`rs480_hazard_index`), and exact-token gates require their named constant
(`rs480_cp_me_ram_inject`, `rs480_cp_me_oracle`,
`rs480_gpu_reset_recover_probe`, `rs480_reset_hang_probe`,
`rs480_cp_ib_scratch_oracle`). `rs480_reset_mask` selects a mask where 0 is
the baseline. `profile_dev` is 0444 load-time-only; development arming binds
to one device through `radeon_dev_arm_holder`
(`policy/build-features.toml` `profile_model.development_arming`). The
registration root `radeon_rs480_re_debugfs_register` states the surface as an
unstable development ABI.

## Open hardening rows

These rows from the development-interface hardening scope remain open; each
names its blocking mechanism.

- Versioned output schema identifiers: no node emits a schema version line,
  so a parser cannot detect a column change. Closing this changes every
  consumer in the steinmarder-r300 probe runners, so the schema line and the
  runner update land together. Tracking:
  rs480_candidate_regs_emit.
- Suspend and teardown invalidation: the parked classifier covers the wedged
  case, and no reader distinguishes a suspended device; a read during suspend
  reaches MMIO on a powered-down engine. Closing this needs a suspend-state
  check beside rs480_debugfs_refuse_if_parked. Tracking:
  rs480_debugfs_refuse_if_parked.
- Nonseekable one-shot writes: rs480_cp_me_ram_inject rejects nonzero ppos
  and mc_flush is a simple-attribute setter; neither calls
  nonseekable_open, so the rejection is per-write policy rather than an fd
  property. Tracking: rs480_cp_me_ram_inject_open.
