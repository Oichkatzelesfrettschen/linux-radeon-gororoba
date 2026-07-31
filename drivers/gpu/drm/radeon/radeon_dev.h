// SPDX-License-Identifier: MIT

#ifndef __RADEON_DEV_H__
#define __RADEON_DEV_H__

struct radeon_device;

extern int radeon_palm_pci_reset_unsafe;
extern int radeon_rs480_safe_regs;
extern int radeon_rs480_candidate_regs;
extern int radeon_rs480_cp_me_ram_dump;
extern int radeon_rs480_cp_me_ram_inject;
extern int radeon_rs480_cp_me_oracle;
extern int radeon_rs480_cp_ib_scratch_oracle;
extern int radeon_rs480_gpu_reset_recover_probe;
extern int radeon_rs480_reset_hang_probe;
extern int radeon_rs480_r400_us_cs;
extern int radeon_rs480_frontier_index;
extern int radeon_rs480_vertex_index;
extern int radeon_rs480_hazard_index;
extern int radeon_rs480_force_clock_index;
extern int radeon_rs480_force_clock_3d_index;
extern int radeon_rs480_gated_read_index;
extern int radeon_rs480_hazard_readers_armed;

void radeon_evergreen_dev_debugfs_init(struct radeon_device *rdev);

#endif
