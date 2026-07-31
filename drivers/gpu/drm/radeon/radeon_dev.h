// SPDX-License-Identifier: MIT

#ifndef __RADEON_DEV_H__
#define __RADEON_DEV_H__

#include <linux/types.h>

#ifndef RADEON_OBSERVE_DEV
#define RADEON_OBSERVE_DEV 0
#endif
#ifndef RADEON_PROBE_DEV
#define RADEON_PROBE_DEV 0
#endif
#ifndef RADEON_MUTATE_DEV
#define RADEON_MUTATE_DEV 0
#endif

#if RADEON_PROBE_DEV && !RADEON_OBSERVE_DEV
#error RADEON_PROBE_DEV requires RADEON_OBSERVE_DEV
#endif
#if RADEON_MUTATE_DEV && !RADEON_PROBE_DEV
#error RADEON_MUTATE_DEV requires RADEON_PROBE_DEV
#endif

struct drm_minor;
struct radeon_device;

#if RADEON_OBSERVE_DEV
extern int radeon_rs480_candidate_regs;
extern int radeon_rs480_safe_regs;
#endif

#if RADEON_PROBE_DEV
extern int radeon_rs480_cp_me_oracle;
extern int radeon_rs480_cp_me_ram_dump;
extern int radeon_rs480_frontier_index;
extern int radeon_rs480_hazard_index;
extern int radeon_rs480_hazard_readers_armed;
extern int radeon_rs480_vertex_index;
#else
#define radeon_rs480_hazard_readers_armed 0
#endif

#if RADEON_MUTATE_DEV
extern int radeon_palm_pci_reset_unsafe;
extern int radeon_rs480_cp_me_ram_inject;
extern int radeon_rs480_cp_ib_scratch_oracle;
extern int radeon_rs480_force_clock_3d_index;
extern int radeon_rs480_force_clock_index;
extern int radeon_rs480_gated_read_index;
extern int radeon_rs480_gpu_reset_recover_probe;
extern int radeon_rs480_r400_us_cs;
extern int radeon_rs480_reset_hang_probe;

void radeon_evergreen_dev_debugfs_init(struct radeon_device *rdev);
bool radeon_rs4xx_dev_apply_r400_us_reg_safe(struct radeon_device *rdev);
u32 radeon_rs4xx_dev_reset_mask(u32 baseline_mask, const char **name_out);
void radeon_debugfs_rs480_mc_flush_init(struct radeon_device *rdev);
static inline bool radeon_palm_dev_pci_reset_unsafe(void)
{
	return radeon_palm_pci_reset_unsafe != 0;
}
#else
static inline void
radeon_evergreen_dev_debugfs_init(struct radeon_device *rdev)
{
}

static inline bool
radeon_rs4xx_dev_apply_r400_us_reg_safe(struct radeon_device *rdev)
{
	return false;
}

static inline u32
radeon_rs4xx_dev_reset_mask(u32 baseline_mask, const char **name_out)
{
	*name_out = "baseline(VAP|GA)";
	return baseline_mask;
}

static inline bool radeon_palm_dev_pci_reset_unsafe(void)
{
	return false;
}
#endif

#if RADEON_OBSERVE_DEV
void radeon_rs4xx_dev_gart_lock(void);
void radeon_rs4xx_dev_gart_unlock(void);
void radeon_rs480_re_debugfs_register(struct drm_minor *minor);
#else
static inline void radeon_rs4xx_dev_gart_lock(void)
{
}

static inline void radeon_rs4xx_dev_gart_unlock(void)
{
}
#endif

#endif
