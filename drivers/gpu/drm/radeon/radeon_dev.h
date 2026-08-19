// SPDX-License-Identifier: MIT

#ifndef __RADEON_DEV_H__
#define __RADEON_DEV_H__

#include <linux/atomic.h>
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

/* Every fork-added readable development node emits this schema line as
 * its first output line, so a probe runner binds its column parsing to
 * an explicit version instead of inferring the layout.  The version
 * increments whenever any node changes its emitted columns, and
 * policy/build-features.toml pins the same value under
 * profile_model.output_schema_version so a manifest drift fails
 * check_all_dev_interfaces.py.
 */
#define RADEON_DEV_OUTPUT_SCHEMA_VERSION 2
#define RADEON_DEV_OUTPUT_SCHEMA_LINE "schema rs480-dev v2\n"

struct drm_minor;
struct radeon_device;

enum radeon_dev_profile {
	RADEON_DEV_PROFILE_OFF,
	RADEON_DEV_PROFILE_OBSERVE,
	RADEON_DEV_PROFILE_PROBE,
	RADEON_DEV_PROFILE_MUTATE,
};

struct radeon_dev_context {
	enum radeon_dev_profile profile;
	atomic_t mutation_tainted;
};

#if RADEON_OBSERVE_DEV
void radeon_dev_context_init(struct radeon_device *rdev);
bool radeon_dev_profile_enabled(struct radeon_device *rdev,
				enum radeon_dev_profile required);
void radeon_dev_mark_mutation(struct radeon_device *rdev,
			      const char *operation);

extern int radeon_rs480_candidate_regs;
extern int radeon_rs480_safe_regs;
#else
static inline void radeon_dev_context_init(struct radeon_device *rdev)
{
}

static inline bool
radeon_dev_profile_enabled(struct radeon_device *rdev,
			   enum radeon_dev_profile required)
{
	return false;
}

static inline void
radeon_dev_mark_mutation(struct radeon_device *rdev, const char *operation)
{
}
#endif

#if RADEON_PROBE_DEV
extern int radeon_rs480_cp_me_oracle;
extern int radeon_rs480_cp_me_ram_dump;
extern int radeon_rs480_frontier_index;
extern int radeon_rs480_hazard_index;
extern int radeon_rs480_hazard_readers_armed;
extern int radeon_rs480_vertex_index;
extern int radeon_rs480_cp_status_arm;
extern int radeon_rs480_status_census_arm;
extern int radeon_rs480_status_census_records;
extern int radeon_rs480_status_census_read_order;
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
extern int radeon_rs480_pll_write_probe_index;
extern int radeon_rs480_r400_us_cs;
extern int radeon_rs480_reset_hang_probe;
extern int radeon_rs480_vap_census_arm;
extern int radeon_rs480_vap_census_records;
extern int radeon_rs480_vap_burst_census_arm;
extern int radeon_rs480_vap_burst_census_words;

void radeon_evergreen_dev_debugfs_register(struct drm_minor *minor);
bool radeon_rs4xx_dev_apply_r400_us_reg_safe(struct radeon_device *rdev);
u32 radeon_rs4xx_dev_reset_mask(struct radeon_device *rdev,
				u32 baseline_mask, const char **name_out);
void radeon_debugfs_rs480_mc_flush_init(struct radeon_device *rdev);
bool radeon_palm_dev_pci_reset_unsafe(struct radeon_device *rdev);
#else
static inline void
radeon_evergreen_dev_debugfs_register(struct drm_minor *minor)
{
}

static inline bool
radeon_rs4xx_dev_apply_r400_us_reg_safe(struct radeon_device *rdev)
{
	return false;
}

static inline u32
radeon_rs4xx_dev_reset_mask(struct radeon_device *rdev,
			    u32 baseline_mask, const char **name_out)
{
	*name_out = "baseline(VAP|GA)";
	return baseline_mask;
}

static inline bool
radeon_palm_dev_pci_reset_unsafe(struct radeon_device *rdev)
{
	return false;
}
#endif

#if RADEON_OBSERVE_DEV
void radeon_rs480_re_debugfs_register(struct drm_minor *minor);
#endif

#endif
