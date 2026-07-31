// SPDX-License-Identifier: MIT

#include <linux/debugfs.h>

#include <drm/drm_file.h>

#include "radeon.h"
#include "r300d.h"

/* Emit the RS400/RS480 CP cache-drain packet sequence from debugfs. */
static int radeon_debugfs_rs480_mc_flush_set(void *data, u64 val)
{
	struct radeon_device *rdev = data;
	struct radeon_ring *ring = &rdev->ring[RADEON_RING_TYPE_GFX_INDEX];
	int r;

	if (rdev->family != CHIP_RS480 && rdev->family != CHIP_RS400)
		return -ENODEV;
	if (rdev->gpu_parked)
		return -EIO;

	r = radeon_ring_lock(rdev, ring, 16);
	if (r)
		return r;

	/* Flush and invalidate the RB3D color and Z caches. */
	radeon_ring_write(ring, PACKET0(0x4E4C, 0));
	radeon_ring_write(ring, 0x0000000A); /* R300_RB3D_DC_FLUSH | R300_RB3D_DC_FREE */
	radeon_ring_write(ring, PACKET0(0x4F18, 0));
	radeon_ring_write(ring, 0x00000003); /* R300_ZC_FLUSH | R300_ZC_FREE */

	/* Stall the CP until the 3D engine reports an idle clean state. */
	radeon_ring_write(ring, PACKET0(0x1720, 0));
	radeon_ring_write(ring, 0x00020000); /* RADEON_WAIT_3D_IDLECLEAN */

	radeon_ring_unlock_commit(rdev, ring, false);
	DRM_INFO("RS482 cache drain packet emitted on the CP ring.\n");
	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(rs480_mc_flush_fops, NULL,
			radeon_debugfs_rs480_mc_flush_set, "%llu\n");

void radeon_debugfs_rs480_mc_flush_init(struct radeon_device *rdev)
{
#if defined(CONFIG_DEBUG_FS)
	debugfs_create_file("radeon_rs480_mc_flush", 0200,
			    rdev_to_drm(rdev)->primary->debugfs_root, rdev,
			    &rs480_mc_flush_fops);
#endif
}
