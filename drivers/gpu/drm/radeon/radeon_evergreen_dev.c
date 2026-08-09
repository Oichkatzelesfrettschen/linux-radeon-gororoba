// SPDX-License-Identifier: MIT

#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/uaccess.h>

#include <drm/drm_device.h>
#include <drm/drm_file.h>

#include "radeon.h"
#include "radeon_asic.h"

/* The Palm debugfs trigger invokes the bounded PCI configuration reset.
 * Registration, the write handler, and the reset body each reject every
 * other Radeon family.  The exact Boolean override remains required on Palm.
 */
static ssize_t
radeon_force_pci_reset_safe_write(struct file *file,
				  const char __user *buf,
				  size_t count, loff_t *ppos)
{
	struct radeon_device *rdev = file_inode(file)->i_private;
	char input[8];
	int rc;

	/* One reset command per descriptor: a nonzero position marks a
	 * continued write or an already-consumed descriptor. */
	if (*ppos != 0)
		return -ESPIPE;
	if (count == 0 || count > sizeof(input) - 1)
		return -EINVAL;
	if (copy_from_user(input, buf, count))
		return -EFAULT;
	input[count] = 0;
	/* The trigger is the exact command "1": sysfs_streq admits one
	 * optional terminal newline and rejects any surplus byte. */
	if (!sysfs_streq(input, "1"))
		return -EINVAL;

	if (!rdev || rdev->family != CHIP_PALM)
		return -ENODEV;

	down_write(&rdev->exclusive_lock);
	rc = radeon_dev_hardware_available(rdev);
	if (rc)
		goto out_unlock;
	*ppos = 1;
	rc = evergreen_gpu_pci_config_reset_safe(rdev);

out_unlock:
	up_write(&rdev->exclusive_lock);
	return rc ? rc : (ssize_t)count;
}

static const struct file_operations radeon_force_pci_reset_safe_fops = {
	.owner = THIS_MODULE,
	/* nonseekable_open clears FMODE_LSEEK and FMODE_PWRITE, so each reset
	 * trigger is a fresh open-write-close descriptor. */
	.open = nonseekable_open,
	.write = radeon_force_pci_reset_safe_write,
};

void radeon_evergreen_dev_debugfs_register(struct drm_minor *minor)
{
	struct radeon_device *rdev;

	if (!minor || minor->type != DRM_MINOR_PRIMARY || !minor->dev ||
	    !minor->debugfs_root)
		return;
	rdev = minor->dev->dev_private;
	if (!rdev || rdev->family != CHIP_PALM ||
	    !radeon_dev_profile_enabled(rdev, RADEON_DEV_PROFILE_MUTATE))
		return;

	debugfs_create_file("radeon_force_pci_reset_safe", 0200,
			    minor->debugfs_root, rdev,
			    &radeon_force_pci_reset_safe_fops);
}
