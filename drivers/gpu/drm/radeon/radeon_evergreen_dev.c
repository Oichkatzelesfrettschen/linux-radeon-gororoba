// SPDX-License-Identifier: MIT

#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/uaccess.h>

#include "radeon.h"
#include "radeon_asic.h"

/* Debugfs trigger that lets userspace invoke
 * evergreen_gpu_pci_config_reset_safe on demand for forensic
 * experimentation on a wedged GPU. The reset is gated by the
 * CHIP_PALM refuse-by-default policy implemented inside
 * evergreen_gpu_pci_config_reset_safe; on Palm silicon a write
 * here returns -EPERM unless radeon.palm_pci_reset_unsafe=1 is
 * set.
 */
static ssize_t
radeon_force_pci_reset_safe_write(struct file *file,
				  const char __user *buf,
				  size_t count, loff_t *ppos)
{
	struct radeon_device *rdev = file_inode(file)->i_private;
	char input[8];
	int rc;

	if (count == 0 || count > sizeof(input) - 1)
		return -EINVAL;
	if (copy_from_user(input, buf, count))
		return -EFAULT;
	input[count] = 0;
	if (input[0] != '1')
		return -EINVAL;

	if (rdev->family != CHIP_PALM)
		radeon_dev_mark_mutation(rdev, "Evergreen debugfs PCI reset");
	rc = evergreen_gpu_pci_config_reset_safe(rdev);
	return rc ? rc : (ssize_t)count;
}

static const struct file_operations radeon_force_pci_reset_safe_fops = {
	.owner = THIS_MODULE,
	/* nonseekable_open clears FMODE_LSEEK and FMODE_PWRITE, so each reset
	 * trigger is a fresh open-write-close descriptor. */
	.open = nonseekable_open,
	.write = radeon_force_pci_reset_safe_write,
};

void radeon_evergreen_dev_debugfs_init(struct radeon_device *rdev)
{
	if (!radeon_dev_profile_enabled(rdev, RADEON_DEV_PROFILE_MUTATE))
		return;

	/* Register the debugfs trigger for the bounded-MC-wait safe variant
	 * of evergreen_gpu_pci_config_reset. The file is created at debugfs
	 * root because the DRM primary minor is unavailable this early in
	 * radeon_driver_load_kms.
	 */
	debugfs_create_file("radeon_force_pci_reset_safe", 0200,
			    NULL, rdev,
			    &radeon_force_pci_reset_safe_fops);
}
