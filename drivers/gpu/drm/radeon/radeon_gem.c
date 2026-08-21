/*
 * Copyright 2008 Advanced Micro Devices, Inc.
 * Copyright 2008 Red Hat Inc.
 * Copyright 2009 Jerome Glisse.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors: Dave Airlie
 *          Alex Deucher
 *          Jerome Glisse
 */

#include <linux/debugfs.h>
#include <linux/iosys-map.h>
#include <linux/pci.h>

#include <drm/drm_device.h>
#include <drm/drm_file.h>
#include <drm/drm_gem_ttm_helper.h>
#include <drm/radeon_drm.h>

#include "radeon.h"
#include "radeon_prime.h"
#include "radeon_trace.h"

struct dma_buf *radeon_gem_prime_export(struct drm_gem_object *gobj,
					int flags);
struct sg_table *radeon_gem_prime_get_sg_table(struct drm_gem_object *obj);
int radeon_gem_prime_pin(struct drm_gem_object *obj);
void radeon_gem_prime_unpin(struct drm_gem_object *obj);

static vm_fault_t radeon_gem_fault(struct vm_fault *vmf)
{
	struct ttm_buffer_object *bo = vmf->vma->vm_private_data;
	struct radeon_device *rdev = radeon_get_rdev(bo->bdev);
	bool hardware_transaction = false;
	vm_fault_t ret;

	/* The RS400/RS480 admission epoch closes before reset invalidates the
	 * anonymous GEM mapping. A fault reserves its BO first, then joins the
	 * epoch before TTM changes placement or installs a CPU aperture PTE.
	 */
	down_read(&rdev->pm.mclk_lock);

	ret = ttm_bo_vm_reserve(bo, vmf);
	if (ret)
		goto unlock_mclk;

	if (radeon_rs4xx_hardware_transaction_begin(rdev)) {
		dev_err_once(rdev->dev,
			     "RS4xx hardware unavailable: SIGBUS on GEM fault\n");
		ret = VM_FAULT_SIGBUS;
		goto unlock_resv;
	}
	hardware_transaction = true;

	ret = radeon_bo_fault_reserve_notify(bo);
	if (ret)
		goto unlock_resv;

	ret = ttm_bo_vm_fault_reserved(vmf, vmf->vma->vm_page_prot,
				       TTM_BO_VM_NUM_PREFAULT);
	if (ret == VM_FAULT_RETRY && !(vmf->flags & FAULT_FLAG_RETRY_NOWAIT))
		goto unlock_transaction;

unlock_resv:
	dma_resv_unlock(bo->base.resv);

unlock_transaction:
	if (hardware_transaction)
		radeon_rs4xx_hardware_transaction_end(rdev);

unlock_mclk:
	up_read(&rdev->pm.mclk_lock);
	return ret;
}

static int radeon_gem_vm_access(struct vm_area_struct *vma,
				unsigned long addr, void *buf, int len,
				int write)
{
	struct ttm_buffer_object *bo = vma->vm_private_data;
	struct radeon_device *rdev = radeon_get_rdev(bo->bdev);
	int ret;

	ret = radeon_rs4xx_hardware_transaction_begin(rdev);
	if (ret)
		return ret;
	ret = ttm_bo_vm_access(vma, addr, buf, len, write);
	radeon_rs4xx_hardware_transaction_end(rdev);
	return ret;
}

static const struct vm_operations_struct radeon_gem_vm_ops = {
	.fault = radeon_gem_fault,
	.open = ttm_bo_vm_open,
	.close = ttm_bo_vm_close,
	.access = radeon_gem_vm_access
};

static void radeon_gem_object_free(struct drm_gem_object *gobj)
{
	struct radeon_bo *robj = gem_to_radeon_bo(gobj);
	struct radeon_device *rdev;
	bool hardware_transaction = false;
	int ret;

	if (robj) {
		rdev = robj->rdev;
		ret = radeon_rs4xx_hardware_transaction_wait_begin(rdev);
		if (ret == -ESHUTDOWN)
			ret = radeon_rs4xx_gart_teardown_wait(rdev);
		else if (ret == 0)
			hardware_transaction = true;
		if (ret) {
			int retained_count = radeon_rs4xx_retain_bo(robj);

			/* TTM cannot preserve an unbind error through its void
			 * unpopulate callback, so the terminal path retains the complete
			 * buffer object and records the exact per-device denominator.
			 */
			dev_err_ratelimited(
				rdev->dev,
				"RS4xx hardware unavailable: retained GEM objects=%d\n",
				retained_count);
			radeon_rs4xx_latch_teardown_refusal(rdev);
			radeon_mn_unregister(robj);
			return;
		}
		radeon_mn_unregister(robj);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 0, 0)
		ttm_bo_fini(&robj->tbo);
	#else
		ttm_bo_put(&robj->tbo);
	#endif
		if (hardware_transaction)
			radeon_rs4xx_hardware_transaction_end(rdev);
	}
}

int radeon_gem_object_create(struct radeon_device *rdev, unsigned long size,
				int alignment, int initial_domain,
				u32 flags, bool kernel,
				struct drm_gem_object **obj)
{
	struct radeon_bo *robj;
	unsigned long max_size;
	int r;

	*obj = NULL;

	/* At least align on page size */
	if (alignment < PAGE_SIZE) {
		alignment = PAGE_SIZE;
	}

	/* Maximum bo size is the unpinned gtt size since we use the gtt to
	 * handle vram to system pool migrations.
	 */
	max_size = rdev->mc.gtt_size - rdev->gart_pin_size;
	if (size > max_size) {
		DRM_DEBUG("Allocation size %ldMb bigger than %ldMb limit\n",
			  size >> 20, max_size >> 20);
		return -ENOMEM;
	}

	r = radeon_rs4xx_hardware_access_begin(rdev);
	if (r)
		return r;

retry:
	r = radeon_bo_create(rdev, size, alignment, kernel, initial_domain,
			     flags, NULL, NULL, &robj);
	if (r) {
		if (r != -ERESTARTSYS) {
			if (initial_domain == RADEON_GEM_DOMAIN_VRAM) {
				initial_domain |= RADEON_GEM_DOMAIN_GTT;
				goto retry;
			}
			DRM_ERROR("Failed to allocate GEM object (%ld, %d, %u, %d)\n",
				  size, initial_domain, alignment, r);
		}
		goto out;
	}
	*obj = &robj->tbo.base;
	robj->pid = task_pid_nr(current);

	mutex_lock(&rdev->gem.mutex);
	list_add_tail(&robj->list, &rdev->gem.objects);
	mutex_unlock(&rdev->gem.mutex);

	r = 0;
out:
	radeon_rs4xx_hardware_access_end(rdev);
	return r;
}

static int radeon_gem_set_domain(struct drm_gem_object *gobj,
			  uint32_t rdomain, uint32_t wdomain)
{
	struct radeon_bo *robj;
	uint32_t domain;
	long r;

	/* FIXME: reeimplement */
	robj = gem_to_radeon_bo(gobj);
	/* work out where to validate the buffer to */
	domain = wdomain;
	if (!domain) {
		domain = rdomain;
	}
	if (!domain) {
		/* Do nothings */
		pr_warn("Set domain without domain !\n");
		return 0;
	}
	if (domain == RADEON_GEM_DOMAIN_CPU) {
		/* Asking for cpu access wait for object idle */
		r = dma_resv_wait_timeout(robj->tbo.base.resv,
					  DMA_RESV_USAGE_BOOKKEEP,
					  true, 30 * HZ);
		if (!r)
			r = -EBUSY;

		if (r < 0 && r != -EINTR) {
			pr_err("Failed to wait for object: %li\n", r);
			return r;
		}
	}
	if (domain == RADEON_GEM_DOMAIN_VRAM && robj->prime_shared_count) {
		/* A BO that is associated with a dma-buf cannot be sensibly migrated to VRAM */
		return -EINVAL;
	}
	return 0;
}

int radeon_gem_init(struct radeon_device *rdev)
{
	INIT_LIST_HEAD(&rdev->gem.objects);
	atomic64_set(&rdev->gem.bo_debug_id, 0);
	return 0;
}

void radeon_gem_fini(struct radeon_device *rdev)
{
	radeon_bo_force_delete(rdev);
}

/*
 * Call from drm_gem_handle_create which appear in both new and open ioctl
 * case.
 */
static int radeon_gem_object_open(struct drm_gem_object *obj, struct drm_file *file_priv)
{
	struct radeon_bo *rbo = gem_to_radeon_bo(obj);
	struct radeon_device *rdev = rbo->rdev;
	struct radeon_fpriv *fpriv = file_priv->driver_priv;
	struct radeon_vm *vm = &fpriv->vm;
	struct radeon_bo_va *bo_va;
	int r;

	if ((rdev->family < CHIP_CAYMAN) ||
	    (!rdev->accel_working)) {
		return 0;
	}

	r = radeon_bo_reserve(rbo, false);
	if (r) {
		return r;
	}

	bo_va = radeon_vm_bo_find(vm, rbo);
	if (!bo_va) {
		bo_va = radeon_vm_bo_add(rdev, vm, rbo);
	} else {
		++bo_va->ref_count;
	}
	radeon_bo_unreserve(rbo);

	return 0;
}

static void radeon_gem_object_close(struct drm_gem_object *obj,
				    struct drm_file *file_priv)
{
	struct radeon_bo *rbo = gem_to_radeon_bo(obj);
	struct radeon_device *rdev = rbo->rdev;
	struct radeon_fpriv *fpriv = file_priv->driver_priv;
	struct radeon_vm *vm = &fpriv->vm;
	struct radeon_bo_va *bo_va;
	int r;

	if ((rdev->family < CHIP_CAYMAN) ||
	    (!rdev->accel_working)) {
		return;
	}

	r = radeon_bo_reserve(rbo, true);
	if (r) {
		dev_err(rdev->dev, "leaking bo va because "
			"we fail to reserve bo (%d)\n", r);
		return;
	}
	bo_va = radeon_vm_bo_find(vm, rbo);
	if (bo_va) {
		if (--bo_va->ref_count == 0) {
			radeon_vm_bo_rmv(rdev, bo_va);
		}
	}
	radeon_bo_unreserve(rbo);
}

static int radeon_gem_handle_lockup(struct radeon_device *rdev, int r)
{
	if (r == -EDEADLK) {
		r = radeon_gpu_reset(rdev);
		if (!r)
			r = -EAGAIN;
	}
	return r;
}

static int radeon_gem_object_mmap(struct drm_gem_object *obj, struct vm_area_struct *vma)
{
	struct radeon_bo *bo = gem_to_radeon_bo(obj);
	struct radeon_device *rdev = radeon_get_rdev(bo->tbo.bdev);
	int ret;

	if (radeon_ttm_tt_has_userptr(rdev, bo->tbo.ttm))
		return -EPERM;

	ret = radeon_rs4xx_hardware_access_begin(rdev);
	if (ret)
		return ret;
	ret = drm_gem_ttm_mmap(obj, vma);
	radeon_rs4xx_hardware_access_end(rdev);
	return ret;
}

static int radeon_gem_object_vmap(struct drm_gem_object *obj,
				  struct iosys_map *map)
{
	struct radeon_bo *bo = gem_to_radeon_bo(obj);

	/* A dma-buf vmap outlives the call that creates it, so an admission
	 * token cannot revoke a VRAM aperture pointer before reset. The RS400
	 * and RS480 object interface keeps that persistent mapping closed.
	 */
	if (radeon_rs4xx_hardware_target(bo->rdev))
		return -EOPNOTSUPP;
	return drm_gem_ttm_vmap(obj, map);
}

const struct drm_gem_object_funcs radeon_gem_object_funcs = {
	.free = radeon_gem_object_free,
	.open = radeon_gem_object_open,
	.close = radeon_gem_object_close,
	.export = radeon_gem_prime_export,
	.pin = radeon_gem_prime_pin,
	.unpin = radeon_gem_prime_unpin,
	.get_sg_table = radeon_gem_prime_get_sg_table,
	.vmap = radeon_gem_object_vmap,
	.vunmap = drm_gem_ttm_vunmap,
	.mmap = radeon_gem_object_mmap,
	.vm_ops = &radeon_gem_vm_ops,
};

/*
 * GEM ioctls.
 */
int radeon_gem_info_ioctl(struct drm_device *dev, void *data,
			  struct drm_file *filp)
{
	struct radeon_device *rdev = dev->dev_private;
	struct drm_radeon_gem_info *args = data;
	struct ttm_resource_manager *man;

	man = ttm_manager_type(&rdev->mman.bdev, TTM_PL_VRAM);

	args->vram_size = (u64)man->size << PAGE_SHIFT;
	args->vram_visible = rdev->mc.visible_vram_size;
	args->vram_visible -= rdev->vram_pin_size;
	args->gart_size = rdev->mc.gtt_size;
	args->gart_size -= rdev->gart_pin_size;

	return 0;
}

int radeon_gem_create_ioctl(struct drm_device *dev, void *data,
			    struct drm_file *filp)
{
	struct radeon_device *rdev = dev->dev_private;
	struct drm_radeon_gem_create *args = data;
	struct drm_gem_object *gobj;
	uint32_t handle;
	int r;

	r = radeon_device_lock_hardware(rdev);
	if (r)
		return r;
	/* create a gem object to contain this object in */
	args->size = roundup(args->size, PAGE_SIZE);
	r = radeon_gem_object_create(rdev, args->size, args->alignment,
				     args->initial_domain, args->flags,
				     false, &gobj);
	if (r) {
		radeon_device_unlock_hardware(rdev);
		r = radeon_gem_handle_lockup(rdev, r);
		return r;
	}
	r = drm_gem_handle_create(filp, gobj, &handle);
	radeon_device_unlock_hardware(rdev);
	/* drop reference from allocate - handle holds it now */
	drm_gem_object_put(gobj);
	if (r) {
		r = radeon_gem_handle_lockup(rdev, r);
		return r;
	}
	args->handle = handle;
	return 0;
}

int radeon_gem_userptr_ioctl(struct drm_device *dev, void *data,
			     struct drm_file *filp)
{
	struct ttm_operation_ctx ctx = { true, false };
	struct radeon_device *rdev = dev->dev_private;
	struct drm_radeon_gem_userptr *args = data;
	struct drm_gem_object *gobj;
	struct radeon_bo *bo;
	uint32_t handle;
	int r;

	args->addr = untagged_addr(args->addr);

	if (offset_in_page(args->addr | args->size))
		return -EINVAL;

	/* reject unknown flag values */
	if (args->flags & ~(RADEON_GEM_USERPTR_READONLY |
	    RADEON_GEM_USERPTR_ANONONLY | RADEON_GEM_USERPTR_VALIDATE |
	    RADEON_GEM_USERPTR_REGISTER))
		return -EINVAL;

	if (args->flags & RADEON_GEM_USERPTR_READONLY) {
		/* readonly pages not tested on older hardware */
		if (rdev->family < CHIP_R600)
			return -EINVAL;

	} else if (!(args->flags & RADEON_GEM_USERPTR_ANONONLY) ||
		   !(args->flags & RADEON_GEM_USERPTR_REGISTER)) {

		/* if we want to write to it we must require anonymous
		   memory and install a MMU notifier */
		return -EACCES;
	}

	r = radeon_device_lock_hardware(rdev);
	if (r)
		return r;

	/* create a gem object to contain this object in */
	r = radeon_gem_object_create(rdev, args->size, 0,
				     RADEON_GEM_DOMAIN_CPU, 0,
				     false, &gobj);
	if (r)
		goto handle_lockup;

	bo = gem_to_radeon_bo(gobj);
	r = radeon_ttm_tt_set_userptr(rdev, bo->tbo.ttm, args->addr, args->flags);
	if (r)
		goto release_object;

	if (args->flags & RADEON_GEM_USERPTR_REGISTER) {
		r = radeon_mn_register(bo, args->addr);
		if (r)
			goto release_object;
	}

	if (args->flags & RADEON_GEM_USERPTR_VALIDATE) {
		mmap_read_lock(current->mm);
		r = radeon_bo_reserve(bo, true);
		if (r) {
			mmap_read_unlock(current->mm);
			goto release_object;
		}

		radeon_ttm_placement_from_domain(bo, RADEON_GEM_DOMAIN_GTT);
		r = ttm_bo_validate(&bo->tbo, &bo->placement, &ctx);
		radeon_bo_unreserve(bo);
		mmap_read_unlock(current->mm);
		if (r)
			goto release_object;
	}

	r = drm_gem_handle_create(filp, gobj, &handle);
	radeon_device_unlock_hardware(rdev);
	/* drop reference from allocate - handle holds it now */
	drm_gem_object_put(gobj);
	if (r)
		goto handle_lockup_unlocked;

	args->handle = handle;
	return 0;

release_object:
	radeon_device_unlock_hardware(rdev);
	drm_gem_object_put(gobj);
	goto handle_lockup_unlocked;

handle_lockup:
	radeon_device_unlock_hardware(rdev);

handle_lockup_unlocked:
	r = radeon_gem_handle_lockup(rdev, r);

	return r;
}

int radeon_gem_set_domain_ioctl(struct drm_device *dev, void *data,
				struct drm_file *filp)
{
	/* transition the BO to a domain -
	 * just validate the BO into a certain domain */
	struct radeon_device *rdev = dev->dev_private;
	struct drm_radeon_gem_set_domain *args = data;
	struct drm_gem_object *gobj;
	int r;

	/* for now if someone requests domain CPU -
	 * just make sure the buffer is finished with */
	r = radeon_device_lock_hardware(rdev);
	if (r)
		return r;

	/* just do a BO wait for now */
	gobj = drm_gem_object_lookup(filp, args->handle);
	if (gobj == NULL) {
		radeon_device_unlock_hardware(rdev);
		return -ENOENT;
	}

	r = radeon_gem_set_domain(gobj, args->read_domains, args->write_domain);

	radeon_device_unlock_hardware(rdev);
	drm_gem_object_put(gobj);
	r = radeon_gem_handle_lockup(rdev, r);
	return r;
}

int radeon_mode_dumb_mmap(struct drm_file *filp,
			  struct drm_device *dev,
			  uint32_t handle, uint64_t *offset_p)
{
	struct drm_gem_object *gobj;
	struct radeon_bo *robj;

	gobj = drm_gem_object_lookup(filp, handle);
	if (gobj == NULL) {
		return -ENOENT;
	}
	robj = gem_to_radeon_bo(gobj);
	if (radeon_ttm_tt_has_userptr(robj->rdev, robj->tbo.ttm)) {
		drm_gem_object_put(gobj);
		return -EPERM;
	}
	*offset_p = radeon_bo_mmap_offset(robj);
	drm_gem_object_put(gobj);
	return 0;
}

int radeon_gem_mmap_ioctl(struct drm_device *dev, void *data,
			  struct drm_file *filp)
{
	struct drm_radeon_gem_mmap *args = data;

	return radeon_mode_dumb_mmap(filp, dev, args->handle, &args->addr_ptr);
}

int radeon_gem_busy_ioctl(struct drm_device *dev, void *data,
			  struct drm_file *filp)
{
	struct drm_radeon_gem_busy *args = data;
	struct drm_gem_object *gobj;
	struct radeon_bo *robj;
	int r;
	uint32_t cur_placement = 0;

	gobj = drm_gem_object_lookup(filp, args->handle);
	if (gobj == NULL) {
		return -ENOENT;
	}
	robj = gem_to_radeon_bo(gobj);

	r = dma_resv_test_signaled(robj->tbo.base.resv, DMA_RESV_USAGE_READ);
	if (r == 0)
		r = -EBUSY;
	else
		r = 0;

	cur_placement = READ_ONCE(robj->tbo.resource->mem_type);
	args->domain = radeon_mem_type_to_domain(cur_placement);
	trace_radeon_gem_busy(task_pid_nr(current), args->handle, robj,
			      args->domain, r);
	drm_gem_object_put(gobj);
	return r;
}

int radeon_gem_wait_idle_ioctl(struct drm_device *dev, void *data,
			      struct drm_file *filp)
{
	struct radeon_device *rdev = dev->dev_private;
	struct drm_radeon_gem_wait_idle *args = data;
	struct drm_gem_object *gobj;
	struct radeon_bo *robj;
	int r = 0;
	int hardware_result;
	uint32_t cur_placement = 0;
	long ret;

	gobj = drm_gem_object_lookup(filp, args->handle);
	if (gobj == NULL) {
		return -ENOENT;
	}
	robj = gem_to_radeon_bo(gobj);

	ret = dma_resv_wait_timeout(robj->tbo.base.resv, DMA_RESV_USAGE_READ,
				    true, 30 * HZ);
	if (ret == 0)
		r = -EBUSY;
	else if (ret < 0)
		r = ret;
	if (r) {
		drm_gem_object_put(gobj);
		return r;
	}

	/* gpu_parked latches under the exclusive_lock writer in
	 * radeon_gpu_reset, so holding the reader across the flag test and the
	 * flush makes them one critical section: a caller either observes an
	 * unparked device and completes the flush before the writer runs, or
	 * observes the parked device and returns. The dma_resv wait above stays
	 * outside the lock because a 30 * HZ hold would stall that writer for
	 * the whole timeout on a wedging GPU.
	 */
	hardware_result = radeon_device_lock_hardware(rdev);
	if (hardware_result) {
		drm_gem_object_put(gobj);
		return hardware_result;
	}

	/* Flush HDP cache via MMIO if necessary */
	cur_placement = READ_ONCE(robj->tbo.resource->mem_type);
	if (rdev->asic->mmio_hdp_flush &&
	    radeon_mem_type_to_domain(cur_placement) == RADEON_GEM_DOMAIN_VRAM)
		robj->rdev->asic->mmio_hdp_flush(rdev);
	radeon_device_unlock_hardware(rdev);
	drm_gem_object_put(gobj);
	return 0;
}

int radeon_gem_set_tiling_ioctl(struct drm_device *dev, void *data,
				struct drm_file *filp)
{
	struct drm_radeon_gem_set_tiling *args = data;
	struct drm_gem_object *gobj;
	struct radeon_bo *robj;
	int r = 0;

	DRM_DEBUG("%d \n", args->handle);
	gobj = drm_gem_object_lookup(filp, args->handle);
	if (gobj == NULL)
		return -ENOENT;
	robj = gem_to_radeon_bo(gobj);
	r = radeon_bo_set_tiling_flags(robj, args->tiling_flags, args->pitch);
	drm_gem_object_put(gobj);
	return r;
}

int radeon_gem_get_tiling_ioctl(struct drm_device *dev, void *data,
				struct drm_file *filp)
{
	struct drm_radeon_gem_get_tiling *args = data;
	struct drm_gem_object *gobj;
	struct radeon_bo *rbo;
	int r = 0;

	DRM_DEBUG("\n");
	gobj = drm_gem_object_lookup(filp, args->handle);
	if (gobj == NULL)
		return -ENOENT;
	rbo = gem_to_radeon_bo(gobj);
	r = radeon_bo_reserve(rbo, false);
	if (unlikely(r != 0))
		goto out;
	radeon_bo_get_tiling_flags(rbo, &args->tiling_flags, &args->pitch);
	radeon_bo_unreserve(rbo);
out:
	drm_gem_object_put(gobj);
	return r;
}

/**
 * radeon_gem_va_update_vm -update the bo_va in its VM
 *
 * @rdev: radeon_device pointer
 * @bo_va: bo_va to update
 *
 * Update the bo_va directly after setting it's address. Errors are not
 * vital here, so they are not reported back to userspace.
 */
static void radeon_gem_va_update_vm(struct radeon_device *rdev,
				    struct radeon_bo_va *bo_va)
{
	struct radeon_bo_list *vm_bos, *entry;
	struct list_head list;
	struct drm_exec exec;
	unsigned domain;
	int r;

	INIT_LIST_HEAD(&list);

	vm_bos = radeon_vm_get_bos(rdev, bo_va->vm, &list);
	if (!vm_bos)
		return;

	drm_exec_init(&exec, DRM_EXEC_INTERRUPTIBLE_WAIT, 0);
	drm_exec_until_all_locked(&exec) {
		list_for_each_entry(entry, &list, list) {
			r = drm_exec_prepare_obj(&exec, &entry->robj->tbo.base,
						 1);
			drm_exec_retry_on_contention(&exec);
			if (unlikely(r))
				goto error_cleanup;
		}

		r = drm_exec_prepare_obj(&exec, &bo_va->bo->tbo.base, 1);
		drm_exec_retry_on_contention(&exec);
		if (unlikely(r))
			goto error_cleanup;
	}

	list_for_each_entry(entry, &list, list) {
		domain = radeon_mem_type_to_domain(entry->robj->tbo.resource->mem_type);
		/* if anything is swapped out don't swap it in here,
		   just abort and wait for the next CS */
		if (domain == RADEON_GEM_DOMAIN_CPU)
			goto error_cleanup;
	}

	mutex_lock(&bo_va->vm->mutex);
	r = radeon_vm_clear_freed(rdev, bo_va->vm);
	if (r)
		goto error_unlock;

	if (bo_va->it.start && bo_va->bo)
		r = radeon_vm_bo_update(rdev, bo_va, bo_va->bo->tbo.resource);

error_unlock:
	mutex_unlock(&bo_va->vm->mutex);

error_cleanup:
	drm_exec_fini(&exec);
	kvfree(vm_bos);

	if (r && r != -ERESTARTSYS)
		DRM_ERROR("Couldn't update BO_VA (%d)\n", r);
}

int radeon_gem_va_ioctl(struct drm_device *dev, void *data,
			  struct drm_file *filp)
{
	struct drm_radeon_gem_va *args = data;
	struct drm_gem_object *gobj;
	struct radeon_device *rdev = dev->dev_private;
	struct radeon_fpriv *fpriv = filp->driver_priv;
	struct radeon_bo *rbo;
	struct radeon_bo_va *bo_va;
	u32 invalid_flags;
	int r = 0;

	if (!rdev->vm_manager.enabled) {
		args->operation = RADEON_VA_RESULT_ERROR;
		return -ENOTTY;
	}

	/* !! DONT REMOVE !!
	 * We don't support vm_id yet, to be sure we don't have broken
	 * userspace, reject anyone trying to use non 0 value thus moving
	 * forward we can use those fields without breaking existant userspace
	 */
	if (args->vm_id) {
		args->operation = RADEON_VA_RESULT_ERROR;
		return -EINVAL;
	}

	if (args->offset < RADEON_VA_RESERVED_SIZE) {
		dev_err(dev->dev,
			"offset 0x%lX is in reserved area 0x%X\n",
			(unsigned long)args->offset,
			RADEON_VA_RESERVED_SIZE);
		args->operation = RADEON_VA_RESULT_ERROR;
		return -EINVAL;
	}

	/* don't remove, we need to enforce userspace to set the snooped flag
	 * otherwise we will endup with broken userspace and we won't be able
	 * to enable this feature without adding new interface
	 */
	invalid_flags = RADEON_VM_PAGE_VALID | RADEON_VM_PAGE_SYSTEM;
	if ((args->flags & invalid_flags)) {
		dev_err(dev->dev, "invalid flags 0x%08X vs 0x%08X\n",
			args->flags, invalid_flags);
		args->operation = RADEON_VA_RESULT_ERROR;
		return -EINVAL;
	}

	switch (args->operation) {
	case RADEON_VA_MAP:
	case RADEON_VA_UNMAP:
		break;
	default:
		dev_err(dev->dev, "unsupported operation %d\n",
			args->operation);
		args->operation = RADEON_VA_RESULT_ERROR;
		return -EINVAL;
	}

	gobj = drm_gem_object_lookup(filp, args->handle);
	if (gobj == NULL) {
		args->operation = RADEON_VA_RESULT_ERROR;
		return -ENOENT;
	}
	rbo = gem_to_radeon_bo(gobj);
	r = radeon_bo_reserve(rbo, false);
	if (r) {
		args->operation = RADEON_VA_RESULT_ERROR;
		drm_gem_object_put(gobj);
		return r;
	}
	bo_va = radeon_vm_bo_find(&fpriv->vm, rbo);
	if (!bo_va) {
		args->operation = RADEON_VA_RESULT_ERROR;
		radeon_bo_unreserve(rbo);
		drm_gem_object_put(gobj);
		return -ENOENT;
	}

	switch (args->operation) {
	case RADEON_VA_MAP:
		if (bo_va->it.start) {
			args->operation = RADEON_VA_RESULT_VA_EXIST;
			args->offset = bo_va->it.start * RADEON_GPU_PAGE_SIZE;
			radeon_bo_unreserve(rbo);
			goto out;
		}
		r = radeon_vm_bo_set_addr(rdev, bo_va, args->offset, args->flags);
		break;
	case RADEON_VA_UNMAP:
		r = radeon_vm_bo_set_addr(rdev, bo_va, 0, 0);
		break;
	default:
		break;
	}
	if (!r)
		radeon_gem_va_update_vm(rdev, bo_va);
	args->operation = RADEON_VA_RESULT_OK;
	if (r) {
		args->operation = RADEON_VA_RESULT_ERROR;
	}
out:
	drm_gem_object_put(gobj);
	return r;
}

int radeon_gem_op_ioctl(struct drm_device *dev, void *data,
			struct drm_file *filp)
{
	struct drm_radeon_gem_op *args = data;
	struct drm_gem_object *gobj;
	struct radeon_bo *robj;
	int r;

	gobj = drm_gem_object_lookup(filp, args->handle);
	if (gobj == NULL) {
		return -ENOENT;
	}
	robj = gem_to_radeon_bo(gobj);

	r = -EPERM;
	if (radeon_ttm_tt_has_userptr(robj->rdev, robj->tbo.ttm))
		goto out;

	r = radeon_bo_reserve(robj, false);
	if (unlikely(r))
		goto out;

	switch (args->op) {
	case RADEON_GEM_OP_GET_INITIAL_DOMAIN:
		args->value = robj->initial_domain;
		break;
	case RADEON_GEM_OP_SET_INITIAL_DOMAIN:
		robj->initial_domain = args->value & (RADEON_GEM_DOMAIN_VRAM |
						      RADEON_GEM_DOMAIN_GTT |
						      RADEON_GEM_DOMAIN_CPU);
		break;
	default:
		r = -EINVAL;
	}

	radeon_bo_unreserve(robj);
out:
	drm_gem_object_put(gobj);
	return r;
}

int radeon_align_pitch(struct radeon_device *rdev, int width, int cpp, bool tiled)
{
	int aligned = width;
	int align_large = (ASIC_IS_AVIVO(rdev)) || tiled;
	int pitch_mask = 0;

	switch (cpp) {
	case 1:
		pitch_mask = align_large ? 255 : 127;
		break;
	case 2:
		pitch_mask = align_large ? 127 : 31;
		break;
	case 3:
	case 4:
		pitch_mask = align_large ? 63 : 15;
		break;
	}

	aligned += pitch_mask;
	aligned &= ~pitch_mask;
	return aligned * cpp;
}

int radeon_mode_dumb_create(struct drm_file *file_priv,
			    struct drm_device *dev,
			    struct drm_mode_create_dumb *args)
{
	struct radeon_device *rdev = dev->dev_private;
	struct drm_gem_object *gobj;
	uint32_t handle;
	int r;

	args->pitch = radeon_align_pitch(rdev, args->width,
					 DIV_ROUND_UP(args->bpp, 8), 0);
	args->size = (u64)args->pitch * args->height;
	args->size = ALIGN(args->size, PAGE_SIZE);

	/* The parked-refusal check in radeon_gem_object_create observes
	 * gpu_parked, which latches under the exclusive_lock writer in
	 * radeon_gpu_reset; the read lock serializes this creator against
	 * that latch the same way the GEM create and userptr ioctls do.
	 */
	r = radeon_device_lock_hardware(rdev);
	if (r)
		return r;
	r = radeon_gem_object_create(rdev, args->size, 0,
				     RADEON_GEM_DOMAIN_VRAM, 0,
				     false, &gobj);
	radeon_device_unlock_hardware(rdev);
	/* radeon_gem_object_create returns -EIO for a parked device and
	 * -ENOMEM for exhaustion; forwarding r keeps those distinguishable
	 * at the ioctl boundary.
	 */
	if (r)
		return r;

	r = drm_gem_handle_create(file_priv, gobj, &handle);
	/* drop reference from allocate - handle holds it now */
	drm_gem_object_put(gobj);
	if (r) {
		return r;
	}
	args->handle = handle;
	return 0;
}

#if defined(CONFIG_DEBUG_FS)
static int radeon_debugfs_gem_info_show(struct seq_file *m, void *unused)
{
	struct radeon_device *rdev = m->private;
	struct radeon_bo *rbo;
	unsigned i = 0;

	mutex_lock(&rdev->gem.mutex);
	list_for_each_entry(rbo, &rdev->gem.objects, list) {
		unsigned domain;
		const char *placement;

		if (READ_ONCE(rbo->rs4xx_terminally_retained)) {
			placement = "RETAINED";
		} else if (!rbo->tbo.resource) {
			placement = "DETACHED";
		} else {
			domain = radeon_mem_type_to_domain(
				rbo->tbo.resource->mem_type);
			switch (domain) {
			case RADEON_GEM_DOMAIN_VRAM:
				placement = "VRAM";
				break;
			case RADEON_GEM_DOMAIN_GTT:
				placement = " GTT";
				break;
			case RADEON_GEM_DOMAIN_CPU:
			default:
				placement = " CPU";
				break;
			}
		}
		seq_printf(m,
			   "bo[0x%08x] id %llu %8ldkB %8ldMB %s pid %8ld\n",
			   i, (unsigned long long)rbo->debug_id,
			   radeon_bo_size(rbo) >> 10,
			   radeon_bo_size(rbo) >> 20, placement,
			   (unsigned long)rbo->pid);
		i++;
	}
	mutex_unlock(&rdev->gem.mutex);
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(radeon_debugfs_gem_info);
#endif

void radeon_gem_debugfs_init(struct radeon_device *rdev)
{
#if defined(CONFIG_DEBUG_FS)
	radeon_debugfs_add_component(rdev, "radeon_gem_info", 0444, rdev,
				     &radeon_debugfs_gem_info_fops);

#endif
}
