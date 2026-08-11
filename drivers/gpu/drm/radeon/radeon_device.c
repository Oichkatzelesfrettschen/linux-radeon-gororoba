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
#include <linux/efi.h>
#include <linux/pci.h>
#include <linux/pm_runtime.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/vga_switcheroo.h>
#include <linux/vgaarb.h>

#include <drm/drm_cache.h>
#include <drm/drm_client_event.h>
#include <drm/drm_crtc_helper.h>
#include <drm/drm_device.h>
#include <drm/drm_file.h>
#include <drm/drm_framebuffer.h>
#include <drm/drm_probe_helper.h>
#include <drm/radeon_drm.h>

#include "radeon_device.h"
#include "radeon_reg.h"
#include "radeon.h"
#include "atom.h"
#include <linux/panic_notifier.h>

static int radeon_rs4xx_hardware_state_errno(int state)
{
	switch (state) {
	case RADEON_RS4XX_HARDWARE_PARKED:
		return -EIO;
	case RADEON_RS4XX_HARDWARE_SUSPENDED:
		return -EHOSTDOWN;
	case RADEON_RS4XX_HARDWARE_SHUTTING_DOWN:
	case RADEON_RS4XX_HARDWARE_SHUTDOWN:
		return -ESHUTDOWN;
	case RADEON_RS4XX_HARDWARE_RESETTING:
	case RADEON_RS4XX_HARDWARE_SUSPENDING:
	case RADEON_RS4XX_HARDWARE_RESUMING:
		return -EBUSY;
	case RADEON_RS4XX_HARDWARE_RUNNING:
		return -EALREADY;
	default:
		return -EIO;
	}
}

static void radeon_rs4xx_queue_parked_publish(struct radeon_device *rdev)
{
	if (!radeon_rs4xx_hardware_target(rdev) ||
	    !READ_ONCE(rdev->rs4xx_parked_publish_work_initialized) ||
	    !atomic_read(&rdev->rs4xx_parked_publish_pending) ||
	    atomic_read(&rdev->rs4xx_parked_publish_running) ||
	    atomic_read(&rdev->rs4xx_hardware_transactions) != 0)
		return;
	queue_work(system_unbound_wq, &rdev->rs4xx_parked_publish_work);
}

bool radeon_rs4xx_hardware_transition_owned(struct radeon_device *rdev)
{
	return radeon_rs4xx_hardware_target(rdev) && in_task() &&
	       READ_ONCE(rdev->rs4xx_hardware_owner) == current;
}

static bool radeon_rs4xx_hardware_transition_owner_admitted(
	struct radeon_device *rdev, int state)
{
	if (READ_ONCE(rdev->gpu_parked))
		return false;

	switch (state) {
	case RADEON_RS4XX_HARDWARE_RESETTING:
	case RADEON_RS4XX_HARDWARE_SUSPENDING:
	case RADEON_RS4XX_HARDWARE_RESUMING:
	case RADEON_RS4XX_HARDWARE_SHUTTING_DOWN:
		return radeon_rs4xx_hardware_transition_owned(rdev);
	default:
		return false;
	}
}

static int radeon_rs4xx_hardware_reader_begin(struct radeon_device *rdev)
{
	int state = atomic_read_acquire(&rdev->rs4xx_hardware_state);

	if (READ_ONCE(rdev->gpu_parked))
		return -EIO;
	if (state != RADEON_RS4XX_HARDWARE_RUNNING &&
	    !radeon_rs4xx_hardware_transition_owner_admitted(rdev, state))
		return radeon_rs4xx_hardware_state_errno(state);

	atomic_inc(&rdev->rs4xx_hardware_readers);
	/* Publish the reader count before the closed-state validation. */
	smp_mb__after_atomic();
	state = atomic_read(&rdev->rs4xx_hardware_state);
	if ((likely(state == RADEON_RS4XX_HARDWARE_RUNNING) &&
	     !READ_ONCE(rdev->gpu_parked)) ||
	    radeon_rs4xx_hardware_transition_owner_admitted(rdev, state))
		return 0;

	if (atomic_dec_and_test(&rdev->rs4xx_hardware_readers))
		wake_up_all(&rdev->rs4xx_hardware_wait);
	return radeon_rs4xx_hardware_state_errno(state);
}

static void radeon_rs4xx_hardware_reader_end(struct radeon_device *rdev)
{
	if (WARN_ON_ONCE(atomic_read(&rdev->rs4xx_hardware_readers) <= 0))
		return;
	if (atomic_dec_and_test(&rdev->rs4xx_hardware_readers))
		wake_up_all(&rdev->rs4xx_hardware_wait);
}

int __radeon_rs4xx_hardware_access_begin(struct radeon_device *rdev)
{
	return radeon_rs4xx_hardware_reader_begin(rdev);
}

void __radeon_rs4xx_hardware_access_end(struct radeon_device *rdev)
{
	radeon_rs4xx_hardware_reader_end(rdev);
}

static bool radeon_rs4xx_hardware_disposition_available(
	struct radeon_device *rdev)
{
	int state = atomic_read_acquire(&rdev->rs4xx_hardware_state);

	if (READ_ONCE(rdev->gpu_parked))
		return true;
	/* SUSPENDED remains unavailable so a destructor resumes cleanup after
	 * resume instead of retaining an object for the rest of the boot.
	 */
	return (state == RADEON_RS4XX_HARDWARE_RUNNING &&
		!atomic_read_acquire(&rdev->rs4xx_hardware_closing)) ||
	       state == RADEON_RS4XX_HARDWARE_PARKED ||
	       state == RADEON_RS4XX_HARDWARE_SHUTTING_DOWN ||
	       state == RADEON_RS4XX_HARDWARE_SHUTDOWN;
}

int radeon_rs4xx_hardware_access_wait_begin(struct radeon_device *rdev)
{
	int r;

	if (!radeon_rs4xx_hardware_target(rdev))
		return 0;

	for (;;) {
		r = radeon_rs4xx_hardware_reader_begin(rdev);
		if (r != -EBUSY && r != -EHOSTDOWN)
			return r;

		/* A delayed TTM destructor waits for reset, suspend, or resume to
		 * publish a stable disposition. Shutdown returns immediately because
		 * ttm_device_fini may already wait for the same destructor.
		 */
		wait_event(rdev->rs4xx_hardware_wait,
			radeon_rs4xx_hardware_disposition_available(rdev));
	}
}

int radeon_rs4xx_hardware_transaction_begin(struct radeon_device *rdev)
{
	int state;

	if (!radeon_rs4xx_hardware_target(rdev))
		return 0;
	if (READ_ONCE(rdev->gpu_parked))
		return -EIO;
	state = atomic_read_acquire(&rdev->rs4xx_hardware_state);
	if (state != RADEON_RS4XX_HARDWARE_RUNNING &&
	    !radeon_rs4xx_hardware_transition_owner_admitted(rdev, state))
		return radeon_rs4xx_hardware_state_errno(state);
	if (state == RADEON_RS4XX_HARDWARE_RUNNING &&
	    atomic_read_acquire(&rdev->rs4xx_hardware_closing))
		return -EBUSY;

	atomic_inc(&rdev->rs4xx_hardware_transactions);
	/* The barrier publishes the transaction root before revalidation. */
	smp_mb__after_atomic();
	state = atomic_read(&rdev->rs4xx_hardware_state);
	if (radeon_rs4xx_hardware_transition_owner_admitted(rdev, state) ||
	    (state == RADEON_RS4XX_HARDWARE_RUNNING &&
	     !READ_ONCE(rdev->gpu_parked) &&
	     !atomic_read(&rdev->rs4xx_hardware_closing)))
		return 0;

	if (atomic_dec_and_test(&rdev->rs4xx_hardware_transactions)) {
		wake_up_all(&rdev->rs4xx_hardware_wait);
		radeon_rs4xx_queue_parked_publish(rdev);
	}
	if (state == RADEON_RS4XX_HARDWARE_RUNNING)
		return -EBUSY;
	return radeon_rs4xx_hardware_state_errno(state);
}

int radeon_rs4xx_hardware_transaction_wait_begin(struct radeon_device *rdev)
{
	int r;

	if (!radeon_rs4xx_hardware_target(rdev))
		return 0;

	for (;;) {
		r = radeon_rs4xx_hardware_transaction_begin(rdev);
		if (r != -EBUSY && r != -EHOSTDOWN)
			return r;

		wait_event(rdev->rs4xx_hardware_wait,
			radeon_rs4xx_hardware_disposition_available(rdev));
	}
}

int radeon_rs4xx_hardware_transaction_try_begin(struct radeon_device *rdev)
{
	return radeon_rs4xx_hardware_transaction_begin(rdev);
}

void radeon_rs4xx_hardware_transaction_end(struct radeon_device *rdev)
{
	if (!radeon_rs4xx_hardware_target(rdev))
		return;
	if (WARN_ON_ONCE(atomic_read(&rdev->rs4xx_hardware_transactions) <= 0))
		return;
	if (atomic_dec_and_test(&rdev->rs4xx_hardware_transactions)) {
		wake_up_all(&rdev->rs4xx_hardware_wait);
		radeon_rs4xx_queue_parked_publish(rdev);
	}
}

static void radeon_rs4xx_publish_parked_hardware_state_locked(
	struct radeon_device *rdev)
{
	int state = atomic_read(&rdev->rs4xx_hardware_state);

	if (state != RADEON_RS4XX_HARDWARE_PARKED &&
	    state != RADEON_RS4XX_HARDWARE_SHUTDOWN)
		atomic_set_release(&rdev->rs4xx_hardware_state,
				   RADEON_RS4XX_HARDWARE_PARKED);
}

static void radeon_rs4xx_publish_parked_hardware_state(
	struct radeon_device *rdev)
{
	unsigned long irqflags;

	spin_lock_irqsave(&rdev->rs4xx_hardware_state_lock, irqflags);
	radeon_rs4xx_publish_parked_hardware_state_locked(rdev);
	spin_unlock_irqrestore(&rdev->rs4xx_hardware_state_lock, irqflags);
}

static int radeon_rs4xx_hardware_transition_start_locked(
	struct radeon_device *rdev,
	enum radeon_rs4xx_hardware_state expected_state,
	enum radeon_rs4xx_hardware_state transition_state,
	bool terminal_shutdown)
{
	int observed_state;
	unsigned long irqflags;

	atomic_set(&rdev->rs4xx_hardware_closing, 1);
	/* Closing excludes callback-bearing transaction roots. Simple readers
	 * close at transition-state publication, and the reader counter drains
	 * every admission that preceded that publication. The full barrier pairs
	 * transition intent with the root post-increment barrier. Either the
	 * transition observes the root count or the root observes closing.
	 */
	smp_mb();
	wait_event(rdev->rs4xx_hardware_wait,
		   atomic_read(&rdev->rs4xx_hardware_transactions) == 0);
	if (!terminal_shutdown && READ_ONCE(rdev->gpu_parked)) {
		radeon_rs4xx_publish_parked_hardware_state(rdev);
		wake_up_all(&rdev->rs4xx_hardware_wait);
		smp_mb();
		wait_event(rdev->rs4xx_hardware_wait,
			   atomic_read(&rdev->rs4xx_hardware_readers) == 0);
		return -EIO;
	}

	WRITE_ONCE(rdev->rs4xx_hardware_owner, current);
	/* Publish the transition owner before the closed state becomes visible. */
	smp_wmb();
	spin_lock_irqsave(&rdev->rs4xx_hardware_state_lock, irqflags);
	if (terminal_shutdown) {
		atomic_set_release(&rdev->rs4xx_hardware_state,
				   transition_state);
	} else {
		observed_state = atomic_read(&rdev->rs4xx_hardware_state);
		if (observed_state != expected_state) {
			spin_unlock_irqrestore(
				&rdev->rs4xx_hardware_state_lock, irqflags);
			WRITE_ONCE(rdev->rs4xx_hardware_owner, NULL);
			wake_up_all(&rdev->rs4xx_hardware_wait);
			return radeon_rs4xx_hardware_state_errno(observed_state);
		}
		atomic_set_release(&rdev->rs4xx_hardware_state,
				   transition_state);
	}
	spin_unlock_irqrestore(&rdev->rs4xx_hardware_state_lock, irqflags);
	wake_up_all(&rdev->rs4xx_hardware_wait);
	/* Pair the closed-state publication with the reader's post-increment
	 * barrier before testing the active-reader count.
	 */
	smp_mb();
	wait_event(rdev->rs4xx_hardware_wait,
		   atomic_read(&rdev->rs4xx_hardware_readers) == 0);
	if (!terminal_shutdown &&
	    (READ_ONCE(rdev->gpu_parked) ||
	     atomic_read_acquire(&rdev->rs4xx_hardware_state) ==
		RADEON_RS4XX_HARDWARE_PARKED)) {
		radeon_rs4xx_publish_parked_hardware_state(rdev);
		WRITE_ONCE(rdev->rs4xx_hardware_owner, NULL);
		wake_up_all(&rdev->rs4xx_hardware_wait);
		return -EIO;
	}
	return 0;
}

int radeon_rs4xx_hardware_transition_begin(
	struct radeon_device *rdev,
	enum radeon_rs4xx_hardware_state expected_state,
	enum radeon_rs4xx_hardware_state transition_state)
{
	int state;

	if (!radeon_rs4xx_hardware_target(rdev))
		return 0;

	mutex_lock(&rdev->rs4xx_hardware_transition_lock);
	if (READ_ONCE(rdev->gpu_parked)) {
		mutex_unlock(&rdev->rs4xx_hardware_transition_lock);
		return -EIO;
	}
	state = atomic_read_acquire(&rdev->rs4xx_hardware_state);
	if (state != expected_state) {
		mutex_unlock(&rdev->rs4xx_hardware_transition_lock);
		return radeon_rs4xx_hardware_state_errno(state);
	}
	state = radeon_rs4xx_hardware_transition_start_locked(
		rdev, expected_state, transition_state, false);
	if (state) {
		mutex_unlock(&rdev->rs4xx_hardware_transition_lock);
		return state;
	}
	return 0;
}

void radeon_rs4xx_hardware_shutdown_begin(
	struct radeon_device *rdev,
	enum radeon_rs4xx_hardware_state *prior_state)
{
	int state;

	if (!radeon_rs4xx_hardware_target(rdev)) {
		if (prior_state)
			*prior_state = RADEON_RS4XX_HARDWARE_RUNNING;
		return;
	}

	mutex_lock(&rdev->rs4xx_hardware_transition_lock);
	state = atomic_read_acquire(&rdev->rs4xx_hardware_state);
	if (prior_state)
		*prior_state = state;
	WARN_ON_ONCE(radeon_rs4xx_hardware_transition_start_locked(
		rdev, state, RADEON_RS4XX_HARDWARE_SHUTTING_DOWN, true));
}

void radeon_rs4xx_hardware_transition_end(
	struct radeon_device *rdev,
	enum radeon_rs4xx_hardware_state final_state)
{
	int published_state;
	int state;
	unsigned long irqflags;

	if (!radeon_rs4xx_hardware_target(rdev))
		return;

	wait_event(rdev->rs4xx_hardware_wait,
		   atomic_read(&rdev->rs4xx_hardware_transactions) == 0 &&
		   atomic_read(&rdev->rs4xx_hardware_readers) == 0);
	WRITE_ONCE(rdev->rs4xx_hardware_owner, NULL);
	/* Clear the transition owner before publishing the terminal state. */
	smp_wmb();
	spin_lock_irqsave(&rdev->rs4xx_hardware_state_lock, irqflags);
	state = atomic_read(&rdev->rs4xx_hardware_state);
	published_state = final_state;
	if (final_state != RADEON_RS4XX_HARDWARE_SHUTDOWN &&
	    (state == RADEON_RS4XX_HARDWARE_PARKED ||
	     READ_ONCE(rdev->gpu_parked)))
		published_state = RADEON_RS4XX_HARDWARE_PARKED;
	atomic_set_release(&rdev->rs4xx_hardware_state, published_state);
	if (published_state == RADEON_RS4XX_HARDWARE_RUNNING)
		atomic_set_release(&rdev->rs4xx_hardware_closing, 0);
	else if (published_state == RADEON_RS4XX_HARDWARE_PARKED)
		atomic_set_release(&rdev->rs4xx_hardware_closing, 1);
	spin_unlock_irqrestore(&rdev->rs4xx_hardware_state_lock, irqflags);
	wake_up_all(&rdev->rs4xx_hardware_wait);
	mutex_unlock(&rdev->rs4xx_hardware_transition_lock);
}

void radeon_rs4xx_latch_parked_state(struct radeon_device *rdev)
{
	unsigned long irqflags;
	int ring_index;

	if (!radeon_rs4xx_hardware_target(rdev))
		return;

	spin_lock_irqsave(&rdev->rs4xx_hardware_state_lock, irqflags);
	WRITE_ONCE(rdev->gpu_parked, true);
	WRITE_ONCE(rdev->accel_working, false);
	WRITE_ONCE(rdev->needs_reset, false);
	for (ring_index = 0; ring_index < RADEON_NUM_RINGS; ++ring_index)
		WRITE_ONCE(rdev->ring[ring_index].ready, false);
	atomic_set_release(&rdev->rs4xx_hardware_closing, 1);
	radeon_rs4xx_publish_parked_hardware_state_locked(rdev);
	spin_unlock_irqrestore(&rdev->rs4xx_hardware_state_lock, irqflags);
	/* The full barrier pairs with each admission counter's post-increment
	 * barrier before the parked publisher tests the counters. The publisher
	 * observes an admitted caller or that caller observes the terminal state.
	 */
	smp_mb();
	wake_up_all(&rdev->rs4xx_hardware_wait);
	if (READ_ONCE(rdev->rs4xx_fence_work_initialized))
		wake_up_all(&rdev->fence_queue);
}

void radeon_rs4xx_latch_teardown_refusal(struct radeon_device *rdev)
{
	/* A void TTM callback cannot return an unbind failure to TTM. The
	 * latch closes later hardware admission. The retained BO and TTM lists
	 * keep the affected storage live while unload retains device ownership.
	 * The process-context publisher queues when the caller has no active
	 * transaction; a callback-owned transaction queues from its final release.
	 */
	radeon_rs4xx_latch_parked_state(rdev);
	atomic_xchg(&rdev->rs4xx_parked_publish_pending, 1);
	radeon_rs4xx_queue_parked_publish(rdev);
}

void radeon_rs4xx_publish_parked_state(struct radeon_device *rdev)
{
	bool transition_owned;

	if (!radeon_rs4xx_hardware_target(rdev))
		return;

	radeon_rs4xx_latch_parked_state(rdev);
	transition_owned = radeon_rs4xx_hardware_transition_owned(rdev);
	if (!transition_owned)
		mutex_lock(&rdev->rs4xx_hardware_transition_lock);
	mutex_lock(&rdev->rs4xx_parked_publish_lock);
	wait_event(rdev->rs4xx_hardware_wait,
		   atomic_read(&rdev->rs4xx_hardware_transactions) == 0 &&
		   atomic_read(&rdev->rs4xx_hardware_readers) == 0);
	(void)radeon_page_flip_quiesce(rdev);
	radeon_irq_kms_fini_hardwareless(rdev);
	if (rdev->rs4xx_pm_work_initialized)
		cancel_delayed_work_sync(&rdev->pm.dynpm_idle_work);
	if (rdev->rs4xx_fence_work_initialized)
		radeon_fence_driver_force_completion_parked(rdev);
	(void)radeon_page_flip_finalize_retained(rdev, false);
	mutex_unlock(&rdev->rs4xx_parked_publish_lock);
	if (!transition_owned)
		mutex_unlock(&rdev->rs4xx_hardware_transition_lock);
}

static void radeon_rs4xx_parked_publish_work(struct work_struct *work_item)
{
	struct radeon_device *rdev = container_of(
		work_item, struct radeon_device, rs4xx_parked_publish_work);

	if (!READ_ONCE(rdev->rs4xx_parked_publish_work_initialized)) {
		atomic_set(&rdev->rs4xx_parked_publish_pending, 0);
		return;
	}
	atomic_set(&rdev->rs4xx_parked_publish_running, 1);
	atomic_set(&rdev->rs4xx_parked_publish_pending, 0);
	radeon_rs4xx_publish_parked_state(rdev);
	/* The refusal request and worker release use fully ordered exchanges. A
	 * refusal leaves pending set for this final queue check or observes running
	 * clear and queues the next worker.
	 */
	atomic_xchg(&rdev->rs4xx_parked_publish_running, 0);
	radeon_rs4xx_queue_parked_publish(rdev);
}

/*
 * RS480/RS482 GPU-hang panic breadcrumb.
 *
 * A panic on this reset-less K8 IGP is very often a ring wedge -- the
 * hardware-TCL draw hang, or a fence that never signals -- and the kernel
 * log tail that would explain it is lost across the reboot unless something
 * captures it.  This panic notifier writes the SOFTWARE-side ring and fence
 * state into the panic log for serial or non-kdump panic paths.  Default kdump
 * jumps to the crash kernel before panic notifiers run, so the vmcore carries
 * the underlying radeon device memory; the formatted log line appears there
 * only when crash_kexec_post_notifiers is enabled at boot.
 *
 * Registration happens after radeon_init() has initialized ring and fence
 * state and before radeon_ib_ring_tests() or optional init-time GPU tests can
 * run.  Because it lives in the module, the breadcrumb does not depend on
 * kdump-load or any userspace unit.
 *
 * It reads ONLY cached driver state, never MMIO: a register read on a wedged
 * GPU would itself stall the northbridge with no completion timeout and could
 * prevent the reboot.  Registration binds to the first RS4xx IGP
 * (CHIP_RS400 or CHIP_RS480): the ring-wedge model behind the breadcrumb is
 * an RS4xx IGP finding,
 * other families keep the stock panic path, and one rdev pointer carries the
 * tracked device for the module lifetime.
 */
static struct radeon_device *radeon_rs480_panic_rdev;

static int radeon_rs480_panic_notify(struct notifier_block *nb,
				     unsigned long action, void *data)
{
	struct radeon_device *rdev = radeon_rs480_panic_rdev;
	int i;

	if (!rdev)
		return NOTIFY_DONE;

	pr_emerg("radeon: panic GPU breadcrumb (software state, no MMIO): needs_reset=%d in_reset=%d\n",
		 rdev->needs_reset, rdev->in_reset);
	for (i = 0; i < RADEON_NUM_RINGS; i++) {
		struct radeon_ring *ring = &rdev->ring[i];
		struct radeon_fence_driver *fdrv = &rdev->fence_drv[i];

		if (!ring->ready && !fdrv->initialized)
			continue;
		pr_emerg("radeon:  ring %d ready=%d wptr=%u last_rptr=%u fence last_seq=0x%llx sync_seq=0x%llx\n",
			 i, ring->ready, ring->wptr,
			 (unsigned int)atomic_read(&ring->last_rptr),
			 (unsigned long long)atomic64_read(&fdrv->last_seq),
			 (unsigned long long)fdrv->sync_seq[i]);
	}
	return NOTIFY_DONE;
}

static struct notifier_block radeon_rs480_panic_nb = {
	.notifier_call = radeon_rs480_panic_notify,
};

static void radeon_rs480_panic_register(struct radeon_device *rdev)
{
	/* Only the first RS4xx IGP (CHIP_RS400 or CHIP_RS480) arms the chain;
	 * the breadcrumb tracks it, and every other family keeps the stock
	 * panic path. */
	if (rdev->family != CHIP_RS400 && rdev->family != CHIP_RS480)
		return;
	/* cmpxchg claims the tracked-device slot for exactly one probe, so
	 * two concurrently probing RS4xx devices cannot both observe NULL
	 * and double-register the notifier.  A register failure releases
	 * the claim with the matching cmpxchg. */
	if (cmpxchg(&radeon_rs480_panic_rdev, NULL, rdev))
		return;
	if (atomic_notifier_chain_register(&panic_notifier_list,
					   &radeon_rs480_panic_nb))
		cmpxchg(&radeon_rs480_panic_rdev, rdev, NULL);
}

static void radeon_rs480_panic_unregister(struct radeon_device *rdev)
{
	/* The tracked device releases its claim before the notifier leaves
	 * the chain; a device that never held the claim returns. */
	if (cmpxchg(&radeon_rs480_panic_rdev, rdev, NULL) != rdev)
		return;
	atomic_notifier_chain_unregister(&panic_notifier_list,
					 &radeon_rs480_panic_nb);
}

static void radeon_device_fini_external_interfaces(struct radeon_device *rdev)
{
	if (rdev->switcheroo_domain_pm_initialized) {
		vga_switcheroo_fini_domain_pm_ops(rdev->dev);
		rdev->switcheroo_domain_pm_initialized = false;
	}
	if (rdev->switcheroo_client_registered) {
		vga_switcheroo_unregister_client(rdev->pdev);
		rdev->switcheroo_client_registered = false;
	}
	if (rdev->vga_client_registered) {
		vga_client_unregister(rdev->pdev);
		rdev->vga_client_registered = false;
	}
}

void radeon_rs4xx_terminal_quiesce(struct radeon_device *rdev)
{
	int state;

	if (!radeon_rs4xx_hardware_target(rdev) ||
	    rdev->rs4xx_terminal_work_quiesced)
		return;
	state = atomic_read_acquire(&rdev->rs4xx_hardware_state);
	if (WARN_ON_ONCE(state != RADEON_RS4XX_HARDWARE_SHUTDOWN &&
			 state != RADEON_RS4XX_HARDWARE_PARKED))
		return;

	/* disable_work_sync rejects queue_work attempts that race terminal
	 * quiescence and waits for queued publisher completion. The initialized
	 * flag closes the helper lifetime check after the work item reaches the
	 * idle, disabled state.
	 */
	disable_work_sync(&rdev->rs4xx_parked_publish_work);
	WRITE_ONCE(rdev->rs4xx_parked_publish_work_initialized, false);
	atomic_set(&rdev->rs4xx_parked_publish_pending, 0);
	atomic_set(&rdev->rs4xx_parked_publish_running, 0);
	WRITE_ONCE(rdev->shutdown, true);
	radeon_device_fini_external_interfaces(rdev);
	radeon_acpi_fini(rdev);
	radeon_audio_component_fini(rdev);
	cancel_delayed_work_sync(&rdev->rs4xx_flip_cleanup_work);
	radeon_irq_kms_fini_hardwareless(rdev);
	radeon_pm_fini_hardwareless(rdev);
	if (rdev->rs4xx_fence_work_initialized) {
		radeon_fence_driver_force_completion_parked(rdev);
		rdev->rs4xx_fence_work_initialized = false;
	}
	if (rdev->mode_info.mode_config_initialized) {
		if (rdev_to_drm(rdev)->mode_config.poll_enabled)
			drm_kms_helper_poll_disable(rdev_to_drm(rdev));
		(void)radeon_page_flip_quiesce(rdev);
		(void)radeon_page_flip_finalize_retained(rdev, false);
	}
	radeon_rs480_panic_unregister(rdev);
	rdev->rs4xx_terminal_work_quiesced = true;
}

static const char radeon_family_name[][16] = {
	"R100",
	"RV100",
	"RS100",
	"RV200",
	"RS200",
	"R200",
	"RV250",
	"RS300",
	"RV280",
	"R300",
	"R350",
	"RV350",
	"RV380",
	"R420",
	"R423",
	"RV410",
	"RS400",
	"RS480",
	"RS600",
	"RS690",
	"RS740",
	"RV515",
	"R520",
	"RV530",
	"RV560",
	"RV570",
	"R580",
	"R600",
	"RV610",
	"RV630",
	"RV670",
	"RV620",
	"RV635",
	"RS780",
	"RS880",
	"RV770",
	"RV730",
	"RV710",
	"RV740",
	"CEDAR",
	"REDWOOD",
	"JUNIPER",
	"CYPRESS",
	"HEMLOCK",
	"PALM",
	"SUMO",
	"SUMO2",
	"BARTS",
	"TURKS",
	"CAICOS",
	"CAYMAN",
	"ARUBA",
	"TAHITI",
	"PITCAIRN",
	"VERDE",
	"OLAND",
	"HAINAN",
	"BONAIRE",
	"KAVERI",
	"KABINI",
	"HAWAII",
	"MULLINS",
	"LAST",
};

#if defined(CONFIG_VGA_SWITCHEROO)
bool radeon_has_atpx_dgpu_power_cntl(void);
bool radeon_is_atpx_hybrid(void);
#else
static inline bool radeon_has_atpx_dgpu_power_cntl(void) { return false; }
static inline bool radeon_is_atpx_hybrid(void) { return false; }
#endif

#define RADEON_PX_QUIRK_DISABLE_PX  (1 << 0)

struct radeon_px_quirk {
	u32 chip_vendor;
	u32 chip_device;
	u32 subsys_vendor;
	u32 subsys_device;
	u32 px_quirk_flags;
};

static struct radeon_px_quirk radeon_px_quirk_list[] = {
	/* Acer aspire 5560g (CPU: AMD A4-3305M; GPU: AMD Radeon HD 6480g + 7470m)
	 * https://bugzilla.kernel.org/show_bug.cgi?id=74551
	 */
	{ PCI_VENDOR_ID_ATI, 0x6760, 0x1025, 0x0672, RADEON_PX_QUIRK_DISABLE_PX },
	/* Asus K73TA laptop with AMD A6-3400M APU and Radeon 6550 GPU
	 * https://bugzilla.kernel.org/show_bug.cgi?id=51381
	 */
	{ PCI_VENDOR_ID_ATI, 0x6741, 0x1043, 0x108c, RADEON_PX_QUIRK_DISABLE_PX },
	/* Asus K53TK laptop with AMD A6-3420M APU and Radeon 7670m GPU
	 * https://bugzilla.kernel.org/show_bug.cgi?id=51381
	 */
	{ PCI_VENDOR_ID_ATI, 0x6840, 0x1043, 0x2122, RADEON_PX_QUIRK_DISABLE_PX },
	/* Asus K53TK laptop with AMD A6-3420M APU and Radeon 7670m GPU
	 * https://bugs.freedesktop.org/show_bug.cgi?id=101491
	 */
	{ PCI_VENDOR_ID_ATI, 0x6741, 0x1043, 0x2122, RADEON_PX_QUIRK_DISABLE_PX },
	/* Asus K73TK laptop with AMD A6-3420M APU and Radeon 7670m GPU
	 * https://bugzilla.kernel.org/show_bug.cgi?id=51381#c52
	 */
	{ PCI_VENDOR_ID_ATI, 0x6840, 0x1043, 0x2123, RADEON_PX_QUIRK_DISABLE_PX },
	{ 0, 0, 0, 0, 0 },
};

bool radeon_is_px(struct drm_device *dev)
{
	struct radeon_device *rdev = dev->dev_private;

	if (rdev->flags & RADEON_IS_PX)
		return true;
	return false;
}

static void radeon_device_handle_px_quirks(struct radeon_device *rdev)
{
	struct radeon_px_quirk *p = radeon_px_quirk_list;

	/* Apply PX quirks */
	while (p && p->chip_device != 0) {
		if (rdev->pdev->vendor == p->chip_vendor &&
		    rdev->pdev->device == p->chip_device &&
		    rdev->pdev->subsystem_vendor == p->subsys_vendor &&
		    rdev->pdev->subsystem_device == p->subsys_device) {
			rdev->px_quirk_flags = p->px_quirk_flags;
			break;
		}
		++p;
	}

	if (rdev->px_quirk_flags & RADEON_PX_QUIRK_DISABLE_PX)
		rdev->flags &= ~RADEON_IS_PX;

	/* disable PX is the system doesn't support dGPU power control or hybrid gfx */
	if (!radeon_is_atpx_hybrid() &&
	    !radeon_has_atpx_dgpu_power_cntl())
		rdev->flags &= ~RADEON_IS_PX;
}

/**
 * radeon_program_register_sequence - program an array of registers.
 *
 * @rdev: radeon_device pointer
 * @registers: pointer to the register array
 * @array_size: size of the register array
 *
 * Programs an array or registers with and and or masks.
 * This is a helper for setting golden registers.
 */
void radeon_program_register_sequence(struct radeon_device *rdev,
				      const u32 *registers,
				      const u32 array_size)
{
	u32 tmp, reg, and_mask, or_mask;
	int i;

	if (array_size % 3)
		return;

	for (i = 0; i < array_size; i +=3) {
		reg = registers[i + 0];
		and_mask = registers[i + 1];
		or_mask = registers[i + 2];

		if (and_mask == 0xffffffff) {
			tmp = or_mask;
		} else {
			tmp = RREG32(reg);
			tmp &= ~and_mask;
			tmp |= or_mask;
		}
		WREG32(reg, tmp);
	}
}

void radeon_pci_config_reset(struct radeon_device *rdev)
{
	pci_write_config_dword(rdev->pdev, 0x7c, RADEON_ASIC_RESET_DATA);
}

/**
 * radeon_surface_init - Clear GPU surface registers.
 *
 * @rdev: radeon_device pointer
 *
 * Clear GPU surface registers (r1xx-r5xx).
 */
void radeon_surface_init(struct radeon_device *rdev)
{
	/* FIXME: check this out */
	if (rdev->family < CHIP_R600) {
		int i;

		for (i = 0; i < RADEON_GEM_MAX_SURFACES; i++) {
			if (rdev->surface_regs[i].bo)
				radeon_bo_get_surface_reg(rdev->surface_regs[i].bo);
			else
				radeon_clear_surface_reg(rdev, i);
		}
		/* enable surfaces */
		WREG32(RADEON_SURFACE_CNTL, 0);
	}
}

/*
 * GPU scratch registers helpers function.
 */
/**
 * radeon_scratch_init - Init scratch register driver information.
 *
 * @rdev: radeon_device pointer
 *
 * Init CP scratch register driver information (r1xx-r5xx)
 */
void radeon_scratch_init(struct radeon_device *rdev)
{
	int i;

	/* FIXME: check this out */
	if (rdev->family < CHIP_R300) {
		rdev->scratch.num_reg = 5;
	} else {
		rdev->scratch.num_reg = 7;
	}
	rdev->scratch.reg_base = RADEON_SCRATCH_REG0;
	for (i = 0; i < rdev->scratch.num_reg; i++) {
		rdev->scratch.free[i] = true;
		rdev->scratch.reg[i] = rdev->scratch.reg_base + (i * 4);
	}
}

/**
 * radeon_scratch_get - Allocate a scratch register
 *
 * @rdev: radeon_device pointer
 * @reg: scratch register mmio offset
 *
 * Allocate a CP scratch register for use by the driver (all asics).
 * Returns 0 on success or -EINVAL on failure.
 */
int radeon_scratch_get(struct radeon_device *rdev, uint32_t *reg)
{
	int i;

	for (i = 0; i < rdev->scratch.num_reg; i++) {
		if (rdev->scratch.free[i]) {
			rdev->scratch.free[i] = false;
			*reg = rdev->scratch.reg[i];
			return 0;
		}
	}
	return -EINVAL;
}

/**
 * radeon_scratch_free - Free a scratch register
 *
 * @rdev: radeon_device pointer
 * @reg: scratch register mmio offset
 *
 * Free a CP scratch register allocated for use by the driver (all asics)
 */
void radeon_scratch_free(struct radeon_device *rdev, uint32_t reg)
{
	int i;

	for (i = 0; i < rdev->scratch.num_reg; i++) {
		if (rdev->scratch.reg[i] == reg) {
			rdev->scratch.free[i] = true;
			return;
		}
	}
}

/*
 * GPU doorbell aperture helpers function.
 */
/**
 * radeon_doorbell_init - Init doorbell driver information.
 *
 * @rdev: radeon_device pointer
 *
 * Init doorbell driver information (CIK)
 * Returns 0 on success, error on failure.
 */
static int radeon_doorbell_init(struct radeon_device *rdev)
{
	/* doorbell bar mapping */
	rdev->doorbell.base = pci_resource_start(rdev->pdev, 2);
	rdev->doorbell.size = pci_resource_len(rdev->pdev, 2);

	rdev->doorbell.num_doorbells = min_t(u32, rdev->doorbell.size / sizeof(u32), RADEON_MAX_DOORBELLS);
	if (rdev->doorbell.num_doorbells == 0)
		return -EINVAL;

	rdev->doorbell.ptr = ioremap(rdev->doorbell.base, rdev->doorbell.num_doorbells * sizeof(u32));
	if (rdev->doorbell.ptr == NULL) {
		return -ENOMEM;
	}
	DRM_INFO("doorbell mmio base: 0x%08X\n", (uint32_t)rdev->doorbell.base);
	DRM_INFO("doorbell mmio size: %u\n", (unsigned)rdev->doorbell.size);

	memset(&rdev->doorbell.used, 0, sizeof(rdev->doorbell.used));

	return 0;
}

/**
 * radeon_doorbell_fini - Tear down doorbell driver information.
 *
 * @rdev: radeon_device pointer
 *
 * Tear down doorbell driver information (CIK)
 */
static void radeon_doorbell_fini(struct radeon_device *rdev)
{
	iounmap(rdev->doorbell.ptr);
	rdev->doorbell.ptr = NULL;
}

/**
 * radeon_doorbell_get - Allocate a doorbell entry
 *
 * @rdev: radeon_device pointer
 * @doorbell: doorbell index
 *
 * Allocate a doorbell for use by the driver (all asics).
 * Returns 0 on success or -EINVAL on failure.
 */
int radeon_doorbell_get(struct radeon_device *rdev, u32 *doorbell)
{
	unsigned long offset = find_first_zero_bit(rdev->doorbell.used, rdev->doorbell.num_doorbells);
	if (offset < rdev->doorbell.num_doorbells) {
		__set_bit(offset, rdev->doorbell.used);
		*doorbell = offset;
		return 0;
	} else {
		return -EINVAL;
	}
}

/**
 * radeon_doorbell_free - Free a doorbell entry
 *
 * @rdev: radeon_device pointer
 * @doorbell: doorbell index
 *
 * Free a doorbell allocated for use by the driver (all asics)
 */
void radeon_doorbell_free(struct radeon_device *rdev, u32 doorbell)
{
	if (doorbell < rdev->doorbell.num_doorbells)
		__clear_bit(doorbell, rdev->doorbell.used);
}

/*
 * radeon_wb_*()
 * Writeback is the method by which the GPU updates special pages
 * in memory with the status of certain GPU events (fences, ring pointers,
 * etc.).
 */

/**
 * radeon_wb_disable - Disable Writeback
 *
 * @rdev: radeon_device pointer
 *
 * Disables Writeback (all asics).  Used for suspend.
 */
void radeon_wb_disable(struct radeon_device *rdev)
{
	rdev->wb.enabled = false;
}

/**
 * radeon_wb_fini - Disable Writeback and free memory
 *
 * @rdev: radeon_device pointer
 *
 * Disables Writeback and frees the Writeback memory (all asics).
 * Used at driver shutdown.
 */
void radeon_wb_fini(struct radeon_device *rdev)
{
	radeon_wb_disable(rdev);
	if (rdev->wb.wb_obj) {
		if (!radeon_bo_reserve(rdev->wb.wb_obj, false)) {
			radeon_bo_kunmap(rdev->wb.wb_obj);
			radeon_bo_unpin(rdev->wb.wb_obj);
			radeon_bo_unreserve(rdev->wb.wb_obj);
		}
		radeon_bo_unref(&rdev->wb.wb_obj);
		rdev->wb.wb = NULL;
		rdev->wb.wb_obj = NULL;
	}
}

/**
 * radeon_wb_init- Init Writeback driver info and allocate memory
 *
 * @rdev: radeon_device pointer
 *
 * Disables Writeback and frees the Writeback memory (all asics).
 * Used at driver startup.
 * Returns 0 on success or an -error on failure.
 */
int radeon_wb_init(struct radeon_device *rdev)
{
	int r;

	if (rdev->wb.wb_obj == NULL) {
		r = radeon_bo_create(rdev, RADEON_GPU_PAGE_SIZE, PAGE_SIZE, true,
				     RADEON_GEM_DOMAIN_GTT, 0, NULL, NULL,
				     &rdev->wb.wb_obj);
		if (r) {
			dev_warn(rdev->dev, "(%d) create WB bo failed\n", r);
			return r;
		}
		r = radeon_bo_reserve(rdev->wb.wb_obj, false);
		if (unlikely(r != 0)) {
			radeon_wb_fini(rdev);
			return r;
		}
		r = radeon_bo_pin(rdev->wb.wb_obj, RADEON_GEM_DOMAIN_GTT,
				&rdev->wb.gpu_addr);
		if (r) {
			radeon_bo_unreserve(rdev->wb.wb_obj);
			dev_warn(rdev->dev, "(%d) pin WB bo failed\n", r);
			radeon_wb_fini(rdev);
			return r;
		}
		r = radeon_bo_kmap(rdev->wb.wb_obj, (void **)&rdev->wb.wb);
		radeon_bo_unreserve(rdev->wb.wb_obj);
		if (r) {
			dev_warn(rdev->dev, "(%d) map WB bo failed\n", r);
			radeon_wb_fini(rdev);
			return r;
		}
	}

	/* clear wb memory */
	memset((char *)rdev->wb.wb, 0, RADEON_GPU_PAGE_SIZE);
	/* disable event_write fences */
	rdev->wb.use_event = false;
	/* disabled via module param */
	if (radeon_no_wb == 1) {
		rdev->wb.enabled = false;
	} else {
		if (rdev->flags & RADEON_IS_AGP) {
			/* often unreliable on AGP */
			rdev->wb.enabled = false;
		} else if (rdev->family < CHIP_R300) {
			/* often unreliable on pre-r300 */
			rdev->wb.enabled = false;
		} else {
			rdev->wb.enabled = true;
			/* event_write fences are only available on r600+ */
			if (rdev->family >= CHIP_R600) {
				rdev->wb.use_event = true;
			}
		}
	}
	/* always use writeback/events on NI, APUs */
	if (rdev->family >= CHIP_PALM) {
		rdev->wb.enabled = true;
		rdev->wb.use_event = true;
	}

	dev_info(rdev->dev, "WB %sabled\n", rdev->wb.enabled ? "en" : "dis");

	return 0;
}

/**
 * radeon_vram_location - try to find VRAM location
 * @rdev: radeon device structure holding all necessary informations
 * @mc: memory controller structure holding memory informations
 * @base: base address at which to put VRAM
 *
 * Function will try to place VRAM at base address provided
 * as parameter (which is so far either PCI aperture address or
 * for IGP TOM base address).
 *
 * If there is not enough space to fit the unvisible VRAM in the 32bits
 * address space then we limit the VRAM size to the aperture.
 *
 * If we are using AGP and if the AGP aperture doesn't allow us to have
 * room for all the VRAM than we restrict the VRAM to the PCI aperture
 * size and print a warning.
 *
 * This function will never fails, worst case are limiting VRAM.
 *
 * Note: GTT start, end, size should be initialized before calling this
 * function on AGP platform.
 *
 * Note 1: We don't explicitly enforce VRAM start to be aligned on VRAM size,
 * this shouldn't be a problem as we are using the PCI aperture as a reference.
 * Otherwise this would be needed for rv280, all r3xx, and all r4xx, but
 * not IGP.
 *
 * Note 2: we use mc_vram_size as on some board we need to program the mc to
 * cover the whole aperture even if VRAM size is inferior to aperture size
 * Novell bug 204882 + along with lots of ubuntu ones
 *
 * Note 3: when limiting vram it's safe to overwrite real_vram_size because
 * we are not in case where real_vram_size is inferior to mc_vram_size (ie
 * not affected by bogus hw of Novell bug 204882 + along with lots of ubuntu
 * ones)
 *
 * Note 4: IGP TOM addr should be the same as the aperture addr, we don't
 * explicitly check for that thought.
 *
 * FIXME: when reducing VRAM size, align new size on power of 2.
 */
void radeon_vram_location(struct radeon_device *rdev, struct radeon_mc *mc, u64 base)
{
	uint64_t limit = (uint64_t)radeon_vram_limit << 20;

	mc->vram_start = base;
	if (mc->mc_vram_size > (rdev->mc.mc_mask - base + 1)) {
		dev_warn(rdev->dev, "limiting VRAM to PCI aperture size\n");
		mc->real_vram_size = mc->aper_size;
		mc->mc_vram_size = mc->aper_size;
	}
	mc->vram_end = mc->vram_start + mc->mc_vram_size - 1;
	if (rdev->flags & RADEON_IS_AGP && mc->vram_end > mc->gtt_start && mc->vram_start <= mc->gtt_end) {
		dev_warn(rdev->dev, "limiting VRAM to PCI aperture size\n");
		mc->real_vram_size = mc->aper_size;
		mc->mc_vram_size = mc->aper_size;
	}
	mc->vram_end = mc->vram_start + mc->mc_vram_size - 1;
	if (limit && limit < mc->real_vram_size)
		mc->real_vram_size = limit;
	dev_info(rdev->dev, "VRAM: %lluM 0x%016llX - 0x%016llX (%lluM used)\n",
			mc->mc_vram_size >> 20, mc->vram_start,
			mc->vram_end, mc->real_vram_size >> 20);
}

/**
 * radeon_gtt_location - try to find GTT location
 * @rdev: radeon device structure holding all necessary informations
 * @mc: memory controller structure holding memory informations
 *
 * Function will try to place GTT before or after VRAM.
 *
 * If GTT size is bigger than space left then we ajust GTT size.
 * Thus function will never fails.
 *
 * FIXME: when reducing GTT size align new size on power of 2.
 */
void radeon_gtt_location(struct radeon_device *rdev, struct radeon_mc *mc)
{
	u64 size_af, size_bf;

	size_af = ((rdev->mc.mc_mask - mc->vram_end) + mc->gtt_base_align) & ~mc->gtt_base_align;
	size_bf = mc->vram_start & ~mc->gtt_base_align;
	if (size_bf > size_af) {
		if (mc->gtt_size > size_bf) {
			dev_warn(rdev->dev, "limiting GTT\n");
			mc->gtt_size = size_bf;
		}
		mc->gtt_start = (mc->vram_start & ~mc->gtt_base_align) - mc->gtt_size;
	} else {
		if (mc->gtt_size > size_af) {
			dev_warn(rdev->dev, "limiting GTT\n");
			mc->gtt_size = size_af;
		}
		mc->gtt_start = (mc->vram_end + 1 + mc->gtt_base_align) & ~mc->gtt_base_align;
	}
	mc->gtt_end = mc->gtt_start + mc->gtt_size - 1;
	dev_info(rdev->dev, "GTT: %lluM 0x%016llX - 0x%016llX\n",
			mc->gtt_size >> 20, mc->gtt_start, mc->gtt_end);
}

/*
 * GPU helpers function.
 */

/*
 * radeon_device_is_virtual - check if we are running is a virtual environment
 *
 * Check if the asic has been passed through to a VM (all asics).
 * Used at driver startup.
 * Returns true if virtual or false if not.
 */
bool radeon_device_is_virtual(void)
{
#ifdef CONFIG_X86
	return boot_cpu_has(X86_FEATURE_HYPERVISOR);
#else
	return false;
#endif
}

/**
 * radeon_card_posted - check if the hw has already been initialized
 *
 * @rdev: radeon_device pointer
 *
 * Check if the asic has been initialized (all asics).
 * Used at driver startup.
 * Returns true if initialized or false if not.
 */
bool radeon_card_posted(struct radeon_device *rdev)
{
	uint32_t reg;

	/* for pass through, always force asic_init for CI */
	if (rdev->family >= CHIP_BONAIRE &&
	    radeon_device_is_virtual())
		return false;

	/* required for EFI mode on macbook2,1 which uses an r5xx asic */
	if (efi_enabled(EFI_BOOT) &&
	    (rdev->pdev->subsystem_vendor == PCI_VENDOR_ID_APPLE) &&
	    (rdev->family < CHIP_R600))
		return false;

	if (ASIC_IS_NODCE(rdev))
		goto check_memsize;

	/* first check CRTCs */
	if (ASIC_IS_DCE4(rdev)) {
		reg = RREG32(EVERGREEN_CRTC_CONTROL + EVERGREEN_CRTC0_REGISTER_OFFSET) |
			RREG32(EVERGREEN_CRTC_CONTROL + EVERGREEN_CRTC1_REGISTER_OFFSET);
			if (rdev->num_crtc >= 4) {
				reg |= RREG32(EVERGREEN_CRTC_CONTROL + EVERGREEN_CRTC2_REGISTER_OFFSET) |
					RREG32(EVERGREEN_CRTC_CONTROL + EVERGREEN_CRTC3_REGISTER_OFFSET);
			}
			if (rdev->num_crtc >= 6) {
				reg |= RREG32(EVERGREEN_CRTC_CONTROL + EVERGREEN_CRTC4_REGISTER_OFFSET) |
					RREG32(EVERGREEN_CRTC_CONTROL + EVERGREEN_CRTC5_REGISTER_OFFSET);
			}
		if (reg & EVERGREEN_CRTC_MASTER_EN)
			return true;
	} else if (ASIC_IS_AVIVO(rdev)) {
		reg = RREG32(AVIVO_D1CRTC_CONTROL) |
		      RREG32(AVIVO_D2CRTC_CONTROL);
		if (reg & AVIVO_CRTC_EN) {
			return true;
		}
	} else {
		reg = RREG32(RADEON_CRTC_GEN_CNTL) |
		      RREG32(RADEON_CRTC2_GEN_CNTL);
		if (reg & RADEON_CRTC_EN) {
			return true;
		}
	}

check_memsize:
	/* then check MEM_SIZE, in case the crtcs are off */
	if (rdev->family >= CHIP_R600)
		reg = RREG32(R600_CONFIG_MEMSIZE);
	else
		reg = RREG32(RADEON_CONFIG_MEMSIZE);

	if (reg)
		return true;

	return false;

}

/**
 * radeon_update_bandwidth_info - update display bandwidth params
 *
 * @rdev: radeon_device pointer
 *
 * Used when sclk/mclk are switched or display modes are set.
 * params are used to calculate display watermarks (all asics)
 */
void radeon_update_bandwidth_info(struct radeon_device *rdev)
{
	fixed20_12 a;
	u32 sclk = rdev->pm.current_sclk;
	u32 mclk = rdev->pm.current_mclk;

	/* sclk/mclk in Mhz */
	a.full = dfixed_const(100);
	rdev->pm.sclk.full = dfixed_const(sclk);
	rdev->pm.sclk.full = dfixed_div(rdev->pm.sclk, a);
	rdev->pm.mclk.full = dfixed_const(mclk);
	rdev->pm.mclk.full = dfixed_div(rdev->pm.mclk, a);

	if (rdev->flags & RADEON_IS_IGP) {
		a.full = dfixed_const(16);
		/* core_bandwidth = sclk(Mhz) * 16 */
		rdev->pm.core_bandwidth.full = dfixed_div(rdev->pm.sclk, a);
	}
}

/**
 * radeon_boot_test_post_card - check and possibly initialize the hw
 *
 * @rdev: radeon_device pointer
 *
 * Check if the asic is initialized and if not, attempt to initialize
 * it (all asics).
 * Returns true if initialized or false if not.
 */
bool radeon_boot_test_post_card(struct radeon_device *rdev)
{
	if (radeon_card_posted(rdev))
		return true;

	if (rdev->bios) {
		DRM_INFO("GPU not posted. posting now...\n");
		if (rdev->is_atom_bios)
			atom_asic_init(rdev->mode_info.atom_context);
		else if (radeon_combios_asic_init(rdev_to_drm(rdev)))
			return false;
		return true;
	} else {
		dev_err(rdev->dev, "Card not posted and no BIOS - ignoring\n");
		return false;
	}
}

/**
 * radeon_dummy_page_init - init dummy page used by the driver
 *
 * @rdev: radeon_device pointer
 *
 * Allocate the dummy page used by the driver (all asics).
 * This dummy page is used by the driver as a filler for gart entries
 * when pages are taken out of the GART
 * Returns 0 on sucess, -ENOMEM on failure.
 */
int radeon_dummy_page_init(struct radeon_device *rdev)
{
	if (rdev->dummy_page.page)
		return 0;
	rdev->dummy_page.page = alloc_page(GFP_DMA32 | GFP_KERNEL | __GFP_ZERO);
	if (rdev->dummy_page.page == NULL)
		return -ENOMEM;
	rdev->dummy_page.addr = dma_map_page(&rdev->pdev->dev, rdev->dummy_page.page,
					0, PAGE_SIZE, DMA_BIDIRECTIONAL);
	if (dma_mapping_error(&rdev->pdev->dev, rdev->dummy_page.addr)) {
		dev_err(&rdev->pdev->dev, "Failed to DMA MAP the dummy page\n");
		__free_page(rdev->dummy_page.page);
		rdev->dummy_page.page = NULL;
		return -ENOMEM;
	}
	rdev->dummy_page.entry = radeon_gart_get_page_entry(rdev->dummy_page.addr,
							    RADEON_GART_PAGE_DUMMY);
	return 0;
}

/**
 * radeon_dummy_page_fini - free dummy page used by the driver
 *
 * @rdev: radeon_device pointer
 *
 * Frees the dummy page used by the driver (all asics).
 */
void radeon_dummy_page_fini(struct radeon_device *rdev)
{
	if (rdev->dummy_page.page == NULL)
		return;
	dma_unmap_page(&rdev->pdev->dev, rdev->dummy_page.addr, PAGE_SIZE,
		       DMA_BIDIRECTIONAL);
	__free_page(rdev->dummy_page.page);
	rdev->dummy_page.page = NULL;
}


/* ATOM accessor methods */
/*
 * ATOM is an interpreted byte code stored in tables in the vbios.  The
 * driver registers callbacks to access registers and the interpreter
 * in the driver parses the tables and executes then to program specific
 * actions (set display modes, asic init, etc.).  See radeon_atombios.c,
 * atombios.h, and atom.c
 */

/**
 * cail_pll_read - read PLL register
 *
 * @info: atom card_info pointer
 * @reg: PLL register offset
 *
 * Provides a PLL register accessor for the atom interpreter (r4xx+).
 * Returns the value of the PLL register.
 */
static uint32_t cail_pll_read(struct card_info *info, uint32_t reg)
{
	struct radeon_device *rdev = info->dev->dev_private;
	uint32_t r;

	r = rdev->pll_rreg(rdev, reg);
	return r;
}

/**
 * cail_pll_write - write PLL register
 *
 * @info: atom card_info pointer
 * @reg: PLL register offset
 * @val: value to write to the pll register
 *
 * Provides a PLL register accessor for the atom interpreter (r4xx+).
 */
static void cail_pll_write(struct card_info *info, uint32_t reg, uint32_t val)
{
	struct radeon_device *rdev = info->dev->dev_private;

	rdev->pll_wreg(rdev, reg, val);
}

/**
 * cail_mc_read - read MC (Memory Controller) register
 *
 * @info: atom card_info pointer
 * @reg: MC register offset
 *
 * Provides an MC register accessor for the atom interpreter (r4xx+).
 * Returns the value of the MC register.
 */
static uint32_t cail_mc_read(struct card_info *info, uint32_t reg)
{
	struct radeon_device *rdev = info->dev->dev_private;
	uint32_t r;

	r = rdev->mc_rreg(rdev, reg);
	return r;
}

/**
 * cail_mc_write - write MC (Memory Controller) register
 *
 * @info: atom card_info pointer
 * @reg: MC register offset
 * @val: value to write to the pll register
 *
 * Provides a MC register accessor for the atom interpreter (r4xx+).
 */
static void cail_mc_write(struct card_info *info, uint32_t reg, uint32_t val)
{
	struct radeon_device *rdev = info->dev->dev_private;

	rdev->mc_wreg(rdev, reg, val);
}

/**
 * cail_reg_write - write MMIO register
 *
 * @info: atom card_info pointer
 * @reg: MMIO register offset
 * @val: value to write to the pll register
 *
 * Provides a MMIO register accessor for the atom interpreter (r4xx+).
 */
static void cail_reg_write(struct card_info *info, uint32_t reg, uint32_t val)
{
	struct radeon_device *rdev = info->dev->dev_private;

	WREG32(reg*4, val);
}

/**
 * cail_reg_read - read MMIO register
 *
 * @info: atom card_info pointer
 * @reg: MMIO register offset
 *
 * Provides an MMIO register accessor for the atom interpreter (r4xx+).
 * Returns the value of the MMIO register.
 */
static uint32_t cail_reg_read(struct card_info *info, uint32_t reg)
{
	struct radeon_device *rdev = info->dev->dev_private;
	uint32_t r;

	r = RREG32(reg*4);
	return r;
}

/**
 * cail_ioreg_write - write IO register
 *
 * @info: atom card_info pointer
 * @reg: IO register offset
 * @val: value to write to the pll register
 *
 * Provides a IO register accessor for the atom interpreter (r4xx+).
 */
static void cail_ioreg_write(struct card_info *info, uint32_t reg, uint32_t val)
{
	struct radeon_device *rdev = info->dev->dev_private;

	WREG32_IO(reg*4, val);
}

/**
 * cail_ioreg_read - read IO register
 *
 * @info: atom card_info pointer
 * @reg: IO register offset
 *
 * Provides an IO register accessor for the atom interpreter (r4xx+).
 * Returns the value of the IO register.
 */
static uint32_t cail_ioreg_read(struct card_info *info, uint32_t reg)
{
	struct radeon_device *rdev = info->dev->dev_private;
	uint32_t r;

	r = RREG32_IO(reg*4);
	return r;
}

/**
 * radeon_atombios_init - init the driver info and callbacks for atombios
 *
 * @rdev: radeon_device pointer
 *
 * Initializes the driver info and register access callbacks for the
 * ATOM interpreter (r4xx+).
 * Returns 0 on sucess, -ENOMEM on failure.
 * Called at driver startup.
 */
int radeon_atombios_init(struct radeon_device *rdev)
{
	struct card_info *atom_card_info =
	    kzalloc(sizeof(struct card_info), GFP_KERNEL);

	if (!atom_card_info)
		return -ENOMEM;

	rdev->mode_info.atom_card_info = atom_card_info;
	atom_card_info->dev = rdev_to_drm(rdev);
	atom_card_info->reg_read = cail_reg_read;
	atom_card_info->reg_write = cail_reg_write;
	/* needed for iio ops */
	if (rdev->rio_mem) {
		atom_card_info->ioreg_read = cail_ioreg_read;
		atom_card_info->ioreg_write = cail_ioreg_write;
	} else {
		DRM_ERROR("Unable to find PCI I/O BAR; using MMIO for ATOM IIO\n");
		atom_card_info->ioreg_read = cail_reg_read;
		atom_card_info->ioreg_write = cail_reg_write;
	}
	atom_card_info->mc_read = cail_mc_read;
	atom_card_info->mc_write = cail_mc_write;
	atom_card_info->pll_read = cail_pll_read;
	atom_card_info->pll_write = cail_pll_write;

	rdev->mode_info.atom_context = atom_parse(atom_card_info, rdev->bios);
	if (!rdev->mode_info.atom_context) {
		radeon_atombios_fini(rdev);
		return -ENOMEM;
	}

	mutex_init(&rdev->mode_info.atom_context->mutex);
	mutex_init(&rdev->mode_info.atom_context->scratch_mutex);
	radeon_atom_initialize_bios_scratch_regs(rdev_to_drm(rdev));
	atom_allocate_fb_scratch(rdev->mode_info.atom_context);
	return 0;
}

/**
 * radeon_atombios_fini - free the driver info and callbacks for atombios
 *
 * @rdev: radeon_device pointer
 *
 * Frees the driver info and register access callbacks for the ATOM
 * interpreter (r4xx+).
 * Called at driver shutdown.
 */
void radeon_atombios_fini(struct radeon_device *rdev)
{
	if (rdev->mode_info.atom_context) {
		kfree(rdev->mode_info.atom_context->scratch);
		kfree(rdev->mode_info.atom_context->iio);
	}
	kfree(rdev->mode_info.atom_context);
	rdev->mode_info.atom_context = NULL;
	kfree(rdev->mode_info.atom_card_info);
	rdev->mode_info.atom_card_info = NULL;
}

/* COMBIOS */
/*
 * COMBIOS is the bios format prior to ATOM. It provides
 * command tables similar to ATOM, but doesn't have a unified
 * parser.  See radeon_combios.c
 */

/**
 * radeon_combios_init - init the driver info for combios
 *
 * @rdev: radeon_device pointer
 *
 * Initializes the driver info for combios (r1xx-r3xx).
 * Returns 0 on sucess.
 * Called at driver startup.
 */
int radeon_combios_init(struct radeon_device *rdev)
{
	radeon_combios_initialize_bios_scratch_regs(rdev_to_drm(rdev));
	return 0;
}

/**
 * radeon_combios_fini - free the driver info for combios
 *
 * @rdev: radeon_device pointer
 *
 * Frees the driver info for combios (r1xx-r3xx).
 * Called at driver shutdown.
 */
void radeon_combios_fini(struct radeon_device *rdev)
{
}

/* if we get transitioned to only one device, take VGA back */
/**
 * radeon_vga_set_decode - enable/disable vga decode
 *
 * @pdev: PCI device
 * @state: enable/disable vga decode
 *
 * Enable/disable vga decode (all asics).
 * Returns VGA resource flags.
 */
static unsigned int radeon_vga_set_decode(struct pci_dev *pdev, bool state)
{
	struct drm_device *dev = pci_get_drvdata(pdev);
	struct radeon_device *rdev;
	unsigned int resources = VGA_RSRC_NORMAL_IO | VGA_RSRC_NORMAL_MEM;
	int r;

	if (!dev || !dev->dev_private)
		return resources;
	rdev = dev->dev_private;
	r = radeon_rs4xx_hardware_access_begin(rdev);
	if (r)
		return resources;
	radeon_vga_set_state(rdev, state);
	radeon_rs4xx_hardware_access_end(rdev);
	if (state)
		resources |= VGA_RSRC_LEGACY_IO | VGA_RSRC_LEGACY_MEM;
	return resources;
}

/**
 * radeon_gart_size_auto - Determine a sensible default GART size
 *                         according to ASIC family.
 *
 * @family: ASIC family name
 */
static int radeon_gart_size_auto(enum radeon_family family)
{
	/* default to a larger gart size on newer asics */
	if (family >= CHIP_TAHITI)
		return 2048;
	else if (family >= CHIP_RV770)
		return 1024;
	else
		return 512;
}

/**
 * radeon_check_arguments - validate module params
 *
 * @rdev: radeon_device pointer
 *
 * Validates certain module parameters and updates
 * the associated values used by the driver (all asics).
 */
static void radeon_check_arguments(struct radeon_device *rdev)
{
	/* vramlimit must be a power of two */
	if (radeon_vram_limit != 0 && !is_power_of_2(radeon_vram_limit)) {
		dev_warn(rdev->dev, "vram limit (%d) must be a power of 2\n",
				radeon_vram_limit);
		radeon_vram_limit = 0;
	}

	if (radeon_gart_size == -1) {
		radeon_gart_size = radeon_gart_size_auto(rdev->family);
	}
	/* gtt size must be power of two and greater or equal to 32M */
	if (radeon_gart_size < 32) {
		dev_warn(rdev->dev, "gart size (%d) too small\n",
				radeon_gart_size);
		radeon_gart_size = radeon_gart_size_auto(rdev->family);
	} else if (!is_power_of_2(radeon_gart_size)) {
		dev_warn(rdev->dev, "gart size (%d) must be a power of 2\n",
				radeon_gart_size);
		radeon_gart_size = radeon_gart_size_auto(rdev->family);
	}
	rdev->mc.gtt_size = (uint64_t)radeon_gart_size << 20;

	/* AGP mode can only be -1, 1, 2, 4, 8 */
	switch (radeon_agpmode) {
	case -1:
	case 0:
	case 1:
	case 2:
	case 4:
	case 8:
		break;
	default:
		dev_warn(rdev->dev, "invalid AGP mode %d (valid mode: "
				"-1, 0, 1, 2, 4, 8)\n", radeon_agpmode);
		radeon_agpmode = 0;
		break;
	}

	if (!is_power_of_2(radeon_vm_size)) {
		dev_warn(rdev->dev, "VM size (%d) must be a power of 2\n",
			 radeon_vm_size);
		radeon_vm_size = 4;
	}

	if (radeon_vm_size < 1) {
		dev_warn(rdev->dev, "VM size (%d) too small, min is 1GB\n",
			 radeon_vm_size);
		radeon_vm_size = 4;
	}

	/*
	 * Max GPUVM size for Cayman, SI and CI are 40 bits.
	 */
	if (radeon_vm_size > 1024) {
		dev_warn(rdev->dev, "VM size (%d) too large, max is 1TB\n",
			 radeon_vm_size);
		radeon_vm_size = 4;
	}

	/* defines number of bits in page table versus page directory,
	 * a page is 4KB so we have 12 bits offset, minimum 9 bits in the
	 * page table and the remaining bits are in the page directory */
	if (radeon_vm_block_size == -1) {

		/* Total bits covered by PD + PTs */
		unsigned bits = ilog2(radeon_vm_size) + 18;

		/* Make sure the PD is 4K in size up to 8GB address space.
		   Above that split equal between PD and PTs */
		if (radeon_vm_size <= 8)
			radeon_vm_block_size = bits - 9;
		else
			radeon_vm_block_size = (bits + 3) / 2;

	} else if (radeon_vm_block_size < 9) {
		dev_warn(rdev->dev, "VM page table size (%d) too small\n",
			 radeon_vm_block_size);
		radeon_vm_block_size = 9;
	}

	if (radeon_vm_block_size > 24 ||
	    (radeon_vm_size * 1024) < (1ull << radeon_vm_block_size)) {
		dev_warn(rdev->dev, "VM page table size (%d) too large\n",
			 radeon_vm_block_size);
		radeon_vm_block_size = 9;
	}
}

/**
 * radeon_switcheroo_set_state - set switcheroo state
 *
 * @pdev: pci dev pointer
 * @state: vga_switcheroo state
 *
 * Callback for the switcheroo driver.  Suspends or resumes
 * the asics before or after it is powered up using ACPI methods.
 */
static void radeon_switcheroo_set_state(struct pci_dev *pdev, enum vga_switcheroo_state state)
{
	struct drm_device *dev = pci_get_drvdata(pdev);
	int r;

	if (radeon_is_px(dev) && state == VGA_SWITCHEROO_OFF)
		return;

	if (state == VGA_SWITCHEROO_ON) {
		/* don't suspend or resume card normally */
		dev->switch_power_state = DRM_SWITCH_POWER_CHANGING;

		r = radeon_resume_kms(dev, true, true);
		if (r) {
			dev_err(&pdev->dev,
				"GPU resume failed; switcheroo state remains off: %d\n",
				r);
			dev->switch_power_state = DRM_SWITCH_POWER_OFF;
			return;
		}

		dev->switch_power_state = DRM_SWITCH_POWER_ON;
		drm_kms_helper_poll_enable(dev);
		pr_info("radeon: switched on\n");
	} else {
		drm_kms_helper_poll_disable(dev);
		dev->switch_power_state = DRM_SWITCH_POWER_CHANGING;
		r = radeon_suspend_kms(dev, true, true, false);
		if (r) {
			dev_err(&pdev->dev,
				"GPU suspend failed; switcheroo state remains on: %d\n",
				r);
			dev->switch_power_state = DRM_SWITCH_POWER_ON;
			drm_kms_helper_poll_enable(dev);
			return;
		}
		dev->switch_power_state = DRM_SWITCH_POWER_OFF;
		pr_info("radeon: switched off\n");
	}
}

/**
 * radeon_switcheroo_can_switch - see if switcheroo state can change
 *
 * @pdev: pci dev pointer
 *
 * Callback for the switcheroo driver.  Check of the switcheroo
 * state can be changed.
 * Returns true if the state can be changed, false if not.
 */
static bool radeon_switcheroo_can_switch(struct pci_dev *pdev)
{
	struct drm_device *dev = pci_get_drvdata(pdev);

	/*
	 * FIXME: open_count is protected by drm_global_mutex but that would lead to
	 * locking inversion with the driver load path. And the access here is
	 * completely racy anyway. So don't bother with locking for now.
	 */
	return atomic_read(&dev->open_count) == 0;
}

static const struct vga_switcheroo_client_ops radeon_switcheroo_ops = {
	.set_gpu_state = radeon_switcheroo_set_state,
	.reprobe = NULL,
	.can_switch = radeon_switcheroo_can_switch,
};

/**
 * radeon_device_init - initialize the driver
 *
 * @rdev: radeon_device pointer
 * @ddev: drm dev pointer
 * @pdev: pci dev pointer
 * @flags: driver flags
 *
 * Initializes the driver info and hw (all asics).
 * Returns 0 for success or an error on failure.
 * Called at driver startup.
 */
int radeon_device_init(struct radeon_device *rdev,
		       struct drm_device *ddev,
		       struct pci_dev *pdev,
		       uint32_t flags)
{
	int r, i;
	int dma_bits;
	bool runtime = false;

	rdev->shutdown = false;
	rdev->flags = flags;
	rdev->family = flags & RADEON_FAMILY_MASK;
	rdev->is_atom_bios = false;
	rdev->usec_timeout = RADEON_MAX_USEC_TIMEOUT;
	rdev->mc.gtt_size = 512 * 1024 * 1024;
	rdev->accel_working = false;
	rdev->rs4xx_terminal_drm_ref_held = false;
	rdev->rs4xx_terminal_retained = false;
	rdev->rs4xx_terminal_work_quiesced = false;
	rdev->rs4xx_unload_completed = false;
	rdev->vga_client_registered = false;
	rdev->switcheroo_client_registered = false;
	rdev->switcheroo_domain_pm_initialized = false;
	rdev->rs4xx_irq_work_initialized = false;
	rdev->rs4xx_pm_work_initialized = false;
	rdev->rs4xx_fence_work_initialized = false;
	rdev->rs4xx_parked_publish_work_initialized = false;
	rdev->debugfs_component_count = 0;
	rdev->debugfs_registration_complete = false;
	rdev->acpi_registered = false;
	atomic_set(&rdev->rs4xx_hardware_state,
		   RADEON_RS4XX_HARDWARE_RUNNING);
	atomic_set(&rdev->rs4xx_hardware_closing, 0);
	atomic_set(&rdev->rs4xx_hardware_transactions, 0);
	atomic_set(&rdev->rs4xx_hardware_readers, 0);
	atomic_set(&rdev->rs4xx_live_bos, 0);
	atomic_set(&rdev->rs4xx_retained_gem_objects, 0);
	atomic_set(&rdev->rs4xx_retained_ttm_tables, 0);
	atomic_long_set(&rdev->rs4xx_retained_ttm_accounted_pages, 0);
	atomic_set(&rdev->rs4xx_parked_publish_pending, 0);
	atomic_set(&rdev->rs4xx_parked_publish_running, 0);
	init_waitqueue_head(&rdev->rs4xx_hardware_wait);
	spin_lock_init(&rdev->rs4xx_hardware_state_lock);
	mutex_init(&rdev->rs4xx_hardware_transition_lock);
	mutex_init(&rdev->rs4xx_parked_publish_lock);
	mutex_init(&rdev->debugfs_component_lock);
	mutex_init(&rdev->rs4xx_unload_lock);
	mutex_init(&rdev->rs4xx_retained_ttm_lock);
	INIT_LIST_HEAD(&rdev->rs4xx_retained_bos_list);
	INIT_LIST_HEAD(&rdev->rs4xx_retained_ttm_tables_list);
	WRITE_ONCE(rdev->rs4xx_hardware_owner, NULL);
	WRITE_ONCE(rdev->rs4xx_gart_fini_error, 0);
	WRITE_ONCE(rdev->rs4xx_ttm_fini_error, 0);
	WRITE_ONCE(rdev->rs4xx_gart_teardown_complete, false);
	mutex_init(&rdev->rs4xx_retained_flip_lock);
	INIT_LIST_HEAD(&rdev->rs4xx_retained_flips);
	INIT_DELAYED_WORK(&rdev->rs4xx_flip_cleanup_work,
			  radeon_page_flip_cleanup_work);
	INIT_WORK(&rdev->rs4xx_parked_publish_work,
		  radeon_rs4xx_parked_publish_work);
	rdev->rs4xx_parked_publish_work_initialized = true;
	WRITE_ONCE(rdev->rs4xx_scanout_release_tracking, false);
	WRITE_ONCE(rdev->rs4xx_scanout_release_failed, false);
	/* set up ring ids */
	for (i = 0; i < RADEON_NUM_RINGS; i++) {
		rdev->ring[i].idx = i;
	}
	rdev->fence_context = dma_fence_context_alloc(RADEON_NUM_RINGS);

	DRM_INFO("initializing kernel modesetting (%s 0x%04X:0x%04X 0x%04X:0x%04X 0x%02X).\n",
		 radeon_family_name[rdev->family], pdev->vendor, pdev->device,
		 pdev->subsystem_vendor, pdev->subsystem_device, pdev->revision);

	/* mutex initialization are all done here so we
	 * can recall function without having locking issues */
	mutex_init(&rdev->ring_lock);
	mutex_init(&rdev->dc_hw_i2c_mutex);
	atomic_set(&rdev->ih.lock, 0);
	mutex_init(&rdev->gem.mutex);
	mutex_init(&rdev->gart.lock);
	mutex_init(&rdev->pm.mutex);
	mutex_init(&rdev->gpu_clock_mutex);
	mutex_init(&rdev->srbm_mutex);
	mutex_init(&rdev->audio.component_mutex);
	init_rwsem(&rdev->pm.mclk_lock);
	init_rwsem(&rdev->exclusive_lock);
	spin_lock_init(&rdev->irq.lock);
	init_waitqueue_head(&rdev->irq.vblank_queue);
	r = radeon_gem_init(rdev);
	if (r)
		return r;

	radeon_check_arguments(rdev);
	/* Adjust VM size here.
	 * Max GPUVM size for cayman+ is 40 bits.
	 */
	rdev->vm_manager.max_pfn = radeon_vm_size << 18;

	/* Set asic functions */
	r = radeon_asic_init(rdev);
	if (r)
		return r;

	/* all of the newer IGP chips have an internal gart
	 * However some rs4xx report as AGP, so remove that here.
	 */
	if ((rdev->family >= CHIP_RS400) &&
	    (rdev->flags & RADEON_IS_IGP)) {
		rdev->flags &= ~RADEON_IS_AGP;
	}

	if (rdev->flags & RADEON_IS_AGP && radeon_agpmode == -1) {
		radeon_agp_disable(rdev);
	}

	/* Set the internal MC address mask
	 * This is the max address of the GPU's
	 * internal address space.
	 */
	if (rdev->family >= CHIP_CAYMAN)
		rdev->mc.mc_mask = 0xffffffffffULL; /* 40 bit MC */
	else if (rdev->family >= CHIP_CEDAR)
		rdev->mc.mc_mask = 0xfffffffffULL; /* 36 bit MC */
	else
		rdev->mc.mc_mask = 0xffffffffULL; /* 32 bit MC */

	/* set DMA mask.
	 * PCIE - can handle 40-bits.
	 * IGP - can handle 40-bits
	 * AGP - generally dma32 is safest
	 * PCI - dma32 for legacy pci gart, 40 bits on newer asics
	 */
	dma_bits = 40;
	if (rdev->flags & RADEON_IS_AGP)
		dma_bits = 32;
	if ((rdev->flags & RADEON_IS_PCI) &&
	    (rdev->family <= CHIP_RS740))
		dma_bits = 32;
#ifdef CONFIG_PPC64
	if (rdev->family == CHIP_CEDAR)
		dma_bits = 32;
#endif

	r = dma_set_mask_and_coherent(&rdev->pdev->dev, DMA_BIT_MASK(dma_bits));
	if (r) {
		pr_warn("radeon: No suitable DMA available\n");
		return r;
	}
	rdev->need_swiotlb = drm_need_swiotlb(dma_bits);

	/* Registers mapping */
	/* TODO: block userspace mapping of io register */
	spin_lock_init(&rdev->mmio_idx_lock);
	spin_lock_init(&rdev->smc_idx_lock);
	spin_lock_init(&rdev->pll_idx_lock);
	spin_lock_init(&rdev->mc_idx_lock);
	spin_lock_init(&rdev->pcie_idx_lock);
	spin_lock_init(&rdev->pciep_idx_lock);
	spin_lock_init(&rdev->pif_idx_lock);
	spin_lock_init(&rdev->cg_idx_lock);
	spin_lock_init(&rdev->uvd_idx_lock);
	spin_lock_init(&rdev->rcu_idx_lock);
	spin_lock_init(&rdev->didt_idx_lock);
	spin_lock_init(&rdev->end_idx_lock);
	if (rdev->family >= CHIP_BONAIRE) {
		rdev->rmmio_base = pci_resource_start(rdev->pdev, 5);
		rdev->rmmio_size = pci_resource_len(rdev->pdev, 5);
	} else {
		rdev->rmmio_base = pci_resource_start(rdev->pdev, 2);
		rdev->rmmio_size = pci_resource_len(rdev->pdev, 2);
	}
	rdev->rmmio = ioremap(rdev->rmmio_base, rdev->rmmio_size);
	if (rdev->rmmio == NULL)
		return -ENOMEM;

	/* doorbell bar mapping */
	if (rdev->family >= CHIP_BONAIRE)
		radeon_doorbell_init(rdev);

	/* io port mapping */
	for (i = 0; i < DEVICE_COUNT_RESOURCE; i++) {
		if (pci_resource_flags(rdev->pdev, i) & IORESOURCE_IO) {
			rdev->rio_mem_size = pci_resource_len(rdev->pdev, i);
			rdev->rio_mem = pci_iomap(rdev->pdev, i, rdev->rio_mem_size);
			break;
		}
	}
	if (rdev->rio_mem == NULL)
		DRM_ERROR("Unable to find PCI I/O BAR\n");

	if (rdev->flags & RADEON_IS_PX)
		radeon_device_handle_px_quirks(rdev);

	/* if we have > 1 VGA cards, then disable the radeon VGA resources */
	/* this will fail for cards that aren't VGA class devices, just
	 * ignore it */
	r = vga_client_register(rdev->pdev, radeon_vga_set_decode);
	if (r)
		dev_warn(rdev->dev,
			 "VGA arbiter client registration failed: %d\n", r);
	else
		rdev->vga_client_registered = true;

	if (rdev->flags & RADEON_IS_PX)
		runtime = true;
	if (!pci_is_thunderbolt_attached(rdev->pdev)) {
		r = vga_switcheroo_register_client(
			rdev->pdev, &radeon_switcheroo_ops, runtime);
		if (r)
			dev_warn(rdev->dev,
				 "VGA switcheroo client registration failed: %d\n",
				 r);
		else
			rdev->switcheroo_client_registered = true;
	}
	if (runtime) {
		r = vga_switcheroo_init_domain_pm_ops(
			rdev->dev, &rdev->vga_pm_domain);
		if (r)
			dev_warn(rdev->dev,
				 "VGA switcheroo PM domain initialization failed: %d\n",
				 r);
		else
			rdev->switcheroo_domain_pm_initialized = true;
	}

	r = radeon_init(rdev);
	if (r)
		goto failed;

	radeon_gem_debugfs_init(rdev);

	if (rdev->flags & RADEON_IS_AGP && !rdev->accel_working) {
		/* Acceleration not working on AGP card try again
		 * with fallback to PCI or PCIE GART
		 */
		radeon_asic_reset(rdev);
		radeon_fini(rdev);
		r = READ_ONCE(rdev->rs4xx_gart_fini_error);
		if (r)
			goto failed;
		radeon_agp_disable(rdev);
		r = radeon_init(rdev);
		if (r)
			goto failed;
	}
	radeon_rs480_panic_register(rdev);

	radeon_audio_component_init(rdev);

	r = radeon_ib_ring_tests(rdev);
	if (r) {
		DRM_ERROR("ib ring test failed (%d).\n", r);
		if (radeon_rs4xx_hardware_target(rdev) &&
		    READ_ONCE(rdev->gpu_parked))
			goto failed;
	}

	/*
	 * Turks/Thames GPU will freeze whole laptop if DPM is not restarted
	 * after the CP ring have chew one packet at least. Hence here we stop
	 * and restart DPM after the radeon_ib_ring_tests().
	 */
	if (rdev->pm.dpm_enabled &&
	    (rdev->pm.pm_method == PM_METHOD_DPM) &&
	    (rdev->family == CHIP_TURKS) &&
	    (rdev->flags & RADEON_IS_MOBILITY)) {
		mutex_lock(&rdev->pm.mutex);
		radeon_dpm_disable(rdev);
		radeon_dpm_enable(rdev);
		mutex_unlock(&rdev->pm.mutex);
	}

	if ((radeon_testing & 1)) {
		if (rdev->accel_working)
			radeon_test_moves(rdev);
		else
			DRM_INFO("radeon: acceleration disabled, skipping move tests\n");
	}
	if ((radeon_testing & 2)) {
		if (rdev->accel_working)
			radeon_test_syncing(rdev);
		else
			DRM_INFO("radeon: acceleration disabled, skipping sync tests\n");
	}
	if (radeon_benchmarking) {
		if (rdev->accel_working)
			radeon_benchmark(rdev, radeon_benchmarking);
		else
			DRM_INFO("radeon: acceleration disabled, skipping benchmarks\n");
	}
	return 0;

failed:
	/* balance pm_runtime_get_sync() in radeon_driver_unload_kms() */
	if (radeon_is_px(ddev))
		pm_runtime_put_noidle(ddev->dev);
	if (rdev->switcheroo_domain_pm_initialized) {
		vga_switcheroo_fini_domain_pm_ops(rdev->dev);
		rdev->switcheroo_domain_pm_initialized = false;
	}
	return r;
}

/**
 * radeon_device_fini - tear down the driver
 *
 * @rdev: radeon_device pointer
 *
 * Tear down the driver info (all asics).
 * Called at driver shutdown.
 */
int radeon_device_fini(struct radeon_device *rdev)
{
	int r;

	r = radeon_rs4xx_terminal_ownership_error(rdev);
	if (r)
		return r;

	DRM_INFO("radeon: finishing device.\n");
	WRITE_ONCE(rdev->shutdown, true);
	radeon_rs480_panic_unregister(rdev);
	/* evict vram memory */
	r = radeon_bo_evict_vram(rdev);
	if (r && radeon_rs4xx_hardware_target(rdev))
		return r;
	r = radeon_rs4xx_terminal_ownership_error(rdev);
	if (r)
		return r;
	radeon_audio_component_fini(rdev);
	radeon_fini(rdev);
	r = radeon_rs4xx_terminal_ownership_error(rdev);
	if (r)
		return r;
	radeon_device_fini_external_interfaces(rdev);
	if (rdev->rio_mem)
		pci_iounmap(rdev->pdev, rdev->rio_mem);
	rdev->rio_mem = NULL;
	iounmap(rdev->rmmio);
	rdev->rmmio = NULL;
	if (rdev->family >= CHIP_BONAIRE)
		radeon_doorbell_fini(rdev);
	return 0;
}

struct radeon_scanout_pin {
	struct radeon_bo *bo;
	unsigned int count;
};

static int radeon_scanout_pin_record(struct radeon_scanout_pin *pins,
				     unsigned int *pin_count,
				     unsigned int pin_limit,
				     struct radeon_bo *bo)
{
	unsigned int pin_index;

	for (pin_index = 0; pin_index < *pin_count; ++pin_index) {
		if (pins[pin_index].bo == bo) {
			pins[pin_index].count++;
			return 0;
		}
	}
	if (*pin_count == pin_limit)
		return -E2BIG;
	pins[*pin_count].bo = bo;
	pins[*pin_count].count = 1;
	(*pin_count)++;
	return 0;
}

static int radeon_suspend_release_scanout_pins(struct radeon_device *rdev)
{
	struct radeon_scanout_pin pins[RADEON_MAX_CRTCS * 2] = { };
	struct drm_device *dev = rdev_to_drm(rdev);
	struct drm_crtc *crtc;
	unsigned int pin_count = 0;
	unsigned int pin_index;
	unsigned int reserved = 0;
	int r = 0;

	list_for_each_entry(crtc, &dev->mode_config.crtc_list, head) {
		struct radeon_crtc *radeon_crtc = to_radeon_crtc(crtc);
		struct drm_framebuffer *fb = crtc->primary->fb;
		struct radeon_bo *bo;

		if (radeon_crtc->cursor_bo) {
			bo = gem_to_radeon_bo(radeon_crtc->cursor_bo);
			r = radeon_scanout_pin_record(pins, &pin_count,
						      ARRAY_SIZE(pins), bo);
			if (r)
				return r;
		}
		if (!fb || !fb->obj[0])
			continue;
		bo = gem_to_radeon_bo(fb->obj[0]);
		if (radeon_fbdev_robj_is_fb(rdev, bo))
			continue;
		r = radeon_scanout_pin_record(pins, &pin_count,
					      ARRAY_SIZE(pins), bo);
		if (r)
			return r;
	}

	/* Every reservation succeeds before any pin count changes, so a busy BO
	 * leaves the complete scanout ownership set intact for suspend rollback.
	 */
	for (reserved = 0; reserved < pin_count; ++reserved) {
		r = ttm_bo_reserve(&pins[reserved].bo->tbo, false, true, NULL);
		if (r)
			goto unreserve;
	}
	for (pin_index = 0; pin_index < pin_count; ++pin_index) {
		if (pins[pin_index].bo->tbo.pin_count < pins[pin_index].count) {
			r = -EINVAL;
			goto unreserve;
		}
	}
	for (pin_index = 0; pin_index < pin_count; ++pin_index) {
		unsigned int unpin_count;

		for (unpin_count = 0;
		     unpin_count < pins[pin_index].count;
		     ++unpin_count)
			radeon_bo_unpin(pins[pin_index].bo);
	}

unreserve:
	while (reserved)
		radeon_bo_unreserve(pins[--reserved].bo);
	return r;
}


/*
 * Suspend & resume.
 */
/*
 * radeon_suspend_kms - initiate device suspend
 *
 * Puts the hw in the suspend state (all asics).
 * Returns 0 for success or an error on failure.
 * Called at driver suspend.
 */
int radeon_suspend_kms(struct drm_device *dev, bool suspend,
		       bool notify_clients, bool freeze)
{
	struct radeon_device *rdev;
	struct pci_dev *pdev;
	struct drm_connector *connector;
	bool displays_disabled = true;
	bool page_flip_buffers_released;
	int suspend_result = 0;
	int i, r;

	if (dev == NULL || dev->dev_private == NULL) {
		return -ENODEV;
	}

	rdev = dev->dev_private;
	pdev = to_pci_dev(dev->dev);

	if (dev->switch_power_state == DRM_SWITCH_POWER_OFF)
		return 0;

	r = radeon_rs4xx_hardware_transition_begin(
		rdev, RADEON_RS4XX_HARDWARE_RUNNING,
		RADEON_RS4XX_HARDWARE_SUSPENDING);
	if (r)
		return r;
	if (radeon_rs4xx_hardware_target(rdev))
		cancel_delayed_work_sync(&rdev->rs4xx_flip_cleanup_work);

	drm_kms_helper_poll_disable(dev);
	if (!radeon_page_flip_quiesce(rdev)) {
		if (radeon_rs4xx_hardware_target(rdev) &&
		    READ_ONCE(rdev->gpu_parked)) {
			r = -EIO;
			goto rs4xx_suspend_parked;
		}
		radeon_rs4xx_hardware_transition_end(
			rdev, RADEON_RS4XX_HARDWARE_RUNNING);
		if (radeon_rs4xx_hardware_target(rdev) &&
		    READ_ONCE(rdev->gpu_parked)) {
			radeon_rs4xx_publish_parked_state(rdev);
			return -EIO;
		}
		if (radeon_rs4xx_hardware_target(rdev))
			queue_delayed_work(system_unbound_wq,
					   &rdev->rs4xx_flip_cleanup_work, 0);
		drm_kms_helper_poll_enable(dev);
		return -EDEADLK;
	}

	drm_modeset_lock_all(dev);
	/* turn off display hw */
	list_for_each_entry(connector, &dev->mode_config.connector_list, head) {
		int connector_result;

		connector_result = drm_helper_connector_dpms(
			connector, DRM_MODE_DPMS_OFF);
		if (connector_result) {
			displays_disabled = false;
			if (!suspend_result)
				suspend_result = connector_result;
			DRM_ERROR("failed to disable connector %u: %d\n",
				  connector->base.id, connector_result);
		}
	}
	drm_modeset_unlock_all(dev);
	page_flip_buffers_released =
		radeon_page_flip_finalize_retained(rdev, displays_disabled);
	page_flip_buffers_released &= displays_disabled;

	if (page_flip_buffers_released)
		r = radeon_suspend_release_scanout_pins(rdev);
	else
		r = -EBUSY;
	if (r) {
		if (!suspend_result)
			suspend_result = r;
		DRM_ERROR("retaining scanout buffers after display shutdown failure\n");
	}
	if (radeon_rs4xx_hardware_target(rdev) &&
	    READ_ONCE(rdev->gpu_parked)) {
		r = -EIO;
		goto rs4xx_suspend_parked;
	}
	if (suspend_result && radeon_rs4xx_hardware_target(rdev)) {
		drm_modeset_lock_all(dev);
		list_for_each_entry(connector,
				    &dev->mode_config.connector_list, head) {
			int connector_result;

			connector_result = drm_helper_connector_dpms(
				connector, DRM_MODE_DPMS_ON);
			if (connector_result)
				DRM_ERROR("failed to restore connector %u: %d\n",
					  connector->base.id, connector_result);
		}
		drm_modeset_unlock_all(dev);
		radeon_rs4xx_hardware_transition_end(
			rdev, RADEON_RS4XX_HARDWARE_RUNNING);
		if (READ_ONCE(rdev->gpu_parked)) {
			radeon_rs4xx_publish_parked_state(rdev);
			return -EIO;
		}
		queue_delayed_work(system_unbound_wq,
				   &rdev->rs4xx_flip_cleanup_work, 0);
		drm_kms_helper_poll_enable(dev);
		return suspend_result;
	}
	/* evict vram memory */
	r = radeon_bo_evict_vram(rdev);
	if (radeon_rs4xx_hardware_target(rdev) &&
	    (r || READ_ONCE(rdev->gpu_parked))) {
		if (!r)
			r = -EIO;
		goto rs4xx_suspend_parked;
	}

	/* wait for gpu to finish processing current batch */
	for (i = 0; i < RADEON_NUM_RINGS; i++) {
		r = radeon_fence_wait_empty(rdev, i);
		if (r) {
			if (radeon_rs4xx_hardware_target(rdev))
				goto rs4xx_suspend_parked;
			/* delay GPU reset to resume */
			radeon_fence_driver_force_completion(rdev, i);
		} else {
			/* finish executing delayed work */
			flush_delayed_work(&rdev->fence_drv[i].lockup_work);
		}
		if (radeon_rs4xx_hardware_target(rdev) &&
		    READ_ONCE(rdev->gpu_parked)) {
			r = -EIO;
			goto rs4xx_suspend_parked;
		}
	}

	radeon_save_bios_scratch_regs(rdev);

	WRITE_ONCE(rdev->asic_suspended, true);
	radeon_suspend(rdev);
	if (radeon_rs4xx_hardware_target(rdev) &&
	    READ_ONCE(rdev->gpu_parked)) {
		r = -EIO;
		goto rs4xx_suspend_parked;
	}
	radeon_hpd_fini(rdev);
	/* evict remaining vram memory
	 * This second call to evict vram is to evict the gart page table
	 * using the CPU.
	 */
	r = radeon_bo_evict_vram(rdev);
	if (radeon_rs4xx_hardware_target(rdev) &&
	    (r || READ_ONCE(rdev->gpu_parked))) {
		if (!r)
			r = -EIO;
		goto rs4xx_suspend_parked;
	}

	radeon_agp_suspend(rdev);

	pci_save_state(pdev);
	if (freeze && rdev->family >= CHIP_CEDAR && !(rdev->flags & RADEON_IS_IGP)) {
		rdev->asic->asic_reset(rdev, true);
		pci_restore_state(pdev);
	} else if (suspend) {
		/* Shut down the device */
		pci_disable_device(pdev);
		pci_set_power_state(pdev, PCI_D3hot);
	}

	if (notify_clients)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 0, 0)
		drm_client_dev_suspend(dev);
#else
		drm_client_dev_suspend(dev, false);
#endif

	radeon_rs4xx_hardware_transition_end(
		rdev, RADEON_RS4XX_HARDWARE_SUSPENDED);

	return 0;

rs4xx_suspend_parked:
	radeon_rs4xx_publish_parked_state(rdev);
	radeon_rs4xx_hardware_transition_end(
		rdev, RADEON_RS4XX_HARDWARE_PARKED);
	return r;
}

static void radeon_rs4xx_system_resume_rollback(struct pci_dev *pdev)
{
	/* pci_restore_state may restore PCI_COMMAND_MASTER before enablement
	 * fails. Save the cleared command register so a later resume retry
	 * restores a device without bus mastering until enablement succeeds.
	 */
	pci_clear_master(pdev);
	pci_save_state(pdev);
	pci_set_power_state(pdev, PCI_D3hot);
}

/*
 * radeon_resume_kms - initiate device resume
 *
 * Bring the hw back to operating state (all asics).
 * Returns 0 for success or an error on failure.
 * Called at driver resume.
 */
int radeon_resume_kms(struct drm_device *dev, bool resume, bool notify_clients)
{
	struct drm_connector *connector;
	struct radeon_device *rdev = dev->dev_private;
	struct pci_dev *pdev = to_pci_dev(dev->dev);
	struct drm_crtc *crtc;
	int r;

	if (dev->switch_power_state == DRM_SWITCH_POWER_OFF)
		return 0;

	r = radeon_rs4xx_hardware_transition_begin(
		rdev, RADEON_RS4XX_HARDWARE_SUSPENDED,
		RADEON_RS4XX_HARDWARE_RESUMING);
	/* RUNNING already satisfies resume and owns no transition to release. */
	if (r == -EALREADY && radeon_rs4xx_hardware_target(rdev) &&
	    !READ_ONCE(rdev->gpu_parked) &&
	    atomic_read_acquire(&rdev->rs4xx_hardware_state) ==
		RADEON_RS4XX_HARDWARE_RUNNING)
		return 0;
	if (r)
		return r;

	if (resume) {
		pci_set_power_state(pdev, PCI_D0);
		pci_restore_state(pdev);
		r = pci_enable_device(pdev);
		if (r) {
			if (radeon_rs4xx_hardware_target(rdev)) {
				radeon_rs4xx_system_resume_rollback(pdev);
				radeon_rs4xx_hardware_transition_end(
					rdev, RADEON_RS4XX_HARDWARE_SUSPENDED);
				return r;
			}
			return -1;
		}
		if (radeon_rs4xx_hardware_target(rdev))
			pci_set_master(pdev);
	}
	/* resume AGP if in use */
	radeon_agp_resume(rdev);
	r = radeon_resume(rdev);
	if (radeon_rs4xx_hardware_target(rdev) &&
	    (r || READ_ONCE(rdev->gpu_parked))) {
		if (!r)
			r = -EIO;
		goto rs4xx_resume_parked;
	}

	r = radeon_ib_ring_tests(rdev);
	if (r) {
		if (radeon_rs4xx_hardware_target(rdev))
			goto rs4xx_resume_parked;
		DRM_ERROR("ib ring test failed (%d).\n", r);
	}

	if ((rdev->pm.pm_method == PM_METHOD_DPM) && rdev->pm.dpm_enabled) {
		/* do dpm late init */
		r = radeon_pm_late_init(rdev);
		if (r) {
			rdev->pm.dpm_enabled = false;
			DRM_ERROR("radeon_pm_late_init failed, disabling dpm\n");
		}
	} else {
		/* resume old pm late */
		radeon_pm_resume(rdev);
	}
	if (radeon_rs4xx_hardware_target(rdev) &&
	    READ_ONCE(rdev->gpu_parked)) {
		r = -EIO;
		goto rs4xx_resume_parked;
	}

	radeon_restore_bios_scratch_regs(rdev);

	/* pin cursors */
	list_for_each_entry(crtc, &dev->mode_config.crtc_list, head) {
		struct radeon_crtc *radeon_crtc = to_radeon_crtc(crtc);

		if (radeon_crtc->cursor_bo) {
			struct radeon_bo *robj = gem_to_radeon_bo(radeon_crtc->cursor_bo);
			r = radeon_bo_reserve(robj, false);
			if (r == 0) {
				/* Only 27 bit offset for legacy cursor */
				r = radeon_bo_pin_restricted(robj,
							     RADEON_GEM_DOMAIN_VRAM,
							     ASIC_IS_AVIVO(rdev) ?
							     0 : 1 << 27,
							     &radeon_crtc->cursor_addr);
				if (r != 0)
					DRM_ERROR("Failed to pin cursor BO (%d)\n", r);
				radeon_bo_unreserve(robj);
			}
		}
		if (radeon_rs4xx_hardware_target(rdev) &&
		    READ_ONCE(rdev->gpu_parked)) {
			r = -EIO;
			goto rs4xx_resume_parked;
		}
	}

	/* init dig PHYs, disp eng pll */
	if (rdev->is_atom_bios) {
		radeon_atom_encoder_init(rdev);
		radeon_atom_disp_eng_pll_init(rdev);
		/* turn on the BL */
		if (rdev->mode_info.bl_encoder) {
			u8 bl_level = radeon_get_backlight_level(rdev,
								 rdev->mode_info.bl_encoder);
			radeon_set_backlight_level(rdev, rdev->mode_info.bl_encoder,
						   bl_level);
		}
	}
	/* reset hpd state */
	radeon_hpd_init(rdev);
	/* blat the mode back in */
	if (notify_clients) {
		drm_helper_resume_force_mode(dev);
		if (radeon_rs4xx_hardware_target(rdev) &&
		    READ_ONCE(rdev->gpu_parked)) {
			r = -EIO;
			goto rs4xx_resume_parked;
		}
		/* turn on display hw */
		drm_modeset_lock_all(dev);
		list_for_each_entry(connector, &dev->mode_config.connector_list, head) {
			drm_helper_connector_dpms(connector, DRM_MODE_DPMS_ON);
		}
		drm_modeset_unlock_all(dev);
	}

	/* set the power state here in case we are a PX system or headless */
	if ((rdev->pm.pm_method == PM_METHOD_DPM) && rdev->pm.dpm_enabled)
		radeon_pm_compute_clocks(rdev);
	if (radeon_rs4xx_hardware_target(rdev) &&
	    READ_ONCE(rdev->gpu_parked)) {
		r = -EIO;
		goto rs4xx_resume_parked;
	}

	WRITE_ONCE(rdev->asic_suspended, false);
	radeon_rs4xx_hardware_transition_end(
		rdev, RADEON_RS4XX_HARDWARE_RUNNING);
	if (radeon_rs4xx_hardware_target(rdev) &&
	    READ_ONCE(rdev->gpu_parked)) {
		radeon_rs4xx_publish_parked_state(rdev);
		return -EIO;
	}
	if (radeon_rs4xx_hardware_target(rdev))
		queue_delayed_work(system_unbound_wq,
				   &rdev->rs4xx_flip_cleanup_work, 0);
	drm_kms_helper_poll_enable(dev);

	if (notify_clients)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 0, 0)
		drm_client_dev_resume(dev);
#else
		drm_client_dev_resume(dev, false);
#endif

	return 0;

rs4xx_resume_parked:
	radeon_rs4xx_publish_parked_state(rdev);
	dev_err(rdev->dev, "RS4xx resume failed: GPU remains parked (%d)\n", r);
	radeon_rs4xx_hardware_transition_end(
		rdev, RADEON_RS4XX_HARDWARE_PARKED);
	return r;
}

/**
 * radeon_gpu_reset_internal - execute a detected or forced GPU reset
 *
 * @rdev: radeon device pointer
 * @force_reset: establish the request under the writer lock
 *
 * Attempt to reset the GPU (all ASICs).
 * Returns 0 for success or an error on failure.
 */
static int radeon_gpu_reset_internal(struct radeon_device *rdev,
				     bool force_reset)
{
	struct drm_crtc *reset_crtc;
	unsigned ring_sizes[RADEON_NUM_RINGS] = { };
	uint32_t *ring_data[RADEON_NUM_RINGS] = { };

	bool saved = false;
	bool gpu_parked;
	bool irq_installed = false;
	bool page_flips_drained = true;
	bool rs4xx_reset;
	unsigned int released_ring_count = 0;
	unsigned int released_ring_dwords = 0;
	unsigned int reset_crtcs_expected = 0;
	unsigned long irqflags;

	int i, r;

	rs4xx_reset = radeon_rs4xx_hardware_target(rdev);
	if (rs4xx_reset) {
		r = radeon_rs4xx_hardware_transition_begin(
			rdev, RADEON_RS4XX_HARDWARE_RUNNING,
			RADEON_RS4XX_HARDWARE_RESETTING);
		if (r)
			return r;
	}

	down_write(&rdev->exclusive_lock);
	if (READ_ONCE(rdev->gpu_parked)) {
		WRITE_ONCE(rdev->needs_reset, false);
		up_write(&rdev->exclusive_lock);
		dev_err_once(rdev->dev,
			     "RS4xx reset re-entry refused after terminal park\n");
		if (rs4xx_reset)
			radeon_rs4xx_hardware_transition_end(
				rdev, RADEON_RS4XX_HARDWARE_PARKED);
		return -EIO;
	}
	if (!force_reset && !READ_ONCE(rdev->needs_reset)) {
		if (READ_ONCE(rdev->gpu_parked)) {
			WRITE_ONCE(rdev->needs_reset, false);
			up_write(&rdev->exclusive_lock);
			if (rs4xx_reset)
				radeon_rs4xx_hardware_transition_end(
					rdev, RADEON_RS4XX_HARDWARE_PARKED);
			return -EIO;
		}
		up_write(&rdev->exclusive_lock);
		if (rs4xx_reset)
			radeon_rs4xx_hardware_transition_end(
				rdev, RADEON_RS4XX_HARDWARE_RUNNING);
		return 0;
	}

	if (force_reset)
		WRITE_ONCE(rdev->needs_reset, true);

	if (rs4xx_reset) {
		/* The RESETTING admission state closes before the writer lock and
		 * drains every admitted hardware transaction. The anonymous GEM
		 * mapping invalidation then removes CPU aperture PTEs before reset
		 * performs its first register access.
		 */
		WRITE_ONCE(rdev->in_reset, true);
		unmap_mapping_range(rdev_to_drm(rdev)->anon_inode->i_mapping,
				    0, 0, 1);
		irq_installed = READ_ONCE(rdev->irq.installed);
		if (irq_installed)
			synchronize_irq(rdev->pdev->irq);
		cancel_delayed_work_sync(&rdev->pm.dynpm_idle_work);
		if (irq_installed) {
			cancel_delayed_work_sync(&rdev->hotplug_work);
			cancel_work_sync(&rdev->dp_work);
		}
		drm_kms_helper_poll_disable(rdev_to_drm(rdev));
		cancel_delayed_work_sync(&rdev->rs4xx_flip_cleanup_work);
		page_flips_drained = radeon_page_flip_quiesce(rdev);
		if (READ_ONCE(rdev->gpu_parked)) {
			radeon_rs4xx_publish_parked_state(rdev);
			WRITE_ONCE(rdev->in_reset, false);
			up_write(&rdev->exclusive_lock);
			radeon_rs4xx_hardware_transition_end(
				rdev, RADEON_RS4XX_HARDWARE_PARKED);
			return -EIO;
		}
	}

	atomic_inc(&rdev->gpu_reset_counter);

	/* Log RS400/RS480 queue and cache state before GPU reset.
	 *
	 * Register readback on RS480 is a non-posted HyperTransport
	 * transaction: the CPU core stalls until the register bus answers.
	 * The CP (0x07xx), MC (0x0150), and RBBM (0x0E40) domains answer
	 * even while the 3D frontend is wedged, but the 3D pipe space at
	 * 0x4000 and above is served through the GA-domain register-bus
	 * client. With VAP/GA latched busy that client never grants the
	 * read and the CPU hard-locks with no fault. RB3D_DSTCACHE_CTLSTAT
	 * (0x4E4C) therefore reads only behind an RBBM_STATUS gate showing
	 * the 3D frontend idle; a wedged frontend logs the skip instead.
	 */
	if (rdev->family == CHIP_RS480 || rdev->family == CHIP_RS400) {
		u32 rbbm_status = RREG32(RADEON_RBBM_STATUS);

		DRM_ERROR("RS4xx reset preflight register capture\n");
		DRM_ERROR("RBBM_STATUS: 0x%08X\n", rbbm_status);
		DRM_ERROR("CP_RB_CNTL: 0x%08X\n", RREG32(RADEON_CP_RB_CNTL));
		DRM_ERROR("CP_RB_RPTR: 0x%08X\n", RREG32(RADEON_CP_RB_RPTR));
		DRM_ERROR("CP_RB_WPTR: 0x%08X\n", RREG32(RADEON_CP_RB_WPTR));
		DRM_ERROR("MC_STATUS: 0x%08X\n", RREG32(RADEON_MC_STATUS));
		if (rbbm_status & RADEON_RBBM_ACTIVE)
			DRM_ERROR("RB3D_DSTCACHE_CTLSTAT: skipped, 3D register bus wedged\n");
		else
			DRM_ERROR("RB3D_DSTCACHE_CTLSTAT: 0x%08X\n", RREG32(0x4E4C));
	}

	radeon_save_bios_scratch_regs(rdev);
	radeon_suspend(rdev);
	if (rs4xx_reset && READ_ONCE(rdev->gpu_parked)) {
		radeon_rs4xx_publish_parked_state(rdev);
		WRITE_ONCE(rdev->in_reset, false);
		up_write(&rdev->exclusive_lock);
		radeon_rs4xx_hardware_transition_end(
			rdev, RADEON_RS4XX_HARDWARE_PARKED);
		return -EIO;
	}
	radeon_hpd_fini(rdev);

	for (i = 0; i < RADEON_NUM_RINGS; ++i) {
		if (rs4xx_reset && READ_ONCE(rdev->gpu_parked)) {
			r = -EIO;
			gpu_parked = true;
			radeon_rs4xx_publish_parked_state(rdev);
			dev_err(rdev->dev,
				"RS4xx reset stops before ASIC reset after terminal park\n");
			goto rs4xx_reset_release_ring_copies;
		}
		ring_sizes[i] = radeon_ring_backup(rdev, &rdev->ring[i],
						   &ring_data[i]);
		if (ring_sizes[i]) {
			saved = true;
			dev_info(rdev->dev, "Saved %d dwords of commands "
				 "on ring %d.\n", ring_sizes[i], i);
		}
	}

	r = radeon_asic_reset(rdev);
	if (!r) {
		int resume_result;

		dev_info(rdev->dev, "GPU reset succeeded, trying to resume\n");
		resume_result = radeon_resume(rdev);
		if (rs4xx_reset && resume_result)
			r = resume_result;
	}

	/* Park the GPU when the ASIC reset fails on an RS400/RS480 IGP.
	 *
	 * A failed reset leaves the GA register-bus client wedged, and every
	 * register in the 0x4000+ 3D pipe space remains a non-posted-read
	 * black hole: the HyperTransport read never completes and the CPU
	 * hard-locks silently. RB3D_BUSY=0 does not make RB3D registers
	 * readable; the readback grant is GA-routed. The resume-side stream
	 * (power management, AtomBIOS encoder tables, HPD, forced modeset)
	 * executes BIOS bytecode and display bring-up with unaudited register
	 * access, so none of it may run against a wedged frontend. Parking
	 * keeps the host alive: fences force-complete so userspace waiters
	 * unblock, acceleration turns off so no new CS reaches the dead
	 * frontend, and the stage breadcrumbs let netconsole pin any residual
	 * hazard to an exact instruction window.
	 */
	gpu_parked = rs4xx_reset &&
		(r != 0 || READ_ONCE(rdev->gpu_parked));
	if (gpu_parked) {
		if (!r)
			r = -EIO;
		/* The terminal latch and IRQ removal precede every failed-reset
		 * cleanup operation. Fence publication remains CPU-only.
		 */
		radeon_rs4xx_publish_parked_state(rdev);
		dev_err(rdev->dev, "RS480 reset failed: parking GPU, skipping resume-side access\n");
	}

rs4xx_reset_release_ring_copies:
	if (!gpu_parked)
		radeon_restore_bios_scratch_regs(rdev);

	for (i = 0; i < RADEON_NUM_RINGS; ++i) {
		if (rs4xx_reset && READ_ONCE(rdev->gpu_parked)) {
			gpu_parked = true;
			if (!r)
				r = -EIO;
		}
		if (!r && ring_data[i]) {
			int restore_result;

			restore_result = radeon_ring_restore(
				rdev, &rdev->ring[i], ring_sizes[i], ring_data[i]);
			if (restore_result) {
				kvfree(ring_data[i]);
				if (rs4xx_reset) {
					r = restore_result;
					radeon_rs4xx_latch_parked_state(rdev);
					gpu_parked = true;
				}
			}
			ring_data[i] = NULL;
		} else if (!gpu_parked) {
			radeon_fence_driver_force_completion(rdev, i);
			kvfree(ring_data[i]);
			ring_data[i] = NULL;
		} else {
			if (ring_data[i]) {
				released_ring_count++;
				released_ring_dwords += ring_sizes[i];
			}
			kvfree(ring_data[i]);
			ring_data[i] = NULL;
		}
		if (rs4xx_reset && READ_ONCE(rdev->gpu_parked)) {
			gpu_parked = true;
			if (!r)
				r = -EIO;
		}
	}

	if (gpu_parked) {
		radeon_rs4xx_publish_parked_state(rdev);
		downgrade_write(&rdev->exclusive_lock);
		WRITE_ONCE(rdev->in_reset, false);
		up_read(&rdev->exclusive_lock);
		radeon_rs4xx_hardware_transition_end(
			rdev, RADEON_RS4XX_HARDWARE_PARKED);
		dev_err(rdev->dev,
			"RS4xx reset failed: GPU parked, released command copies rings=%u dwords=%u, error=%d\n",
			released_ring_count, released_ring_dwords, r);
		return r;
	}

	if ((rdev->pm.pm_method == PM_METHOD_DPM) && rdev->pm.dpm_enabled) {
		/* do dpm late init */
		r = radeon_pm_late_init(rdev);
		if (r) {
			rdev->pm.dpm_enabled = false;
			DRM_ERROR("radeon_pm_late_init failed, disabling dpm\n");
		}
	} else {
		/* resume old pm late */
		radeon_pm_resume(rdev);
	}
	if (rs4xx_reset && READ_ONCE(rdev->gpu_parked)) {
		radeon_rs4xx_publish_parked_state(rdev);
		WRITE_ONCE(rdev->in_reset, false);
		up_write(&rdev->exclusive_lock);
		radeon_rs4xx_hardware_transition_end(
			rdev, RADEON_RS4XX_HARDWARE_PARKED);
		return -EIO;
	}

	/* init dig PHYs, disp eng pll */
	if (rdev->is_atom_bios) {
		radeon_atom_encoder_init(rdev);
		radeon_atom_disp_eng_pll_init(rdev);
		/* turn on the BL */
		if (rdev->mode_info.bl_encoder) {
			u8 bl_level = radeon_get_backlight_level(rdev,
								 rdev->mode_info.bl_encoder);
			radeon_set_backlight_level(rdev, rdev->mode_info.bl_encoder,
						   bl_level);
		}
	}
	/* reset hpd state */
	radeon_hpd_init(rdev);
	if (rs4xx_reset && READ_ONCE(rdev->gpu_parked)) {
		radeon_rs4xx_publish_parked_state(rdev);
		WRITE_ONCE(rdev->in_reset, false);
		up_write(&rdev->exclusive_lock);
		radeon_rs4xx_hardware_transition_end(
			rdev, RADEON_RS4XX_HARDWARE_PARKED);
		return -EIO;
	}

	WRITE_ONCE(rdev->needs_reset, false);
	if (rs4xx_reset) {
		spin_lock_irqsave(&rdev->irq.lock, irqflags);
		if (READ_ONCE(rdev->irq.installed) &&
		    !READ_ONCE(rdev->gpu_parked))
			radeon_irq_set(rdev);
		spin_unlock_irqrestore(&rdev->irq.lock, irqflags);
	} else {
		rdev->in_reset = true;
	}

	downgrade_write(&rdev->exclusive_lock);

	if (rs4xx_reset) {
		list_for_each_entry(reset_crtc,
				    &rdev_to_drm(rdev)->mode_config.crtc_list,
				    head)
			if (reset_crtc->enabled)
				reset_crtcs_expected++;
		WRITE_ONCE(rdev->rs4xx_reset_reprogram_failed, false);
		WRITE_ONCE(rdev->rs4xx_reset_reprogram_completed, 0);
		WRITE_ONCE(rdev->rs4xx_reset_reprogramming, true);
	}
	drm_helper_resume_force_mode(rdev_to_drm(rdev));
	if (rs4xx_reset) {
		WRITE_ONCE(rdev->rs4xx_reset_reprogramming, false);
		if (READ_ONCE(rdev->gpu_parked) ||
		    READ_ONCE(rdev->rs4xx_reset_reprogram_failed) ||
		    READ_ONCE(rdev->rs4xx_reset_reprogram_completed) !=
			reset_crtcs_expected) {
			dev_err(rdev->dev,
				"RS4xx reset display restore failed: expected=%u completed=%u\n",
				reset_crtcs_expected,
				READ_ONCE(rdev->rs4xx_reset_reprogram_completed));
			r = -EIO;
			goto rs4xx_reset_parked_after_downgrade;
		}
		if (!radeon_page_flip_finalize_retained(rdev, true))
			page_flips_drained = false;
		if (!page_flips_drained)
			queue_delayed_work(system_unbound_wq,
					   &rdev->rs4xx_flip_cleanup_work,
					   0);
		if (READ_ONCE(rdev->gpu_parked)) {
			r = -EIO;
			goto rs4xx_reset_parked_after_downgrade;
		}
	}

	/* set the power state here in case we are a PX system or headless */
	if ((rdev->pm.pm_method == PM_METHOD_DPM) && rdev->pm.dpm_enabled)
		radeon_pm_compute_clocks(rdev);

	if (!r) {
		r = radeon_ib_ring_tests(rdev);
		if (rs4xx_reset && READ_ONCE(rdev->gpu_parked))
			goto rs4xx_reset_parked_after_downgrade;
		if (r && saved)
			r = -EAGAIN;
	} else {
		/* bad news, how to tell it to userspace ? */
		dev_info(rdev->dev, "GPU reset failed\n");
	}

	if (rs4xx_reset && READ_ONCE(rdev->gpu_parked)) {
		if (!r)
			r = -EIO;
		goto rs4xx_reset_parked_after_downgrade;
	}
	WRITE_ONCE(rdev->needs_reset, r == -EAGAIN);
	WRITE_ONCE(rdev->in_reset, false);
	up_read(&rdev->exclusive_lock);
	if (rs4xx_reset) {
		radeon_rs4xx_hardware_transition_end(
			rdev, RADEON_RS4XX_HARDWARE_RUNNING);
		if (READ_ONCE(rdev->gpu_parked)) {
			radeon_rs4xx_publish_parked_state(rdev);
			return -EIO;
		}
		drm_kms_helper_poll_enable(rdev_to_drm(rdev));
	}
	return r;

rs4xx_reset_parked_after_downgrade:
	if (!r)
		r = -EIO;
	radeon_rs4xx_publish_parked_state(rdev);
	WRITE_ONCE(rdev->needs_reset, false);
	WRITE_ONCE(rdev->in_reset, false);
	up_read(&rdev->exclusive_lock);
	radeon_rs4xx_hardware_transition_end(
		rdev, RADEON_RS4XX_HARDWARE_PARKED);
	return r;
}

/**
 * radeon_gpu_reset - reset the ASIC after a detected hang
 *
 * @rdev: radeon device pointer
 *
 * The reset executes when needs_reset is set.  Returns 0 for success or an
 * error on failure.
 */
int radeon_gpu_reset(struct radeon_device *rdev)
{
	return radeon_gpu_reset_internal(rdev, false);
}

#if RADEON_MUTATE_DEV
/**
 * radeon_gpu_reset_forced - establish and execute one reset request
 *
 * @rdev: radeon device pointer
 *
 * The writer lock owns the needs_reset transition and the complete production
 * reset.  Returns 0 for success or an error on failure.
 */
int radeon_gpu_reset_forced(struct radeon_device *rdev)
{
	return radeon_gpu_reset_internal(rdev, true);
}
#endif
