/* SPDX-License-Identifier: MIT */

/* RS480 reset-mask atomic claim loop, shared verbatim between
 * radeon_rs4xx_dev.c and the userspace race calibration harness
 * scripts/calibrate_rs480_reset_mask_claim.c.  The includer supplies
 * READ_ONCE and cmpxchg: the kernel build takes them from
 * <linux/compiler.h> and <linux/atomic.h>, the harness maps them onto
 * compiler atomics with sequentially consistent ordering.
 */
#ifndef RADEON_RS4XX_RESET_MASK_CLAIM_H
#define RADEON_RS4XX_RESET_MASK_CLAIM_H

/* Consume one armed selection from *selp and return it, or return
 * baseline when nothing was claimed.  *selp is writable concurrently
 * (a 0644 sysfs module param in the kernel build), so the nonbaseline
 * value returns only for a selector this caller claimed:
 * cmpxchg(sel -> baseline) succeeds for exactly one caller per armed
 * selection, so concurrent callers consume at most one selection, and
 * a concurrent disarm or selector replacement fails the cmpxchg, after
 * which the re-read observes the new value.  An out-of-range value
 * yields baseline with no consume.
 */
static inline unsigned int rs480_reset_mask_claim(unsigned int *selp,
						  unsigned int baseline,
						  unsigned int count)
{
	unsigned int sel;

	do {
		sel = READ_ONCE(*selp);
		if (sel == baseline || sel >= count)
			return baseline;
	} while (cmpxchg(selp, sel, baseline) != sel);
	return sel;
}

#endif
