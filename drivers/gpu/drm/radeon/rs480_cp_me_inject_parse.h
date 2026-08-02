/* CP-ME injection command parser, shared verbatim between
 * radeon_rs4xx_dev.c and the userspace calibration harness
 * scripts/calibrate_rs480_cp_me_inject_parse.c.  The includer supplies
 * sscanf: the kernel build takes it from <linux/sprintf.h> via radeon.h,
 * the harness from <stdio.h>.
 */
#ifndef RS480_CP_ME_INJECT_PARSE_H
#define RS480_CP_ME_INJECT_PARSE_H

/* Parse "ARM <addr> <datah> <datal>" exactly.  The trailing " %c"
 * conversion skips whitespace and then matches any surplus byte, so a
 * payload with text after the third value converts four items and
 * rejects, while trailing whitespace alone still converts three.
 * Returns 1 on an exact command, 0 otherwise.
 */
static inline int rs480_cp_me_inject_parse(const char *kbuf,
					   unsigned int *addr,
					   unsigned int *new_h,
					   unsigned int *new_l)
{
	char extra;

	return sscanf(kbuf, "ARM %x %x %x %c",
		      addr, new_h, new_l, &extra) == 3;
}

#endif
