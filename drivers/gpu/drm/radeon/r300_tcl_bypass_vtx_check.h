/* TCL-bypass vertex-output width decision, shared verbatim between
 * r300.c and the userspace calibration harness
 * scripts/calibrate_r300_tcl_bypass_vtx_check.c.  The function is pure:
 * every input arrives decoded in the argument struct, so the kernel
 * caller and the harness exercise identical arithmetic and scope
 * boundaries.
 */
#ifndef R300_TCL_BYPASS_VTX_CHECK_H
#define R300_TCL_BYPASS_VTX_CHECK_H

#ifndef R300_VAP_OUTPUT_VTX_FMT_0__POS_PRESENT
#define R300_VAP_OUTPUT_VTX_FMT_0__POS_PRESENT (1 << 0)
#endif

enum r300_tcl_bypass_vtx_verdict {
	/* The pinned-input premises do not all hold, so the width claim is
	 * outside the proven scope and the ordinary CS tracking stands
	 * alone. */
	R300_TCL_BYPASS_VTX_DECLINE,
	/* The streamed vertex meets or exceeds the tuple width. */
	R300_TCL_BYPASS_VTX_PASS,
	/* The streamed vertex underdelivers the tuple width, the shape
	 * that starves the GA and wedges the vertex front end. */
	R300_TCL_BYPASS_VTX_REJECT,
};

struct r300_tcl_bypass_vtx_inputs {
	/* VAP_CNTL_STATUS written in this CS with R300_VAP_TCL_BYPASS set. */
	unsigned char tcl_bypass_seen;
	unsigned char fmt0_seen;	/* VAP_OUT_VTX_FMT_0 written */
	unsigned char fmt1_seen;	/* VAP_OUT_VTX_FMT_1 written */
	unsigned char vtx_size_seen;	/* VAP_VTX_SIZE written */
	/* All eight VAP_PROG_STREAM_CNTL_EXT_0..7 written identity. */
	unsigned char ext_identity_complete;
	unsigned char prim_walk;	/* VAP_VF_CNTL bits 5:4 */
	unsigned int fmt0;		/* VAP_OUT_VTX_FMT_0 value */
	unsigned int fmt1;		/* VAP_OUT_VTX_FMT_1 value */
	unsigned int vtx_size;		/* VAP_VTX_SIZE dwords per vertex */
};

/* The proven shape is position (4 dwords) plus texture coordinates (each
 * a 3-bit component count, 0 to 4), anchored by the retained RS482
 * capture where VTX_SIZE 12 retired and VTX_SIZE 8 hung the identical
 * position-plus-two-texcoord tuple.  A tuple without position, a color or
 * point-size bit (GUESS-marked dword weights in r300_reg.h), an
 * undecoded upper format bit, a component count above 4, an incomplete
 * pinned-input set, and a PRIM_WALK 3 immediate draw each decline.
 */
static inline enum r300_tcl_bypass_vtx_verdict
r300_tcl_bypass_vtx_check(const struct r300_tcl_bypass_vtx_inputs *in,
			  unsigned int *required_dwords)
{
	unsigned int required = 4;
	unsigned int comp_cnt;
	unsigned int i;

	if (!in->tcl_bypass_seen || !in->fmt0_seen || !in->fmt1_seen ||
	    !in->vtx_size_seen || !in->ext_identity_complete)
		return R300_TCL_BYPASS_VTX_DECLINE;
	if (in->prim_walk == 3)
		return R300_TCL_BYPASS_VTX_DECLINE;
	if (!(in->fmt0 & R300_VAP_OUTPUT_VTX_FMT_0__POS_PRESENT))
		return R300_TCL_BYPASS_VTX_DECLINE;
	if (in->fmt0 & ~R300_VAP_OUTPUT_VTX_FMT_0__POS_PRESENT)
		return R300_TCL_BYPASS_VTX_DECLINE;
	if (in->fmt1 & ~0x00FFFFFFUL)
		return R300_TCL_BYPASS_VTX_DECLINE;

	for (i = 0; i < 8; i++) {
		comp_cnt = (in->fmt1 >> (3 * i)) & 0x7;
		if (comp_cnt > 4)
			return R300_TCL_BYPASS_VTX_DECLINE;
		required += comp_cnt;
	}

	if (required_dwords)
		*required_dwords = required;
	if (in->vtx_size < required)
		return R300_TCL_BYPASS_VTX_REJECT;
	return R300_TCL_BYPASS_VTX_PASS;
}

#endif
