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

/* PSC selector halves: each VAP_PROG_STREAM_CNTL_EXT register carries a
 * 16-bit swizzle-and-write-mask half per vertex element.  The identity
 * half selects X, Y, Z, W with a full write mask, so one fetched dword
 * maps to one delivered lane.  The XY01 half selects X, Y, FP_ZERO,
 * FP_ONE with a full write mask: a two-dword FLOAT_2 fetch delivers a
 * complete four-lane vector with Z and W synthesized as constants.
 */
#define R300_TCL_BYPASS_PSC_IDENTITY_HALF 0xF688u
#define R300_TCL_BYPASS_PSC_XY01_HALF 0xFB08u

/* VAP_PROG_STREAM_CNTL element-half fields: DATA_TYPE bits 0:3,
 * SKIP_DWORDS bits 4:7, DST_VEC_LOC bits 8:12, LAST_VEC bit 13.
 * FLOAT_1 through FLOAT_4 encode as 0 through 3, so the fetch width of
 * a plain-float element is DATA_TYPE plus one dword.
 */
#define R300_TCL_BYPASS_PSC_DATA_TYPE_FLOAT_2 1u
#define R300_TCL_BYPASS_PSC_DATA_TYPE_FLOAT_4 3u
#define R300_TCL_BYPASS_PSC_LAST_VEC (1u << 13)

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
	/* Bit i: VAP_PROG_STREAM_CNTL_i written in this CS. */
	unsigned char psc_cntl_seen_mask;
	/* Bit i: VAP_PROG_STREAM_CNTL_EXT_i written in this CS. */
	unsigned char psc_ext_seen_mask;
	unsigned char prim_walk;	/* VAP_VF_CNTL bits 5:4 */
	unsigned int fmt0;		/* VAP_OUT_VTX_FMT_0 value */
	unsigned int fmt1;		/* VAP_OUT_VTX_FMT_1 value */
	unsigned int vtx_size;		/* VAP_VTX_SIZE dwords per vertex */
	unsigned int psc_cntl[8];	/* VAP_PROG_STREAM_CNTL_0..7 values */
	unsigned int psc_ext[8];	/* VAP_PROG_STREAM_CNTL_EXT_0..7 values */
};

/* The proven output shape is position (4 dwords) plus texture
 * coordinates (each a 3-bit component count, 0 to 4), anchored by the
 * retained RS482 capture where VTX_SIZE 12 retired and VTX_SIZE 8 hung
 * the identical position-plus-two-texcoord tuple.  A tuple without
 * position, a color or point-size bit (GUESS-marked dword weights in
 * r300_reg.h), an undecoded upper format bit, a component count above
 * 4, an incomplete pinned-input set, and a PRIM_WALK 3 immediate draw
 * each decline.
 *
 * The delivered width comes from the PSC element list.  The element
 * walk consumes VAP_PROG_STREAM_CNTL halves through the LAST_VEC bit;
 * every consumed element needs its CNTL and EXT registers written in
 * this CS, and EXT registers past the last element carry no meaning, so
 * their content and write state stay out of the decision.  An
 * all-identity element list keeps the anchored arithmetic: one fetched
 * dword is one delivered lane, so VAP_VTX_SIZE is the delivered width.
 * A FLOAT_2 element under the XY01 selector fetches two dwords and
 * delivers a complete four-lane vector; that list leaves the
 * identity regime, so VAP_VTX_SIZE must equal the summed fetch widths
 * exactly (the underfeed rejects, the overfeed leaves the proven scope)
 * and the delivered width is the summed per-element delivery.  A
 * nonzero SKIP_DWORDS field, a selector half outside identity and XY01,
 * XY01 paired with a data type other than FLOAT_2, and a non-identity
 * list containing an element of unknowable fetch width each decline.
 */
static inline enum r300_tcl_bypass_vtx_verdict
r300_tcl_bypass_vtx_check(const struct r300_tcl_bypass_vtx_inputs *in,
			  unsigned int *required_dwords,
			  unsigned int *fetch_dwords)
{
	unsigned int required = 4;
	unsigned int delivered = 0;
	unsigned int fetch = 0;
	unsigned int comp_cnt;
	unsigned int identity_only = 1;
	unsigned int widths_known = 1;
	unsigned int last_seen = 0;
	unsigned int e;
	unsigned int i;

	if (!in->tcl_bypass_seen || !in->fmt0_seen || !in->fmt1_seen ||
	    !in->vtx_size_seen)
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

	for (e = 0; e < 16; e++) {
		unsigned int word = e / 2;
		unsigned int cntl_half;
		unsigned int sel_half;
		unsigned int data_type;

		if (!(in->psc_cntl_seen_mask & (1u << word)) ||
		    !(in->psc_ext_seen_mask & (1u << word)))
			return R300_TCL_BYPASS_VTX_DECLINE;
		cntl_half = (e & 1) ? (in->psc_cntl[word] >> 16)
				    : (in->psc_cntl[word] & 0xFFFFu);
		sel_half = (e & 1) ? (in->psc_ext[word] >> 16)
				   : (in->psc_ext[word] & 0xFFFFu);
		data_type = cntl_half & 0xFu;
		if ((cntl_half >> 4) & 0xFu)
			return R300_TCL_BYPASS_VTX_DECLINE;

		if (sel_half == R300_TCL_BYPASS_PSC_IDENTITY_HALF) {
			if (data_type <= R300_TCL_BYPASS_PSC_DATA_TYPE_FLOAT_4) {
				fetch += data_type + 1;
				delivered += data_type + 1;
			} else {
				widths_known = 0;
			}
		} else if (sel_half == R300_TCL_BYPASS_PSC_XY01_HALF &&
			   data_type == R300_TCL_BYPASS_PSC_DATA_TYPE_FLOAT_2) {
			identity_only = 0;
			fetch += 2;
			delivered += 4;
		} else {
			return R300_TCL_BYPASS_VTX_DECLINE;
		}

		if (cntl_half & R300_TCL_BYPASS_PSC_LAST_VEC) {
			last_seen = 1;
			break;
		}
	}
	if (!last_seen)
		return R300_TCL_BYPASS_VTX_DECLINE;

	if (identity_only) {
		delivered = in->vtx_size;
		fetch = in->vtx_size;
	} else if (!widths_known) {
		return R300_TCL_BYPASS_VTX_DECLINE;
	}

	if (required_dwords)
		*required_dwords = required;
	if (fetch_dwords)
		*fetch_dwords = fetch;

	if (!identity_only) {
		if (in->vtx_size < fetch)
			return R300_TCL_BYPASS_VTX_REJECT;
		if (in->vtx_size != fetch)
			return R300_TCL_BYPASS_VTX_DECLINE;
	}
	if (delivered < required)
		return R300_TCL_BYPASS_VTX_REJECT;
	return R300_TCL_BYPASS_VTX_PASS;
}

#endif
