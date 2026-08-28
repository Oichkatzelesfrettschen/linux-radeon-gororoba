// SPDX-License-Identifier: MIT

/* Calibration for the TCL-bypass vertex-output width decision.
 *
 * Compiles the exact kernel decision function from
 * drivers/gpu/drm/radeon/r300_tcl_bypass_vtx_check.h and drives it
 * through the full decline/pass/reject matrix.  Build and run from the
 * repository root:
 *
 *   cc -O2 -Wall -Wextra -I drivers/gpu/drm/radeon \
 *      scripts/calibrate_r300_tcl_bypass_vtx_check.c \
 *      -o build/calibrate_r300_tcl_bypass_vtx_check
 *   build/calibrate_r300_tcl_bypass_vtx_check
 *
 * Exit 0: every case yields its expected verdict and each known-bad
 * shape mishandles at least one case, so the harness distinguishes good
 * from bad.  Exit 1: a case failed.  Exit 2: a known-bad shape passed
 * the whole matrix, so the harness lost its discrimination.
 *
 * Two known-bad shapes anchor the discrimination: the width comparison
 * without the position-presence premise, and the identity-assumption
 * shape that treats VAP_VTX_SIZE as the delivered width regardless of
 * the PSC selectors -- the exact reading the XY01 extension replaces.
 *
 * The anchor tuple is the retained RS482 capture: position plus two
 * 4-component texcoords, required width 12, where VTX_SIZE 12 retired
 * and VTX_SIZE 8 hung the engine.
 */

#include <stdio.h>
#include <string.h>

#include "r300_tcl_bypass_vtx_check.h"

#define POS R300_VAP_OUTPUT_VTX_FMT_0__POS_PRESENT
#define COLOR_PRESENT (1u << 1)
#define PT_SIZE_PRESENT (1u << 16)
/* Two 4-component texcoords in the 3-bit-per-slot FMT_1 encoding. */
#define TWO_TEX4 (4u | (4u << 3))
/* One 4-component texcoord. */
#define ONE_TEX4 4u

#define IDENT R300_TCL_BYPASS_PSC_IDENTITY_HALF
#define XY01 R300_TCL_BYPASS_PSC_XY01_HALF
#define FLOAT_2 R300_TCL_BYPASS_PSC_DATA_TYPE_FLOAT_2
#define FLOAT_4 R300_TCL_BYPASS_PSC_DATA_TYPE_FLOAT_4
#define LAST R300_TCL_BYPASS_PSC_LAST_VEC

struct calib_case {
	const char *name;
	struct r300_tcl_bypass_vtx_inputs in;
	enum r300_tcl_bypass_vtx_verdict expected;
	unsigned int expected_required;
	/* Nonzero: the fetch width the check must report. */
	unsigned int expected_fetch;
};

/* One CNTL element half: data type, destination vector, optional LAST. */
static unsigned int cntl_half(unsigned int data_type, unsigned int dst_vec,
			      unsigned int last)
{
	return data_type | (dst_vec << 8) | (last ? LAST : 0);
}

/* Pinned anchor premises; each case starts here and mutates one axis.
 * The PSC list declares the anchor's three identity FLOAT_4 elements:
 * position plus two texcoords, elements 0 and 1 in CNTL_0 and element 2
 * closing the list in CNTL_1.
 */
static struct r300_tcl_bypass_vtx_inputs pinned(void)
{
	struct r300_tcl_bypass_vtx_inputs in;

	memset(&in, 0, sizeof(in));
	in.tcl_bypass_seen = 1;
	in.fmt0_seen = 1;
	in.fmt1_seen = 1;
	in.vtx_size_seen = 1;
	in.fmt0 = POS;
	in.fmt1 = TWO_TEX4;
	in.vtx_size = 8;
	in.psc_cntl[0] = cntl_half(FLOAT_4, 0, 0) |
			 (cntl_half(FLOAT_4, 6, 0) << 16);
	in.psc_cntl[1] = cntl_half(FLOAT_4, 7, 1);
	in.psc_ext[0] = IDENT | (IDENT << 16);
	in.psc_ext[1] = IDENT;
	in.psc_cntl_seen_mask = 0x3;
	in.psc_ext_seen_mask = 0x3;
	return in;
}

/* The FLOAT_4 + FLOAT_2 producer tuple: slot vector under identity,
 * model stream under XY01, one CNTL word closing the list, output
 * position plus one texcoord (required 8), fetch 4 + 2 = 6.
 */
static struct r300_tcl_bypass_vtx_inputs float2_tuple(void)
{
	struct r300_tcl_bypass_vtx_inputs in;

	memset(&in, 0, sizeof(in));
	in.tcl_bypass_seen = 1;
	in.fmt0_seen = 1;
	in.fmt1_seen = 1;
	in.vtx_size_seen = 1;
	in.fmt0 = POS;
	in.fmt1 = ONE_TEX4;
	in.vtx_size = 6;
	in.psc_cntl[0] = cntl_half(FLOAT_4, 0, 0) |
			 (cntl_half(FLOAT_2, 6, 1) << 16);
	in.psc_ext[0] = IDENT | (XY01 << 16);
	in.psc_cntl_seen_mask = 0x1;
	in.psc_ext_seen_mask = 0x1;
	return in;
}

/* Position plus COLOR_0: two identity FLOAT_4 elements, DST_VEC 0 for
 * position and DST_VEC 2 for COLOR_0, anchored by the retained RS482
 * direct GA Flat capture (VAP_OUT_VTX_FMT_0 = 0x3, VTX_SIZE 8).
 */
static struct r300_tcl_bypass_vtx_inputs color0_tuple(void)
{
	struct r300_tcl_bypass_vtx_inputs in;

	memset(&in, 0, sizeof(in));
	in.tcl_bypass_seen = 1;
	in.fmt0_seen = 1;
	in.fmt1_seen = 1;
	in.vtx_size_seen = 1;
	in.fmt0 = POS | COLOR_PRESENT;
	in.fmt1 = 0;
	in.vtx_size = 8;
	in.psc_cntl[0] = cntl_half(FLOAT_4, 0, 0) |
			 (cntl_half(FLOAT_4, 2, 1) << 16);
	in.psc_ext[0] = IDENT | (IDENT << 16);
	in.psc_cntl_seen_mask = 0x1;
	in.psc_ext_seen_mask = 0x1;
	return in;
}

#define NCASES 38
static struct calib_case cases[NCASES];

static void build_cases(void)
{
	unsigned int n = 0;
	struct calib_case *c;

	c = &cases[n++];
	c->name = "anchor underdelivery: pos+2tex4 required 12 supplied 8";
	c->in = pinned();
	c->expected = R300_TCL_BYPASS_VTX_REJECT;
	c->expected_required = 12;

	c = &cases[n++];
	c->name = "anchor exact: supplied 12";
	c->in = pinned();
	c->in.vtx_size = 12;
	c->expected = R300_TCL_BYPASS_VTX_PASS;
	c->expected_required = 12;

	c = &cases[n++];
	c->name = "anchor overdelivery: supplied 16";
	c->in = pinned();
	c->in.vtx_size = 16;
	c->expected = R300_TCL_BYPASS_VTX_PASS;
	c->expected_required = 12;

	c = &cases[n++];
	c->name = "position only, supplied 4";
	c->in = pinned();
	c->in.fmt1 = 0;
	c->in.vtx_size = 4;
	c->expected = R300_TCL_BYPASS_VTX_PASS;
	c->expected_required = 4;

	c = &cases[n++];
	c->name = "no position, texcoords present";
	c->in = pinned();
	c->in.fmt0 = 0;
	c->in.vtx_size = 4;
	c->expected = R300_TCL_BYPASS_VTX_DECLINE;

	c = &cases[n++];
	c->name = "empty format tuple";
	c->in = pinned();
	c->in.fmt0 = 0;
	c->in.fmt1 = 0;
	c->in.vtx_size = 0;
	c->expected = R300_TCL_BYPASS_VTX_DECLINE;

	c = &cases[n++];
	c->name = "color present, texcoord tuple underdelivers required 16";
	c->in = pinned();
	c->in.fmt0 = POS | COLOR_PRESENT;
	c->expected = R300_TCL_BYPASS_VTX_REJECT;
	c->expected_required = 16;

	c = &cases[n++];
	c->name = "color0 tuple exact: pos+color0 required 8 supplied 8";
	c->in = color0_tuple();
	c->expected = R300_TCL_BYPASS_VTX_PASS;
	c->expected_required = 8;

	c = &cases[n++];
	c->name = "color0 tuple underdelivery: required 8 supplied 7";
	c->in = color0_tuple();
	c->in.vtx_size = 7;
	c->expected = R300_TCL_BYPASS_VTX_REJECT;
	c->expected_required = 8;

	c = &cases[n++];
	c->name = "color0 plus one texcoord2: required 10 supplied 10";
	c->in = color0_tuple();
	c->in.fmt1 = 2u;
	c->in.psc_cntl[0] = cntl_half(FLOAT_4, 0, 0) |
			    (cntl_half(FLOAT_4, 2, 0) << 16);
	c->in.psc_cntl[1] = cntl_half(FLOAT_2, 6, 1);
	c->in.psc_ext[1] = IDENT;
	c->in.psc_cntl_seen_mask = 0x3;
	c->in.psc_ext_seen_mask = 0x3;
	c->in.vtx_size = 10;
	c->expected = R300_TCL_BYPASS_VTX_PASS;
	c->expected_required = 10;

	c = &cases[n++];
	c->name = "color0 plus one texcoord2: required 10 supplied 9";
	c->in = color0_tuple();
	c->in.fmt1 = 2u;
	c->in.psc_cntl[0] = cntl_half(FLOAT_4, 0, 0) |
			    (cntl_half(FLOAT_4, 2, 0) << 16);
	c->in.psc_cntl[1] = cntl_half(FLOAT_2, 6, 1);
	c->in.psc_ext[1] = IDENT;
	c->in.psc_cntl_seen_mask = 0x3;
	c->in.psc_ext_seen_mask = 0x3;
	c->in.vtx_size = 9;
	c->expected = R300_TCL_BYPASS_VTX_REJECT;
	c->expected_required = 10;

	c = &cases[n++];
	c->name = "COLOR_1 beyond modeled FMT0 bits";
	c->in = pinned();
	c->in.fmt0 = POS | (1u << 2);
	c->expected = R300_TCL_BYPASS_VTX_DECLINE;

	c = &cases[n++];
	c->name = "color0 tuple PSC word unwritten";
	c->in = color0_tuple();
	c->in.psc_cntl_seen_mask = 0;
	c->expected = R300_TCL_BYPASS_VTX_DECLINE;

	c = &cases[n++];
	c->name = "color0 tuple duplicate destination vector";
	c->in = color0_tuple();
	c->in.psc_cntl[0] = cntl_half(FLOAT_4, 0, 0) |
			    (cntl_half(FLOAT_4, 0, 1) << 16);
	c->expected = R300_TCL_BYPASS_VTX_DECLINE;

	c = &cases[n++];
	c->name = "point size present";
	c->in = pinned();
	c->in.fmt0 = POS | PT_SIZE_PRESENT;
	c->expected = R300_TCL_BYPASS_VTX_DECLINE;

	c = &cases[n++];
	c->name = "component count above 4";
	c->in = pinned();
	c->in.fmt1 = 5u;
	c->in.vtx_size = 32;
	c->expected = R300_TCL_BYPASS_VTX_DECLINE;

	c = &cases[n++];
	c->name = "undecoded upper FMT_1 bits";
	c->in = pinned();
	c->in.fmt1 = TWO_TEX4 | 0x01000000u;
	c->expected = R300_TCL_BYPASS_VTX_DECLINE;

	c = &cases[n++];
	c->name = "no TCL-bypass write";
	c->in = pinned();
	c->in.tcl_bypass_seen = 0;
	c->expected = R300_TCL_BYPASS_VTX_DECLINE;

	c = &cases[n++];
	c->name = "FMT_0 unwritten";
	c->in = pinned();
	c->in.fmt0_seen = 0;
	c->expected = R300_TCL_BYPASS_VTX_DECLINE;

	c = &cases[n++];
	c->name = "FMT_1 unwritten";
	c->in = pinned();
	c->in.fmt1_seen = 0;
	c->expected = R300_TCL_BYPASS_VTX_DECLINE;

	c = &cases[n++];
	c->name = "VTX_SIZE unwritten";
	c->in = pinned();
	c->in.vtx_size_seen = 0;
	c->expected = R300_TCL_BYPASS_VTX_DECLINE;

	c = &cases[n++];
	c->name = "consumed CNTL word unwritten";
	c->in = pinned();
	c->in.psc_cntl_seen_mask = 0x1;
	c->expected = R300_TCL_BYPASS_VTX_DECLINE;

	c = &cases[n++];
	c->name = "consumed EXT word unwritten";
	c->in = pinned();
	c->in.psc_ext_seen_mask = 0x1;
	c->expected = R300_TCL_BYPASS_VTX_DECLINE;

	c = &cases[n++];
	c->name = "tail words past LAST unwritten and zero";
	c->in = pinned();
	c->in.psc_cntl[1] = cntl_half(FLOAT_4, 6, 1) |
			    (cntl_half(FLOAT_4, 7, 0) << 16);
	c->in.psc_cntl[0] = cntl_half(FLOAT_4, 0, 0) |
			    (cntl_half(FLOAT_4, 1, 0) << 16);
	c->in.vtx_size = 12;
	c->expected = R300_TCL_BYPASS_VTX_PASS;
	c->expected_required = 12;

	c = &cases[n++];
	c->name = "no LAST element declared";
	c->in = pinned();
	c->in.psc_cntl[1] = cntl_half(FLOAT_4, 7, 0);
	c->expected = R300_TCL_BYPASS_VTX_DECLINE;

	c = &cases[n++];
	c->name = "nonzero SKIP_DWORDS";
	c->in = pinned();
	c->in.psc_cntl[0] |= 1u << 4;
	c->expected = R300_TCL_BYPASS_VTX_DECLINE;

	c = &cases[n++];
	c->name = "selector outside identity and XY01";
	c->in = pinned();
	c->in.psc_ext[0] = IDENT | (0xFB10u << 16);
	c->expected = R300_TCL_BYPASS_VTX_DECLINE;

	c = &cases[n++];
	c->name = "PRIM_WALK 3 immediate draw";
	c->in = pinned();
	c->in.prim_walk = 3;
	c->expected = R300_TCL_BYPASS_VTX_DECLINE;

	c = &cases[n++];
	c->name = "float2 tuple exact: fetch 6 delivered 8 required 8";
	c->in = float2_tuple();
	c->expected = R300_TCL_BYPASS_VTX_PASS;
	c->expected_required = 8;
	c->expected_fetch = 6;

	c = &cases[n++];
	c->name = "float2 tuple underfeed: VTX_SIZE 5 under fetch 6";
	c->in = float2_tuple();
	c->in.vtx_size = 5;
	c->expected = R300_TCL_BYPASS_VTX_REJECT;
	c->expected_required = 8;

	c = &cases[n++];
	c->name = "float2 tuple overfeed: VTX_SIZE 7 over fetch 6";
	c->in = float2_tuple();
	c->in.vtx_size = 7;
	c->expected = R300_TCL_BYPASS_VTX_DECLINE;

	c = &cases[n++];
	c->name = "XY01 over a FLOAT_4 fetch";
	c->in = float2_tuple();
	c->in.psc_cntl[0] = cntl_half(FLOAT_4, 0, 0) |
			    (cntl_half(FLOAT_4, 6, 1) << 16);
	c->in.vtx_size = 8;
	c->expected = R300_TCL_BYPASS_VTX_DECLINE;

	c = &cases[n++];
	c->name = "identity FLOAT_2 underdelivers position";
	c->in = float2_tuple();
	c->in.psc_cntl[0] = cntl_half(FLOAT_2, 0, 1);
	c->in.psc_ext[0] = IDENT;
	c->in.fmt1 = 0;
	c->in.vtx_size = 2;
	c->expected = R300_TCL_BYPASS_VTX_REJECT;
	c->expected_required = 4;

	c = &cases[n++];
	c->name = "identity BYTE element keeps the anchored arithmetic";
	c->in = pinned();
	c->in.psc_cntl[1] = cntl_half(4 /* DATA_TYPE_BYTE */, 7, 1);
	c->in.vtx_size = 12;
	c->expected = R300_TCL_BYPASS_VTX_PASS;
	c->expected_required = 12;
	c->expected_fetch = 12;

	c = &cases[n++];
	c->name = "sixteen elements without LAST_VEC";
	c->in = pinned();
	for (unsigned int w = 0; w < 8; w++) {
		c->in.psc_cntl[w] = cntl_half(FLOAT_4, (2 * w) & 0x1F, 0) |
				    (cntl_half(FLOAT_4, (2 * w + 1) & 0x1F, 0)
				     << 16);
		c->in.psc_ext[w] = IDENT | (IDENT << 16);
	}
	c->in.psc_cntl_seen_mask = 0xFF;
	c->in.psc_ext_seen_mask = 0xFF;
	c->expected = R300_TCL_BYPASS_VTX_DECLINE;

	c = &cases[n++];
	c->name = "unknowable width beside a synthesized element";
	c->in = float2_tuple();
	c->in.psc_cntl[0] = cntl_half(4 /* DATA_TYPE_BYTE */, 0, 0) |
			    (cntl_half(FLOAT_2, 6, 1) << 16);
	c->expected = R300_TCL_BYPASS_VTX_DECLINE;

	c = &cases[n++];
	c->name = "identity overfeed keeps the anchored arithmetic";
	c->in = pinned();
	c->in.psc_cntl[1] = cntl_half(FLOAT_4, 7, 1);
	c->in.vtx_size = 16;
	c->expected = R300_TCL_BYPASS_VTX_PASS;
	c->expected_required = 12;
	c->expected_fetch = 16;

	c = &cases[n++];
	c->name = "two elements writing one destination vector";
	c->in = float2_tuple();
	c->in.psc_cntl[0] = cntl_half(FLOAT_4, 0, 0) |
			    (cntl_half(FLOAT_2, 0, 1) << 16);
	c->expected = R300_TCL_BYPASS_VTX_DECLINE;

	if (n != NCASES) {
		printf("case table drifted: built %u of %u\n", n,
		       (unsigned int)NCASES);
		__builtin_trap();
	}
}

/* Known-bad shape: the width comparison without the position-presence
 * premise.  A no-position texcoord tuple reaches the comparison and is
 * judged, which is outside the retained-evidence scope. */
static enum r300_tcl_bypass_vtx_verdict
tcl_bypass_vtx_check_no_pos_premise(const struct r300_tcl_bypass_vtx_inputs *in)
{
	struct r300_tcl_bypass_vtx_inputs relaxed = *in;

	relaxed.fmt0 |= R300_VAP_OUTPUT_VTX_FMT_0__POS_PRESENT;
	if (in->fmt0 & ~R300_VAP_OUTPUT_VTX_FMT_0__POS_PRESENT)
		return R300_TCL_BYPASS_VTX_DECLINE;
	return r300_tcl_bypass_vtx_check(&relaxed, NULL, NULL);
}

/* Known-bad shape: a selector-blind checker.  VAP_VTX_SIZE is taken as
 * the delivered width whatever the PSC selectors say, so a synthesized
 * XY01 tuple is judged by its fetch width -- the failure class the
 * per-element decode exists to prevent. */
static enum r300_tcl_bypass_vtx_verdict
tcl_bypass_vtx_check_identity_assumption(
	const struct r300_tcl_bypass_vtx_inputs *in)
{
	unsigned int required = 4;
	unsigned int comp_cnt;
	unsigned int i;

	if (!in->tcl_bypass_seen || !in->fmt0_seen || !in->fmt1_seen ||
	    !in->vtx_size_seen || !in->psc_cntl_seen_mask ||
	    !in->psc_ext_seen_mask)
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
	if (in->vtx_size < required)
		return R300_TCL_BYPASS_VTX_REJECT;
	return R300_TCL_BYPASS_VTX_PASS;
}

/* Known-bad shape: the width baseline omits COLOR_0's four-dword
 * contribution, so a COLOR_0 tuple is judged by the position-only
 * floor -- the miscount the COLOR_0 width addition exists to
 * prevent. */
static enum r300_tcl_bypass_vtx_verdict
tcl_bypass_vtx_check_color0_width_miss(
	const struct r300_tcl_bypass_vtx_inputs *in)
{
	unsigned int required = 4;
	unsigned int delivered = 0;
	unsigned int fetch = 0;
	unsigned int dst_vec_mask = 0;
	unsigned int comp_cnt;
	unsigned int identity_only = 1;
	unsigned int widths_known = 1;
	unsigned int last_seen = 0;
	unsigned int e, i;

	if (!in->tcl_bypass_seen || !in->fmt0_seen || !in->fmt1_seen ||
	    !in->vtx_size_seen)
		return R300_TCL_BYPASS_VTX_DECLINE;
	if (in->prim_walk == 3)
		return R300_TCL_BYPASS_VTX_DECLINE;
	if (!(in->fmt0 & R300_VAP_OUTPUT_VTX_FMT_0__POS_PRESENT))
		return R300_TCL_BYPASS_VTX_DECLINE;
	if (in->fmt0 & ~(R300_VAP_OUTPUT_VTX_FMT_0__POS_PRESENT |
			 R300_VAP_OUTPUT_VTX_FMT_0__COLOR_PRESENT))
		return R300_TCL_BYPASS_VTX_DECLINE;
	if (in->fmt1 & ~0x00FFFFFFUL)
		return R300_TCL_BYPASS_VTX_DECLINE;
	/* Known-bad: the COLOR_0 +4 addition is missing here. */
	for (i = 0; i < 8; i++) {
		comp_cnt = (in->fmt1 >> (3 * i)) & 0x7;
		if (comp_cnt > 4)
			return R300_TCL_BYPASS_VTX_DECLINE;
		required += comp_cnt;
	}
	for (e = 0; e < 16; e++) {
		unsigned int word = e / 2;
		unsigned int cntl_half_v, sel_half, data_type, dst_vec;

		if (!(in->psc_cntl_seen_mask & (1u << word)) ||
		    !(in->psc_ext_seen_mask & (1u << word)))
			return R300_TCL_BYPASS_VTX_DECLINE;
		cntl_half_v = (e & 1) ? (in->psc_cntl[word] >> 16)
				      : (in->psc_cntl[word] & 0xFFFFu);
		sel_half = (e & 1) ? (in->psc_ext[word] >> 16)
				   : (in->psc_ext[word] & 0xFFFFu);
		data_type = cntl_half_v & 0xFu;
		dst_vec = (cntl_half_v >> 8) & 0x1Fu;
		if ((cntl_half_v >> 4) & 0xFu)
			return R300_TCL_BYPASS_VTX_DECLINE;
		if (dst_vec_mask & (1u << dst_vec))
			return R300_TCL_BYPASS_VTX_DECLINE;
		dst_vec_mask |= 1u << dst_vec;

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
		if (cntl_half_v & R300_TCL_BYPASS_PSC_LAST_VEC) {
			last_seen = 1;
			break;
		}
	}
	if (!last_seen)
		return R300_TCL_BYPASS_VTX_DECLINE;
	if (!identity_only && !widths_known)
		return R300_TCL_BYPASS_VTX_DECLINE;

	if (identity_only) {
		delivered = in->vtx_size;
		fetch = in->vtx_size;
	}
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

static const char *verdict_name(enum r300_tcl_bypass_vtx_verdict v)
{
	switch (v) {
	case R300_TCL_BYPASS_VTX_DECLINE: return "DECLINE";
	case R300_TCL_BYPASS_VTX_PASS: return "PASS";
	case R300_TCL_BYPASS_VTX_REJECT: return "REJECT";
	}
	return "?";
}

int main(void)
{
	unsigned int i;
	unsigned int failures = 0;
	unsigned int no_pos_deviations = 0;
	unsigned int identity_deviations = 0;
	unsigned int color0_width_deviations = 0;

	build_cases();
	for (i = 0; i < NCASES; i++) {
		const struct calib_case *c = &cases[i];
		unsigned int required = 0;
		unsigned int fetch = 0;
		enum r300_tcl_bypass_vtx_verdict got =
			r300_tcl_bypass_vtx_check(&c->in, &required, &fetch);

		if (got != c->expected ||
		    (c->expected != R300_TCL_BYPASS_VTX_DECLINE &&
		     required != c->expected_required) ||
		    (c->expected_fetch != 0 && fetch != c->expected_fetch)) {
			printf("FAIL %s: got %s required %u fetch %u, expected %s required %u fetch %u\n",
			       c->name, verdict_name(got), required, fetch,
			       verdict_name(c->expected),
			       c->expected_required, c->expected_fetch);
			failures++;
		}

		if (tcl_bypass_vtx_check_no_pos_premise(&c->in) != c->expected)
			no_pos_deviations++;
		if (tcl_bypass_vtx_check_identity_assumption(&c->in) !=
		    c->expected)
			identity_deviations++;
		if (tcl_bypass_vtx_check_color0_width_miss(&c->in) !=
		    c->expected)
			color0_width_deviations++;
	}

	if (failures) {
		printf("calibration FAILED: %u case(s)\n", failures);
		return 1;
	}
	if (!no_pos_deviations || !identity_deviations ||
	    !color0_width_deviations) {
		printf("a known-bad shape passed the whole matrix: discrimination lost (no-pos %u, identity %u, color0-width %u)\n",
		       no_pos_deviations, identity_deviations,
		       color0_width_deviations);
		return 2;
	}
	printf("calibration PASS: %u cases, no-pos known-bad deviates on %u, identity known-bad deviates on %u, color0-width known-bad deviates on %u\n",
	       (unsigned int)NCASES, no_pos_deviations, identity_deviations,
	       color0_width_deviations);
	return 0;
}
