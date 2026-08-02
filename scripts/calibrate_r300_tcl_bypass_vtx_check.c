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
 * Exit 0: every case yields its expected verdict and the known-bad
 * shape (the width comparison without the position-presence premise)
 * mishandles at least one case, so the harness distinguishes good from
 * bad.  Exit 1: a case failed.  Exit 2: the known-bad shape passed the
 * whole matrix, so the harness lost its discrimination.
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

struct calib_case {
	const char *name;
	struct r300_tcl_bypass_vtx_inputs in;
	enum r300_tcl_bypass_vtx_verdict expected;
	unsigned int expected_required;
};


/* Pinned anchor premises; each case starts here and mutates one axis. */
static struct r300_tcl_bypass_vtx_inputs pinned(void)
{
	struct r300_tcl_bypass_vtx_inputs in;

	memset(&in, 0, sizeof(in));
	in.tcl_bypass_seen = 1;
	in.fmt0_seen = 1;
	in.fmt1_seen = 1;
	in.vtx_size_seen = 1;
	in.ext_identity_complete = 1;
	in.fmt0 = POS;
	in.fmt1 = TWO_TEX4;
	in.vtx_size = 8;
	return in;
}

#define NCASES 16
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
	c->name = "color present";
	c->in = pinned();
	c->in.fmt0 = POS | COLOR_PRESENT;
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
	c->name = "EXT set incomplete or nonidentity";
	c->in = pinned();
	c->in.ext_identity_complete = 0;
	c->expected = R300_TCL_BYPASS_VTX_DECLINE;

	c = &cases[n++];
	c->name = "PRIM_WALK 3 immediate draw";
	c->in = pinned();
	c->in.prim_walk = 3;
	c->expected = R300_TCL_BYPASS_VTX_DECLINE;
}

/* Known-bad shape: the width comparison without the position-presence
 * premise.  A no-position texcoord tuple reaches the comparison and is
 * judged, which is outside the retained-evidence scope. */
static enum r300_tcl_bypass_vtx_verdict
tcl_bypass_vtx_check_no_pos_premise(const struct r300_tcl_bypass_vtx_inputs *in)
{
	unsigned int required = 0;
	unsigned int comp_cnt;
	unsigned int i;

	if (!in->tcl_bypass_seen || !in->fmt0_seen || !in->fmt1_seen ||
	    !in->vtx_size_seen || !in->ext_identity_complete)
		return R300_TCL_BYPASS_VTX_DECLINE;
	if (in->prim_walk == 3)
		return R300_TCL_BYPASS_VTX_DECLINE;
	if (in->fmt0 & ~R300_VAP_OUTPUT_VTX_FMT_0__POS_PRESENT)
		return R300_TCL_BYPASS_VTX_DECLINE;
	if (in->fmt1 & ~0x00FFFFFFUL)
		return R300_TCL_BYPASS_VTX_DECLINE;
	if (in->fmt0 & R300_VAP_OUTPUT_VTX_FMT_0__POS_PRESENT)
		required += 4;
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
	unsigned int bad_deviations = 0;

	build_cases();
	for (i = 0; i < NCASES; i++) {
		const struct calib_case *c = &cases[i];
		unsigned int required = 0;
		enum r300_tcl_bypass_vtx_verdict got =
			r300_tcl_bypass_vtx_check(&c->in, &required);

		if (got != c->expected ||
		    (c->expected != R300_TCL_BYPASS_VTX_DECLINE &&
		     required != c->expected_required)) {
			printf("FAIL %s: got %s required %u, expected %s required %u\n",
			       c->name, verdict_name(got), required,
			       verdict_name(c->expected),
			       c->expected_required);
			failures++;
		}

		if (tcl_bypass_vtx_check_no_pos_premise(&c->in) != c->expected)
			bad_deviations++;
	}

	if (failures) {
		printf("calibration FAILED: %u case(s)\n", failures);
		return 1;
	}
	if (!bad_deviations) {
		printf("known-bad shape passed the whole matrix: discrimination lost\n");
		return 2;
	}
	printf("calibration PASS: %u cases, known-bad deviates on %u\n",
	       (unsigned int)NCASES, bad_deviations);
	return 0;
}
