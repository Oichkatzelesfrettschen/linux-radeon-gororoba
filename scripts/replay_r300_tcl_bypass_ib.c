// SPDX-License-Identifier: MIT

/* Offline replay of a raw PM4 indirect buffer through the TCL-bypass
 * vertex-output width decision.
 *
 * The tool walks a little-endian dword stream the way r300_cs_parse
 * does: PACKET0 writes update the same register tracking that
 * r300_packet0_check keeps (VAP_VF_CNTL 0x2084, VAP_OUT_VTX_FMT_0/1
 * 0x2090/0x2094, VAP_VTX_SIZE 0x20B4, VAP_CNTL_STATUS 0x2140,
 * VAP_PROG_STREAM_CNTL_EXT_0..7 0x21E0-0x21FC), and each PACKET3 draw
 * (VBUF/IMMD/INDX and the _2 forms, opcodes 0x28-0x2A/0x34-0x36)
 * evaluates r300_tcl_bypass_vtx_check exactly as
 * r300_cs_tcl_bypass_vtx_output_check does at parse time, taking
 * VAP_VF_CNTL from the draw packet payload for the packet forms that
 * carry it.  The decision function is compiled from the same header the
 * kernel uses, so a verdict here is the verdict the CS parser returns
 * for the same dwords.
 *
 * Usage: replay_r300_tcl_bypass_ib [--set-vtx-size N] ib.bin
 *
 * --set-vtx-size N rewrites the payload of every VAP_VTX_SIZE write in
 * the stream before replay, which turns one retained capture into the
 * malformed/corrected pair without touching packet structure.
 *
 * Output: one "draw idx=... verdict=..." line per draw packet plus a
 * final "replay draws=N pass=N reject=N decline=N" summary.  Exit 0
 * with at least one draw found, 1 on stream decode failure, 2 on usage
 * or I/O failure.
 */

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "r300_tcl_bypass_vtx_check.h"

#define R300_VAP_TCL_BYPASS (1u << 8)

struct tracker {
	unsigned int vap_vf_cntl;
	unsigned int fmt0, fmt1, vtx_size, cntl_status;
	unsigned char fmt0_seen, fmt1_seen, vtx_size_seen, cntl_status_seen;
	unsigned char psc_ext_seen_mask, psc_ext_nonident;
};

static const char *verdict_name(enum r300_tcl_bypass_vtx_verdict v)
{
	switch (v) {
	case R300_TCL_BYPASS_VTX_PASS: return "PASS";
	case R300_TCL_BYPASS_VTX_REJECT: return "REJECT";
	default: return "DECLINE";
	}
}

static void track_write(struct tracker *t, unsigned int reg,
			unsigned int val)
{
	if (reg == 0x2084) {
		t->vap_vf_cntl = val;
	} else if (reg == 0x2090) {
		t->fmt0 = val;
		t->fmt0_seen = 1;
	} else if (reg == 0x2094) {
		t->fmt1 = val;
		t->fmt1_seen = 1;
	} else if (reg == 0x20B4) {
		t->vtx_size = val & 0x7F;
		t->vtx_size_seen = 1;
	} else if (reg == 0x2140) {
		t->cntl_status = val;
		t->cntl_status_seen = 1;
	} else if (reg >= 0x21E0 && reg <= 0x21FC) {
		if (val != 0xF688F688)
			t->psc_ext_nonident = 1;
		t->psc_ext_seen_mask |= 1u << ((reg - 0x21E0) >> 2);
	}
}

/* Emit the full premise vector for one draw, evaluating every decline
 * condition independently rather than short-circuiting, so a corpus census
 * can attribute each decline to its cause set.  "first" names the condition
 * r300_tcl_bypass_vtx_check returns on, in that function's own order. */
static void emit_reasons(const struct tracker *t, long idx, unsigned int op,
			 enum r300_tcl_bypass_vtx_verdict v,
			 unsigned int required)
{
	unsigned int pos_bit = R300_VAP_OUTPUT_VTX_FMT_0__POS_PRESENT;
	int tcl = t->cntl_status_seen && (t->cntl_status & R300_VAP_TCL_BYPASS);
	int ext_complete = t->psc_ext_seen_mask == 0xff && !t->psc_ext_nonident;
	unsigned int pw = (t->vap_vf_cntl >> 4) & 0x3;
	int pos = t->fmt0_seen && (t->fmt0 & pos_bit);
	unsigned int fmt0_extra = t->fmt0_seen ? (t->fmt0 & ~pos_bit) : 0;
	unsigned int fmt1_undec = t->fmt1_seen ? (t->fmt1 & ~0x00FFFFFFu) : 0;
	int comp_gt4 = 0;
	unsigned int i;
	const char *first = "-";

	if (t->fmt1_seen)
		for (i = 0; i < 8; i++)
			if (((t->fmt1 >> (3 * i)) & 0x7) > 4)
				comp_gt4 = 1;

	if (!tcl)
		first = "no_tcl_bypass";
	else if (!t->fmt0_seen)
		first = "no_fmt0";
	else if (!t->fmt1_seen)
		first = "no_fmt1";
	else if (!t->vtx_size_seen)
		first = "no_vtx_size";
	else if (!ext_complete)
		first = t->psc_ext_seen_mask != 0xff ? "ext_incomplete"
						     : "ext_nonidentity";
	else if (pw == 3)
		first = "prim_walk_immediate";
	else if (!pos)
		first = "position_absent";
	else if (fmt0_extra)
		first = "fmt0_beyond_position";
	else if (fmt1_undec)
		first = "fmt1_undecoded";
	else if (comp_gt4)
		first = "component_gt4";

	printf("reason idx=%ld op=0x%02X verdict=%s first=%s pin_tcl=%d "
	       "pin_fmt0=%u pin_fmt1=%u pin_vtx=%u ext_mask=0x%02x "
	       "ext_nonident=%u pw_imm=%d pos_present=%d fmt0_extra=0x%08x "
	       "fmt1_undecoded=0x%08x comp_gt4=%d vtx_size=%u required=%u\n",
	       idx, op, verdict_name(v), first, tcl, t->fmt0_seen,
	       t->fmt1_seen, t->vtx_size_seen, t->psc_ext_seen_mask,
	       t->psc_ext_nonident, pw == 3, pos, fmt0_extra, fmt1_undec,
	       comp_gt4, t->vtx_size, required);
}

static enum r300_tcl_bypass_vtx_verdict
draw_check(const struct tracker *t, unsigned int *required)
{
	struct r300_tcl_bypass_vtx_inputs in = {
		.tcl_bypass_seen = t->cntl_status_seen &&
			(t->cntl_status & R300_VAP_TCL_BYPASS),
		.fmt0_seen = t->fmt0_seen,
		.fmt1_seen = t->fmt1_seen,
		.vtx_size_seen = t->vtx_size_seen,
		.ext_identity_complete = !t->psc_ext_nonident &&
			t->psc_ext_seen_mask == 0xff,
		.prim_walk = (t->vap_vf_cntl >> 4) & 0x3,
		.fmt0 = t->fmt0,
		.fmt1 = t->fmt1,
		.vtx_size = t->vtx_size,
	};

	return r300_tcl_bypass_vtx_check(&in, required);
}

int main(int argc, char **argv)
{
	uint32_t *ib;
	long size, ndw, i;
	unsigned int forced_vtx_size = 0;
	int force = 0, reasons = 0, arg = 1;
	unsigned int draws = 0, pass = 0, reject = 0, decline = 0;
	struct tracker t;
	FILE *f;

	setbuf(stdout, NULL);
	while (arg < argc && argv[arg][0] == '-') {
		if (strcmp(argv[arg], "--reasons") == 0) {
			reasons = 1;
			arg += 1;
		} else if (strcmp(argv[arg], "--set-vtx-size") == 0 &&
			   arg + 1 < argc) {
			forced_vtx_size =
				(unsigned int)strtoul(argv[arg + 1], NULL, 0);
			force = 1;
			arg += 2;
		} else {
			break;
		}
	}
	if (arg != argc - 1) {
		fprintf(stderr,
			"usage: %s [--reasons] [--set-vtx-size N] ib.bin\n",
			argv[0]);
		return 2;
	}
	f = fopen(argv[arg], "rb");
	if (!f) {
		fprintf(stderr, "open %s: %s\n", argv[arg], strerror(errno));
		return 2;
	}
	fseek(f, 0, SEEK_END);
	size = ftell(f);
	fseek(f, 0, SEEK_SET);
	if (size <= 0 || (size & 3)) {
		fprintf(stderr, "ib size %ld is not a dword multiple\n", size);
		fclose(f);
		return 2;
	}
	ib = malloc((size_t)size);
	if (!ib || fread(ib, 1, (size_t)size, f) != (size_t)size) {
		fprintf(stderr, "read %s failed\n", argv[arg]);
		fclose(f);
		return 2;
	}
	fclose(f);
	ndw = size >> 2;

	/* Retained steinmarder captures wrap the dword stream in an
	 * R3RKIB1 container: an 8-byte magic, a header-size dword at
	 * byte offset 0xC, and the payload dword count at byte offset
	 * 0x14, with the raw stream starting at header-size.  A bare
	 * file replays from byte 0. */
	if (size >= 24 && memcmp(ib, "R3RKIB1\0", 8) == 0) {
		uint32_t hdr_size = ib[3];
		uint32_t payload_ndw = ib[5];

		if ((hdr_size & 3) || hdr_size >= (uint32_t)size ||
		    hdr_size / 4 + payload_ndw > (uint32_t)ndw) {
			fprintf(stderr, "R3RKIB1 header inconsistent\n");
			free(ib);
			return 2;
		}
		memmove(ib, ib + hdr_size / 4, (size_t)payload_ndw * 4);
		ndw = payload_ndw;
	}

	memset(&t, 0, sizeof(t));
	for (i = 0; i < ndw;) {
		uint32_t header = ib[i];
		unsigned int type = header >> 30;
		unsigned int count = (header >> 16) & 0x3FFF;

		if (type == 0) {
			unsigned int reg = (header & 0x1FFF) << 2;
			unsigned int one_reg = (header >> 15) & 1;
			unsigned int j;

			if ((long)(i + 1 + count) >= ndw) {
				fprintf(stderr,
					"PACKET0 at %ld overruns stream\n", i);
				free(ib);
				return 1;
			}
			for (j = 0; j <= count; j++) {
				unsigned int r = one_reg ? reg : reg + 4 * j;

				if (force && r == 0x20B4)
					ib[i + 1 + j] = forced_vtx_size;
				track_write(&t, r, ib[i + 1 + j]);
			}
			i += 2 + count;
		} else if (type == 2) {
			i += 1;
		} else if (type == 3) {
			unsigned int op = (header >> 8) & 0xFF;
			int is_draw = 0;

			if ((long)(i + 1 + count) >= ndw) {
				fprintf(stderr,
					"PACKET3 at %ld overruns stream\n", i);
				free(ib);
				return 1;
			}
			switch (op) {
			case 0x28: /* 3D_DRAW_VBUF: VF_CNTL at payload+1 */
			case 0x2A: /* 3D_DRAW_INDX */
				t.vap_vf_cntl = ib[i + 2];
				is_draw = 1;
				break;
			case 0x29: /* 3D_DRAW_IMMD: VF_CNTL at payload+1 */
				t.vap_vf_cntl = ib[i + 2];
				is_draw = 1;
				break;
			case 0x34: /* 3D_DRAW_VBUF_2: VF_CNTL at payload */
			case 0x35: /* 3D_DRAW_IMMD_2 */
			case 0x36: /* 3D_DRAW_INDX_2 */
				t.vap_vf_cntl = ib[i + 1];
				is_draw = 1;
				break;
			default:
				break;
			}
			if (is_draw) {
				unsigned int required = 0;
				enum r300_tcl_bypass_vtx_verdict v =
					draw_check(&t, &required);

				draws++;
				if (v == R300_TCL_BYPASS_VTX_PASS)
					pass++;
				else if (v == R300_TCL_BYPASS_VTX_REJECT)
					reject++;
				else
					decline++;
				printf("draw idx=%ld op=0x%02X vf_cntl=0x%08x "
				       "tcl_bypass=%u fmt0=0x%08x fmt1=0x%08x "
				       "vtx_size=%u required=%u ext_mask=0x%02x "
				       "ext_nonident=%u verdict=%s\n",
				       i, op, t.vap_vf_cntl,
				       t.cntl_status_seen &&
				       !!(t.cntl_status & R300_VAP_TCL_BYPASS),
				       t.fmt0, t.fmt1, t.vtx_size, required,
				       t.psc_ext_seen_mask,
				       t.psc_ext_nonident, verdict_name(v));
				if (reasons)
					emit_reasons(&t, i, op, v,
						     required);
			}
			i += 2 + count;
		} else {
			fprintf(stderr, "unknown packet type %u at %ld\n",
				type, i);
			free(ib);
			return 1;
		}
	}
	free(ib);
	printf("replay draws=%u pass=%u reject=%u decline=%u\n",
	       draws, pass, reject, decline);
	return draws ? 0 : 1;
}
