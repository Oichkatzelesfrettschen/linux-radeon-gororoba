// SPDX-License-Identifier: MIT

/* Offline replay of a raw PM4 indirect buffer through the r300 command-stream
 * parser and the r100 tracking state it feeds.
 *
 * The tool walks a little-endian dword stream in the order r300_cs_parse
 * does: radeon_cs_packet_parse frames each packet and bounds it against the
 * chunk, r100_cs_parse_packet0 admits a register only when the r300 safe
 * bitmap carries its bit, r300_packet0_check updates the tracking state a
 * register controls, r100_packet3_load_vbpntr binds the vertex arrays, and
 * every draw opcode runs r100_cs_track_check over the resulting state.  Each
 * relocation is consumed the way radeon_cs_packet_next_reloc consumes it: the
 * type-3 NOP that must follow the consuming packet carries a dword index into
 * the relocation chunk, and the buffer object is entry index/4.
 *
 * The safe bitmap and the register numbers come from the kernel tree this
 * tool is built in, so an acceptance here is the parser's acceptance for the
 * same dwords and the same buffer objects.
 *
 * Scope: the texture path is modeled to the point the fixed cell reaches --
 * TX_ENABLE selects which texture units the check walks, and a unit enabled
 * without a bound texture buffer is rejected.  The mip-level and cube-face
 * size arithmetic of r100_cs_track_texture_check is outside the model, which
 * is sound only for a stream whose TX_ENABLE clause leaves every unit off;
 * the tool reports the enabled mask so a stream that turns one on is visible
 * rather than silently under-checked.
 *
 * Usage: replay_r300_cs_track [options] bundle.txt ib.bin
 *
 * The bundle names the chip family and one line per relocation entry, in
 * chunk order, giving the buffer object's role, byte size, and domains.  The
 * sizes come from the bundle rather than from the tool so a capture and its
 * buffer objects travel together.
 *
 * Options build the malformed controls out of the same stream:
 *   --set-dword IDX=VAL     rewrite one IB dword before the walk
 *   --truncate NDW          replay only the first NDW dwords
 *   --set-bo-size SLOT=N    resize one buffer object
 *   --set-bo-domains SLOT=R,W  rewrite one entry's read and write domains
 *   --set-vtx-size N        rewrite the payload of every VAP_VTX_SIZE write
 *   --verbose               report each tracking decision
 *
 * Output ends in one summary line.  Exit 0 when the stream parses and every
 * draw passes, 1 when the parser rejects it, 2 on usage or I/O failure.
 */

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "r300_reg_safe.h"
#include "r300_tcl_bypass_vtx_check.h"

/* Register numbers this model tracks, spelled as r300_packet0_check spells
 * them so the two read the same.
 */
#define R300_VAP_VF_CNTL		0x2084
#define R300_VAP_ALT_NUM_VERTICES	0x2088
#define R300_VAP_OUT_VTX_FMT_0		0x2090
#define R300_VAP_OUT_VTX_FMT_1		0x2094
#define R300_VAP_VF_MAX_VTX_INDX	0x2134
#define R300_VAP_VTX_SIZE		0x20B4
#define R300_VAP_CNTL_STATUS		0x2140
#define R300_VAP_PSC_EXT_0		0x21E0
#define R300_VAP_PSC_EXT_7		0x21FC
#define R300_SC_SCISSOR1		0x43E4
#define R300_TX_ENABLE			0x4104
#define R300_RB3D_CCTL			0x4E00
#define R300_RB3D_COLOROFFSET0		0x4E28
#define R300_RB3D_COLORPITCH0		0x4E38
#define R300_RB3D_COLOR_CHANNEL_MASK	0x4E0C
#define R300_RB3D_ZCACHE_CTLSTAT	0x4F18
#define R300_RB3D_BLENDCNTL		0x4E04
#define R300_ZB_CNTL			0x4F00
#define R300_ZB_FORMAT			0x4F10
#define R300_ZB_DEPTHOFFSET		0x4F20
#define R300_ZB_DEPTHPITCH		0x4F24
#define R300_RB3D_AARESOLVE_OFFSET	0x4E80
#define R300_RB3D_AARESOLVE_PITCH	0x4E84
#define R300_RB3D_AARESOLVE_CTL		0x4E88

#define R300_VAP_TCL_BYPASS		(1u << 8)
#define R300_MAX_CB			4
#define R300_TRACK_MAX_TEXTURE		16
#define R300_MAX_ARRAYS			16
#define MAX_BO				16

/* radeon_cs_packet_parse and its accessors. */
#define PACKET_GET_TYPE(h)	(((h) >> 30) & 3)
#define PACKET_GET_COUNT(h)	(((h) >> 16) & 0x3FFF)
#define PACKET0_GET_REG(h)	(((h) & 0x1FFF) << 2)
#define PACKET0_GET_ONE_REG_WR(h) (((h) >> 15) & 1)
#define PACKET3_GET_OPCODE(h)	(((h) >> 8) & 0xFF)
#define PACKET_TYPE0 0
#define PACKET_TYPE2 2
#define PACKET_TYPE3 3
#define PACKET3_NOP 0x10

#define PACKET3_3D_LOAD_VBPNTR	0x2F
#define PACKET3_INDX_BUFFER	0x33
#define PACKET3_3D_DRAW_IMMD	0x29
#define PACKET3_3D_DRAW_INDX	0x2A
#define PACKET3_3D_DRAW_VBUF	0x28
#define PACKET3_3D_DRAW_IMMD_2	0x35
#define PACKET3_3D_DRAW_INDX_2	0x36
#define PACKET3_3D_DRAW_VBUF_2	0x34

/* The chip families the model distinguishes.  The scissor bias and the
 * VAP_ALT_NUM_VERTICES admission both turn on the RV515 boundary.
 */
enum family {
	FAMILY_RS480 = 0,
	FAMILY_RV515 = 1,
};

struct bo {
	char role[32];
	unsigned long size;
	unsigned int read_domains;
	unsigned int write_domain;
	int present;
};

struct cb {
	int bound;		/* a relocation resolved a buffer object */
	unsigned int bo;
	unsigned int pitch;
	unsigned int cpp;
	unsigned int offset;
};

struct array {
	int bound;
	unsigned int bo;
	unsigned int esize;
};

struct track {
	unsigned int num_cb;
	unsigned int maxy;
	unsigned int vtx_size;
	unsigned int vap_vf_cntl;
	unsigned int vap_alt_nverts;
	unsigned int immd_dwords;
	unsigned int num_arrays;
	unsigned int max_indx;
	unsigned int color_channel_mask;
	unsigned int tex_enable_mask;
	unsigned int vap_out_vtx_fmt_0, vap_out_vtx_fmt_1, vap_cntl_status;
	int vap_out_vtx_fmt_0_seen, vap_out_vtx_fmt_1_seen;
	int vap_cntl_status_seen, vap_vtx_size_seen;
	uint8_t vap_psc_ext_seen_mask;
	int vap_psc_ext_nonident;
	int z_enabled;
	int zb_cb_clear;
	int blend_read_enable;
	int aaresolve;
	int cb_dirty, zb_dirty, tex_dirty, aa_dirty;
	struct cb cb[R300_MAX_CB];
	struct cb zb;
	struct cb aa;
	struct array arrays[R300_MAX_ARRAYS];
};

struct parser {
	const uint32_t *ib;
	long ndw;
	unsigned int idx;	/* the cursor radeon_cs_packet_next_reloc reads */
	struct bo bos[MAX_BO];
	unsigned int nbo;
	enum family family;
	int verbose;
	struct track track;
};

struct packet {
	unsigned int idx, type, count, reg, opcode, one_reg_wr;
};

static int verbose_on;

static void note(const char *fmt, ...)
{
	va_list ap;

	if (!verbose_on)
		return;
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

static void reject(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	printf("REJECT ");
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
}

/* radeon_cs_packet_parse: frame one packet and bound it against the chunk.
 * The bound is >= rather than >, so a packet whose last dword is the chunk's
 * last dword is rejected; the model keeps that comparison as written.
 */
static int packet_parse(struct parser *p, struct packet *pkt, unsigned int idx)
{
	uint32_t header;

	if ((long)idx >= p->ndw) {
		reject("packet at %u after CS end %ld", idx, p->ndw);
		return -EINVAL;
	}
	header = p->ib[idx];
	pkt->idx = idx;
	pkt->type = PACKET_GET_TYPE(header);
	pkt->count = PACKET_GET_COUNT(header);
	pkt->one_reg_wr = 0;
	switch (pkt->type) {
	case PACKET_TYPE0:
		pkt->reg = PACKET0_GET_REG(header);
		pkt->one_reg_wr = PACKET0_GET_ONE_REG_WR(header);
		break;
	case PACKET_TYPE3:
		pkt->opcode = PACKET3_GET_OPCODE(header);
		break;
	case PACKET_TYPE2:
		pkt->count = (unsigned int)-1;
		break;
	default:
		reject("unknown packet type %u at %u", pkt->type, idx);
		return -EINVAL;
	}
	if ((long)(pkt->count + 1 + pkt->idx) >= p->ndw) {
		reject("packet (%u:%u:%u) ends after CS buffer (%ld)", pkt->idx,
		       pkt->type, pkt->count, p->ndw);
		return -EINVAL;
	}
	return 0;
}

/* radeon_cs_packet_next_reloc: the type-3 NOP at the cursor names a
 * relocation-chunk dword index, and the buffer object is entry index/4.
 */
static int next_reloc(struct parser *p, unsigned int *bo_out)
{
	struct packet nop;
	unsigned int idx;
	int r;

	r = packet_parse(p, &nop, p->idx);
	if (r)
		return r;
	p->idx += nop.count + 2;
	if (nop.type != PACKET_TYPE3 || nop.opcode != PACKET3_NOP) {
		reject("no packet3 NOP for relocation at %u", nop.idx);
		return -EINVAL;
	}
	idx = p->ib[nop.idx + 1];
	if (idx >= p->nbo * 4) {
		reject("reloc index %u past relocation chunk end %u", idx,
		       p->nbo * 4);
		return -EINVAL;
	}
	*bo_out = idx / 4;
	note("  reloc -> entry %u (%s)\n", *bo_out, p->bos[*bo_out].role);
	return 0;
}

/* r300_cs_tcl_bypass_vtx_output_check: the TCL-bypass vertex-output width
 * decision, taken from the same header the kernel compiles.
 */
static int tcl_bypass_vtx_check(struct parser *p)
{
	struct track *t = &p->track;
	struct r300_tcl_bypass_vtx_inputs in = {
		.tcl_bypass_seen = t->vap_cntl_status_seen &&
			(t->vap_cntl_status & R300_VAP_TCL_BYPASS),
		.fmt0_seen = t->vap_out_vtx_fmt_0_seen,
		.fmt1_seen = t->vap_out_vtx_fmt_1_seen,
		.vtx_size_seen = t->vap_vtx_size_seen,
		.ext_identity_complete = !t->vap_psc_ext_nonident &&
			t->vap_psc_ext_seen_mask == 0xff,
		.prim_walk = (t->vap_vf_cntl >> 4) & 0x3,
		.fmt0 = t->vap_out_vtx_fmt_0,
		.fmt1 = t->vap_out_vtx_fmt_1,
		.vtx_size = t->vtx_size,
	};
	unsigned int required = 0;
	enum r300_tcl_bypass_vtx_verdict v;

	v = r300_tcl_bypass_vtx_check(&in, &required);
	note("  tcl-bypass width: verdict=%s vtx_size=%u required=%u\n",
	     v == R300_TCL_BYPASS_VTX_PASS ? "PASS" :
	     v == R300_TCL_BYPASS_VTX_REJECT ? "REJECT" : "DECLINE",
	     t->vtx_size, required);
	if (v != R300_TCL_BYPASS_VTX_REJECT)
		return 0;
	reject("TCL-bypass draw: VAP_VTX_SIZE %u dwords < %u dwords required "
	       "by VAP_OUT_VTX_FMT 0x%08x/0x%08x", t->vtx_size, required,
	       t->vap_out_vtx_fmt_0, t->vap_out_vtx_fmt_1);
	return -EINVAL;
}

/* r100_cs_track_check.  The dirty flags gate each family of bound checks the
 * way the kernel clears them after every draw.
 */
static int track_check(struct parser *p)
{
	struct track *t = &p->track;
	unsigned int num_cb = t->cb_dirty ? t->num_cb : 0;
	unsigned int prim_walk, nverts, i;
	unsigned long size;

	/* A target with no channel written, no clear, and no blend read is
	 * not a buffer the draw can overrun, so the bound check is skipped.
	 * This is the arm that lets a semantically blank stream through.
	 */
	if (num_cb && !t->zb_cb_clear && !t->color_channel_mask &&
	    !t->blend_read_enable)
		num_cb = 0;

	for (i = 0; i < num_cb; i++) {
		if (!t->cb[i].bound) {
			reject("no buffer for color buffer %u", i);
			return -EINVAL;
		}
		size = (unsigned long)t->cb[i].pitch * t->cb[i].cpp * t->maxy;
		size += t->cb[i].offset;
		if (size > p->bos[t->cb[i].bo].size) {
			reject("buffer too small for color buffer %u "
			       "(need %lu have %lu) pitch %u cpp %u offset %u "
			       "maxy %u",
			       i, size, p->bos[t->cb[i].bo].size,
			       t->cb[i].pitch, t->cb[i].cpp, t->cb[i].offset,
			       t->maxy);
			return -EINVAL;
		}
		note("  color %u bound: need %lu have %lu\n", i, size,
		     p->bos[t->cb[i].bo].size);
	}
	t->cb_dirty = 0;

	if (t->zb_dirty && t->z_enabled) {
		if (!t->zb.bound) {
			reject("no buffer for z buffer");
			return -EINVAL;
		}
		size = (unsigned long)t->zb.pitch * t->zb.cpp * t->maxy;
		size += t->zb.offset;
		if (size > p->bos[t->zb.bo].size) {
			reject("buffer too small for z buffer (need %lu have "
			       "%lu)", size, p->bos[t->zb.bo].size);
			return -EINVAL;
		}
	}
	t->zb_dirty = 0;

	if (t->aa_dirty && t->aaresolve) {
		if (!t->aa.bound) {
			reject("no buffer for AA resolve buffer");
			return -EINVAL;
		}
		size = (unsigned long)t->aa.pitch * t->cb[0].cpp * t->maxy;
		size += t->aa.offset;
		if (size > p->bos[t->aa.bo].size) {
			reject("buffer too small for AA resolve buffer "
			       "(need %lu have %lu)", size,
			       p->bos[t->aa.bo].size);
			return -EINVAL;
		}
	}
	t->aa_dirty = 0;

	prim_walk = (t->vap_vf_cntl >> 4) & 0x3;
	if (t->vap_vf_cntl & (1 << 14))
		nverts = t->vap_alt_nverts;
	else
		nverts = (t->vap_vf_cntl >> 16) & 0xFFFF;

	switch (prim_walk) {
	case 1:
		for (i = 0; i < t->num_arrays; i++) {
			size = (unsigned long)t->arrays[i].esize *
			       t->max_indx * 4UL;
			if (!t->arrays[i].bound) {
				reject("(PW %u) vertex array %u no buffer "
				       "bound", prim_walk, i);
				return -EINVAL;
			}
			if (size > p->bos[t->arrays[i].bo].size) {
				reject("(PW %u) vertex array %u need %lu "
				       "dwords have %lu dwords", prim_walk, i,
				       size >> 2,
				       p->bos[t->arrays[i].bo].size >> 2);
				return -EINVAL;
			}
			note("  array %u bound: need %lu have %lu\n", i, size,
			     p->bos[t->arrays[i].bo].size);
		}
		break;
	case 2:
		for (i = 0; i < t->num_arrays; i++) {
			size = (unsigned long)t->arrays[i].esize *
			       (nverts - 1) * 4UL;
			if (!t->arrays[i].bound) {
				reject("(PW %u) vertex array %u no buffer "
				       "bound", prim_walk, i);
				return -EINVAL;
			}
			if (size > p->bos[t->arrays[i].bo].size) {
				reject("(PW %u) vertex array %u need %lu "
				       "dwords have %lu dwords", prim_walk, i,
				       size >> 2,
				       p->bos[t->arrays[i].bo].size >> 2);
				return -EINVAL;
			}
		}
		break;
	case 3:
		size = (unsigned long)t->vtx_size * nverts;
		if (size != t->immd_dwords) {
			reject("IMMD draw %u dwords but needs %lu dwords",
			       t->immd_dwords, size);
			return -EINVAL;
		}
		break;
	default:
		reject("invalid primitive walk %u for VAP_VF_CNTL",
		       prim_walk);
		return -EINVAL;
	}

	if (t->tex_dirty) {
		t->tex_dirty = 0;
		/* Only the enabled units reach the size arithmetic, and this
		 * model carries no texture buffer, so an enabled unit is a
		 * unit the model cannot check rather than one it accepts.
		 */
		if (t->tex_enable_mask) {
			reject("texture units 0x%x enabled; this model carries "
			       "no texture buffer to check them against",
			       t->tex_enable_mask);
			return -EINVAL;
		}
	}
	return 0;
}

/* Registers r300_packet0_check names without moving state this model
 * carries.  The switch's default arm is a rejection, so a register the safe
 * bitmap flags and the switch does not name is forbidden; separating the two
 * lists keeps that rejection exact.  The texture format, size, and pitch
 * ranges move texture tracking state the model does not carry, which is the
 * scope cut the header states.
 */
static int register_is_accepted_untracked(unsigned int reg)
{
	/* Texture format, size, filter, and border ranges. */
	if (reg >= 0x4400 && reg <= 0x443C)
		return 1;
	if (reg >= 0x4480 && reg <= 0x44FC)
		return 1;
	if (reg >= 0x4500 && reg <= 0x453C)
		return 1;
	switch (reg) {
	case 0x43a4:	/* SC_HYPERZ_EN, clamped rather than rejected */
	case 0x4f1c:	/* ZB_BW_CNTL */
	case 0x4f30:	/* ZB_MASK_OFFSET */
	case 0x4f34:	/* ZB_ZMASK_PITCH */
	case 0x4f44:	/* ZB_HIZ_OFFSET */
	case 0x4f54:	/* ZB_HIZ_PITCH */
	case 0x4028:	/* GB_Z_PEQ_CONFIG */
		return 1;
	default:
		return 0;
	}
}

/* Registers whose case consumes one relocation without moving state this
 * model checks.  Each still pops an entry, so the relocation order stays
 * exact.
 */
static int register_consumes_reloc(unsigned int reg)
{
	/* R300_TX_OFFSET_0 .. +60, sixteen texture units. */
	if (reg >= 0x4C00 && reg <= 0x4C3C)
		return 1;
	switch (reg) {
	case 0x4F58:	/* R300_ZB_ZPASS_ADDR */
	case 0x1420:	/* RADEON_DST_PITCH_OFFSET */
	case 0x1428:	/* RADEON_SRC_PITCH_OFFSET */
		return 1;
	default:
		return 0;
	}
}

/* r300_packet0_check.  The switch's default arm rejects, so a register the
 * safe bitmap flags reaches one of three outcomes: it moves tracking state,
 * it is accepted without moving state this model carries, or it is
 * forbidden.
 */
static int packet0_check(struct parser *p, unsigned int idx, unsigned int reg)
{
	struct track *t = &p->track;
	uint32_t v = p->ib[idx];
	unsigned int i, bo;
	int r;

	switch (reg) {
	case R300_RB3D_COLOROFFSET0:
	case R300_RB3D_COLOROFFSET0 + 4:
	case R300_RB3D_COLOROFFSET0 + 8:
	case R300_RB3D_COLOROFFSET0 + 12:
		i = (reg - R300_RB3D_COLOROFFSET0) >> 2;
		r = next_reloc(p, &bo);
		if (r) {
			reject("no reloc for ib[%u]=0x%04X", idx, reg);
			return r;
		}
		t->cb[i].bound = 1;
		t->cb[i].bo = bo;
		t->cb[i].offset = v;
		t->cb_dirty = 1;
		break;
	case R300_ZB_DEPTHOFFSET:
		r = next_reloc(p, &bo);
		if (r) {
			reject("no reloc for ib[%u]=0x%04X", idx, reg);
			return r;
		}
		t->zb.bound = 1;
		t->zb.bo = bo;
		t->zb.offset = v;
		t->zb_dirty = 1;
		break;
	case R300_VAP_CNTL_STATUS:
		t->vap_cntl_status_seen = 1;
		t->vap_cntl_status = v;
		break;
	case R300_VAP_OUT_VTX_FMT_0:
		t->vap_out_vtx_fmt_0_seen = 1;
		t->vap_out_vtx_fmt_0 = v;
		break;
	case R300_VAP_OUT_VTX_FMT_1:
		t->vap_out_vtx_fmt_1_seen = 1;
		t->vap_out_vtx_fmt_1 = v;
		break;
	case R300_VAP_VTX_SIZE:
		t->vtx_size = v & 0x7F;
		t->vap_vtx_size_seen = 1;
		break;
	case R300_VAP_VF_MAX_VTX_INDX:
		t->max_indx = v & 0x00FFFFFFUL;
		break;
	case R300_VAP_ALT_NUM_VERTICES:
		if (p->family < FAMILY_RV515) {
			reject("VAP_ALT_NUM_VERTICES is RV515 and later");
			return -EINVAL;
		}
		t->vap_alt_nverts = v & 0xFFFFFF;
		break;
	case R300_SC_SCISSOR1:
		t->maxy = ((v >> 13) & 0x1FFF) + 1;
		if (p->family < FAMILY_RV515)
			t->maxy -= 1440;
		t->cb_dirty = 1;
		t->zb_dirty = 1;
		note("  maxy %u from SC_SCISSOR1 0x%08x\n", t->maxy, v);
		break;
	case R300_RB3D_CCTL:
		if (v & (1 << 10)) {
			reject("invalid RB3D_CCTL: cannot enable CMASK");
			return -EINVAL;
		}
		t->num_cb = ((v >> 5) & 0x3) + 1;
		t->cb_dirty = 1;
		break;
	case R300_RB3D_COLORPITCH0:
	case R300_RB3D_COLORPITCH0 + 4:
	case R300_RB3D_COLORPITCH0 + 8:
	case R300_RB3D_COLORPITCH0 + 12:
		i = (reg - R300_RB3D_COLORPITCH0) >> 2;
		t->cb[i].pitch = v & 0x3FFE;
		switch ((v >> 21) & 0xF) {
		case 9: case 11: case 12:
			t->cb[i].cpp = 1;
			break;
		case 3: case 4: case 13: case 15:
			t->cb[i].cpp = 2;
			break;
		case 5:
			if (p->family < FAMILY_RV515) {
				reject("invalid color buffer format (%u)",
				       (v >> 21) & 0xF);
				return -EINVAL;
			}
			/* fallthrough */
		case 6:
			t->cb[i].cpp = 4;
			break;
		case 10:
			t->cb[i].cpp = 8;
			break;
		case 7:
			t->cb[i].cpp = 16;
			break;
		default:
			reject("invalid color buffer format (%u)",
			       (v >> 21) & 0xF);
			return -EINVAL;
		}
		t->cb_dirty = 1;
		break;
	case R300_ZB_CNTL:
		t->z_enabled = (v & 2) != 0;
		t->zb_dirty = 1;
		break;
	case R300_ZB_FORMAT:
		switch (v & 0xF) {
		case 0: case 1:
			t->zb.cpp = 2;
			break;
		case 2:
			t->zb.cpp = 4;
			break;
		default:
			reject("invalid z buffer format (%u)", v & 0xF);
			return -EINVAL;
		}
		t->zb_dirty = 1;
		break;
	case R300_ZB_DEPTHPITCH:
		t->zb.pitch = v & 0x3FFC;
		t->zb_dirty = 1;
		break;
	case R300_TX_ENABLE:
		t->tex_enable_mask = v & 0xFFFF;
		t->tex_dirty = 1;
		break;
	case R300_RB3D_COLOR_CHANNEL_MASK:
		t->color_channel_mask = v;
		t->cb_dirty = 1;
		break;
	case R300_RB3D_ZCACHE_CTLSTAT:
		t->zb_cb_clear = (v & (1 << 5)) != 0;
		t->cb_dirty = 1;
		t->zb_dirty = 1;
		break;
	case R300_RB3D_BLENDCNTL:
		t->blend_read_enable = (v & (1 << 2)) != 0;
		t->cb_dirty = 1;
		break;
	case R300_RB3D_AARESOLVE_OFFSET:
		r = next_reloc(p, &bo);
		if (r) {
			reject("no reloc for ib[%u]=0x%04X", idx, reg);
			return r;
		}
		t->aa.bound = 1;
		t->aa.bo = bo;
		t->aa.offset = v;
		t->aa_dirty = 1;
		break;
	case R300_RB3D_AARESOLVE_PITCH:
		t->aa.pitch = v & 0x3FFE;
		t->aa_dirty = 1;
		break;
	case R300_RB3D_AARESOLVE_CTL:
		t->aaresolve = v & 0x1;
		t->aa_dirty = 1;
		break;
	case R300_VAP_VF_CNTL:
		t->vap_vf_cntl = v;
		break;
	default:
		if (reg >= R300_VAP_PSC_EXT_0 && reg <= R300_VAP_PSC_EXT_7) {
			if (v != 0xF688F688)
				t->vap_psc_ext_nonident = 1;
			t->vap_psc_ext_seen_mask |=
				(uint8_t)(1u << ((reg - R300_VAP_PSC_EXT_0) / 4));
			break;
		}
		if (register_consumes_reloc(reg)) {
			r = next_reloc(p, &bo);
			if (r) {
				reject("no reloc for ib[%u]=0x%04X", idx, reg);
				return r;
			}
			break;
		}
		if (register_is_accepted_untracked(reg))
			break;
		reject("forbidden register 0x%04X in cs at %u (val=%08x)", reg,
		       idx, v);
		return -EINVAL;
	}
	return 0;
}

/* r100_cs_parse_packet0: the safe bitmap decides which registers reach the
 * check, and a register run past the bitmap's range is rejected whole.
 */
static int parse_packet0(struct parser *p, struct packet *pkt)
{
	const unsigned int *auth = r300_reg_safe_bm;
	const unsigned int n = (unsigned int)(sizeof(r300_reg_safe_bm) /
					      sizeof(r300_reg_safe_bm[0]));
	unsigned int reg = pkt->reg;
	unsigned int idx = pkt->idx + 1;
	unsigned int i, j, m;
	int r;

	if (pkt->one_reg_wr) {
		if ((reg >> 7) > n) {
			reject("register 0x%04X past the safe bitmap", reg);
			return -EINVAL;
		}
	} else {
		if (((reg + (pkt->count << 2)) >> 7) > n) {
			reject("register run 0x%04X+%u past the safe bitmap",
			       reg, pkt->count);
			return -EINVAL;
		}
	}
	for (i = 0; i <= pkt->count; i++, idx++) {
		j = reg >> 7;
		m = 1u << ((reg >> 2) & 31);
		if (auth[j] & m) {
			r = packet0_check(p, idx, reg);
			if (r)
				return r;
		} else {
			/* The bitmap flags the registers the check owns, so a
			 * register it does not flag is written through
			 * unvalidated.
			 */
			note("  reg 0x%04X passes unchecked\n", reg);
		}
		if (pkt->one_reg_wr) {
			if (!(auth[j] & m))
				break;
		} else {
			reg += 4;
		}
	}
	return 0;
}

/* r100_packet3_load_vbpntr. */
static int load_vbpntr(struct parser *p, struct packet *pkt)
{
	struct track *t = &p->track;
	unsigned int idx = pkt->idx + 1;
	unsigned int c, i, bo, v;
	int r;

	c = p->ib[idx++] & 0x1F;
	if (c > 16) {
		reject("only 16 vertex buffers are allowed, %u requested", c);
		return -EINVAL;
	}
	t->num_arrays = c;
	for (i = 0; i + 1 < c; i += 2, idx += 3) {
		r = next_reloc(p, &bo);
		if (r)
			return r;
		v = p->ib[idx];
		t->arrays[i + 0].bound = 1;
		t->arrays[i + 0].bo = bo;
		t->arrays[i + 0].esize = (v >> 8) & 0x7F;
		r = next_reloc(p, &bo);
		if (r)
			return r;
		t->arrays[i + 1].bound = 1;
		t->arrays[i + 1].bo = bo;
		t->arrays[i + 1].esize = (v >> 24) & 0x7F;
	}
	if (c & 1) {
		r = next_reloc(p, &bo);
		if (r)
			return r;
		v = p->ib[idx];
		t->arrays[i + 0].bound = 1;
		t->arrays[i + 0].bo = bo;
		t->arrays[i + 0].esize = (v >> 8) & 0x7F;
	}
	note("  vbpntr: %u arrays, esize %u\n", c, t->arrays[0].esize);
	return 0;
}

struct draw_stats {
	unsigned int draws;
	unsigned int checks_passed;
};

static int packet3_check(struct parser *p, struct packet *pkt,
			 struct draw_stats *stats)
{
	struct track *t = &p->track;
	unsigned int idx = pkt->idx + 1;
	unsigned int bo;
	int r;

	switch (pkt->opcode) {
	case PACKET3_NOP:
		break;
	case PACKET3_3D_LOAD_VBPNTR:
		r = load_vbpntr(p, pkt);
		if (r)
			return r;
		break;
	case PACKET3_INDX_BUFFER:
		r = next_reloc(p, &bo);
		if (r)
			return r;
		if ((unsigned long)p->ib[idx + 2] + 1 > p->bos[bo].size) {
			reject("buffer too small for PACKET3 INDX_BUFFER "
			       "(need %u have %lu)", p->ib[idx + 2] + 1,
			       p->bos[bo].size);
			return -EINVAL;
		}
		break;
	case PACKET3_3D_DRAW_IMMD:
		if (((p->ib[idx + 1] >> 4) & 0x3) != 3) {
			reject("PRIM_WALK must be 3 for IMMD draw");
			return -EINVAL;
		}
		t->vtx_size = p->ib[idx] & 0x7F;
		t->vap_vf_cntl = p->ib[idx + 1];
		t->immd_dwords = pkt->count - 1;
		goto draw;
	case PACKET3_3D_DRAW_IMMD_2:
		if (((p->ib[idx] >> 4) & 0x3) != 3) {
			reject("PRIM_WALK must be 3 for IMMD draw");
			return -EINVAL;
		}
		t->vap_vf_cntl = p->ib[idx];
		t->immd_dwords = pkt->count;
		goto draw;
	case PACKET3_3D_DRAW_VBUF:
		t->vap_vf_cntl = p->ib[idx + 1];
		goto draw;
	case PACKET3_3D_DRAW_INDX:
		t->vap_vf_cntl = p->ib[idx + 1];
		goto draw;
	case PACKET3_3D_DRAW_VBUF_2:
	case PACKET3_3D_DRAW_INDX_2:
		t->vap_vf_cntl = p->ib[idx];
		goto draw;
	default:
		reject("unknown packet3 opcode 0x%02X", pkt->opcode);
		return -EINVAL;
	}
	return 0;

draw:
	stats->draws++;
	note("draw idx=%u op=0x%02X vf_cntl=0x%08x\n", pkt->idx, pkt->opcode,
	     t->vap_vf_cntl);
	/* r300_cs_track_check runs the width decision before the bound
	 * checks, so a stream failing both reports the width first.
	 */
	r = tcl_bypass_vtx_check(p);
	if (r)
		return r;
	r = track_check(p);
	if (r)
		return r;
	stats->checks_passed++;
	return 0;
}

/* r300_cs_parse. */
static int cs_parse(struct parser *p, struct draw_stats *stats)
{
	struct packet pkt;
	int r;

	p->idx = 0;
	do {
		r = packet_parse(p, &pkt, p->idx);
		if (r)
			return r;
		p->idx += pkt.count + 2;
		switch (pkt.type) {
		case PACKET_TYPE0:
			r = parse_packet0(p, &pkt);
			break;
		case PACKET_TYPE2:
			break;
		case PACKET_TYPE3:
			r = packet3_check(p, &pkt, stats);
			break;
		default:
			reject("unknown packet type %u", pkt.type);
			return -EINVAL;
		}
		if (r)
			return r;
	} while ((long)p->idx < p->ndw);
	return 0;
}

/* --- Bundle and stream input --- */

static int parse_bundle(struct parser *p, const char *path)
{
	char line[512];
	FILE *f = fopen(path, "r");

	if (!f) {
		fprintf(stderr, "open %s: %s\n", path, strerror(errno));
		return 2;
	}
	while (fgets(line, sizeof(line), f)) {
		char role[32];
		unsigned int slot, rd, wd;
		unsigned long size;
		char fam[32];

		if (line[0] == '#' || line[0] == '\n')
			continue;
		if (sscanf(line, "family %31s", fam) == 1) {
			if (strcmp(fam, "rs480") == 0)
				p->family = FAMILY_RS480;
			else if (strcmp(fam, "rv515") == 0)
				p->family = FAMILY_RV515;
			else {
				fprintf(stderr, "unknown family %s\n", fam);
				fclose(f);
				return 2;
			}
			continue;
		}
		if (sscanf(line,
			   "bo %u role=%31s size=%lu read_domains=%i "
			   "write_domain=%i",
			   &slot, role, &size, (int *)&rd, (int *)&wd) == 5) {
			if (slot >= MAX_BO) {
				fprintf(stderr, "bo slot %u past %u\n", slot,
					MAX_BO);
				fclose(f);
				return 2;
			}
			snprintf(p->bos[slot].role, sizeof(p->bos[slot].role),
				 "%s", role);
			p->bos[slot].size = size;
			p->bos[slot].read_domains = rd;
			p->bos[slot].write_domain = wd;
			p->bos[slot].present = 1;
			if (slot + 1 > p->nbo)
				p->nbo = slot + 1;
			continue;
		}
		fprintf(stderr, "unparsed bundle line: %s", line);
		fclose(f);
		return 2;
	}
	fclose(f);
	for (unsigned int i = 0; i < p->nbo; i++) {
		if (!p->bos[i].present) {
			fprintf(stderr, "relocation entry %u has no bo line\n",
				i);
			return 2;
		}
	}
	if (p->nbo == 0) {
		fprintf(stderr, "bundle declares no buffer object\n");
		return 2;
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct parser p;
	struct draw_stats stats = { 0, 0 };
	uint32_t *ib = NULL;
	long size, ndw, truncate = 0;
	unsigned int forced_vtx_size = 0;
	int force_vtx = 0, arg = 1, rc;
	FILE *f;
	struct { long idx; uint32_t value; int set; } dword_mutations[8];
	unsigned int nmut = 0;
	struct { unsigned int slot; unsigned long size; int set; } bo_sizes[8];
	unsigned int nsizes = 0;

	setbuf(stdout, NULL);
	memset(&p, 0, sizeof(p));
	memset(dword_mutations, 0, sizeof(dword_mutations));
	memset(bo_sizes, 0, sizeof(bo_sizes));

	while (arg < argc && argv[arg][0] == '-') {
		if (strcmp(argv[arg], "--verbose") == 0) {
			verbose_on = 1;
			p.verbose = 1;
			arg += 1;
		} else if (strcmp(argv[arg], "--set-vtx-size") == 0 &&
			   arg + 1 < argc) {
			forced_vtx_size = (unsigned int)strtoul(argv[arg + 1],
								NULL, 0);
			force_vtx = 1;
			arg += 2;
		} else if (strcmp(argv[arg], "--truncate") == 0 &&
			   arg + 1 < argc) {
			truncate = strtol(argv[arg + 1], NULL, 0);
			arg += 2;
		} else if (strcmp(argv[arg], "--set-dword") == 0 &&
			   arg + 1 < argc && nmut < 8) {
			long i;
			unsigned long v;

			if (sscanf(argv[arg + 1], "%li=%li", &i, (long *)&v)
			    != 2) {
				fprintf(stderr, "bad --set-dword %s\n",
					argv[arg + 1]);
				return 2;
			}
			dword_mutations[nmut].idx = i;
			dword_mutations[nmut].value = (uint32_t)v;
			dword_mutations[nmut].set = 1;
			nmut++;
			arg += 2;
		} else if (strcmp(argv[arg], "--set-bo-size") == 0 &&
			   arg + 1 < argc && nsizes < 8) {
			unsigned int slot;
			unsigned long v;

			if (sscanf(argv[arg + 1], "%u=%lu", &slot, &v) != 2) {
				fprintf(stderr, "bad --set-bo-size %s\n",
					argv[arg + 1]);
				return 2;
			}
			bo_sizes[nsizes].slot = slot;
			bo_sizes[nsizes].size = v;
			bo_sizes[nsizes].set = 1;
			nsizes++;
			arg += 2;
		} else {
			break;
		}
	}
	if (arg != argc - 2) {
		fprintf(stderr,
			"usage: %s [options] bundle.txt ib.bin\n", argv[0]);
		return 2;
	}

	rc = parse_bundle(&p, argv[arg]);
	if (rc)
		return rc;
	for (unsigned int i = 0; i < nsizes; i++) {
		if (bo_sizes[i].slot >= p.nbo) {
			fprintf(stderr, "--set-bo-size slot %u past %u\n",
				bo_sizes[i].slot, p.nbo);
			return 2;
		}
		p.bos[bo_sizes[i].slot].size = bo_sizes[i].size;
	}

	f = fopen(argv[arg + 1], "rb");
	if (!f) {
		fprintf(stderr, "open %s: %s\n", argv[arg + 1],
			strerror(errno));
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
	ndw = size / 4;
	ib = malloc((size_t)size);
	if (!ib || fread(ib, 1, (size_t)size, f) != (size_t)size) {
		fprintf(stderr, "read %s failed\n", argv[arg + 1]);
		fclose(f);
		free(ib);
		return 2;
	}
	fclose(f);

	if (truncate > 0 && truncate < ndw)
		ndw = truncate;
	for (unsigned int i = 0; i < nmut; i++) {
		if (dword_mutations[i].idx < 0 ||
		    dword_mutations[i].idx >= ndw) {
			fprintf(stderr, "--set-dword index %ld past %ld\n",
				dword_mutations[i].idx, ndw);
			free(ib);
			return 2;
		}
		ib[dword_mutations[i].idx] = dword_mutations[i].value;
	}
	if (force_vtx) {
		for (long i = 0; i + 1 < ndw; i++) {
			if (PACKET_GET_TYPE(ib[i]) == PACKET_TYPE0 &&
			    PACKET0_GET_REG(ib[i]) == R300_VAP_VTX_SIZE)
				ib[i + 1] = forced_vtx_size;
		}
	}

	p.ib = ib;
	p.ndw = ndw;
	rc = cs_parse(&p, &stats);

	printf("replay dwords=%ld relocs=%u draws=%u passed=%u verdict=%s\n",
	       ndw, p.nbo, stats.draws, stats.checks_passed,
	       rc ? "REJECT" : (stats.draws ? "ACCEPT" : "ACCEPT-NO-DRAW"));
	free(ib);
	return rc ? 1 : 0;
}
