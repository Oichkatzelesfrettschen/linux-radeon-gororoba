/* SPDX-License-Identifier: MIT */

#include "radeon.h"

#define R100_TRACK_MAX_TEXTURE 3
#define R200_TRACK_MAX_TEXTURE 6
#define R300_TRACK_MAX_TEXTURE 16

#define R100_MAX_CB 1
#define R300_MAX_CB 4

/*
 * CS functions
 */
struct r100_cs_track_cb {
	struct radeon_bo	*robj;
	unsigned		pitch;
	unsigned		cpp;
	unsigned		offset;
};

struct r100_cs_track_array {
	struct radeon_bo	*robj;
	unsigned		esize;
};

/* The legacy 2D engine's destination surface as the command stream
 * describes it.  DST_PITCH_OFFSET names the buffer object through its
 * relocation and packs the pitch in 64-byte units above a 1 KiB-granular
 * offset, DP_GUI_MASTER_CNTL carries the destination datatype that fixes
 * the bytes per pixel, DST_Y_X carries the origin, and the write to
 * DST_WIDTH_HEIGHT launches the operation, so that write runs the
 * footprint check over this state, and so does DST_HEIGHT_WIDTH, the
 * same launch with the halves swapped.  cpp stays 0 for a datatype the
 * tracker does not size, which the launch refuses.  robj and object_size
 * come from the object the relocation decoder consumed, so the bound is
 * the consumed object's and never a role the stream claims.
 */
struct r100_cs_track_2d_dst {
	struct radeon_bo	*robj;
	unsigned long		object_size;
	unsigned		pitch;
	unsigned		offset;
	unsigned		cpp;
	unsigned		x;
	unsigned		y;
	bool			pitch_offset_seen;
	bool			gui_master_cntl_seen;
	bool			pitch_offset_cntl;
	bool			y_x_seen;
};

struct r100_cs_track_2d_src {
	struct radeon_bo	*robj;
	unsigned long		object_size;
	unsigned		pitch;
	unsigned		offset;
	unsigned		cpp;
	unsigned		x;
	unsigned		y;
	bool			pitch_offset_seen;
	bool			gui_master_cntl_seen;
	bool			pitch_offset_cntl;
	bool			source_memory;
	bool			source_required;
	bool			y_x_seen;
};

struct r100_cs_cube_info {
	struct radeon_bo	*robj;
	unsigned		offset;
	unsigned		width;
	unsigned		height;
};

#define R100_TRACK_COMP_NONE   0
#define R100_TRACK_COMP_DXT1   1
#define R100_TRACK_COMP_DXT35  2

struct r100_cs_track_texture {
	struct radeon_bo	*robj;
	struct r100_cs_cube_info cube_info[5]; /* info for 5 non-primary faces */
	unsigned		pitch;
	unsigned		width;
	unsigned		height;
	unsigned		num_levels;
	unsigned		cpp;
	unsigned		tex_coord_type;
	unsigned		txdepth;
	unsigned		width_11;
	unsigned		height_11;
	bool			use_pitch;
	bool			enabled;
	bool                    lookup_disable;
	bool			roundup_w;
	bool			roundup_h;
	unsigned                compress_format;
};

struct r100_cs_track {
	unsigned			num_cb;
	unsigned                        num_texture;
	unsigned			maxy;
	unsigned			vtx_size;
	unsigned			vap_vf_cntl;
	unsigned			vap_alt_nverts;
	unsigned			immd_dwords;
	unsigned			num_arrays;
	unsigned			max_indx;
	unsigned			color_channel_mask;
	unsigned			vap_out_vtx_fmt_0;
	unsigned			vap_out_vtx_fmt_1;
	unsigned			vap_cntl_status;
	bool				vap_out_vtx_fmt_0_seen;
	bool				vap_out_vtx_fmt_1_seen;
	bool				vap_cntl_status_seen;
	bool				vap_vtx_size_seen;
	u8				vap_psc_cntl_seen_mask;
	u8				vap_psc_ext_seen_mask;
	unsigned			vap_psc_cntl[8];
	unsigned			vap_psc_ext[8];
	struct r100_cs_track_array	arrays[16];
	struct r100_cs_track_cb 	cb[R300_MAX_CB];
	struct r100_cs_track_cb 	zb;
	struct r100_cs_track_cb 	aa;
	struct r100_cs_track_texture	textures[R300_TRACK_MAX_TEXTURE];
	struct r100_cs_track_2d_dst	dst2d;
	struct r100_cs_track_2d_src	src2d;
	bool				dp_cntl_seen;
	bool				xdir_left_to_right;
	bool				ydir_top_to_bottom;
	bool				z_enabled;
	bool                            separate_cube;
	bool				zb_cb_clear;
	bool				blend_read_enable;
	bool				cb_dirty;
	bool				zb_dirty;
	bool				tex_dirty;
	bool				aa_dirty;
	bool				aaresolve;
};

int r100_cs_track_check(struct radeon_device *rdev, struct r100_cs_track *track);
void r100_cs_track_clear(struct radeon_device *rdev, struct r100_cs_track *track);

int r100_cs_packet_parse_vline(struct radeon_cs_parser *p);

int r200_packet0_check(struct radeon_cs_parser *p,
		       struct radeon_cs_packet *pkt,
		       unsigned idx, unsigned reg);

int r100_reloc_pitch_offset(struct radeon_cs_parser *p,
			    struct radeon_cs_packet *pkt,
			    unsigned idx,
			    unsigned reg);
int r100_reloc_pitch_offset_ex(struct radeon_cs_parser *p,
			       struct radeon_cs_packet *pkt,
			       unsigned idx, unsigned reg,
			       struct radeon_bo **out_robj,
			       u32 *out_offset, u32 *out_pitch);
void r100_cs_track_2d_dst_bind(struct r100_cs_track *track,
			       struct radeon_bo *robj, u32 offset,
			       u32 pitch);
void r100_cs_track_2d_dst_gui_master_cntl(struct r100_cs_track *track,
					  u32 value);
void r100_cs_track_2d_dst_y_x(struct r100_cs_track *track, u32 value);
void r100_cs_track_2d_src_bind(struct r100_cs_track *track,
				       struct radeon_bo *robj, u32 offset,
				       u32 pitch);
void r100_cs_track_2d_src_y_x(struct r100_cs_track *track, u32 value);
void r100_cs_track_2d_dp_cntl(struct r100_cs_track *track, u32 value);
int r100_cs_track_2d_dst_check(struct radeon_cs_parser *p,
			       struct radeon_cs_packet *pkt,
			       unsigned idx, unsigned reg,
			       u32 width, u32 height);
int r100_cs_track_2d_src_check(struct radeon_cs_parser *p,
				       struct radeon_cs_packet *pkt,
				       unsigned idx, unsigned reg,
				       u32 width, u32 height);
int r100_packet3_load_vbpntr(struct radeon_cs_parser *p,
			     struct radeon_cs_packet *pkt,
			     int idx);
