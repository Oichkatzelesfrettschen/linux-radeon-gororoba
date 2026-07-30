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
#include <linux/mutex.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include <drm/drm_device.h>
#include <drm/drm_file.h>

#include "radeon.h"
#include "radeon_asic.h"
#include "rs400d.h"

/* This files gather functions specifics to : rs400,rs480 */
static void rs400_debugfs_pcie_gart_info_init(struct radeon_device *rdev);
static void rs480_safe_regs_debugfs_init(struct radeon_device *rdev);
static void rs480_candidate_regs_debugfs_init(struct radeon_device *rdev);

void rs400_gart_adjust_size(struct radeon_device *rdev)
{
	/* Check gart size */
	switch (rdev->mc.gtt_size/(1024*1024)) {
	case 32:
	case 64:
	case 128:
	case 256:
	case 512:
	case 1024:
	case 2048:
		break;
	default:
		DRM_ERROR("Unable to use IGP GART size %uM\n",
			  (unsigned)(rdev->mc.gtt_size >> 20));
		DRM_ERROR("Valid GART size for IGP are 32M,64M,128M,256M,512M,1G,2G\n");
		DRM_ERROR("Forcing to 32M GART size\n");
		rdev->mc.gtt_size = 32 * 1024 * 1024;
		return;
	}
}

void rs400_gart_tlb_flush(struct radeon_device *rdev)
{
	uint32_t tmp;
	unsigned int timeout = rdev->usec_timeout;

	WREG32_MC(RS480_GART_CACHE_CNTRL, RS480_GART_CACHE_INVALIDATE);
	do {
		tmp = RREG32_MC(RS480_GART_CACHE_CNTRL);
		if ((tmp & RS480_GART_CACHE_INVALIDATE) == 0)
			break;
		udelay(1);
		timeout--;
	} while (timeout > 0);
	WREG32_MC(RS480_GART_CACHE_CNTRL, 0);
}

int rs400_gart_init(struct radeon_device *rdev)
{
	int r;

	if (rdev->gart.ptr) {
		WARN(1, "RS400 GART already initialized\n");
		return 0;
	}
	/* Check gart size */
	switch (rdev->mc.gtt_size / (1024 * 1024)) {
	case 32:
	case 64:
	case 128:
	case 256:
	case 512:
	case 1024:
	case 2048:
		break;
	default:
		return -EINVAL;
	}
	/* Initialize common gart structure */
	r = radeon_gart_init(rdev);
	if (r)
		return r;
	rs400_debugfs_pcie_gart_info_init(rdev);
	rdev->gart.table_size = rdev->gart.num_gpu_pages * 4;
	return radeon_gart_table_ram_alloc(rdev);
}

int rs400_gart_enable(struct radeon_device *rdev)
{
	uint32_t size_reg;
	uint32_t tmp;

	tmp = RREG32_MC(RS690_AIC_CTRL_SCRATCH);
	tmp |= RS690_DIS_OUT_OF_PCI_GART_ACCESS;
	WREG32_MC(RS690_AIC_CTRL_SCRATCH, tmp);
	/* Check gart size */
	switch (rdev->mc.gtt_size / (1024 * 1024)) {
	case 32:
		size_reg = RS480_VA_SIZE_32MB;
		break;
	case 64:
		size_reg = RS480_VA_SIZE_64MB;
		break;
	case 128:
		size_reg = RS480_VA_SIZE_128MB;
		break;
	case 256:
		size_reg = RS480_VA_SIZE_256MB;
		break;
	case 512:
		size_reg = RS480_VA_SIZE_512MB;
		break;
	case 1024:
		size_reg = RS480_VA_SIZE_1GB;
		break;
	case 2048:
		size_reg = RS480_VA_SIZE_2GB;
		break;
	default:
		return -EINVAL;
	}
	/* It should be fine to program it to max value */
	if (rdev->family == CHIP_RS690 || (rdev->family == CHIP_RS740)) {
		WREG32_MC(RS690_MCCFG_AGP_BASE, 0xFFFFFFFF);
		WREG32_MC(RS690_MCCFG_AGP_BASE_2, 0);
	} else {
		WREG32(RADEON_AGP_BASE, 0xFFFFFFFF);
		WREG32(RS480_AGP_BASE_2, 0);
	}
	tmp = REG_SET(RS690_MC_AGP_TOP, rdev->mc.gtt_end >> 16);
	tmp |= REG_SET(RS690_MC_AGP_START, rdev->mc.gtt_start >> 16);
	if ((rdev->family == CHIP_RS690) || (rdev->family == CHIP_RS740)) {
		WREG32_MC(RS690_MCCFG_AGP_LOCATION, tmp);
		tmp = RREG32(RADEON_BUS_CNTL) & ~RS600_BUS_MASTER_DIS;
		WREG32(RADEON_BUS_CNTL, tmp);
	} else {
		WREG32(RADEON_MC_AGP_LOCATION, tmp);
		tmp = RREG32(RADEON_BUS_CNTL) & ~RADEON_BUS_MASTER_DIS;
		WREG32(RADEON_BUS_CNTL, tmp);
	}
	/* Table should be in 32bits address space so ignore bits above. */
	tmp = (u32)rdev->gart.table_addr & 0xfffff000;
	tmp |= (upper_32_bits(rdev->gart.table_addr) & 0xff) << 4;

	WREG32_MC(RS480_GART_BASE, tmp);
	/* TODO: more tweaking here */
	WREG32_MC(RS480_GART_FEATURE_ID,
		  (RS480_TLB_ENABLE |
		   RS480_GTW_LAC_EN | RS480_1LEVEL_GART));
	/* Disable snooping */
	WREG32_MC(RS480_AGP_MODE_CNTL,
		  (1 << RS480_REQ_TYPE_SNOOP_SHIFT) | RS480_REQ_TYPE_SNOOP_DIS);
	/* Disable AGP mode */
	/* FIXME: according to doc we should set HIDE_MMCFG_BAR=0,
	 * AGPMODE30=0 & AGP30ENHANCED=0 in NB_CNTL */
	if ((rdev->family == CHIP_RS690) || (rdev->family == CHIP_RS740)) {
		tmp = RREG32_MC(RS480_MC_MISC_CNTL);
		tmp |= RS480_GART_INDEX_REG_EN | RS690_BLOCK_GFX_D3_EN;
		WREG32_MC(RS480_MC_MISC_CNTL, tmp);
	} else {
		tmp = RREG32_MC(RS480_MC_MISC_CNTL);
		tmp |= RS480_GART_INDEX_REG_EN;
		WREG32_MC(RS480_MC_MISC_CNTL, tmp);
	}
	/* Enable gart */
	WREG32_MC(RS480_AGP_ADDRESS_SPACE_SIZE, (RS480_GART_EN | size_reg));
	rs400_gart_tlb_flush(rdev);
	DRM_INFO("PCIE GART of %uM enabled (table at 0x%016llX).\n",
		 (unsigned)(rdev->mc.gtt_size >> 20),
		 (unsigned long long)rdev->gart.table_addr);
	rdev->gart.ready = true;
	return 0;
}

void rs400_gart_disable(struct radeon_device *rdev)
{
	uint32_t tmp;

	tmp = RREG32_MC(RS690_AIC_CTRL_SCRATCH);
	tmp |= RS690_DIS_OUT_OF_PCI_GART_ACCESS;
	WREG32_MC(RS690_AIC_CTRL_SCRATCH, tmp);
	WREG32_MC(RS480_AGP_ADDRESS_SPACE_SIZE, 0);
}

void rs400_gart_fini(struct radeon_device *rdev)
{
	radeon_gart_fini(rdev);
	rs400_gart_disable(rdev);
	radeon_gart_table_ram_free(rdev);
}

#define RS400_PTE_UNSNOOPED (1 << 0)
#define RS400_PTE_WRITEABLE (1 << 2)
#define RS400_PTE_READABLE  (1 << 3)

uint64_t rs400_gart_get_page_entry(uint64_t addr, uint32_t flags)
{
	uint32_t entry;

	entry = (lower_32_bits(addr) & PAGE_MASK) |
		((upper_32_bits(addr) & 0xff) << 4);
	if (flags & RADEON_GART_PAGE_READ)
		entry |= RS400_PTE_READABLE;
	if (flags & RADEON_GART_PAGE_WRITE)
		entry |= RS400_PTE_WRITEABLE;
	if (!(flags & RADEON_GART_PAGE_SNOOP))
		entry |= RS400_PTE_UNSNOOPED;
	return entry;
}

void rs400_gart_set_page(struct radeon_device *rdev, unsigned i,
			 uint64_t entry)
{
	u32 *gtt = rdev->gart.ptr;
	gtt[i] = cpu_to_le32(lower_32_bits(entry));
}

int rs400_mc_wait_for_idle(struct radeon_device *rdev)
{
	unsigned i;
	uint32_t tmp;

	for (i = 0; i < rdev->usec_timeout; i++) {
		/* read MC_STATUS */
		tmp = RREG32(RADEON_MC_STATUS);
		if (tmp & RADEON_MC_IDLE) {
			return 0;
		}
		udelay(1);
	}
	return -1;
}

static void rs400_gpu_init(struct radeon_device *rdev)
{
	/* Earlier code was calling r420_pipes_init and then
	 * rs400_mc_wait_for_idle(rdev). The problem is that
	 * at least on my Mobility Radeon Xpress 200M RC410 card
	 * that ends up in this code path ends up num_gb_pipes == 3
	 * while the card seems to have only one pipe. With the
	 * r420 pipe initialization method.
	 *
	 * Problems shown up as HyperZ glitches, see:
	 * https://bugs.freedesktop.org/show_bug.cgi?id=110897
	 *
	 * Delegating initialization to r300 code seems to work
	 * and results in proper pipe numbers. The rs400 cards
	 * are said to be not r400, but r300 kind of cards.
	 */
	r300_gpu_init(rdev);

	if (rs400_mc_wait_for_idle(rdev)) {
		pr_warn("rs400: Failed to wait MC idle while programming pipes. Bad things might happen. %08x\n",
			RREG32(RADEON_MC_STATUS));
	}
}

static void rs400_mc_init(struct radeon_device *rdev)
{
	u64 base;

	rs400_gart_adjust_size(rdev);
	rdev->mc.igp_sideport_enabled = radeon_combios_sideport_present(rdev);
	/* DDR for all card after R300 & IGP */
	rdev->mc.vram_is_ddr = true;
	rdev->mc.vram_width = 128;
	r100_vram_init_sizes(rdev);
	base = (RREG32(RADEON_NB_TOM) & 0xffff) << 16;
	radeon_vram_location(rdev, &rdev->mc, base);
	rdev->mc.gtt_base_align = rdev->mc.gtt_size - 1;
	radeon_gtt_location(rdev, &rdev->mc);
	radeon_update_bandwidth_info(rdev);
}

uint32_t rs400_mc_rreg(struct radeon_device *rdev, uint32_t reg)
{
	unsigned long flags;
	uint32_t r;

	spin_lock_irqsave(&rdev->mc_idx_lock, flags);
	WREG32(RS480_NB_MC_INDEX, reg & 0xff);
	r = RREG32(RS480_NB_MC_DATA);
	WREG32(RS480_NB_MC_INDEX, 0xff);
	spin_unlock_irqrestore(&rdev->mc_idx_lock, flags);
	return r;
}

void rs400_mc_wreg(struct radeon_device *rdev, uint32_t reg, uint32_t v)
{
	unsigned long flags;

	spin_lock_irqsave(&rdev->mc_idx_lock, flags);
	WREG32(RS480_NB_MC_INDEX, ((reg) & 0xff) | RS480_NB_MC_IND_WR_EN);
	WREG32(RS480_NB_MC_DATA, (v));
	WREG32(RS480_NB_MC_INDEX, 0xff);
	spin_unlock_irqrestore(&rdev->mc_idx_lock, flags);
}

#if defined(CONFIG_DEBUG_FS)
static int rs400_debugfs_gart_info_show(struct seq_file *m, void *unused)
{
	struct radeon_device *rdev = m->private;
	uint32_t tmp;

	tmp = RREG32(RADEON_HOST_PATH_CNTL);
	seq_printf(m, "HOST_PATH_CNTL 0x%08x\n", tmp);
	tmp = RREG32(RADEON_BUS_CNTL);
	seq_printf(m, "BUS_CNTL 0x%08x\n", tmp);
	tmp = RREG32_MC(RS690_AIC_CTRL_SCRATCH);
	seq_printf(m, "AIC_CTRL_SCRATCH 0x%08x\n", tmp);
	if (rdev->family == CHIP_RS690 || (rdev->family == CHIP_RS740)) {
		tmp = RREG32_MC(RS690_MCCFG_AGP_BASE);
		seq_printf(m, "MCCFG_AGP_BASE 0x%08x\n", tmp);
		tmp = RREG32_MC(RS690_MCCFG_AGP_BASE_2);
		seq_printf(m, "MCCFG_AGP_BASE_2 0x%08x\n", tmp);
		tmp = RREG32_MC(RS690_MCCFG_AGP_LOCATION);
		seq_printf(m, "MCCFG_AGP_LOCATION 0x%08x\n", tmp);
		tmp = RREG32_MC(RS690_MCCFG_FB_LOCATION);
		seq_printf(m, "MCCFG_FB_LOCATION 0x%08x\n", tmp);
		tmp = RREG32(RS690_HDP_FB_LOCATION);
		seq_printf(m, "HDP_FB_LOCATION 0x%08x\n", tmp);
	} else {
		tmp = RREG32(RADEON_AGP_BASE);
		seq_printf(m, "AGP_BASE 0x%08x\n", tmp);
		tmp = RREG32(RS480_AGP_BASE_2);
		seq_printf(m, "AGP_BASE_2 0x%08x\n", tmp);
		tmp = RREG32(RADEON_MC_AGP_LOCATION);
		seq_printf(m, "MC_AGP_LOCATION 0x%08x\n", tmp);
	}
	tmp = RREG32_MC(RS480_GART_BASE);
	seq_printf(m, "GART_BASE 0x%08x\n", tmp);
	tmp = RREG32_MC(RS480_GART_FEATURE_ID);
	seq_printf(m, "GART_FEATURE_ID 0x%08x\n", tmp);
	tmp = RREG32_MC(RS480_AGP_MODE_CNTL);
	seq_printf(m, "AGP_MODE_CONTROL 0x%08x\n", tmp);
	tmp = RREG32_MC(RS480_MC_MISC_CNTL);
	seq_printf(m, "MC_MISC_CNTL 0x%08x\n", tmp);
	tmp = RREG32_MC(0x5F);
	seq_printf(m, "MC_MISC_UMA_CNTL 0x%08x\n", tmp);
	tmp = RREG32_MC(RS480_AGP_ADDRESS_SPACE_SIZE);
	seq_printf(m, "AGP_ADDRESS_SPACE_SIZE 0x%08x\n", tmp);
	tmp = RREG32_MC(RS480_GART_CACHE_CNTRL);
	seq_printf(m, "GART_CACHE_CNTRL 0x%08x\n", tmp);
	tmp = RREG32_MC(0x3B);
	seq_printf(m, "MC_GART_ERROR_ADDRESS 0x%08x\n", tmp);
	tmp = RREG32_MC(0x3C);
	seq_printf(m, "MC_GART_ERROR_ADDRESS_HI 0x%08x\n", tmp);
	tmp = RREG32_MC(0x30);
	seq_printf(m, "GART_ERROR_0 0x%08x\n", tmp);
	tmp = RREG32_MC(0x31);
	seq_printf(m, "GART_ERROR_1 0x%08x\n", tmp);
	tmp = RREG32_MC(0x32);
	seq_printf(m, "GART_ERROR_2 0x%08x\n", tmp);
	tmp = RREG32_MC(0x33);
	seq_printf(m, "GART_ERROR_3 0x%08x\n", tmp);
	tmp = RREG32_MC(0x34);
	seq_printf(m, "GART_ERROR_4 0x%08x\n", tmp);
	tmp = RREG32_MC(0x35);
	seq_printf(m, "GART_ERROR_5 0x%08x\n", tmp);
	tmp = RREG32_MC(0x36);
	seq_printf(m, "GART_ERROR_6 0x%08x\n", tmp);
	tmp = RREG32_MC(0x37);
	seq_printf(m, "GART_ERROR_7 0x%08x\n", tmp);
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(rs400_debugfs_gart_info);
#endif


/* rs480_safe_regs_show -- seq_file iterator for radeon_rs480_safe_regs.
 *
 * Each line: "NAME (0xOFFSET) = 0xVALUE\n"
 *
 * Register selection policy: read-only status and identity registers only.
 * No command-processor, DMA, or power-management control registers.  The
 * list is pinned to the set empirically confirmed on RS482 (1002:5974)
 * via radeontool on 6.18.26-1-cachyos-lts; SAFE_REGS.tsv in the DKMS
 * package is the canonical source of truth.
 */
#if defined(CONFIG_DEBUG_FS)
struct rs480_safe_reg {
	u32 offset;
	const char *name;
};

static const struct rs480_safe_reg rs480_safe_reg_list[] = {
	/* PCI shadow / identity */
	{ 0x0f2c, "ADAPTER_ID" },
	{ 0x0f04, "COMMAND" },
	{ 0x0f08, "STATUS" },
	{ 0x0f0c, "CACHE_LINE" },
	{ 0x0f50, "CAPABILITIES_ID" },
	{ 0x0f5c, "AGP_STATUS" },
	/* BIOS scratch: power/connector/display/PLL state written by BIOS init */
	{ 0x0010, "BIOS_0_SCRATCH" },
	{ 0x0014, "BIOS_1_SCRATCH" },
	{ 0x0018, "BIOS_2_SCRATCH" },
	{ 0x001c, "BIOS_3_SCRATCH" },
	{ 0x0020, "BIOS_4_SCRATCH" },
	{ 0x0024, "BIOS_5_SCRATCH" },
	{ 0x0028, "BIOS_6_SCRATCH" },
	{ 0x002c, "BIOS_7_SCRATCH" },
	/* Memory configuration */
	{ 0x0140, "CONFIG_MEMSIZE" },
	{ 0x0100, "CONFIG_APER_0_BASE" },
	{ 0x0104, "CONFIG_APER_1_BASE" },
	{ 0x0108, "CONFIG_APER_SIZE" },
	{ 0x015c, "NB_TOM" },
	{ 0x0148, "MC_FB_LOCATION" },
	{ 0x014c, "MC_AGP_LOCATION" },
	{ 0x0170, "AGP_BASE" },
	{ 0x0174, "AGP_CNTL" },
	/* Bus configuration */
	{ 0x0030, "BUS_CNTL" },
	{ 0x0034, "BUS_CNTL1" },
	/* GPU status (RBBM busy bits, read-only) */
	{ 0x0e40, "RBBM_STATUS" },
	/* Pixel clock readback */
	{ 0x01e4, "PIXCLKS_CNTL" },
	/* Display geometry -- CRTC1 */
	{ 0x0200, "CRTC_GEN_CNTL" },
	{ 0x01c8, "CRTC_EXT_CNTL" },
	{ 0x0250, "CRTC_H_TOTAL_DISP" },
	{ 0x0260, "CRTC_H_SYNC_STRT_WID" },
	{ 0x0280, "CRTC_V_TOTAL_DISP" },
	{ 0x0284, "CRTC_V_SYNC_STRT_WID" },
	/* Display geometry -- CRTC2 */
	{ 0x0300, "CRTC2_GEN_CNTL" },
	/* Display geometry -- FP shadow */
	{ 0x0400, "FP_CRTC_H_TOTAL_DISP" },
	{ 0x0404, "FP_CRTC_V_TOTAL_DISP" },
	{ 0x0408, "FP_H_SYNC_STRT_WID" },
	{ 0x040c, "FP_V_SYNC_STRT_WID" },
	{ 0x0430, "FP_HORZ_STRETCH" },
	{ 0x0434, "FP_VERT_STRETCH" },
	/* Display output routing */
	{ 0x0180, "DISP_OUTPUT_CNTL" },
	{ 0x0d00, "DAC_CNTL" },
	{ 0x0d04, "DAC_EXT_CNTL" },
	/* LVDS / FP transmitter state */
	{ 0x0210, "LVDS_GEN_CNTL" },
	{ 0x02cc, "LVDS_PLL_CNTL" },
	{ 0x0204, "FP_GEN_CNTL" },
	{ 0x0208, "FP2_GEN_CNTL" },
	/* GPIO / DDC idle state */
	{ 0x0060, "GPIO_MONID" },
	{ 0x006c, "GPIO_DVI_DDC" },
	{ 0x0064, "GPIO_CRT2_DDC" },
	{ 0x0068, "GPIO_VGA_DDC" },
};

static int rs480_safe_regs_show(struct seq_file *m, void *unused)
{
	struct radeon_device *rdev = m->private;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(rs480_safe_reg_list); i++) {
		u32 val = RREG32(rs480_safe_reg_list[i].offset);

		seq_printf(m, "%-24s (0x%04x) = 0x%08x\n",
			   rs480_safe_reg_list[i].name,
			   rs480_safe_reg_list[i].offset,
			   val);
	}
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(rs480_safe_regs);
#endif /* CONFIG_DEBUG_FS */

#if defined(CONFIG_DEBUG_FS)
struct rs480_candidate_reg {
	u32 offset;
	const char *name;
	u8 access;
};

/* Read-hazard skip guard.  Offsets whose RREG32/RREG32_MC does not complete in
 * the current power/clock state freeze the reset-less K8 northbridge, which has
 * no MMIO completion timeout.  A reader must not issue the read; it returns this
 * sentinel and marks the line SKIPPED instead.  Seeded from the 2026-06-12 VAP/PVS
 * wedge findings. */
#define RS480_READ_HAZARD_SENTINEL 0xA2A4DEADu

static bool rs480_offset_is_read_hazard(u32 offset)
{
	/* VAP/PVS vertex engine clock-gates at rest; any MMIO access stalls. */
	if (offset >= 0x2200 && offset <= 0x2504)
		return true;
	switch (offset) {
	case 0x180C: /* BIF_SLAVE_CNTL */
	case 0x03B4: /* CRTC8_IDX */
		return true;
	default:
		return false;
	}
}

static u32 rs480_candidate_reg_read(struct radeon_device *rdev,
				    const struct rs480_candidate_reg *reg)
{
	if (rs480_offset_is_read_hazard(reg->offset))
		return RS480_READ_HAZARD_SENTINEL;
	if (reg->access)
		return RREG32_MC(reg->offset);
	return RREG32(reg->offset);
}

static const struct rs480_candidate_reg rs480_candidate_config_reg_list[] = {
	{ 0x0114, "CONFIG_MEMSIZE_EMBEDDED", 0 },
	{ 0x010c, "CONFIG_REG_1_BASE", 0 },
	{ 0x0110, "CONFIG_REG_APER_SIZE", 0 },
};

static const struct rs480_candidate_reg rs480_candidate_gart_mc_reg_list[] = {
	{ 0x0164, "AGP_BASE_2", 0 },
	{ 0x002B, "GART_FEATURE_ID", 1 },
	{ 0x002C, "GART_BASE", 1 },
};

static const struct rs480_candidate_reg rs480_candidate_vap_reg_list[] = {
	{ 0x2080, "R300_VAP_CNTL", 0 },
	{ 0x2140, "R300_VAP_CNTL_STATUS", 0 },
};

static const struct rs480_candidate_reg rs480_candidate_ga_reg_list[] = {
	{ 0x4274, "R300_GA_ENHANCE", 0 },
	{ 0x4288, "R300_GA_POLY_MODE", 0 },
	{ 0x425C, "R500_GA_IDLE", 0 },
};

static const struct rs480_candidate_reg rs480_candidate_sc_reg_list[] = {
	{ 0x43A4, "R300_SC_HYPERZ", 0 },
	{ 0x43E0, "SC_SCISSOR0", 0 },
};

static const struct rs480_candidate_reg rs480_candidate_gb_reg_list[] = {
	{ 0x4028, "R300_GB_Z_PEQ_CONFIG", 0 },
};

static const struct rs480_candidate_reg rs480_candidate_rb3d_reg_list[] = {
	{ 0x4E4C, "R300_RB3D_DSTCACHE_CTLSTAT", 0 },
};

static const struct rs480_candidate_reg rs480_candidate_zb_reg_list[] = {
	{ 0x4F14, "R300_ZB_ZTOP", 0 },
	{ 0x4F18, "R300_ZB_ZCACHE_CTLSTAT", 0 },
	{ 0x4F1C, "R300_ZB_BW_CNTL", 0 },
	{ 0x4F30, "R300_ZB_ZMASK_OFFSET", 0 },
	{ 0x4F34, "R300_ZB_ZMASK_PITCH", 0 },
	{ 0x4F58, "R300_ZB_ZPASS_DATA", 0 },
	{ 0x4F5C, "R300_ZB_ZPASS_ADDR", 0 },
	/*
	 * Leave ZB_HIZ_* out of the first RS482 candidate cohort.  Mesa still
	 * models RS482 with no HiZ RAM, and the retained zpass bundle did not
	 * show any ZB_HIZ_* writes to validate against.
	 */
};

static int rs480_candidate_config_regs_show(struct seq_file *m, void *unused)
{
	struct radeon_device *rdev = m->private;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(rs480_candidate_config_reg_list); i++) {
		u32 val = rs480_candidate_reg_read(rdev,
					  &rs480_candidate_config_reg_list[i]);

		seq_printf(m, "%-24s (0x%04x) = 0x%08x\n",
			   rs480_candidate_config_reg_list[i].name,
			   rs480_candidate_config_reg_list[i].offset,
			   val);
	}
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(rs480_candidate_config_regs);
static int rs480_candidate_gart_mc_regs_show(struct seq_file *m, void *unused)
{
	struct radeon_device *rdev = m->private;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(rs480_candidate_gart_mc_reg_list); i++) {
		u32 val = rs480_candidate_reg_read(rdev,
					  &rs480_candidate_gart_mc_reg_list[i]);

		seq_printf(m, "%-24s (0x%04x) = 0x%08x\n",
			   rs480_candidate_gart_mc_reg_list[i].name,
			   rs480_candidate_gart_mc_reg_list[i].offset,
			   val);
	}
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(rs480_candidate_gart_mc_regs);
static int rs480_candidate_regs_emit(struct seq_file *m,
				     struct radeon_device *rdev,
				     const struct rs480_candidate_reg *list,
				     unsigned int count)
{
	unsigned int i;

	for (i = 0; i < count; i++) {
		u32 val = rs480_candidate_reg_read(rdev, &list[i]);

		seq_printf(m, "%-24s (0x%04x) = 0x%08x\n",
			   list[i].name,
			   list[i].offset,
			   val);
	}
	return 0;
}

static int rs480_candidate_vap_regs_show(struct seq_file *m, void *unused)
{
	if (radeon_rs480_hazard_readers_armed != 1) {
		seq_puts(m, "disarmed (rs480_hazard_readers_armed != 1): "
			    "VAP/PVS clock-gates at rest and an MMIO read can stall the "
			    "reset-less K8 northbridge.  Set rs480_hazard_readers_armed=1 "
			    "to arm an attended read.\n");
		return 0;
	}
	return rs480_candidate_regs_emit(m, m->private,
					 rs480_candidate_vap_reg_list,
					 ARRAY_SIZE(rs480_candidate_vap_reg_list));
}

DEFINE_SHOW_ATTRIBUTE(rs480_candidate_vap_regs);
static int rs480_candidate_ga_regs_show(struct seq_file *m, void *unused)
{
	return rs480_candidate_regs_emit(m, m->private,
					 rs480_candidate_ga_reg_list,
					 ARRAY_SIZE(rs480_candidate_ga_reg_list));
}

DEFINE_SHOW_ATTRIBUTE(rs480_candidate_ga_regs);
static int rs480_candidate_sc_regs_show(struct seq_file *m, void *unused)
{
	return rs480_candidate_regs_emit(m, m->private,
					 rs480_candidate_sc_reg_list,
					 ARRAY_SIZE(rs480_candidate_sc_reg_list));
}

DEFINE_SHOW_ATTRIBUTE(rs480_candidate_sc_regs);
static int rs480_candidate_gb_regs_show(struct seq_file *m, void *unused)
{
	return rs480_candidate_regs_emit(m, m->private,
					 rs480_candidate_gb_reg_list,
					 ARRAY_SIZE(rs480_candidate_gb_reg_list));
}

DEFINE_SHOW_ATTRIBUTE(rs480_candidate_gb_regs);
static int rs480_candidate_rb3d_regs_show(struct seq_file *m, void *unused)
{
	return rs480_candidate_regs_emit(m, m->private,
					 rs480_candidate_rb3d_reg_list,
					 ARRAY_SIZE(rs480_candidate_rb3d_reg_list));
}

DEFINE_SHOW_ATTRIBUTE(rs480_candidate_rb3d_regs);
static int rs480_candidate_zb_regs_show(struct seq_file *m, void *unused)
{
	return rs480_candidate_regs_emit(m, m->private,
					 rs480_candidate_zb_reg_list,
					 ARRAY_SIZE(rs480_candidate_zb_reg_list));
}

DEFINE_SHOW_ATTRIBUTE(rs480_candidate_zb_regs);
/*
 * COMBIOS firmware-READ candidate cohort.  These MMIO registers are the
 * read-modify-write targets the RS482 COMBIOS itself reads during ASIC_INIT
 * POST, which makes them the natural read-safe seed.  POST runs with the engine
 * quiescent, so firmware-read does not by itself prove live-driver read-safety;
 * this cohort is therefore the driver-locked (access 0 -> RREG32) standalone
 * subset only.  Four firmware-read registers are deliberately excluded: the two
 * index/data aperture ports MM_DATA (0x0004) and CLOCK_CNTL_INDEX (0x0008),
 * whose standalone read returns whatever the driver last indexed; CP_RB_CNTL
 * (0x0704), the active CP ring control that the live driver owns; and GPIOPAD_MASK
 * (0x0198), a GPIO pad mask the driver may drive for DDC -- excluded pending a
 * per-register driver-ownership review.
 */
static const struct rs480_candidate_reg rs480_candidate_firmware_read_reg_list[] = {
	{ 0x0050, "CRTC_GEN_CNTL", 0 },
	{ 0x0058, "DAC_CNTL", 0 },
	{ 0x0130, "HOST_PATH_CNTL", 0 },
	{ 0x01D0, "AIC_CNTL", 0 },
	{ 0x027C, "CRTC_MORE_CNTL", 0 },
	{ 0x04DC, "OV0_FLAG_CNTL", 0 },
	{ 0x0D00, "DISP_MISC_CNTL", 0 },
	{ 0x0D04, "DAC_MACRO_CNTL", 0 },
	{ 0x0D64, "DISP_OUTPUT_CNTL", 0 },
};

static int rs480_candidate_firmware_read_regs_show(struct seq_file *m, void *unused)
{
	if (radeon_rs480_hazard_readers_armed != 1) {
		seq_puts(m, "disarmed (rs480_hazard_readers_armed != 1): this cohort "
			    "includes HOST_PATH_CNTL (0x0130), which gates the HyperTransport "
			    "host path and is classified unsafe_forbidden.  Set "
			    "rs480_hazard_readers_armed=1 to arm an attended read.\n");
		return 0;
	}
	return rs480_candidate_regs_emit(m, m->private,
					 rs480_candidate_firmware_read_reg_list,
					 ARRAY_SIZE(rs480_candidate_firmware_read_reg_list));
}

DEFINE_SHOW_ATTRIBUTE(rs480_candidate_firmware_read_regs);

static const struct rs480_candidate_reg rs480_candidate_vip_straggler_reg_list[] = {
	{ 0x0900, "RADEON_VID_BUFFER_CONTROL", 0 },
	{ 0x0910, "RADEON_FCP_CNTL", 0 },
	{ 0x0800, "RADEON_TV_MASTER_CNTL", 0 },
};

static int rs480_candidate_vip_straggler_regs_show(struct seq_file *m, void *unused)
{
	if (radeon_rs480_hazard_readers_armed != 1) {
		seq_puts(m, "disarmed (rs480_hazard_readers_armed != 1): VIP control "
			    "(VID_BUFFER_CONTROL 0x0900, FCP_CNTL 0x0910) and TV_MASTER_CNTL 0x0800 "
			    "are untested VIP/TV-domain reads.  FORCE_VIP and FORCE_TV_SCLK are "
			    "BIOS-set, but the domains may still stall.  Set "
			    "rs480_hazard_readers_armed=1 to arm an attended read.\n");
		return 0;
	}
	return rs480_candidate_regs_emit(m, m->private,
					 rs480_candidate_vip_straggler_reg_list,
					 ARRAY_SIZE(rs480_candidate_vip_straggler_reg_list));
}

DEFINE_SHOW_ATTRIBUTE(rs480_candidate_vip_straggler_regs);

/* Driver-only-read benign memory-controller cohort, RS480-verifiable subset.
 *
 * Two MMIO words whose read is provably side-effect-free on RS400/RS480.
 * MEM_TIMING_CNTL (EXT_MEM_CNTL, 0x0144) has direct driver precedent on this
 * silicon: r100_bandwidth_update() reads it with a plain RREG32 in the
 * RADEON_IS_IGP path and again in the CHIP_RS400/CHIP_RS480 cas-latency block.
 * MEM_STR_CNTL (0x0150) rests on the direct-read property rather than RS480
 * precedent: it is a non-indexed config register (the driver reads it in
 * combios memory detection), and its aliased decode at the same offset,
 * MC_STATUS, is a status register -- a single non-indexed RREG32 is
 * side-effect-free under either decode.  Both are direct registers (access 0
 * -> RREG32), distinct from the MC_IND_INDEX/MC_IND_DATA indirect aperture
 * (0x01f8/0x01fc) whose standalone read returns whatever the driver last
 * indexed.
 *
 * MC_READ_CNTL_AB (0x017c) is deliberately excluded: on RS480 it decodes as
 * RADEON_PCI_GART_PAGE, which the live driver never touches, and the only
 * MC_READ_CNTL_AB read in the tree is gated
 * ASIC_IS_R300(rdev) && !(rdev->flags & RADEON_IS_IGP) in
 * r100_bandwidth_update(), so an IGP never executes it.  Its RS480 read
 * semantics are therefore uncharacterized; certifying it needs a spec
 * statement on PCI_GART_PAGE read behavior or evidence of an RS480 driver read.
 */
static const struct rs480_candidate_reg rs480_candidate_mc_benign_reg_list[] = {
	{ 0x0144, "RADEON_MEM_TIMING_CNTL", 0 },
	{ 0x0150, "RADEON_MEM_STR_CNTL", 0 },
};

static int rs480_candidate_mc_benign_regs_show(struct seq_file *m, void *unused)
{
	return rs480_candidate_regs_emit(m, m->private,
					 rs480_candidate_mc_benign_reg_list,
					 ARRAY_SIZE(rs480_candidate_mc_benign_reg_list));
}

DEFINE_SHOW_ATTRIBUTE(rs480_candidate_mc_benign_regs);

/* GART aperture status cohort (RS400/RS480 IGP).
 *
 * The four words that describe the live GART: GART_BASE (0x2c, the GPU address
 * the page table maps from), GART_FEATURE_ID (0x2b, the feature/route flags),
 * GART_CACHE_CNTRL (0x2e, the TLB invalidate control whose bit 0 the driver
 * polls in rs400_gart_tlb_flush), and AGP_ADDRESS_SPACE_SIZE (0x38, whose
 * bit 0 RS480_GART_EN enables the GART and whose size field encodes the aperture
 * span -- 1024M on this part).  GART_BASE (0x2c) and GART_FEATURE_ID (0x2b) also
 * appear in the gart_mc candidate cohort at the same offsets; the duplication is
 * intentional so each cohort is a self-contained view -- this one the focused
 * GART-aperture status, gart_mc the original broader candidate set.  All four
 * are MC-aperture registers: the live
 * driver reads them with RREG32_MC in rs400_gart_enable/disable, so access 1
 * selects the controlled indirect read here (write MC_IND_INDEX, then read
 * MC_IND_DATA), which is distinct from a bare MC_IND_DATA read that would return
 * whatever the driver last indexed.  The indirect read is not locked against a
 * concurrent driver MC-aperture access (the same write-index/read-data race the
 * existing gart_mc cohort carries); it is read-only and low-probability, but a
 * value caught mid-race should be re-read rather than trusted.
 */
static const struct rs480_candidate_reg rs480_candidate_gart_status_reg_list[] = {
	{ 0x002c, "GART_BASE", 1 },
	{ 0x002b, "GART_FEATURE_ID", 1 },
	{ 0x002e, "GART_CACHE_CNTRL", 1 },
	{ 0x0038, "AGP_ADDRESS_SPACE_SIZE", 1 },
};

static int rs480_candidate_gart_status_regs_show(struct seq_file *m, void *unused)
{
	return rs480_candidate_regs_emit(m, m->private,
					 rs480_candidate_gart_status_reg_list,
					 ARRAY_SIZE(rs480_candidate_gart_status_reg_list));
}

DEFINE_SHOW_ATTRIBUTE(rs480_candidate_gart_status_regs);

/* UMA frame-buffer status (RS400/RS480 IGP).
 *
 * The IGP has no dedicated VRAM: the "VRAM" is a stolen-system-memory region the
 * BIOS reserves and advertises through NB_TOM (0x15c, base/top in 64KiB units).
 * r100_vram_init_sizes derives real_vram_size = ((top - base + 1) << 16) from it
 * and that is the authoritative GPU-usable VRAM.  visible_vram_size is the
 * CPU-mapped window and is clamped to the BAR0 aperture (128M here); it is NOT
 * the total -- real_vram_size and mc_vram_size are not BAR-capped, so the driver
 * can place non-CPU-mapped BOs in the part of the UMA region beyond the window.
 *
 * The driver only READS this layout; it cannot enlarge it.  Writing a larger
 * CONFIG_MEMSIZE than NB_TOM advertises would point the engine at system memory
 * the BIOS did not reserve (OS-owned RAM) -- memory corruption, not more VRAM.
 * The only safe path to a larger UMA is the BIOS frame-buffer-size option, which
 * sets NB_TOM; the driver then reports the new size here automatically.  This
 * node is read-only status, deliberately not a size setter.
 */
static int rs480_uma_status_show(struct seq_file *m, void *unused)
{
	struct radeon_device *rdev = m->private;
	u32 tom = RREG32(RADEON_NB_TOM);
	u32 base = tom & 0xffff;
	u32 top = tom >> 16;
	u64 nb_tom_size = ((u64)(top - base + 1)) << 16;

	seq_printf(m, "NB_TOM            (0x015c) = 0x%08x  base 0x%04x top 0x%04x -> %llu MiB\n",
		   tom, base, top, (unsigned long long)(nb_tom_size >> 20));
	seq_printf(m, "CONFIG_MEMSIZE    (0x00f8) = 0x%08x\n",
		   RREG32(RADEON_CONFIG_MEMSIZE));
	seq_printf(m, "MC_FB_LOCATION    (0x0148) = 0x%08x\n",
		   RREG32(RADEON_MC_FB_LOCATION));
	seq_printf(m, "MC_MISC_UMA_CNTL  (MC 0x5f) = 0x%08x\n", RREG32_MC(0x5F));
	seq_printf(m, "real_vram_size    = %llu MiB (NB_TOM-derived, GPU-usable total)\n",
		   (unsigned long long)(rdev->mc.real_vram_size >> 20));
	seq_printf(m, "mc_vram_size      = %llu MiB\n",
		   (unsigned long long)(rdev->mc.mc_vram_size >> 20));
	seq_printf(m, "visible_vram_size = %llu MiB (CPU window, BAR0-capped)\n",
		   (unsigned long long)(rdev->mc.visible_vram_size >> 20));
	seq_printf(m, "aper_size (BAR0)  = %llu MiB @ 0x%llx\n",
		   (unsigned long long)((u64)rdev->mc.aper_size >> 20),
		   (unsigned long long)rdev->mc.aper_base);
	seq_printf(m, "igp_sideport      = %s\n",
		   rdev->mc.igp_sideport_enabled ? "enabled" : "absent");
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(rs480_uma_status);

/* SCLK_CNTL (engine-clock control) read-only status.
 *
 * SCLK_CNTL lives in the PLL index space (R_00000D_SCLK_CNTL, r300d.h), not
 * the BAR0 MMIO window the other nodes read, so it is reached through
 * RREG32_PLL (rdev->pll_rreg == r100_pll_rreg on RS400/RS480) under the
 * driver's own clock lock -- the index/data dance the kernel already uses in
 * r300_clock_startup.  That is a low-hazard read on the always-clocked
 * clock-control aperture, not the northbridge MMIO hard-lock class of the
 * gated CAP/IDCT frontier.
 *
 * This is STATUS, not a de-risker.  On the RS480 IGP this register reads
 * near-all-ones: every FORCE bit and every DYN_STOP_LAT bit set, only
 * SCLK_SRC_SEL distinguishable, and it is the only such value among the PLL
 * indices.  That cannot separate "the BIOS forced every block on" from "the
 * force/latency fields are unimplemented on this IGP and read as one", so a
 * set FORCE_IDCT (bit 22) / FORCE_VIP (bit 23) reported here does NOT prove
 * the IDCT/VIP blocks are clocked.  Do not treat it as permission to
 * MMIO-read the gated CAP/IDCT frontier registers; that read stays
 * operator-gated and accepted-wedge.  The node never writes SCLK_CNTL and
 * there is deliberately no FORCE-on knob -- a PLL write is a separate,
 * separately-armed experiment.
 */
static int rs480_sclk_cntl_show(struct seq_file *m, void *unused)
{
	struct radeon_device *rdev = m->private;
	/* PLL index 0x0d == R_00000D_SCLK_CNTL (r300d.h / r100d.h). */
	u32 sclk = RREG32_PLL(0x0000000D);

	seq_printf(m, "SCLK_CNTL (PLL 0x0d) = 0x%08x\n", sclk);
	seq_printf(m, "  FORCE_CP   (bit 16) = %u\n", (sclk >> 16) & 0x1);
	seq_printf(m, "  FORCE_IDCT (bit 22) = %u\n", (sclk >> 22) & 0x1);
	seq_printf(m, "  FORCE_VIP  (bit 23) = %u\n", (sclk >> 23) & 0x1);
	seq_printf(m, "  FORCEON region (bits 15-31) = 0x%05x\n",
		   (sclk >> 15) & 0x1ffff);
	seq_printf(m, "  note: a near-all-ones read is ambiguous (force-on vs"
		      " unimplemented-reads-one); a set FORCE_IDCT/FORCE_VIP here"
		      " does NOT de-risk the gated CAP/IDCT MMIO read.\n");
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(rs480_sclk_cntl);

/* CP MicroEngine instruction-memory read-back dump.
 *
 * The loaded R300_cp.bin is the entire CP-ME instruction memory: a 256-microword
 * ME_RAM overlay loaded through CP_ME_RAM_ADDR (the write pointer) and read back
 * through CP_ME_RAM_RADDR -- write the address, then read the (DATAH, DATAL)
 * microword pair.  CP_ME_RAM_RADDR is 8-bit on RS48x: read-back of 0x000, 0x100
 * and 0x200 returns identical data, so the read pointer wraps mod-256 and the
 * addressable memory is exactly the 256-word overlay.  There is no separately
 * addressable on-chip ROM through this port: the class-0x08 branch targets and
 * the PACKET3 dispatch handler refs are encoded operands that resolve to in-RAM
 * microwords by their low byte (DATAL = condition<<8 | 8-bit target), not
 * addresses into a larger ROM.  The kernel itself writes CP_ME_RAM_RADDR during
 * resume on r600 and later, so the read pointer is a driver-exercised access --
 * but it is still a CP register on reset-less R300 silicon, so the dump is gated
 * default-off and must only be read with the engine idle.
 *
 * The sweep is a seq_file iterator (one microword per step), so seq_file never
 * re-runs the whole sweep when paginating.  All 256 microwords must read back
 * equal to R300_cp.bin -- a self-calibration verified by the offline analysis
 * (the 8-bit-RADDR read-back, 256/256 match).
 */
#define RS480_CP_ME_RAM_DUMP_LIMIT 0x100u	/* 256 microwords; CP_ME_RAM_RADDR is 8-bit, higher wraps */

static void *rs480_cp_me_ram_seq_start(struct seq_file *m, loff_t *pos)
{
	if (!radeon_rs480_cp_me_ram_dump)
		return NULL;
	if (*pos >= RS480_CP_ME_RAM_DUMP_LIMIT)
		return NULL;
	return pos;
}

static void *rs480_cp_me_ram_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;
	if (*pos >= RS480_CP_ME_RAM_DUMP_LIMIT)
		return NULL;
	return pos;
}

static void rs480_cp_me_ram_seq_stop(struct seq_file *m, void *v)
{
}

static int rs480_cp_me_ram_seq_show(struct seq_file *m, void *v)
{
	struct radeon_device *rdev = m->private;
	unsigned int addr = (unsigned int)*(loff_t *)v;
	u32 datah, datal;

	WREG32(RADEON_CP_ME_RAM_RADDR, addr);
	datah = RREG32(RADEON_CP_ME_RAM_DATAH);
	datal = RREG32(RADEON_CP_ME_RAM_DATAL);
	seq_printf(m, "%04x %08x %08x\n", addr, datah, datal);
	return 0;
}

static const struct seq_operations rs480_cp_me_ram_seq_ops = {
	.start = rs480_cp_me_ram_seq_start,
	.next  = rs480_cp_me_ram_seq_next,
	.stop  = rs480_cp_me_ram_seq_stop,
	.show  = rs480_cp_me_ram_seq_show,
};

static int rs480_cp_me_ram_dump_open(struct inode *inode, struct file *file)
{
	int ret = seq_open(file, &rs480_cp_me_ram_seq_ops);

	if (!ret)
		((struct seq_file *)file->private_data)->private = inode->i_private;
	return ret;
}

static const struct file_operations rs480_cp_me_ram_dump_fops = {
	.owner   = THIS_MODULE,
	.open    = rs480_cp_me_ram_dump_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};

/* CP MicroEngine instruction-memory injection -- increment 1: write, verify,
 * restore, NEVER execute.
 *
 * The dump node above proves the ME_RAM read-back port; this proves the write
 * port and its restore.  The engine loads R300_cp.bin through CP_ME_RAM_ADDR
 * (write pointer, auto-incrementing past DATAL), so one microword is written by
 * ADDR, then the (DATAH, DATAL) pair.  To inject one word and undo it without
 * ever running it: require the GFX fence stream and GUI to be idle, save the
 * original via the RADDR read pointer, stop the command queue with
 * CP_CSQ_CNTL=CSQ_PRIDIS_INDDIS (the microcode stays loaded --
 * r100_cp_disable()/r100_cp_init() would reload R300_cp.bin and clobber the
 * write), write the modified word, read it straight back through RADDR to prove
 * the write took, then restore the original word and re-read it to prove the
 * restore took before re-enabling the queue.  The modified word is never live,
 * so no modified microcode executes -- that is the increment-2 stop-line and is
 * deliberately absent from this build.
 *
 * Two gates guard the write.  The address is bounded to the 256-microword
 * R300_cp.bin overlay: those words are known-writable and the restore is
 * cross-checkable against the loaded firmware, whereas a write above the
 * overlay lands in the on-chip ME ROM, no-ops, and would read back != written
 * -- a false "not writable" verdict.  The module param must equal an exact arm
 * token (not merely be nonzero) and the debugfs write must carry the literal
 * ARM keyword, so neither a stray sysfs value nor an unprefixed write alone
 * arms a live CP_ME_RAM write.
 */
#define RS480_CP_ME_INJECT_ARM_TOKEN  0x494e4a31u	/* "INJ1" */
#define RS480_CP_ME_INJECT_ADDR_LIMIT 0x100u		/* R300_cp.bin overlay window */

/* Per-device inject state.  A file-static result buffer would be shared across
 * every radeon instance; the result and its lock belong to one rdev, allocated
 * for the device lifetime and reached through the debugfs node's i_private. */
struct rs480_cp_me_inject_ctx {
	struct radeon_device *rdev;
	struct mutex lock;
	char result[160];
};

static int rs480_cp_me_ram_inject_wait_idle(struct radeon_device *rdev)
{
	int ret = 0;

	mutex_lock(&rdev->ring_lock);
	if (!rdev->ring[RADEON_RING_TYPE_GFX_INDEX].ready) {
		ret = -ENODEV;
		goto out;
	}
	ret = radeon_fence_wait_empty(rdev, RADEON_RING_TYPE_GFX_INDEX);
	if (ret)
		goto out;
	if (r100_gui_wait_for_idle(rdev))
		ret = -EBUSY;
out:
	mutex_unlock(&rdev->ring_lock);
	return ret;
}

static int rs480_cp_me_ram_inject_one(struct radeon_device *rdev, u32 addr,
				      u32 new_h, u32 new_l,
				      u32 *rb_h, u32 *rb_l,
				      u32 *restored_h, u32 *restored_l)
{
	u32 orig_h, orig_l, csq;

	/* save the original microword through the read pointer */
	WREG32(RADEON_CP_ME_RAM_RADDR, addr);
	orig_h = RREG32(RADEON_CP_ME_RAM_DATAH);
	orig_l = RREG32(RADEON_CP_ME_RAM_DATAL);

	/* stop the queue only; the loaded microcode is preserved */
	csq = RREG32(RADEON_CP_CSQ_CNTL);
	WREG32(RADEON_CP_CSQ_CNTL, RADEON_CSQ_PRIDIS_INDDIS);

	/* write the modified microword */
	WREG32(RADEON_CP_ME_RAM_ADDR, addr);
	WREG32(RADEON_CP_ME_RAM_DATAH, new_h);
	WREG32(RADEON_CP_ME_RAM_DATAL, new_l);

	/* read it straight back -- increment 1 never executes the word */
	WREG32(RADEON_CP_ME_RAM_RADDR, addr);
	*rb_h = RREG32(RADEON_CP_ME_RAM_DATAH);
	*rb_l = RREG32(RADEON_CP_ME_RAM_DATAL);

	/* restore the original microword */
	WREG32(RADEON_CP_ME_RAM_ADDR, addr);
	WREG32(RADEON_CP_ME_RAM_DATAH, orig_h);
	WREG32(RADEON_CP_ME_RAM_DATAL, orig_l);

	/* confirm the restore took before re-enabling the queue */
	WREG32(RADEON_CP_ME_RAM_RADDR, addr);
	*restored_h = RREG32(RADEON_CP_ME_RAM_DATAH);
	*restored_l = RREG32(RADEON_CP_ME_RAM_DATAL);

	WREG32(RADEON_CP_CSQ_CNTL, csq);

	/* -EIO is the dangerous outcome: the restore read-back does not match the
	 * saved word, so the loaded microcode is left modified -- the caller must
	 * see the failure, not a success return.  -ENXIO is the safe negative: the
	 * word restored cleanly but the write never took (an address backed by ME
	 * ROM rather than the writable R300_cp.bin overlay reads back != written). */
	if (*restored_h != orig_h || *restored_l != orig_l)
		return -EIO;
	if (*rb_h != new_h || *rb_l != new_l)
		return -ENXIO;
	return 0;
}

static ssize_t rs480_cp_me_ram_inject_write(struct file *file,
					    const char __user *ubuf,
					    size_t len, loff_t *ppos)
{
	struct rs480_cp_me_inject_ctx *ctx = file_inode(file)->i_private;
	struct radeon_device *rdev = ctx->rdev;
	u32 addr, new_h, new_l, rb_h, rb_l, rs_h, rs_l;
	char kbuf[64];
	int ret;

	/* One self-contained "ARM ..." command per write; reject a continued or
	 * seeked write so a split payload cannot arm with a truncated address. */
	if (*ppos != 0)
		return -EINVAL;
	if (radeon_rs480_cp_me_ram_inject != RS480_CP_ME_INJECT_ARM_TOKEN)
		return -EACCES;
	if (len >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, ubuf, len))
		return -EFAULT;
	kbuf[len] = '\0';

	/* "ARM <addr> <datah> <datal>" -- the ARM keyword is the second gate */
	if (sscanf(kbuf, "ARM %x %x %x", &addr, &new_h, &new_l) != 3)
		return -EINVAL;
	if (addr >= RS480_CP_ME_INJECT_ADDR_LIMIT)
		return -ERANGE;

	mutex_lock(&ctx->lock);
	ret = rs480_cp_me_ram_inject_wait_idle(rdev);
	if (ret) {
		snprintf(ctx->result, sizeof(ctx->result),
			 "addr=%04x idle_gate=failed ret=%d\n", addr, ret);
		mutex_unlock(&ctx->lock);
		dev_warn_ratelimited(rdev->dev,
				     "rs480_cp_me_ram_inject: idle gate failed at addr=%04x ret=%d\n",
				     addr, ret);
		return ret;
	}
	ret = rs480_cp_me_ram_inject_one(rdev, addr, new_h, new_l,
					 &rb_h, &rb_l, &rs_h, &rs_l);
	snprintf(ctx->result, sizeof(ctx->result),
		 "addr=%04x wrote=%08x:%08x read=%08x:%08x write_ok=%d restored=%08x:%08x restore_ok=%d\n",
		 addr, new_h, new_l, rb_h, rb_l,
		 (rb_h == new_h && rb_l == new_l), rs_h, rs_l, (ret != -EIO));
	mutex_unlock(&ctx->lock);

	if (ret == -EIO)
		dev_err_ratelimited(rdev->dev,
				    "rs480_cp_me_ram_inject: restore mismatch at addr=%04x\n",
				    addr);
	else if (ret == -ENXIO)
		dev_warn_ratelimited(rdev->dev,
				     "rs480_cp_me_ram_inject: write did not stick at addr=%04x\n",
				     addr);
	else
		dev_info(rdev->dev, "rs480_cp_me_ram_inject: %s", ctx->result);
	/* Propagate the failure: -EIO (restore failed) or -ENXIO (not writable). */
	return ret ? ret : len;
}

static int rs480_cp_me_ram_inject_show(struct seq_file *m, void *unused)
{
	struct rs480_cp_me_inject_ctx *ctx = m->private;

	mutex_lock(&ctx->lock);
	seq_printf(m, "%s", ctx->result[0] ?
		   ctx->result : "no inject performed\n");
	mutex_unlock(&ctx->lock);
	return 0;
}

static int rs480_cp_me_ram_inject_open(struct inode *inode, struct file *file)
{
	return single_open(file, rs480_cp_me_ram_inject_show, inode->i_private);
}

static const struct file_operations rs480_cp_me_ram_inject_fops = {
	.owner   = THIS_MODULE,
	.open    = rs480_cp_me_ram_inject_open,
	.read    = seq_read,
	.write   = rs480_cp_me_ram_inject_write,
	.llseek  = seq_lseek,
	.release = single_release,
};

/* CP-ME oracle Run #1: inject -> restart -> ring-test -> restore mechanical loop.
 *
 * Increment-1 (the inject node above) proved CP_ME_RAM write-verify-restore with
 * no execute.  This proves the next step -- that a microcode write survives a CSQ
 * stop/restart and the engine still services the ring afterward -- with a
 * PREDICTED POSITIVE rather than an exploratory observation.  The target is word
 * 0xff of the 256-word R300_cp.bin overlay, which is all-zero tail padding after
 * the last real instruction at word 0xfb (verified against the firmware blob and
 * the microword decode); no workload executes it.  The stronger invariant is in
 * the write itself: only DATAL (the operand) is replaced with the sentinel, while
 * DATAH (the opcode, 0x00 = const_or_control) is preserved from the original.  So
 * even in the worst case -- the PC falling through 0xfb into the padding -- the
 * executed opcode at 0xff is unchanged; only an operand that opcode 0x00 ignores
 * differs.  ring_test issues only a PACKET0 scratch write, so the loop is
 * isolated to the inject/restart/restore machinery.
 *
 * The sequence mirrors increment-1's quiesce/restart exactly: save the word, stop
 * the queue with CSQ_PRIDIS_INDDIS, write the sentinel, read it back, restore the
 * saved CSQ value (not a guessed constant) to restart, run the gfx ring test with
 * the sentinel live (must PASS -- dead word), quiesce again, restore the original
 * word, restart, and run the ring test once more.
 *
 * HARDWARE OUTCOME: firing this on an RS480 IGP hard-locked both CPU cores.  The
 * CSQ stop/restart desyncs the live CP, and the ring_test scratch poll then reads
 * MMIO that never returns, because the K8 northbridge / HyperTransport has no
 * PCIe-style completion timeout.  The RS480 CP-ME oracle CSQ-toggle ring_test
 * safety RCA retains the bounded evidence.  The node
 * therefore excludes every RADEON_IS_IGP part and returns early.  The live-fire
 * sequence is retained, commented, for a future discrete Radeon, where a
 * wedged-CP poll returns 0xffffffff once the PCIe completion timeout fires, so
 * ring_test fails cleanly and the GPU reset path (radeon_gpu_reset ->
 * rs400_startup -> r100_cp_init re-uploads FIRMWARE_R300) recovers without a
 * reboot.  Inert unless radeon_rs480_cp_me_oracle is armed to the exact token;
 * root-only; run with the display quiesced.
 */
#define RS480_CP_ME_ORACLE_ARM_TOKEN 0x4f524331u	/* "ORC1" */
#define RS480_CP_ME_ORACLE_ADDR      0xffu		/* dead tail-padding microword */
#define RS480_CP_ME_ORACLE_SENTINEL  0xdeadbeefu

static int rs480_cp_me_oracle_show(struct seq_file *m, void *unused)
{
	struct radeon_device *rdev = m->private;

	if (radeon_rs480_cp_me_oracle != RS480_CP_ME_ORACLE_ARM_TOKEN) {
		seq_printf(m, "oracle disarmed: set rs480_cp_me_oracle=0x%08x\n",
			   RS480_CP_ME_ORACLE_ARM_TOKEN);
		return 0;
	}

	/* IGP exclusion.  The live-fire loop stops and restarts the command queue
	 * and then polls a scratch register through r100_ring_test.  On an IGP that
	 * poll MMIO read crosses the K8 northbridge / HyperTransport, which has no
	 * PCIe-style completion timeout: a wedged CP makes the read never return and
	 * hard-locks both CPU cores.  The RS480 CP-ME oracle CSQ-toggle ring_test
	 * safety RCA retains the bounded evidence.  Refuse on
	 * every RADEON_IS_IGP part.  The safe CP_ME_RAM read/verify/restore is still
	 * available through the radeon_rs480_cp_me_ram_inject node. */
	if (rdev->flags & RADEON_IS_IGP) {
		seq_puts(m,
			 "oracle live-fire excluded on IGP: CSQ stop/restart + ring_test "
			 "scratch poll hard-locks the K8 northbridge (no MMIO completion "
			 "timeout).  Use radeon_rs480_cp_me_ram_inject for safe CP_ME_RAM "
			 "read/verify/restore.  See the RS480 CP-ME oracle "
			 "CSQ-toggle ring_test safety RCA.\n");
		return 0;
	}

	/* The live-fire path below drives the gfx ring through radeon_ring_test.
	 * With acceleration disabled the ring is never initialized, so refuse before
	 * the inject/restart sequence rather than touch an uninitialized ring. */
	if (!rdev->accel_working) {
		seq_puts(m,
			 "oracle live-fire requires acceleration; rdev->accel_working is off\n");
		return 0;
	}

	/*
	 * Dedicated-Radeon live-fire path, retained (commented) for future analysis
	 * on a discrete card -- this lane has no discrete target to validate it on.
	 * On a discrete GPU a wedged-CP scratch poll returns 0xffffffff once the
	 * PCIe completion timeout fires, so r100_ring_test fails cleanly and the
	 * driver recovers, which makes the operation sound there.  To exercise on a
	 * dedicated Radeon, restore the block below: it injects the sentinel into
	 * dead microword 0xff, stops the command queue (CSQ_PRIDIS_INDDIS), restarts
	 * from the saved CSQ value, runs the gfx ring test (predicted PASS -- the
	 * word never executes), restores the original word, and re-tests.
	 *
	 * Uncommenting requires three things this lane has not wired, because no
	 * discrete card validated them:
	 *   - the oracle node's i_private must be the shared rs480_cp_me_inject_ctx
	 *     (today it is rdev), so the live-fire holds ctx->lock and serializes
	 *     against radeon_rs480_cp_me_ram_inject -- both write CP_ME_RAM;
	 *   - the target word must read back all-zero first (a nonzero word is a real
	 *     instruction, not dead padding -- abort);
	 *   - the inject read-back must match the opcode (DATAH preserved) AND the
	 *     operand (DATAL == sentinel); on any mismatch restore and abort rather
	 *     than ring-test a half-written microword.
	 *
	 *	struct rs480_cp_me_inject_ctx *ctx = m->private;
	 *	struct radeon_device *rdev = ctx->rdev;
	 *	struct radeon_ring *ring = &rdev->ring[RADEON_RING_TYPE_GFX_INDEX];
	 *	const u32 addr = RS480_CP_ME_ORACLE_ADDR;
	 *	u32 orig_h, orig_l, rb_h, rb_l, csq;
	 *	int r;
	 *
	 *	mutex_lock(&ctx->lock);
	 *	WREG32(RADEON_CP_ME_RAM_RADDR, addr);
	 *	orig_h = RREG32(RADEON_CP_ME_RAM_DATAH);
	 *	orig_l = RREG32(RADEON_CP_ME_RAM_DATAL);
	 *	seq_printf(m, "target 0x%02x original = %08x:%08x\n", addr, orig_h, orig_l);
	 *
	 *	if (orig_h || orig_l) {
	 *		seq_printf(m, "abort: word 0x%02x not dead padding (%08x:%08x)\n",
	 *			   addr, orig_h, orig_l);
	 *		mutex_unlock(&ctx->lock);
	 *		return 0;
	 *	}
	 *
	 *	csq = RREG32(RADEON_CP_CSQ_CNTL);
	 *	WREG32(RADEON_CP_CSQ_CNTL, RADEON_CSQ_PRIDIS_INDDIS);
	 *
	 *	WREG32(RADEON_CP_ME_RAM_ADDR, addr);
	 *	WREG32(RADEON_CP_ME_RAM_DATAH, orig_h);
	 *	WREG32(RADEON_CP_ME_RAM_DATAL, RS480_CP_ME_ORACLE_SENTINEL);
	 *
	 *	WREG32(RADEON_CP_ME_RAM_RADDR, addr);
	 *	rb_h = RREG32(RADEON_CP_ME_RAM_DATAH);
	 *	rb_l = RREG32(RADEON_CP_ME_RAM_DATAL);
	 *	if (rb_h != orig_h || rb_l != RS480_CP_ME_ORACLE_SENTINEL) {
	 *		seq_printf(m, "abort: inject readback %08x:%08x != %08x:%08x; restoring\n",
	 *			   rb_h, rb_l, orig_h, RS480_CP_ME_ORACLE_SENTINEL);
	 *		WREG32(RADEON_CP_ME_RAM_ADDR, addr);
	 *		WREG32(RADEON_CP_ME_RAM_DATAH, orig_h);
	 *		WREG32(RADEON_CP_ME_RAM_DATAL, orig_l);
	 *		WREG32(RADEON_CP_CSQ_CNTL, csq);
	 *		mutex_unlock(&ctx->lock);
	 *		return 0;
	 *	}
	 *
	 *	WREG32(RADEON_CP_CSQ_CNTL, csq);
	 *	r = radeon_ring_test(rdev, RADEON_RING_TYPE_GFX_INDEX, ring);
	 *	seq_printf(m, "ring_test with sentinel live: %s\n", r ? "FAIL" : "PASS");
	 *
	 *	WREG32(RADEON_CP_CSQ_CNTL, RADEON_CSQ_PRIDIS_INDDIS);
	 *	WREG32(RADEON_CP_ME_RAM_ADDR, addr);
	 *	WREG32(RADEON_CP_ME_RAM_DATAH, orig_h);
	 *	WREG32(RADEON_CP_ME_RAM_DATAL, orig_l);
	 *	WREG32(RADEON_CP_ME_RAM_RADDR, addr);
	 *	rb_h = RREG32(RADEON_CP_ME_RAM_DATAH);
	 *	rb_l = RREG32(RADEON_CP_ME_RAM_DATAL);
	 *	seq_printf(m, "restored: readback %08x:%08x (%s)\n", rb_h, rb_l,
	 *		   (rb_h == orig_h && rb_l == orig_l) ? "OK" : "MISMATCH");
	 *	WREG32(RADEON_CP_CSQ_CNTL, csq);
	 *	mutex_unlock(&ctx->lock);
	 *
	 *	r = radeon_ring_test(rdev, RADEON_RING_TYPE_GFX_INDEX, ring);
	 *	seq_printf(m, "ring_test after restore: %s\n", r ? "FAIL" : "PASS");
	 *	seq_puts(m, "oracle Run #1 complete\n");
	 */
	seq_puts(m,
		 "oracle live-fire retained (commented) for dedicated-Radeon analysis; "
		 "not compiled in this lane.  See the RS480 CP-ME oracle "
		 "CSQ-toggle ring_test safety RCA.\n");
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(rs480_cp_me_oracle);
#endif /* CONFIG_DEBUG_FS */

/* drm_driver.debugfs_init hook.  drm_debugfs_register() assigns
 * minor->debugfs_root before calling this, and only for the primary minor (it
 * skips dev->render), so the rs480 RE nodes land under /sys/kernel/debug/dri/N/
 * here.  Calling these inits from rs400_init() instead would run them before
 * drm_dev_register() populates primary->debugfs_root on 6.7+ DRM, dropping every
 * node at the debugfs top level (confirmed identical on 6.18 and 7.0).
 * Defensive guards reject malformed minor inputs before dereferencing the DRM
 * device, and debugfs_create_file() is itself non-fatal, so a failure here
 * never blocks radeon from loading.  mc_flush keeps its caller-side family/accel
 * gate. */
void radeon_rs480_re_debugfs_register(struct drm_minor *minor)
{
	struct radeon_device *rdev;

	if (!minor || minor->type != DRM_MINOR_PRIMARY || !minor->dev ||
	    !minor->debugfs_root)
		return;
	rdev = minor->dev->dev_private;
	if (!rdev)
		return;

	rs480_safe_regs_debugfs_init(rdev);
	rs480_candidate_regs_debugfs_init(rdev);
	if ((rdev->family == CHIP_RS480 || rdev->family == CHIP_RS400) &&
	    rdev->accel_working)
		radeon_debugfs_rs480_mc_flush_init(rdev);
}

static void rs480_safe_regs_debugfs_init(struct radeon_device *rdev)
{
#if defined(CONFIG_DEBUG_FS)
	struct dentry *root = rdev_to_drm(rdev)->primary->debugfs_root;

	if (!radeon_rs480_safe_regs)
		return;

	/* RS482 (1002:5974) and RS485 (1002:5975) both enumerate as
	 * CHIP_RS480 in the radeon family table.
	 */
	if (rdev->family != CHIP_RS400 && rdev->family != CHIP_RS480)
		return;

	debugfs_create_file("radeon_rs480_safe_regs", 0444, root, rdev,
			    &rs480_safe_regs_fops);
#endif
}

static void rs480_candidate_regs_debugfs_init(struct radeon_device *rdev)
{
#if defined(CONFIG_DEBUG_FS)
	struct dentry *root = rdev_to_drm(rdev)->primary->debugfs_root;
	struct rs480_cp_me_inject_ctx *inject_ctx;

	if (!radeon_rs480_candidate_regs)
		return;

	if (rdev->family != CHIP_RS400 && rdev->family != CHIP_RS480)
		return;

	/* Compatibility alias for the first config-aperture candidate cohort. */
	debugfs_create_file("radeon_rs480_candidate_regs", 0444, root, rdev,
			    &rs480_candidate_config_regs_fops);
	debugfs_create_file("radeon_rs480_candidate_config_regs", 0444, root, rdev,
			    &rs480_candidate_config_regs_fops);
	debugfs_create_file("radeon_rs480_candidate_gart_mc_regs", 0444, root, rdev,
			    &rs480_candidate_gart_mc_regs_fops);
	debugfs_create_file("radeon_rs480_candidate_vap_regs", 0444, root, rdev,
			    &rs480_candidate_vap_regs_fops);
	debugfs_create_file("radeon_rs480_candidate_ga_regs", 0444, root, rdev,
			    &rs480_candidate_ga_regs_fops);
	debugfs_create_file("radeon_rs480_candidate_sc_regs", 0444, root, rdev,
			    &rs480_candidate_sc_regs_fops);
	debugfs_create_file("radeon_rs480_candidate_gb_regs", 0444, root, rdev,
			    &rs480_candidate_gb_regs_fops);
	debugfs_create_file("radeon_rs480_candidate_rb3d_regs", 0444, root, rdev,
			    &rs480_candidate_rb3d_regs_fops);
	debugfs_create_file("radeon_rs480_candidate_zb_regs", 0444, root, rdev,
			    &rs480_candidate_zb_regs_fops);
	debugfs_create_file("radeon_rs480_candidate_z_regs", 0444, root, rdev,
			    &rs480_candidate_zb_regs_fops);
	debugfs_create_file("radeon_rs480_candidate_firmware_read_regs", 0444, root, rdev,
			    &rs480_candidate_firmware_read_regs_fops);
	debugfs_create_file("radeon_rs480_candidate_vip_straggler_regs", 0444, root, rdev,
			    &rs480_candidate_vip_straggler_regs_fops);
	debugfs_create_file("radeon_rs480_candidate_mc_benign_regs", 0444, root, rdev,
			    &rs480_candidate_mc_benign_regs_fops);
	debugfs_create_file("radeon_rs480_candidate_gart_status_regs", 0444, root, rdev,
			    &rs480_candidate_gart_status_regs_fops);
	debugfs_create_file("radeon_rs480_uma_status", 0444, root, rdev,
			    &rs480_uma_status_fops);
	debugfs_create_file("radeon_rs480_sclk_cntl", 0444, root, rdev,
			    &rs480_sclk_cntl_fops);
	/* CP_ME_RAM read-back dump.  Created on RS400/RS480 when the candidate-regs
	 * group is enabled, but inert until the operator sets
	 * radeon_rs480_cp_me_ram_dump=1 (the seq start() gate), because the read
	 * sweep writes the CP_ME_RAM_RADDR pointer on reset-less silicon.
	 */
	debugfs_create_file("radeon_rs480_cp_me_ram_dump", 0444, root, rdev,
			    &rs480_cp_me_ram_dump_fops);
	/* CP_ME_RAM injection -- increment 1 (write-verify-restore, no execute).
	 * Mode 0600: a write here pokes a live CP register, so it is root-only and
	 * additionally inert until radeon_rs480_cp_me_ram_inject equals the exact
	 * arm token and the write payload carries the ARM keyword.
	 */
	inject_ctx = devm_kzalloc(rdev->dev, sizeof(*inject_ctx), GFP_KERNEL);
	if (inject_ctx) {
		inject_ctx->rdev = rdev;
		mutex_init(&inject_ctx->lock);
		debugfs_create_file("radeon_rs480_cp_me_ram_inject", 0600, root,
				    inject_ctx, &rs480_cp_me_ram_inject_fops);
	}
	/* CP-ME oracle Run #1.  Mode 0400: reading it runs a live CP_ME_RAM
	 * inject/restart/ring-test/restore loop, so it is root-only and inert
	 * until radeon_rs480_cp_me_oracle equals the exact arm token. */
	debugfs_create_file("radeon_rs480_cp_me_oracle", 0400, root, rdev,
			    &rs480_cp_me_oracle_fops);
#endif
}

static void rs400_debugfs_pcie_gart_info_init(struct radeon_device *rdev)
{
#if defined(CONFIG_DEBUG_FS)
	struct dentry *root = rdev_to_drm(rdev)->primary->debugfs_root;

	debugfs_create_file("rs400_gart_info", 0444, root, rdev,
			    &rs400_debugfs_gart_info_fops);
#endif
}

static void rs400_mc_program(struct radeon_device *rdev)
{
	struct r100_mc_save save;

	/* Stops all mc clients */
	r100_mc_stop(rdev, &save);

	/* Wait for mc idle */
	if (rs400_mc_wait_for_idle(rdev))
		dev_warn(rdev->dev, "rs400: Wait MC idle timeout before updating MC.\n");
	WREG32(R_000148_MC_FB_LOCATION,
		S_000148_MC_FB_START(rdev->mc.vram_start >> 16) |
		S_000148_MC_FB_TOP(rdev->mc.vram_end >> 16));

	r100_mc_resume(rdev, &save);
}

static int rs400_startup(struct radeon_device *rdev)
{
	int r;

	r100_set_common_regs(rdev);

	rs400_mc_program(rdev);
	/* Resume clock */
	r300_clock_startup(rdev);
	/* Initialize GPU configuration (# pipes, ...) */
	rs400_gpu_init(rdev);
	r100_enable_bm(rdev);
	/* Initialize GART (initialize after TTM so we can allocate
	 * memory through TTM but finalize after TTM) */
	r = rs400_gart_enable(rdev);
	if (r)
		return r;

	/* allocate wb buffer */
	r = radeon_wb_init(rdev);
	if (r)
		return r;

	r = radeon_fence_driver_start_ring(rdev, RADEON_RING_TYPE_GFX_INDEX);
	if (r) {
		dev_err(rdev->dev, "failed initializing CP fences (%d).\n", r);
		return r;
	}

	/* Enable IRQ */
	if (!rdev->irq.installed) {
		r = radeon_irq_kms_init(rdev);
		if (r)
			return r;
	}

	r100_irq_set(rdev);
	rdev->config.r300.hdp_cntl = RREG32(RADEON_HOST_PATH_CNTL);
	/* 1M ring buffer */
	r = r100_cp_init(rdev, 1024 * 1024);
	if (r) {
		dev_err(rdev->dev, "failed initializing CP (%d).\n", r);
		return r;
	}

	r = radeon_ib_pool_init(rdev);
	if (r) {
		dev_err(rdev->dev, "IB initialization failed (%d).\n", r);
		return r;
	}

	return 0;
}

int rs400_resume(struct radeon_device *rdev)
{
	int r;

	/* Make sur GART are not working */
	rs400_gart_disable(rdev);
	/* Resume clock before doing reset */
	r300_clock_startup(rdev);
	/* setup MC before calling post tables */
	rs400_mc_program(rdev);
	/* Reset gpu before posting otherwise ATOM will enter infinite loop */
	if (radeon_asic_reset(rdev)) {
		dev_warn(rdev->dev, "GPU reset failed ! (0xE40=0x%08X, 0x7C0=0x%08X)\n",
			RREG32(R_000E40_RBBM_STATUS),
			RREG32(R_0007C0_CP_STAT));
	}
	/* post */
	radeon_combios_asic_init(rdev_to_drm(rdev));
	/* Resume clock after posting */
	r300_clock_startup(rdev);
	/* Initialize surface registers */
	radeon_surface_init(rdev);

	rdev->accel_working = true;
	r = rs400_startup(rdev);
	if (r) {
		rdev->accel_working = false;
	}
	return r;
}

int rs400_suspend(struct radeon_device *rdev)
{
	radeon_pm_suspend(rdev);
	r100_cp_disable(rdev);
	radeon_wb_disable(rdev);
	r100_irq_disable(rdev);
	rs400_gart_disable(rdev);
	return 0;
}

void rs400_fini(struct radeon_device *rdev)
{
	radeon_pm_fini(rdev);
	r100_cp_fini(rdev);
	radeon_wb_fini(rdev);
	radeon_ib_pool_fini(rdev);
	radeon_gem_fini(rdev);
	rs400_gart_fini(rdev);
	radeon_irq_kms_fini(rdev);
	radeon_fence_driver_fini(rdev);
	radeon_bo_fini(rdev);
	radeon_atombios_fini(rdev);
	kfree(rdev->bios);
	rdev->bios = NULL;
}

int rs400_init(struct radeon_device *rdev)
{
	int r;

	/* Disable VGA */
	r100_vga_render_disable(rdev);
	/* Initialize scratch registers */
	radeon_scratch_init(rdev);
	/* Initialize surface registers */
	radeon_surface_init(rdev);
	/* TODO: disable VGA need to use VGA request */
	/* restore some register to sane defaults */
	r100_restore_sanity(rdev);
	/* BIOS*/
	if (!radeon_get_bios(rdev)) {
		if (ASIC_IS_AVIVO(rdev))
			return -EINVAL;
	}
	if (rdev->is_atom_bios) {
		dev_err(rdev->dev, "Expecting combios for RS400/RS480 GPU\n");
		return -EINVAL;
	} else {
		r = radeon_combios_init(rdev);
		if (r)
			return r;
	}
	/* Reset gpu before posting otherwise ATOM will enter infinite loop */
	if (radeon_asic_reset(rdev)) {
		dev_warn(rdev->dev,
			"GPU reset failed ! (0xE40=0x%08X, 0x7C0=0x%08X)\n",
			RREG32(R_000E40_RBBM_STATUS),
			RREG32(R_0007C0_CP_STAT));
	}
	/* check if cards are posted or not */
	if (radeon_boot_test_post_card(rdev) == false)
		return -EINVAL;

	/* Initialize clocks */
	radeon_get_clock_info(rdev_to_drm(rdev));
	/* initialize memory controller */
	rs400_mc_init(rdev);
	/* Fence driver */
	radeon_fence_driver_init(rdev);
	/* Memory manager */
	r = radeon_bo_init(rdev);
	if (r)
		return r;
	r = rs400_gart_init(rdev);
	if (r)
		return r;
	r300_set_reg_safe(rdev);

	/* Initialize power management */
	radeon_pm_init(rdev);

	rdev->accel_working = true;
	r = rs400_startup(rdev);
	if (r) {
		/* Somethings want wront with the accel init stop accel */
		dev_err(rdev->dev, "Disabling GPU acceleration\n");
		r100_cp_fini(rdev);
		radeon_wb_fini(rdev);
		radeon_ib_pool_fini(rdev);
		rs400_gart_fini(rdev);
		radeon_irq_kms_fini(rdev);
		rdev->accel_working = false;
	}
	return 0;
}
