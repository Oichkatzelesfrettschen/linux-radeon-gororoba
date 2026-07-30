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
#include <linux/pci.h>
#include <linux/uaccess.h>

#include <drm/drm_device.h>
#include <drm/drm_file.h>

#include "radeon.h"
#include "radeon_asic.h"
#include "rs400d.h"
#include "radeon_object.h"

#include "rs480_reg_safe.h"

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

	/* The GART cache serves the 3D engine's fetch path, and the MC
	 * indirect data read polls a block held by the wedged GA client: on a
	 * parked GPU the RREG32_MC below is a non-posted black hole. Teardown
	 * still rewrites the PTEs in system RAM; nothing fetches through
	 * these TLBs again before a reboot, so the flush is skippable.
	 */
	if (rdev->gpu_parked) {
		dev_err_once(rdev->dev, "parked: skipping GART tlb flush (MC indirect unreadable)\n");
		return;
	}

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
/* rs480_debugfs_refuse_if_parked -- after a failed RS480 reset the GA-routed
 * register bus never grants a non-posted read, so a debugfs register read
 * black-holes the K8 northbridge and sync-floods the box (cold cycle only).
 * Every RS480 RE debugfs reader refuses hardware access once gpu_parked is
 * set; the node reports the parked state instead of touching MMIO. */
static bool rs480_debugfs_refuse_if_parked(struct seq_file *m,
					   struct radeon_device *rdev)
{
	if (!rdev->gpu_parked)
		return false;
	/* seq_file iterators call .show per position; emit once per open. */
	if (m->count == 0)
		seq_puts(m,
			 "gpu parked: RS480 register read disabled to avoid non-posted MMIO black hole\n");
	return true;
}

static int rs400_debugfs_gart_info_show(struct seq_file *m, void *unused)
{
	struct radeon_device *rdev = m->private;
	if (rs480_debugfs_refuse_if_parked(m, rdev))
		return 0;
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
	/* Config aperture/base registers, read-only in the public register
	 * text (no documented write side-effect on read).  Promoted from the
	 * candidate config cohort after a clean RREG32 read confirmed them
	 * readable with no hang on the RS480 IGP. */
	{ 0x010c, "CONFIG_REG_1_BASE" },
	{ 0x0110, "CONFIG_REG_APER_SIZE" },
	{ 0x0114, "CONFIG_MEMSIZE_EMBEDDED" },
	/* RS400 secondary display-output path, observed northbridge-safe on the
	 * real RS480 IGP through the attended frontier probe (the three reads
	 * returned values with the heartbeat advancing and no wedge).  FP2_2 and
	 * TMDS2 carry live secondary-output state; reading them has no documented
	 * write side-effect. */
	{ 0x0388, "RS400_FP2_2_GEN_CNTL" },
	{ 0x0394, "RS400_TMDS2_CNTL" },
	{ 0x03a4, "RS400_TMDS2_TRANSMITTER_CNTL" },
	/* Hazard-tier read-safe registers, each read clean on the real RS480 IGP
	 * through the radeon_rs480_hazard_read node (every read returned, no
	 * core wedge; the SE_VPORT reads are verified against SCLK_CNTL FORCE_CP=1).
	 * They were parked only by a name-pattern regex (SCRATCH / PORT_ matching
	 * VPORT_ / SEMAPHORE), not a measured hazard, so they promote to the
	 * read-only safe-regs list; radeon_rs480_hazard_read is retained as the
	 * observation provenance. */
	{ 0x00c0, "BIOS_8_SCRATCH" },
	{ 0x00c4, "BIOS_9_SCRATCH" },
	{ 0x00c8, "BIOS_10_SCRATCH" },
	{ 0x00cc, "BIOS_11_SCRATCH" },
	{ 0x00d0, "BIOS_12_SCRATCH" },
	{ 0x00d4, "BIOS_13_SCRATCH" },
	{ 0x00d8, "BIOS_14_SCRATCH" },
	{ 0x00dc, "BIOS_15_SCRATCH" },
	{ 0x013c, "SW_SEMAPHORE" },
	{ 0x15e0, "GUI_SCRATCH_REG0" },
	{ 0x15e4, "GUI_SCRATCH_REG1" },
	{ 0x15e8, "GUI_SCRATCH_REG2" },
	{ 0x15ec, "GUI_SCRATCH_REG3" },
	{ 0x15f0, "GUI_SCRATCH_REG4" },
	{ 0x15f4, "GUI_SCRATCH_REG5" },
	{ 0x1720, "WAIT_UNTIL" },
	{ 0x1d98, "SE_VPORT_XSCALE" },
	{ 0x1d9c, "SE_VPORT_XOFFSET" },
	{ 0x1da0, "SE_VPORT_YSCALE" },
	{ 0x1da4, "SE_VPORT_YOFFSET" },
	{ 0x1da8, "SE_VPORT_ZSCALE" },
	{ 0x1dac, "SE_VPORT_ZOFFSET" },
	{ 0x02f0, "GRPH_BUFFER_CNTL" },
	{ 0x03f0, "GRPH2_BUFFER_CNTL" },
	{ 0x0e38, "RS400_DMIF_MEM_CNTL1" },
};

static int rs480_safe_regs_show(struct seq_file *m, void *unused)
{
	struct radeon_device *rdev = m->private;
	if (rs480_debugfs_refuse_if_parked(m, rdev))
		return 0;
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
	if (rdev->gpu_parked)
		return RS480_READ_HAZARD_SENTINEL;
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
	if (rs480_debugfs_refuse_if_parked(m, rdev))
		return 0;
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
	if (rs480_debugfs_refuse_if_parked(m, rdev))
		return 0;
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
	if (rs480_debugfs_refuse_if_parked(m, rdev))
		return 0;
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
	if (rs480_debugfs_refuse_if_parked(m, rdev))
		return 0;
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
	if (rs480_debugfs_refuse_if_parked(m, rdev))
		return 0;
	/* PLL index 0x0d == R_00000D_SCLK_CNTL (r300d.h / r100d.h). */
	u32 sclk = RREG32_PLL(0x0000000D);
	/* PLL index 0x1e == R300_SCLK_CNTL2.  It holds the R300 3D-engine force
	 * bits TCL (bit 13), CBA (bit 14) and GA (bit 15) that the first PLL
	 * register does not carry.  This read resolves whether those domains gate
	 * at rest before any 3D MMIO read is attempted; the read itself is
	 * driver-mediated (r100_pll_rreg) and does not touch the 3D MMIO aperture. */
	u32 sclk2 = RREG32_PLL(0x0000001E);

	seq_printf(m, "SCLK_CNTL (PLL 0x0d) = 0x%08x\n", sclk);
	seq_printf(m, "  FORCE_CP   (bit 16) = %u\n", (sclk >> 16) & 0x1);
	seq_printf(m, "  FORCE_IDCT (bit 22) = %u\n", (sclk >> 22) & 0x1);
	seq_printf(m, "  FORCE_VIP  (bit 23) = %u\n", (sclk >> 23) & 0x1);
	seq_printf(m, "  FORCE_VAP  (bit 21) = %u\n", (sclk >> 21) & 0x1);
	seq_printf(m, "  FORCE_TX   (bit 27) = %u\n", (sclk >> 27) & 0x1);
	seq_printf(m, "  FORCE_US   (bit 28) = %u\n", (sclk >> 28) & 0x1);
	seq_printf(m, "  FORCE_SU   (bit 30) = %u\n", (sclk >> 30) & 0x1);
	seq_printf(m, "  FORCEON region (bits 15-31) = 0x%05x\n",
		   (sclk >> 15) & 0x1ffff);
	seq_printf(m, "SCLK_CNTL2 (PLL 0x1e) = 0x%08x\n", sclk2);
	seq_printf(m, "  FORCE_TCL  (bit 13) = %u\n", (sclk2 >> 13) & 0x1);
	seq_printf(m, "  FORCE_CBA  (bit 14) = %u\n", (sclk2 >> 14) & 0x1);
	seq_printf(m, "  FORCE_GA   (bit 15) = %u\n", (sclk2 >> 15) & 0x1);
	seq_printf(m, "  note: a near-all-ones read is ambiguous (force-on vs"
		      " unimplemented-reads-one); a set FORCE_IDCT/FORCE_VIP here"
		      " does NOT de-risk the gated CAP/IDCT MMIO read.\n");
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(rs480_sclk_cntl);

/* PLL-indirect clock-tree read-out.
 *
 * The clock generators live in the PLL index space (CLOCK_CNTL_INDEX +
 * CLOCK_CNTL_DATA), not the BAR0 MMIO window, so they are reached through
 * RREG32_PLL.  r100_pll_rreg (rdev->pll_rreg on RS400/RS480) takes
 * rdev->pll_idx_lock across the index write and the data read, the same lock
 * the driver's own modeset clock path holds, so a read here cannot race the
 * shared index pointer -- this is the index/data port done safely, unlike the
 * BAR0 PALETTE/FOG data ports the hazard-read node deliberately excludes.  The
 * aperture is always clocked (the 0018 SCLK_CNTL read returns on this IGP), so
 * these reads complete instead of stalling the K8 northbridge.
 *
 * The 6-bit index (reg & 0x3f in r100_pll_rreg) bounds the table to the PLL
 * indices named in radeon_reg.h; the node never sweeps undefined indices and
 * never writes the PLL space.  The dividers and feedback registers carry the
 * documented multi-bit fields the dot-clock and memory-clock frequencies are
 * derived from, decoded after the raw dump.
 */
struct rs480_pll_reg {
	u8 index;
	const char *name;
};

static const struct rs480_pll_reg rs480_pll_reg_list[] = {
	/* Pixel PLL: display dot-clock generation. */
	{ 0x02, "PPLL_CNTL" },
	{ 0x03, "PPLL_REF_DIV" },
	{ 0x04, "PPLL_DIV_0" },
	{ 0x05, "PPLL_DIV_1" },
	{ 0x06, "PPLL_DIV_2" },
	{ 0x07, "PPLL_DIV_3" },
	/* System, memory, and engine PLLs. */
	{ 0x0a, "M_SPLL_REF_FB_DIV" },
	{ 0x0c, "SPLL_CNTL" },
	{ 0x0d, "SCLK_CNTL" },
	{ 0x0e, "MPLL_CNTL" },
	{ 0x12, "MCLK_CNTL" },
	{ 0x1f, "MCLK_MISC" },
	{ 0x35, "SCLK_MORE_CNTL" },
	/* Clock sources, pins, and clock power management. */
	{ 0x01, "CLK_PIN_CNTL" },
	{ 0x08, "VCLK_ECP_CNTL" },
	{ 0x09, "HTOTAL_CNTL" },
	{ 0x0b, "AGP_PLL_CNTL" },
	{ 0x13, "PLL_TEST_CNTL" },
	{ 0x14, "CLK_PWRMGT_CNTL" },
	{ 0x15, "PLL_PWRMGT_CNTL" },
	/* Secondary-display and TV-out PLLs.  These may be unimplemented on the
	 * laptop IGP; a read of an unimplemented PLL index returns the data
	 * port, it does not stall. */
	{ 0x20, "TV_PLL_FINE_CNTL" },
	{ 0x21, "TV_PLL_CNTL" },
	{ 0x22, "TV_PLL_CNTL1" },
	{ 0x2b, "P2PLL_REF_DIV" },
	{ 0x2e, "HTOTAL2_CNTL" },
};

static int rs480_pll_regs_show(struct seq_file *m, void *unused)
{
	struct radeon_device *rdev = m->private;
	if (rs480_debugfs_refuse_if_parked(m, rdev))
		return 0;
	unsigned int i;
	u32 ppll_ref, ppll_div3, m_spll, vclk;

	for (i = 0; i < ARRAY_SIZE(rs480_pll_reg_list); i++)
		seq_printf(m, "%-18s (PLL 0x%02x) = 0x%08x\n",
			   rs480_pll_reg_list[i].name,
			   rs480_pll_reg_list[i].index,
			   RREG32_PLL(rs480_pll_reg_list[i].index));

	/* Decode the divider and feedback fields (radeon_reg.h masks):
	 *   PPLL_REF_DIV.ref_div      bits [9:0]   (PPLL_REF_DIV_MASK 0x03ff)
	 *   PPLL_DIV_3.fb_div         bits [10:0]  (PPLL_FB3_DIV_MASK 0x07ff)
	 *   PPLL_DIV_3.post_div       bits [18:16] (PPLL_POST3_DIV_MASK)
	 *   M_SPLL_REF_FB_DIV.ref_div bits [7:0],  .mpll_fb [15:8], .spll_fb [23:16]
	 *   VCLK_ECP_CNTL.src_sel     bits [1:0]   (VCLK_SRC_SEL_MASK 0x03)
	 */
	ppll_ref  = RREG32_PLL(0x03);
	ppll_div3 = RREG32_PLL(0x07);
	m_spll    = RREG32_PLL(0x0a);
	vclk      = RREG32_PLL(0x08);
	seq_puts(m, "\nderived fields:\n");
	seq_printf(m, "  PPLL_REF_DIV.ref_div      = %u\n", ppll_ref & 0x03ff);
	seq_printf(m, "  PPLL_DIV_3.fb_div         = %u\n", ppll_div3 & 0x07ff);
	seq_printf(m, "  PPLL_DIV_3.post_div(2:0)  = %u\n", (ppll_div3 >> 16) & 0x7);
	seq_printf(m, "  M_SPLL_REF_FB_DIV.ref_div = %u\n", m_spll & 0xff);
	seq_printf(m, "  M_SPLL_REF_FB_DIV.mpll_fb = %u\n", (m_spll >> 8) & 0xff);
	seq_printf(m, "  M_SPLL_REF_FB_DIV.spll_fb = %u\n", (m_spll >> 16) & 0xff);
	seq_printf(m, "  VCLK_ECP_CNTL.src_sel     = %u\n", vclk & 0x03);
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(rs480_pll_regs);

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
	if (rs480_debugfs_refuse_if_parked(m, rdev))
		return 0;
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
	if (rdev->gpu_parked)
		return -EIO;
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
	if (rs480_debugfs_refuse_if_parked(m, rdev))
		return 0;

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

/* Attended single-step frontier probe.  The residual frontier is exhausted:
 * the selected CAP0/CAP1 VIP video-capture registers and the IDCT video-decode
 * registers have all been read directly (0x00000000, no wedge) and are retired.
 * Keep the debugfs node inert so stale operators see the exhausted state instead
 * of arming a historical hazardous MMIO read. */
static const struct rs480_candidate_reg rs480_frontier_probe_reg_list[] = {
};

static int rs480_frontier_probe_show(struct seq_file *m, void *unused)
{
	struct radeon_device *rdev = m->private;
	if (rs480_debugfs_refuse_if_parked(m, rdev))
		return 0;
	int idx = radeon_rs480_frontier_index;
	const struct rs480_candidate_reg *reg;
	u32 value;

	if (!ARRAY_SIZE(rs480_frontier_probe_reg_list)) {
		seq_puts(m, "frontier probe exhausted: no residual registers\n");
		return 0;
	}

	if (idx < 0 || idx >= (int)ARRAY_SIZE(rs480_frontier_probe_reg_list)) {
		seq_printf(m,
			   "frontier probe disarmed: set rs480_frontier_index=N (0..%zu)\n",
			   ARRAY_SIZE(rs480_frontier_probe_reg_list) - 1);
		return 0;
	}

	reg = &rs480_frontier_probe_reg_list[idx];
	value = rs480_candidate_reg_read(rdev, reg);
	seq_printf(m, "index %d: %s (0x%04x) = 0x%08x\n",
		   idx, reg->name, reg->offset, value);
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(rs480_frontier_probe);

/* Attended vertex-engine probe.  The VAP_PVS/SE_TCL vertex engine (0x2200-0x2504)
 * gates its clock at rest, so a passive RREG32 stalls the reset-less K8
 * northbridge -- confirmed wedges at 0x220c (PVS vector-port shadow) and 0x2280,
 * each a physical recovery.  This node tests whether a read COMPLETES while the
 * engine is held clocked by a continuous HB-TCL draw loop (the open falsification
 * of the clock-gating ceiling).  The two confirmed-wedge offsets and the
 * write-only FIFO ports (0x2200, 0x2208) are excluded so they cannot be armed;
 * only the named control registers are reachable.  Disarmed at index -1. */
static const struct rs480_candidate_reg rs480_vertex_engine_reg_list[] = {
	{ 0x221C, "VAP_CLIP_CNTL", 0 },
	{ 0x2284, "VAP_PVS_STATE_FLUSH_REG", 0 },
	{ 0x2288, "VAP_PVS_VTX_TIMEOUT_REG", 0 },
	{ 0x22D0, "VAP_PVS_CODE_CNTL_0", 0 },
	{ 0x22D4, "VAP_PVS_CONST_CNTL", 0 },
	{ 0x22D8, "VAP_PVS_CODE_CNTL_1", 0 },
	{ 0x22DC, "VAP_PVS_FLOW_CNTL_OPC", 0 },
};

static int rs480_vertex_probe_show(struct seq_file *m, void *unused)
{
	struct radeon_device *rdev = m->private;
	if (rs480_debugfs_refuse_if_parked(m, rdev))
		return 0;
	int idx = radeon_rs480_vertex_index;
	const struct rs480_candidate_reg *reg;
	u32 value;

	if (idx < 0 || idx >= (int)ARRAY_SIZE(rs480_vertex_engine_reg_list)) {
		seq_printf(m,
			   "vertex probe disarmed: hold the engine clocked (HB-TCL draw loop), then set rs480_vertex_index=N (0..%zu)\n",
			   ARRAY_SIZE(rs480_vertex_engine_reg_list) - 1);
		return 0;
	}

	reg = &rs480_vertex_engine_reg_list[idx];
	value = rs480_candidate_reg_read(rdev, reg);
	seq_printf(m, "index %d: %s (0x%04x) = 0x%08x\n",
		   idx, reg->name, reg->offset, value);
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(rs480_vertex_probe);

/* Single-register first-observation read of the BAR0 hazard tier.
 *
 * The 471-register vet flagged 62 registers hazard_exclude_by_name with a name
 * regex.  Re-reading the match basis (the matched_pattern column of
 * rs482_unreferenced_430_name_class_vet.tsv) shows the registers below are regex
 * FALSE POSITIVES, not wedge hazards: SCRATCH matched the BIOS_8..15 and GUI
 * scratch registers, PORT_ matched SE_VPORT_* (the viewport transform, not an
 * I/O port), and SEMAPHORE and WAIT_UNTIL matched two engine-status words.  A
 * plain RREG32 of any of them is read-safe -- scratch and viewport are ordinary
 * registers, the SE block is always clocked on an R300-class part, and a read
 * neither acquires the semaphore nor advances any index or FIFO pointer.  They
 * stayed unpromoted only because the regex parked them, and most still carry no
 * per-register observed value.
 *
 * This node takes that first observation under discipline: one register per
 * open, selected by radeon_rs480_hazard_index (default -1 disarmed), so each
 * value is captured deliberately before the register is promoted into the
 * read-only safe-regs list.  It is NOT a wedge-hazard probe and shares no
 * mechanism with the attended frontier_probe node above.
 *
 * Kept out of the list at compile time:
 *   - CRTC8_IDX (0x03b4) and BIF_SLAVE_CNTL (0x180c): the two genuine
 *     northbridge-stall registers.  A 32-bit read can stall the K8 northbridge,
 *     which has no MMIO completion timeout, wedging both cores past the
 *     single-core-only software autoreboot net (physical power cycle only).
 *   - the index/data/FIFO/aperture ports (PALETTE_INDEX/DATA, FOG_TABLE_INDEX/
 *     DATA, PCIE_PORT_INDEX/DATA, DVI_I2C_DATA, CRC_CMDFIFO_*, CP_CSQ_APER_*,
 *     VIPH_CH*, CP_ME_RAM_RADDR, HOST_DATA_LAST): a read without the matching
 *     index write desyncs the live driver's pointer state and returns only a
 *     transient word.
 *   - the CP command-engine and VIP/CAP capture registers (CP_GUI_COMMAND,
 *     CP_IB*, CP_RESYNC_*, CP_CSQ*, CP_ME_CNTL, CP_VID_*, FCP_CNTL,
 *     CAP0/CAP1_PORT_MODE_CNTL): a read races the running CP or touches a
 *     possibly-unclocked capture block, so they belong on the attended frontier
 *     lane, not this first-observation lane.
 */
static const struct rs480_candidate_reg rs480_hazard_read_reg_list[] = {
	{ 0x00c0, "BIOS_8_SCRATCH", 0 },
	{ 0x00c4, "BIOS_9_SCRATCH", 0 },
	{ 0x00c8, "BIOS_10_SCRATCH", 0 },
	{ 0x00cc, "BIOS_11_SCRATCH", 0 },
	{ 0x00d0, "BIOS_12_SCRATCH", 0 },
	{ 0x00d4, "BIOS_13_SCRATCH", 0 },
	{ 0x00d8, "BIOS_14_SCRATCH", 0 },
	{ 0x00dc, "BIOS_15_SCRATCH", 0 },
	{ 0x013c, "SW_SEMAPHORE", 0 },
	{ 0x15e0, "GUI_SCRATCH_REG0", 0 },
	{ 0x15e4, "GUI_SCRATCH_REG1", 0 },
	{ 0x15e8, "GUI_SCRATCH_REG2", 0 },
	{ 0x15ec, "GUI_SCRATCH_REG3", 0 },
	{ 0x15f0, "GUI_SCRATCH_REG4", 0 },
	{ 0x15f4, "GUI_SCRATCH_REG5", 0 },
	{ 0x1720, "WAIT_UNTIL", 0 },
	{ 0x1d98, "SE_VPORT_XSCALE", 0 },
	{ 0x1d9c, "SE_VPORT_XOFFSET", 0 },
	{ 0x1da0, "SE_VPORT_YSCALE", 0 },
	{ 0x1da4, "SE_VPORT_YOFFSET", 0 },
	{ 0x1da8, "SE_VPORT_ZSCALE", 0 },
	{ 0x1dac, "SE_VPORT_ZOFFSET", 0 },
};

static int rs480_hazard_read_show(struct seq_file *m, void *unused)
{
	struct radeon_device *rdev = m->private;
	if (rs480_debugfs_refuse_if_parked(m, rdev))
		return 0;
	int idx = radeon_rs480_hazard_index;
	const struct rs480_candidate_reg *reg;

	if (idx < 0 || idx >= (int)ARRAY_SIZE(rs480_hazard_read_reg_list)) {
		seq_printf(m,
			   "hazard read disarmed: set rs480_hazard_index=N (0..%zu)\n",
			   ARRAY_SIZE(rs480_hazard_read_reg_list) - 1);
		return 0;
	}

	reg = &rs480_hazard_read_reg_list[idx];
	seq_printf(m, "index %d: %s (0x%04x) = 0x%08x\n",
		   idx, reg->name, reg->offset,
		   rs480_candidate_reg_read(rdev, reg));
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(rs480_hazard_read);

/* CP IB scratch-write baseline oracle.
 *
 * Submits one fence-bearing IB that writes a sentinel to a scratch register and
 * reads it back -- the r100_ib_test() path the driver already runs at every
 * resume.  It is the calibrated control for a later CP-ME differential probe: a
 * plain command-stream scratch write with no microcode injection, no
 * CP_CSQ_CNTL stop/restart, and no r100_ring_test poll.  The injection-bearing
 * step adds only an idle-gated CP_ME_RAM write before the same submission, so a
 * baseline captured here isolates the microword effect from the harness.
 *
 * SAFE on the K8 IGP, unlike radeon_rs480_cp_me_oracle: r100_ib_test fences a
 * write through the live ring instead of toggling the command queue, so it never
 * desyncs the CP or polls a register the wedged northbridge would never return.
 * The RS480 CP-ME oracle CSQ-toggle ring_test safety RCA is the boundary this
 * node stays inside.  Armed only when radeon_rs480_cp_ib_scratch_oracle equals
 * the token; refuses unless the gfx ring is initialized (accel_working and
 * ring->ready) rather than touch an uninitialized ring.
 */
#define RS480_CP_IB_SCRATCH_ORACLE_ARM_TOKEN 0x49425343u	/* "IBSC" */

static int rs480_cp_ib_scratch_oracle_show(struct seq_file *m, void *unused)
{
	struct radeon_device *rdev = m->private;
	if (rs480_debugfs_refuse_if_parked(m, rdev))
		return 0;
	struct radeon_ring *ring = &rdev->ring[RADEON_RING_TYPE_GFX_INDEX];
	int r;

	if (radeon_rs480_cp_ib_scratch_oracle !=
	    RS480_CP_IB_SCRATCH_ORACLE_ARM_TOKEN) {
		seq_printf(m,
			   "ib scratch oracle disarmed: set rs480_cp_ib_scratch_oracle=0x%08x\n",
			   RS480_CP_IB_SCRATCH_ORACLE_ARM_TOKEN);
		return 0;
	}

	if (!rdev->accel_working || !ring->ready) {
		seq_puts(m,
			 "ib scratch oracle requires an initialized gfx ring "
			 "(accel_working and ring->ready)\n");
		return 0;
	}

	/* r100_ib_test preseeds the scratch register with 0xCAFEDEAD, submits an
	 * IB whose PACKET0 stores 0xDEADBEEF to it, waits the IB fence, and returns
	 * 0 only when the read-back equals 0xDEADBEEF.  The preseed proves the
	 * value came from the IB, not a stale register.  The scratch offset, value,
	 * and completion time are logged to dmesg by the driver. */
	r = r100_ib_test(rdev, ring);
	seq_printf(m,
		   "ib scratch oracle: r100_ib_test => %s (r=%d)\n"
		   "fence-bearing CS scratch write; no inject, no CSQ toggle, no "
		   "ring_test poll; scratch offset/value/usecs in dmesg\n",
		   r ? "FAIL" : "PASS", r);
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(rs480_cp_ib_scratch_oracle);

/* GPU-reset recovery probe (idle-gated direct reset).
 *
 * Sets needs_reset and calls radeon_gpu_reset() directly -- the deterministic
 * one-shot the stock radeon_gpu_reset debugfs node cannot deliver.  That node
 * only sets needs_reset and wakes the fence queue, so it fires nothing unless a
 * task is already blocked in a GEM or CS fence wait; this node forces the reset
 * itself.
 *
 * The handler holds no exclusive_lock.  radeon_gpu_reset takes down_write on
 * rdev->exclusive_lock, and the stock radeon_debugfs_gpu_reset holds that rwsem
 * for read, so a handler modelled on it that also called the reset would
 * deadlock.  Setting needs_reset without the lock is the same unsynchronized
 * store the stock node performs.
 *
 * Idle-gated by design.  It refuses unless RBBM_STATUS reads back !GUI_ACTIVE,
 * so r300_asic_reset early-returns at its own !GUI_ACTIVE gate and the
 * RBBM_SOFT_RESET CP reset -- the sequence the radeon driver flags as
 * "sometimes ends up hard locking the computer" on R3XX/R4XX -- never executes.
 * The probe therefore exercises radeon_suspend, an asic_reset that is a no-op on
 * the idle engine, radeon_resume through rs400_startup and r100_cp_init, and the
 * closing radeon_ib_ring_tests.  A PASS proves the suspend/resume/CSQ-resync
 * recovery path survives on this IGP; it does not prove a wedged ring recovers,
 * because the wedged-engine soft-reset is exactly the half the idle gate skips.
 *
 * Root-only, armed only when radeon_rs480_gpu_reset_recover_probe equals the
 * token, and only with an initialized gfx ring.  Run with the display quiesced:
 * the reset tears the GPU down and rebuilds it, invalidating live GL contexts.
 */
#define RS480_GPU_RESET_RECOVER_PROBE_ARM_TOKEN 0x52435652u	/* "RCVR" */

static int rs480_gpu_reset_recover_probe_show(struct seq_file *m, void *unused)
{
	struct radeon_device *rdev = m->private;
	if (rs480_debugfs_refuse_if_parked(m, rdev))
		return 0;
	struct radeon_ring *ring = &rdev->ring[RADEON_RING_TYPE_GFX_INDEX];
	u32 status;
	int r;

	if (radeon_rs480_gpu_reset_recover_probe !=
	    RS480_GPU_RESET_RECOVER_PROBE_ARM_TOKEN) {
		seq_printf(m,
			   "gpu-reset recovery probe disarmed: set rs480_gpu_reset_recover_probe=0x%08x\n",
			   RS480_GPU_RESET_RECOVER_PROBE_ARM_TOKEN);
		return 0;
	}

	if (!rdev->accel_working || !ring->ready) {
		seq_puts(m,
			 "gpu-reset recovery probe requires an initialized gfx ring "
			 "(accel_working and ring->ready)\n");
		return 0;
	}

	/* Idle gate: refuse while the engine is busy so r300_asic_reset skips the
	 * RBBM_SOFT_RESET CP reset (the documented hard-locking path). */
	status = RREG32(R_000E40_RBBM_STATUS);
	if (G_000E40_GUI_ACTIVE(status)) {
		seq_printf(m,
			   "gpu-reset recovery probe refused: RBBM_STATUS=0x%08x GUI_ACTIVE; runs "
			   "only idle so r300_asic_reset skips the RBBM_SOFT_RESET CP reset\n",
			   status);
		return 0;
	}

	/* Force the deterministic reset: set needs_reset (the unlocked store the
	 * stock node makes) and drive radeon_gpu_reset() ourselves.  No
	 * exclusive_lock is held here; radeon_gpu_reset takes its own down_write. */
	rdev->needs_reset = true;
	r = radeon_gpu_reset(rdev);
	if (rdev->gpu_parked) {
		seq_printf(m,
			   "gpu-reset recovery probe: parked after reset (r=%d); skipping post RBBM_STATUS\n",
			   r);
		return 0;
	}

	status = RREG32(R_000E40_RBBM_STATUS);
	seq_printf(m,
		   "gpu-reset recovery probe: radeon_gpu_reset => %s (r=%d) post RBBM_STATUS=0x%08x\n"
		   "idle-gated: exercised suspend/resume/cp_init recovery, NOT wedged-ring "
		   "soft-reset; reset chain and ib-ring-test verdict in dmesg\n",
		   r ? "FAIL" : "PASS", r, status);
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(rs480_gpu_reset_recover_probe);

/* RBBM_SOFT_RESET is low RBBM control space, not the gated VAP aperture
 * (0x2200-0x2504) whose raw write wedges the K8 northbridge.  r300d.h is not
 * included here (its R_000E40 family collides with rs400d.h), so the soft-reset
 * bit-setters are spelled locally from the R3xx register definition. */
#define RS480_RBBM_SOFT_RESET            0x0000F0
#define RS480_SOFT_RESET_CP(x)           (((x) & 0x1) << 0)
#define RS480_SOFT_RESET_VAP(x)          (((x) & 0x1) << 2)
#define RS480_SOFT_RESET_GA(x)           (((x) & 0x1) << 13)

/* SCLK_CNTL (PLL 0x0d) clock force bits: CP (16), E2/2D (20), SE (21), TX (27),
 * US (28), SU (30); SCLK_CNTL2 (PLL 0x1e): TCL (13), CBA (14), GA (15).  The
 * fire runs with the display quiesced, which can gate the 2D (E2) and geometry
 * (VAP/GA) domains; the reset writes those blocks and the 2D-blit trigger drives
 * E2, so all are force-clocked across the sequence and restored after. */
#define RS480_SCLK_CNTL_FORCE_3D    (BIT(16) | BIT(20) | BIT(21) | BIT(27) | BIT(28) | BIT(30))
#define RS480_SCLK_CNTL2_FORCE_3D   (BIT(13) | BIT(14) | BIT(15))

struct rs480_soft_reset_result {
	u32 at_reset;	/* RBBM_STATUS read immediately before the SOFT_RESET write */
	u32 post;	/* RBBM_STATUS after the reset */
	int ib_test;	/* r100_ib_test after cp_init: 0 means the CP executes again */
};

/* Run the documented R300 RBBM_SOFT_RESET sequence (r300_asic_reset body),
 * rebuild the CP ring, and verify the CP runs an IB again.
 *
 * This is the contained re-use of r300_asic_reset that radeon_gpu_reset cannot
 * deliver on an idle engine: r300_asic_reset early-returns at !GUI_ACTIVE before
 * the soft-reset writes, so issuing them directly is the only way to drive them
 * without first hanging the engine.
 *
 * exclusive_lock is held for write across the register sequence to serialise
 * against a concurrent command submission -- the same rwsem radeon_gpu_reset
 * takes for write -- and released before r100_ib_test so the recovery IB submits
 * through the normal ring path.
 *
 * res->at_reset is read immediately before the SOFT_RESET write, so a busy-engine
 * caller sees the true engine state at the instant of reset, not an earlier
 * sample taken before r100_mc_stop.  res->ib_test demonstrates recovery: the
 * driver's own reset ends with radeon_ib_ring_tests because an idle RBBM_STATUS
 * does not prove the CP executes again.
 *
 * Recovery is r100_cp_init, not rs400_startup: the soft-reset tears down the CP
 * ring and the VAP/GA/CP engine blocks but leaves GART, the memory controller,
 * the writeback buffer, fences, and the IB pool live, so the full startup would
 * double-initialise them.
 *
 * CP_CSQ_CNTL = 0 is the register the CSQ-toggle ring_test RCA forbade, but here
 * it is the driver-native reset write paired with mdelay, not the r100_ring_test
 * poll that never returned on the wedge -- the reset's risk profile, not the
 * forbidden poll's. */
static void rs480_soft_reset(struct radeon_device *rdev,
			     struct rs480_soft_reset_result *res)
{
	struct radeon_ring *ring = &rdev->ring[RADEON_RING_TYPE_GFX_INDEX];
	struct r100_mc_save save;
	u32 sclk, sclk2, tmp;

	down_write(&rdev->exclusive_lock);
	sclk = RREG32_PLL(0x0000000D);
	sclk2 = RREG32_PLL(0x0000001E);
	WREG32_PLL(0x0000000D, sclk | RS480_SCLK_CNTL_FORCE_3D);
	WREG32_PLL(0x0000001E, sclk2 | RS480_SCLK_CNTL2_FORCE_3D);

	r100_mc_stop(rdev, &save);
	WREG32(RADEON_CP_CSQ_CNTL, 0);
	tmp = RREG32(RADEON_CP_RB_CNTL);
	WREG32(RADEON_CP_RB_CNTL, tmp | RADEON_RB_RPTR_WR_ENA);
	WREG32(RADEON_CP_RB_RPTR_WR, 0);
	WREG32(RADEON_CP_RB_WPTR, 0);
	WREG32(RADEON_CP_RB_CNTL, tmp);
	pci_save_state(rdev->pdev);
	r100_bm_disable(rdev);
	res->at_reset = RREG32(R_000E40_RBBM_STATUS);
	WREG32(RS480_RBBM_SOFT_RESET,
	       RS480_SOFT_RESET_VAP(1) | RS480_SOFT_RESET_GA(1));
	RREG32(RS480_RBBM_SOFT_RESET);
	mdelay(500);
	WREG32(RS480_RBBM_SOFT_RESET, 0);
	mdelay(1);
	WREG32(RS480_RBBM_SOFT_RESET, RS480_SOFT_RESET_CP(1));
	RREG32(RS480_RBBM_SOFT_RESET);
	mdelay(500);
	WREG32(RS480_RBBM_SOFT_RESET, 0);
	mdelay(1);
	pci_restore_state(rdev->pdev);
	r100_enable_bm(rdev);
	res->post = RREG32(R_000E40_RBBM_STATUS);
	r100_mc_resume(rdev, &save);

	r100_cp_init(rdev, 1024 * 1024);
	WREG32_PLL(0x0000001E, sclk2);
	WREG32_PLL(0x0000000D, sclk);
	up_write(&rdev->exclusive_lock);

	res->ib_test = r100_ib_test(rdev, ring);
}

/* RBBM soft-reset recovery probe (idle, stage 1 of the hang-recovery test).
 * Drives the RBBM_SOFT_RESET sequence -- the half of r300_asic_reset that 0040
 * skips on an idle engine -- so the operator learns whether the soft-reset write
 * wedges this reset-less northbridge before a real hang is induced, and whether
 * the CP runs an IB again afterward.  Root-only, armed by token, idle-only, run
 * display-quiesced. */
#define RS480_RESET_HANG_PROBE_SOFT_RESET_TOKEN 0x53525354u	/* "SRST" */

/* In-busy stage (Mode H): busy the 2D engine with a real BITBLT, then run the
 * soft-reset while it drains.  GUI_ACTIVE (RBBM_STATUS bit 31) is the OR of the
 * engine-busy bits; the 2D engine (E2/RB2D, bits 17/18) is driven by
 * PACKET3_BITBLT_MULTI through r100_copy_blit -- the live r300/rs400 copy hook --
 * without touching the gated VAP aperture (0x2200-0x2504) a geometry draw would.
 * So it raises GUI_ACTIVE for the reset's RBBM_STATUS read without driving the
 * wedge-prone geometry path.
 *
 * The reset still asserts SOFT_RESET_VAP|GA|CP, not E2, so this proves the
 * documented soft-reset write survives while the engine is globally GUI_ACTIVE
 * (E2 busy); it is not a 2D-block-specific reset.  rs480_soft_reset samples
 * RBBM_STATUS at the instant of the reset write, so res.at_reset (E2_BUSY,
 * GUI_ACTIVE) records whether the reset actually landed on a busy engine or the
 * blit drained first through r100_mc_stop and the run degenerated to the idle
 * case.  The blit fence can never signal once the CP is reset, so
 * radeon_fence_driver_force_completion retires it before the ref is dropped. */
#define RS480_RESET_HANG_PROBE_BLIT_RESET_TOKEN 0x48414E47u	/* "HANG" */

static int rs480_blit_busy_reset(struct radeon_device *rdev, struct seq_file *m)
{
	struct rs480_soft_reset_result res;
	struct radeon_bo *bo = NULL;
	struct radeon_fence *fence;
	u64 gpu_addr;
	unsigned long sz = 2 * 1024 * 1024;
	unsigned pages = (sz / 2) / RADEON_GPU_PAGE_SIZE;
	int r;

	r = radeon_bo_create(rdev, sz, PAGE_SIZE, true, RADEON_GEM_DOMAIN_GTT,
			     0, NULL, NULL, &bo);
	if (r) {
		seq_printf(m, "blit-reset: scratch bo create failed (%d)\n", r);
		return 0;
	}
	r = radeon_bo_reserve(bo, false);
	if (r)
		goto unref;
	r = radeon_bo_pin(bo, RADEON_GEM_DOMAIN_GTT, &gpu_addr);
	radeon_bo_unreserve(bo);
	if (r) {
		seq_printf(m, "blit-reset: scratch bo pin failed (%d)\n", r);
		goto unref;
	}

	fence = r100_copy_blit(rdev, gpu_addr, gpu_addr + (sz / 2), pages, NULL);
	if (IS_ERR(fence)) {
		seq_printf(m, "blit-reset: BITBLT emit failed (%ld)\n", PTR_ERR(fence));
		goto unpin;
	}

	rs480_soft_reset(rdev, &res);
	radeon_fence_driver_force_completion(rdev, RADEON_RING_TYPE_GFX_INDEX);
	radeon_fence_unref(&fence);

	seq_printf(m,
		   "reset-hang probe blit-reset: at-reset RBBM_STATUS=0x%08x (E2_BUSY=%u GUI_ACTIVE=%u) post=0x%08x ib_test=%s(%d) %s\n"
		   "2D BITBLT busied E2; RBBM_SOFT_RESET(VAP|GA|CP) asserted while the engine was %s; CP rebuilt and re-tested. "
		   "Proves the soft-reset write survives on a globally-active engine, not 2D-block-specific recovery\n",
		   res.at_reset, G_000E40_E2_BUSY(res.at_reset), G_000E40_GUI_ACTIVE(res.at_reset),
		   res.post, res.ib_test ? "FAIL" : "PASS", res.ib_test,
		   (G_000E40_GA_BUSY(res.post) || G_000E40_VAP_BUSY(res.post)) ? "ENGINE-BUSY(reset suspect)" : "ENGINE-IDLE(reset clean)",
		   G_000E40_GUI_ACTIVE(res.at_reset) ? "busy" : "idle(blit drained before the reset write, race lost)");
unpin:
	radeon_bo_reserve(bo, false);
	radeon_bo_unpin(bo);
	radeon_bo_unreserve(bo);
unref:
	radeon_bo_unref(&bo);
	return 0;
}

/* Wedged-3D stages: recover a busy geometry frontend through the production
 * reset path radeon.lockup_timeout invokes -- radeon_gpu_reset ->
 * radeon_asic_reset -> r300_asic_reset -- not the standalone rs480_soft_reset
 * scaffold the SRST/HANG stages drive.  The fault is induced out of band (a
 * userspace 3D draw for the drainable stage; the pre-fix #996 TEXCOORD_XY
 * rectangular-point-sprite blit on has_tcl=false for the hung stage), so these
 * stages only validate recovery.  radeon_gpu_reset runs the full production
 * recovery: radeon_ring_backup saves the in-flight ring, radeon_asic_reset drives
 * r300_asic_reset (which, with the IGP force-clock, recovers instead of
 * hard-locking), then radeon_ring_restore re-emits on success or
 * radeon_fence_driver_force_completion retires the wedged fence on failure,
 * closing with radeon_ib_ring_tests.  It early-returns unless rdev->needs_reset,
 * which lockup detection sets and these stages set by hand.  Return code: 0
 * recovered; -EAGAIN reset landed but the ring re-test failed and commands were
 * saved (partial, another reset pending); other negative failed.
 *
 * Two stages preserve the ladder cadence.  WD3A drainable gates on a busy
 * frontend alone (VAP or GA busy), so a legitimate mid-flight 3D draw whose 3D
 * backend is still busy is accepted -- the first reset of an actually-busy
 * VAP/GA block, reboot-safe.  WD3B hung gates on the #996 signature (frontend
 * busy with RB3D/RE idle, the live 0x8411c100 shape), the production stall
 * lockup_timeout exists for.  A RECOVERED verdict must be corroborated by the
 * r300_asic_reset dmesg lines ("GPU reset succeed" and a non-idle at-reset
 * RBBM_STATUS); if the fault drains in the gap before r300_asic_reset samples
 * RBBM_STATUS it early-returns at !GUI_ACTIVE and resets nothing. */
#define RS480_RESET_HANG_PROBE_WEDGED_3D_DRAINABLE_TOKEN 0x57443341u	/* "WD3A" */
#define RS480_RESET_HANG_PROBE_WEDGED_3D_HUNG_TOKEN      0x57443342u	/* "WD3B" */

static bool rs480_frontend_busy(u32 status)
{
	return G_000E40_VAP_BUSY(status) || G_000E40_GA_BUSY(status);
}

static bool rs480_frontend_wedged(u32 status)
{
	return rs480_frontend_busy(status) &&
	       !G_000E40_RB3D_BUSY(status) && !G_000E40_RE_BUSY(status);
}

static int rs480_wedged_3d_reset(struct radeon_device *rdev, struct seq_file *m,
				 bool require_backend_idle)
{
	const char *stage = require_backend_idle ? "hung" : "drainable";
	u32 pre, post;
	int r;

	pre = RREG32(R_000E40_RBBM_STATUS);
	if (require_backend_idle ? !rs480_frontend_wedged(pre)
				 : !rs480_frontend_busy(pre)) {
		seq_printf(m,
			   "reset-hang probe wedged-3D(%s) refused: RBBM_STATUS=0x%08x lacks the "
			   "%s; induce the userspace 3D fault before reading this node\n",
			   stage, pre,
			   require_backend_idle
				   ? "frontend-wedge signature (VAP_BUSY|GA_BUSY set, RB3D/RE idle)"
				   : "busy-frontend signature (VAP_BUSY|GA_BUSY set)");
		return 0;
	}

	rdev->needs_reset = true;
	r = radeon_gpu_reset(rdev);
	/* No register read after a failed reset: the parked GPU keeps its MC
	 * stopped and display requests off, and the first post-park MMIO read
	 * is the proven host-killer. The r300_asic_reset dmesg ladder carries
	 * the at-reset and post-soft-reset RBBM values; report those.
	 */
	dev_err(rdev->dev, "probe: radeon_gpu_reset returned %d, no post-park register read\n", r);
	post = r ? 0x5041524B /* "PARK" */ : RREG32(R_000E40_RBBM_STATUS);

	seq_printf(m,
		   "reset-hang probe wedged-3D(%s): pre RBBM_STATUS=0x%08x (VAP_BUSY=%u GA_BUSY=%u RB3D_BUSY=%u RE_BUSY=%u) "
		   "radeon_gpu_reset=%d post=0x%08x -> %s\n"
		   "production path: ring backup, r300_asic_reset (IGP force-clocked), ring restore or fence "
		   "force-completion, radeon_ib_ring_tests; corroborate RECOVERED with the r300_asic_reset dmesg "
		   "\"GPU reset succeed\" line and a non-idle at-reset RBBM_STATUS\n",
		   stage, pre, G_000E40_VAP_BUSY(pre), G_000E40_GA_BUSY(pre),
		   G_000E40_RB3D_BUSY(pre), G_000E40_RE_BUSY(pre),
		   r, post,
		   r == 0 ? "RECOVERED(corroborate via dmesg)" :
		   r == -EAGAIN ? "PARTIAL(reset landed, ring re-test failed, commands saved)" :
		   "FAILED");
	return 0;
}

static int rs480_reset_hang_probe_show(struct seq_file *m, void *unused)
{
	struct radeon_device *rdev = m->private;
	if (rs480_debugfs_refuse_if_parked(m, rdev))
		return 0;
	struct radeon_ring *ring = &rdev->ring[RADEON_RING_TYPE_GFX_INDEX];
	struct rs480_soft_reset_result res;
	u32 pre;

	if (radeon_rs480_reset_hang_probe != RS480_RESET_HANG_PROBE_SOFT_RESET_TOKEN &&
	    radeon_rs480_reset_hang_probe != RS480_RESET_HANG_PROBE_BLIT_RESET_TOKEN &&
	    radeon_rs480_reset_hang_probe != RS480_RESET_HANG_PROBE_WEDGED_3D_DRAINABLE_TOKEN &&
	    radeon_rs480_reset_hang_probe != RS480_RESET_HANG_PROBE_WEDGED_3D_HUNG_TOKEN) {
		seq_printf(m,
			   "reset-hang probe disarmed: set rs480_reset_hang_probe=0x%08x for the idle "
			   "soft-reset stage, 0x%08x for the 2D-blit in-busy stage, 0x%08x for the "
			   "wedged-3D drainable stage, or 0x%08x for the wedged-3D hung stage\n",
			   RS480_RESET_HANG_PROBE_SOFT_RESET_TOKEN,
			   RS480_RESET_HANG_PROBE_BLIT_RESET_TOKEN,
			   RS480_RESET_HANG_PROBE_WEDGED_3D_DRAINABLE_TOKEN,
			   RS480_RESET_HANG_PROBE_WEDGED_3D_HUNG_TOKEN);
		return 0;
	}

	if (!rdev->accel_working || !ring->ready) {
		seq_puts(m,
			 "reset-hang probe requires an initialized gfx ring "
			 "(accel_working and ring->ready)\n");
		return 0;
	}

	if (radeon_rs480_reset_hang_probe == RS480_RESET_HANG_PROBE_BLIT_RESET_TOKEN)
		return rs480_blit_busy_reset(rdev, m);

	if (radeon_rs480_reset_hang_probe == RS480_RESET_HANG_PROBE_WEDGED_3D_DRAINABLE_TOKEN)
		return rs480_wedged_3d_reset(rdev, m, false);

	if (radeon_rs480_reset_hang_probe == RS480_RESET_HANG_PROBE_WEDGED_3D_HUNG_TOKEN)
		return rs480_wedged_3d_reset(rdev, m, true);

	pre = RREG32(R_000E40_RBBM_STATUS);
	if (G_000E40_GUI_ACTIVE(pre)) {
		seq_printf(m,
			   "reset-hang probe refused: RBBM_STATUS=0x%08x GUI_ACTIVE; the idle "
			   "soft-reset stage runs only on an idle engine\n", pre);
		return 0;
	}

	rs480_soft_reset(rdev, &res);
	seq_printf(m,
		   "reset-hang probe soft-reset(idle): at-reset RBBM_STATUS=0x%08x post=0x%08x ib_test=%s(%d) %s\n"
		   "VAP/GA/E2 force-clocked, RBBM_SOFT_RESET asserted, CP rebuilt and re-tested; proves the "
		   "soft-reset writes survive AND the CP executes again on the idle engine, NOT in-hang recovery\n",
		   res.at_reset, res.post, res.ib_test ? "FAIL" : "PASS", res.ib_test,
		   (G_000E40_GA_BUSY(res.post) || G_000E40_VAP_BUSY(res.post)) ? "ENGINE-BUSY(reset suspect)" : "ENGINE-IDLE(reset clean)");
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(rs480_reset_hang_probe);
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

/* Per-domain force-clock-then-read.  A register in a clock-gated engine block
 * stalls the reset-less K8 if its clock is gated.  For a domain whose SCLK_CNTL
 * FORCE bit provably gates the clock, forcing the bit on before the read makes
 * the access complete; restoring SCLK_CNTL after leaves clock policy intact.
 * Validated per domain: FORCE_VIP gates the VIP/CAP block (the CAP read
 * completes); FORCE_IDCT does NOT de-risk IDCT, so IDCT is not listed.
 * The DISP1/DISP2 display-controller entries are a hypothesis under test, not
 * yet validated: a display-config read that stalls with the FORCE bit clear
 * and completes with it set confirms the bit gates that domain; completion in
 * both states means the domain does not gate and the entry is plainly safe.
 * Disarmed by default (radeon_rs480_force_clock_index == -1). */
#define RS480_SCLK_CNTL_PLL_INDEX 0x0000000Du
#define RS480_SCLK_FORCE_VIP      (1u << 23)
#define RS480_SCLK_FORCE_DISP1    (1u << 18)
#define RS480_SCLK_FORCE_DISP2    (1u << 15)
#define RS480_SCLK_FORCE_OV0      (1u << 31)
#define RS480_SCLK_FORCE_TV_SCLK  (1u << 29)

struct rs480_force_clock_reg {
	u32 force_bit;
	u32 offset;
	const char *name;
	const char *domain;
};

static const struct rs480_force_clock_reg rs480_force_clock_list[] = {
	{ RS480_SCLK_FORCE_VIP, 0x0958, "RADEON_CAP0_CONFIG",       "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x0970, "RADEON_CAP0_BUF_STATUS",   "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x09c8, "RADEON_CAP1_CONFIG",       "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x09e0, "RADEON_CAP1_BUF_STATUS",   "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x09e8, "RADEON_CAP1_DWNSC_XRATIO", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x0920, "RADEON_CAP0_BUF0_OFFSET", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x0924, "RADEON_CAP0_BUF1_OFFSET", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x0928, "RADEON_CAP0_BUF0_EVEN_OFFSET", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x092c, "RADEON_CAP0_BUF1_EVEN_OFFSET", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x0930, "RADEON_CAP0_BUF_PITCH", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x0934, "RADEON_CAP0_V_WINDOW", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x0938, "RADEON_CAP0_H_WINDOW", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x093c, "RADEON_CAP0_VBI0_OFFSET", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x0940, "RADEON_CAP0_VBI1_OFFSET", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x0944, "RADEON_CAP0_VBI_V_WINDOW", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x0948, "RADEON_CAP0_VBI_H_WINDOW", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x094c, "RADEON_CAP0_PORT_MODE_CNTL", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x0950, "RADEON_CAP0_TRIG_CNTL", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x0954, "RADEON_CAP0_DEBUG", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x095c, "RADEON_CAP0_ANC_ODD_OFFSET", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x0960, "RADEON_CAP0_ANC_EVEN_OFFSET", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x0964, "RADEON_CAP0_ANC_H_WINDOW", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x0968, "RADEON_CAP0_VIDEO_SYNC_TEST", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x096c, "RADEON_CAP0_ONESHOT_BUF_OFFSET", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x0980, "RADEON_CAP0_VBI2_OFFSET", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x0984, "RADEON_CAP0_VBI3_OFFSET", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x0988, "RADEON_CAP0_ANC2_OFFSET", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x098c, "RADEON_CAP0_ANC3_OFFSET", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x0990, "RADEON_CAP1_BUF0_OFFSET", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x0994, "RADEON_CAP1_BUF1_OFFSET", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x0998, "RADEON_CAP1_BUF0_EVEN_OFFSET", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x099c, "RADEON_CAP1_BUF1_EVEN_OFFSET", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x09a0, "RADEON_CAP1_BUF_PITCH", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x09a4, "RADEON_CAP1_V_WINDOW", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x09a8, "RADEON_CAP1_H_WINDOW", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x09ac, "RADEON_CAP1_VBI_ODD_OFFSET", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x09b0, "RADEON_CAP1_VBI_EVEN_OFFSET", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x09b4, "RADEON_CAP1_VBI_V_WINDOW", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x09b8, "RADEON_CAP1_VBI_H_WINDOW", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x09bc, "RADEON_CAP1_PORT_MODE_CNTL", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x09c0, "RADEON_CAP1_TRIG_CNTL", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x09c4, "RADEON_CAP1_DEBUG", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x09cc, "RADEON_CAP1_ANC_ODD_OFFSET", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x09d0, "RADEON_CAP1_ANC_EVEN_OFFSET", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x09d4, "RADEON_CAP1_ANC_H_WINDOW", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x09d8, "RADEON_CAP1_VIDEO_SYNC_TEST", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x09dc, "RADEON_CAP1_ONESHOT_BUF_OFFSET", "VIP" },
	{ RS480_SCLK_FORCE_VIP, 0x09ec, "RADEON_CAP1_XSHARPNESS", "VIP" },
	/* Display-controller domains.  In RADEON_SCLK_CNTL (PLL 0x0d) bit 18 is
	 * FORCE_DISP1 and bit 15 is FORCE_DISP2.  The R300 GA/TCL/CBA force bits
	 * occupy the separate R300_SCLK_CNTL2 register, so bit 15 here selects
	 * DISP2, not GA.  FORCE_VAP (bit 21) is deliberately absent: it gates the
	 * vertex block whose VAP_CLIP_CNTL read stalls the reset-less K8.  These
	 * config registers carry no read-to-clear or index/data side effect. */
	{ RS480_SCLK_FORCE_DISP1, 0x0050, "RADEON_CRTC_GEN_CNTL",   "DISP1" },
	{ RS480_SCLK_FORCE_DISP1, 0x0224, "RADEON_CRTC_OFFSET",     "DISP1" },
	{ RS480_SCLK_FORCE_DISP1, 0x022c, "RADEON_CRTC_PITCH",      "DISP1" },
	{ RS480_SCLK_FORCE_DISP1, 0x02d0, "RADEON_LVDS_GEN_CNTL",   "DISP1" },
	{ RS480_SCLK_FORCE_DISP2, 0x03f8, "RADEON_CRTC2_GEN_CNTL",  "DISP2" },
	{ RS480_SCLK_FORCE_DISP2, 0x0324, "RADEON_CRTC2_OFFSET",    "DISP2" },
	{ RS480_SCLK_FORCE_DISP2, 0x032c, "RADEON_CRTC2_PITCH",     "DISP2" },
	/* Remaining DISP1 timing/panel config (bit 18) and DISP2 timing (bit 15).
	 * Same domains as the validated CRTC/CRTC2/LVDS rows above. */
	{ RS480_SCLK_FORCE_DISP1, 0x020c, "RADEON_CRTC_V_SYNC_STRT_WID", "DISP1" },
	{ RS480_SCLK_FORCE_DISP1, 0x0214, "RADEON_CRTC_CRNT_FRAME",      "DISP1" },
	{ RS480_SCLK_FORCE_DISP1, 0x023c, "RADEON_DISPLAY_BASE_ADDR",    "DISP1" },
	{ RS480_SCLK_FORCE_DISP1, 0x027c, "RADEON_CRTC_MORE_CNTL",       "DISP1" },
	{ RS480_SCLK_FORCE_DISP1, 0x028c, "RADEON_FP_HORZ_STRETCH",      "DISP1" },
	{ RS480_SCLK_FORCE_DISP1, 0x0290, "RADEON_FP_VERT_STRETCH",      "DISP1" },
	{ RS480_SCLK_FORCE_DISP1, 0x02c4, "RADEON_FP_H_SYNC_STRT_WID",   "DISP1" },
	{ RS480_SCLK_FORCE_DISP1, 0x02c8, "RADEON_FP_V_SYNC_STRT_WID",   "DISP1" },
	{ RS480_SCLK_FORCE_DISP1, 0x02d4, "RADEON_LVDS_PLL_CNTL",        "DISP1" },
	{ RS480_SCLK_FORCE_DISP2, 0x0304, "RADEON_CRTC2_H_SYNC_STRT_WID","DISP2" },
	{ RS480_SCLK_FORCE_DISP2, 0x0308, "RADEON_CRTC2_V_TOTAL_DISP",   "DISP2" },
	{ RS480_SCLK_FORCE_DISP2, 0x030c, "RADEON_CRTC2_V_SYNC_STRT_WID","DISP2" },
	{ RS480_SCLK_FORCE_DISP2, 0x033c, "RADEON_DISPLAY2_BASE_ADDR",   "DISP2" },
	/* Overlay scaler config.  FORCE_OV0 (bit 31) is unambiguous in SCLK_CNTL.
	 * The OV0 block is powered only when an overlay is active, so these reads
	 * are a hypothesis under test: a stall with the pipe idle that resolves
	 * under FORCE_OV0 confirms the bit gates the block; completion in both
	 * states means the block stays clocked. */
	{ RS480_SCLK_FORCE_OV0,   0x0420, "RADEON_OV0_SCALE_CNTL",       "OV0" },
	{ RS480_SCLK_FORCE_OV0,   0x04dc, "RADEON_OV0_FLAG_CNTL",        "OV0" },
	{ RS480_SCLK_FORCE_OV0,   0x04e0, "RADEON_OV0_COLOUR_CNTL",      "OV0" },
	/* Remaining DISP1 display config (validated domain). */
	{ RS480_SCLK_FORCE_DISP1,    0x0058, "DAC_CNTL", "DISP1" },
	{ RS480_SCLK_FORCE_DISP1,    0x0218, "RADEON_CRTC_GUI_TRIG_VLINE", "DISP1" },
	{ RS480_SCLK_FORCE_DISP1,    0x0228, "RADEON_CRTC_OFFSET_CNTL", "DISP1" },
	{ RS480_SCLK_FORCE_DISP1,    0x0254, "RADEON_FP_CRTC_V_TOTAL_DISP", "DISP1" },
	{ RS480_SCLK_FORCE_DISP1,    0x0350, "R300_CRTC_TILE_X0_Y0", "DISP1" },
	{ RS480_SCLK_FORCE_DISP1,    0x0d14, "RADEON_DISP_HW_DEBUG", "DISP1" },
	{ RS480_SCLK_FORCE_DISP1,    0x0d64, "RADEON_DISP_OUTPUT_CNTL", "DISP1" },
	{ RS480_SCLK_FORCE_DISP1,    0x0e3c, "RS400_DISP1_REQ_CNTL1", "DISP1" },
	/* Remaining DISP2 display config (validated domain). */
	{ RS480_SCLK_FORCE_DISP2,    0x0318, "RADEON_CRTC2_GUI_TRIG_VLINE", "DISP2" },
	{ RS480_SCLK_FORCE_DISP2,    0x0328, "RADEON_CRTC2_OFFSET_CNTL", "DISP2" },
	{ RS480_SCLK_FORCE_DISP2,    0x038c, "RADEON_FP_HORZ2_STRETCH", "DISP2" },
	{ RS480_SCLK_FORCE_DISP2,    0x0390, "RADEON_FP_VERT2_STRETCH", "DISP2" },
	{ RS480_SCLK_FORCE_DISP2,    0x03c4, "RADEON_FP_H2_SYNC_STRT_WID", "DISP2" },
	{ RS480_SCLK_FORCE_DISP2,    0x0e30, "RS400_DISP2_REQ_CNTL1", "DISP2" },
	{ RS480_SCLK_FORCE_DISP2,    0x0e34, "RS400_DISP2_REQ_CNTL2", "DISP2" },
	/* Remaining OV0 overlay config (validated domain). */
	{ RS480_SCLK_FORCE_OV0,      0x0410, "RADEON_OV0_REG_LOAD_CNTL", "OV0" },
	{ RS480_SCLK_FORCE_OV0,      0x0424, "RADEON_OV0_V_INC", "OV0" },
	{ RS480_SCLK_FORCE_OV0,      0x0428, "RADEON_OV0_P1_V_ACCUM_INIT", "OV0" },
	{ RS480_SCLK_FORCE_OV0,      0x042c, "RADEON_OV0_P23_V_ACCUM_INIT", "OV0" },
	{ RS480_SCLK_FORCE_OV0,      0x0440, "RADEON_OV0_VID_BUF0_BASE_ADRS", "OV0" },
	{ RS480_SCLK_FORCE_OV0,      0x0444, "RADEON_OV0_VID_BUF1_BASE_ADRS", "OV0" },
	{ RS480_SCLK_FORCE_OV0,      0x0448, "RADEON_OV0_VID_BUF2_BASE_ADRS", "OV0" },
	{ RS480_SCLK_FORCE_OV0,      0x044c, "RADEON_OV0_VID_BUF3_BASE_ADRS", "OV0" },
	{ RS480_SCLK_FORCE_OV0,      0x0450, "RADEON_OV0_VID_BUF4_BASE_ADRS", "OV0" },
	{ RS480_SCLK_FORCE_OV0,      0x0454, "RADEON_OV0_VID_BUF5_BASE_ADRS", "OV0" },
	{ RS480_SCLK_FORCE_OV0,      0x0460, "RADEON_OV0_VID_BUF_PITCH0_VALUE", "OV0" },
	{ RS480_SCLK_FORCE_OV0,      0x0464, "RADEON_OV0_VID_BUF_PITCH1_VALUE", "OV0" },
	{ RS480_SCLK_FORCE_OV0,      0x0470, "RADEON_OV0_AUTO_FLIP_CNTL", "OV0" },
	{ RS480_SCLK_FORCE_OV0,      0x0474, "RADEON_OV0_DEINTERLACE_PATTERN", "OV0" },
	{ RS480_SCLK_FORCE_OV0,      0x0480, "RADEON_OV0_H_INC", "OV0" },
	{ RS480_SCLK_FORCE_OV0,      0x0484, "RADEON_OV0_STEP_BY", "OV0" },
	{ RS480_SCLK_FORCE_OV0,      0x0488, "RADEON_OV0_P1_H_ACCUM_INIT", "OV0" },
	{ RS480_SCLK_FORCE_OV0,      0x048c, "RADEON_OV0_P23_H_ACCUM_INIT", "OV0" },
	{ RS480_SCLK_FORCE_OV0,      0x0494, "RADEON_OV0_P1_X_START_END", "OV0" },
	{ RS480_SCLK_FORCE_OV0,      0x0498, "RADEON_OV0_P2_X_START_END", "OV0" },
	{ RS480_SCLK_FORCE_OV0,      0x049c, "RADEON_OV0_P3_X_START_END", "OV0" },
	{ RS480_SCLK_FORCE_OV0,      0x04a0, "RADEON_OV0_FILTER_CNTL", "OV0" },
	{ RS480_SCLK_FORCE_OV0,      0x04b0, "RADEON_OV0_FOUR_TAP_COEF_0", "OV0" },
	{ RS480_SCLK_FORCE_OV0,      0x04b4, "RADEON_OV0_FOUR_TAP_COEF_1", "OV0" },
	{ RS480_SCLK_FORCE_OV0,      0x04b8, "RADEON_OV0_FOUR_TAP_COEF_2", "OV0" },
	{ RS480_SCLK_FORCE_OV0,      0x04bc, "RADEON_OV0_FOUR_TAP_COEF_3", "OV0" },
	{ RS480_SCLK_FORCE_OV0,      0x04c0, "RADEON_OV0_FOUR_TAP_COEF_4", "OV0" },
	{ RS480_SCLK_FORCE_OV0,      0x04e4, "RADEON_OV0_VIDEO_KEY_CLR_LOW", "OV0" },
	{ RS480_SCLK_FORCE_OV0,      0x04e8, "RADEON_OV0_VIDEO_KEY_CLR_HIGH", "OV0" },
	{ RS480_SCLK_FORCE_OV0,      0x04ec, "RADEON_OV0_GRAPHICS_KEY_CLR_LOW", "OV0" },
	{ RS480_SCLK_FORCE_OV0,      0x04f0, "RADEON_OV0_GRAPHICS_KEY_CLR_HIGH", "OV0" },
	{ RS480_SCLK_FORCE_OV0,      0x04f4, "RADEON_OV0_KEY_CNTL", "OV0" },
	{ RS480_SCLK_FORCE_OV0,      0x04f8, "RADEON_OV0_TEST", "OV0" },
	/* VIP control stragglers (validated FORCE_VIP domain). */
	{ RS480_SCLK_FORCE_VIP,      0x0900, "RADEON_VID_BUFFER_CONTROL", "VIP" },
	{ RS480_SCLK_FORCE_VIP,      0x0910, "RADEON_FCP_CNTL", "VIP" },
	/* TV-out config under FORCE_TV_SCLK (bit 29).  Hypothesis under
	 * test: the TV encoder block is powered only with TV-out active, so a
	 * forced-clock read may still stall if the block is unpowered. */
	{ RS480_SCLK_FORCE_TV_SCLK,  0x0800, "RADEON_TV_MASTER_CNTL", "TV" },
	{ RS480_SCLK_FORCE_TV_SCLK,  0x0804, "RADEON_TV_RGB_CNTL", "TV" },
	{ RS480_SCLK_FORCE_TV_SCLK,  0x0808, "RADEON_TV_SYNC_CNTL", "TV" },
	{ RS480_SCLK_FORCE_TV_SCLK,  0x080c, "RADEON_TV_HTOTAL", "TV" },
	{ RS480_SCLK_FORCE_TV_SCLK,  0x0810, "RADEON_TV_HDISP", "TV" },
	{ RS480_SCLK_FORCE_TV_SCLK,  0x0818, "RADEON_TV_HSTART", "TV" },
	{ RS480_SCLK_FORCE_TV_SCLK,  0x081c, "RADEON_TV_HCOUNT", "TV" },
	{ RS480_SCLK_FORCE_TV_SCLK,  0x0820, "RADEON_TV_VTOTAL", "TV" },
	{ RS480_SCLK_FORCE_TV_SCLK,  0x0824, "RADEON_TV_VDISP", "TV" },
	{ RS480_SCLK_FORCE_TV_SCLK,  0x0828, "RADEON_TV_VCOUNT", "TV" },
	{ RS480_SCLK_FORCE_TV_SCLK,  0x082c, "RADEON_TV_FTOTAL", "TV" },
	{ RS480_SCLK_FORCE_TV_SCLK,  0x0830, "RADEON_TV_FCOUNT", "TV" },
	{ RS480_SCLK_FORCE_TV_SCLK,  0x0834, "RADEON_TV_FRESTART", "TV" },
	{ RS480_SCLK_FORCE_TV_SCLK,  0x0838, "RADEON_TV_HRESTART", "TV" },
	{ RS480_SCLK_FORCE_TV_SCLK,  0x083c, "RADEON_TV_VRESTART", "TV" },
	{ RS480_SCLK_FORCE_TV_SCLK,  0x084c, "RADEON_TV_VSCALER_CNTL1", "TV" },
	{ RS480_SCLK_FORCE_TV_SCLK,  0x0850, "RADEON_TV_TIMING_CNTL", "TV" },
	{ RS480_SCLK_FORCE_TV_SCLK,  0x0854, "RADEON_TV_VSCALER_CNTL2", "TV" },
	{ RS480_SCLK_FORCE_TV_SCLK,  0x0858, "RADEON_TV_Y_FALL_CNTL", "TV" },
	{ RS480_SCLK_FORCE_TV_SCLK,  0x085c, "RADEON_TV_Y_RISE_CNTL", "TV" },
	{ RS480_SCLK_FORCE_TV_SCLK,  0x0860, "RADEON_TV_Y_SAW_TOOTH_CNTL", "TV" },
	{ RS480_SCLK_FORCE_TV_SCLK,  0x0864, "RADEON_TV_UPSAMP_AND_GAIN_CNTL", "TV" },
	{ RS480_SCLK_FORCE_TV_SCLK,  0x0868, "RADEON_TV_GAIN_LIMIT_SETTINGS", "TV" },
	{ RS480_SCLK_FORCE_TV_SCLK,  0x086c, "RADEON_TV_LINEAR_GAIN_SETTINGS", "TV" },
	{ RS480_SCLK_FORCE_TV_SCLK,  0x0870, "RADEON_TV_MODULATOR_CNTL1", "TV" },
	{ RS480_SCLK_FORCE_TV_SCLK,  0x0874, "RADEON_TV_MODULATOR_CNTL2", "TV" },
	{ RS480_SCLK_FORCE_TV_SCLK,  0x0888, "RADEON_TV_PRE_DAC_MUX_CNTL", "TV" },
	{ RS480_SCLK_FORCE_TV_SCLK,  0x088c, "RADEON_TV_DAC_CNTL", "TV" },
	{ RS480_SCLK_FORCE_TV_SCLK,  0x0890, "RADEON_TV_CRC_CNTL", "TV" },
	{ RS480_SCLK_FORCE_TV_SCLK,  0x08ac, "RADEON_TV_UV_ADR", "TV" },
};

static int rs480_force_clock_read_show(struct seq_file *m, void *unused)
{
	struct radeon_device *rdev = m->private;
	if (rs480_debugfs_refuse_if_parked(m, rdev))
		return 0;
	const struct rs480_force_clock_reg *e;
	u32 sclk_orig, value;
	int idx = radeon_rs480_force_clock_index;

	if (idx < 0 || idx >= (int)ARRAY_SIZE(rs480_force_clock_list)) {
		seq_printf(m, "disarmed (radeon_rs480_force_clock_index = %d)\n", idx);
		return 0;
	}
	e = &rs480_force_clock_list[idx];
	sclk_orig = RREG32_PLL(RS480_SCLK_CNTL_PLL_INDEX);
	WREG32_PLL(RS480_SCLK_CNTL_PLL_INDEX, sclk_orig | e->force_bit);
	value = RREG32(e->offset);
	WREG32_PLL(RS480_SCLK_CNTL_PLL_INDEX, sclk_orig);
	seq_printf(m, "index %d: %s (0x%04x) domain=%s force_bit=0x%08x = 0x%08x\n",
		   idx, e->name, e->offset, e->domain, e->force_bit, value);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(rs480_force_clock_read);

/* 3D-engine force-clock-then-read.  The display force-clock node forces ONE
 * domain bit in SCLK_CNTL (PLL 0x0d); that does not reach the 3D engine,
 * because the R300 vertex/geometry/clip force bits TCL/CBA/GA live in the
 * separate R300_SCLK_CNTL2 (PLL 0x1e) register, and the 3D blocks feed each
 * other (VAP -> GA -> SU -> RB).  This node forces the WHOLE 3D clock set in
 * both PLL registers before the read, so no 3D block is gated when its
 * control register is sampled, then restores both registers.
 *
 * Force set, grounded in radeon_reg.h and radeon_clocks.c r300_set_clock_gating:
 *   SCLK_CNTL  (0x0d): VAP (bit 21), TX (bit 27), US (bit 28), SU (bit 30),
 *                      RB (bit 28, shared with US).
 *   SCLK_CNTL2 (0x1e): TCL (bit 13), CBA (bit 14), GA (bit 15).
 *
 * HAZARD: this is the 3D execution engine, the block class whose VAP write to
 * VAP_CLIP_CNTL wedged the reset-less K8.  Forcing the clock before a READ is
 * the mechanism the display cohort proved safe, but a stalled 3D read leaves
 * the restore WREG32_PLL unrun and freezes both cores -- a physical power
 * cycle.  The table holds only 3D CONTROL and STATUS registers (no instruction
 * or parameter memory), the VAP entries are ordered last, and the node is
 * disarmed by default (radeon_rs480_force_clock_3d_index == -1). */
#define RS480_SCLK_CNTL2_PLL_INDEX 0x0000001Eu
#define RS480_SCLK_3D_FORCE_ALL    ((1u << 21) | (1u << 27) | (1u << 28) | \
				    (1u << 30))
#define RS480_SCLK2_3D_FORCE_ALL   ((1u << 13) | (1u << 14) | (1u << 15))

struct rs480_force_clock_3d_reg {
	u32 offset;
	const char *name;
	const char *domain;
};

static const struct rs480_force_clock_3d_reg rs480_force_clock_3d_list[] = {
	/* GA/GB geometry-assembly control (GA domain).  GA_IDLE and GB_Z_PEQ_CONFIG
	 * are already driver-read (candidate_reader_validated), so they anchor the
	 * sweep: a clean read here confirms the node forces the 3D clock correctly. */
	{ 0x425c, "R500_GA_IDLE",            "GA" },
	{ 0x4274, "R300_GA_ENHANCE",         "GA" },
	{ 0x4278, "R300_GA_COLOR_CONTROL",   "GA" },
	{ 0x4234, "R300_GA_LINE_CNTL",       "GA" },
	{ 0x4008, "R300_GB_ENABLE",          "GA" },
	{ 0x4018, "R300_GB_TILE_CONFIG",     "GA" },
	{ 0x4028, "R300_GB_Z_PEQ_CONFIG",    "GA" },
	/* RB3D color/Z backend control (RB domain). */
	{ 0x4e00, "R300_RB3D_CCTL",          "RB" },
	{ 0x4f00, "R300_ZB_CNTL",            "RB" },
	{ 0x4f10, "R300_ZB_FORMAT",          "RB" },
	{ 0x4f1c, "R300_ZB_BW_CNTL",         "RB" },
	/* US fragment-shader config (US domain). */
	{ 0x4600, "R300_US_CONFIG",          "US" },
	/* VAP vertex control (VAP domain) -- ordered last: VAP is the block whose
	 * write wedged the northbridge, so it is the highest-risk read. */
	{ 0x2140, "R300_VAP_CNTL_STATUS",    "VAP" },
	{ 0x2080, "R300_VAP_CNTL",           "VAP" },
	/* Expanded GA/SU geometry-setup, raster, blend, fog, and stencil control
	 * (the whole 3D clock set is forced regardless of which block owns the
	 * register, so the domain tag is informational). */
	{ 0x401c, "R300_GB_SELECT",              "GA" },
	{ 0x4020, "R300_GB_AA_CONFIG",           "GA" },
	{ 0x402c, "R300_GB_PIPE_SELECT",         "GA" },
	{ 0x4238, "R300_GA_LINE_STIPPLE_CONFIG", "GA" },
	{ 0x4270, "R500_GA_FIFO_CNTL",           "GA" },
	{ 0x428c, "R300_GA_ROUND_MODE",          "GA" },
	{ 0x4294, "R300_GA_FOG_SCALE",           "GA" },
	{ 0x42b4, "R300_SU_POLY_OFFSET_ENABLE",  "SU" },
	{ 0x4300, "R300_RS_COUNT",               "RS" },
	{ 0x4bc0, "R300_FG_FOG_BLEND",           "RB" },
	{ 0x4bd4, "R300_FG_ALPHA_FUNC",          "RB" },
	{ 0x4e04, "R300_RB3D_CBLEND",            "RB" },
	{ 0x4e08, "R300_RB3D_ABLEND",            "RB" },
	{ 0x4e0c, "RB3D_COLOR_CHANNEL_MASK",     "RB" },
	{ 0x4f08, "R300_ZB_STENCILREFMASK",      "RB" },
	/* Further VAP/SU/SC/FG/RB3D control and config (whole 3D clock set forced). */
	{ 0x2084, "R300_VAP_VF_CNTL",            "VAP" },
	{ 0x2098, "R300_VAP_VPORT_XSCALE",       "VAP" },
	{ 0x20a0, "R300_VAP_VPORT_YSCALE",       "VAP" },
	{ 0x20a8, "R300_VAP_VPORT_ZSCALE",       "VAP" },
	{ 0x2180, "R300_VAP_VTX_STATE_CNTL",     "VAP" },
	{ 0x21dc, "R300_VAP_PSC_SGN_NORM_CNTL",  "VAP" },
	{ 0x42a4, "R300_SU_POLY_OFFSET_FRONT_SCALE", "SU" },
	{ 0x42ac, "R300_SU_POLY_OFFSET_BACK_SCALE",  "SU" },
	{ 0x42c0, "R300_SU_DEPTH_SCALE",         "SU" },
	{ 0x43e8, "R300_SC_SCREENDOOR",          "SC" },
	{ 0x4bc4, "R300_FG_FOG_FACTOR",          "RB" },
	{ 0x4ea0, "RB3D_DISCARD_SRC_PIXEL_LTE_THRESHOLD", "RB" },
	{ 0x4ea4, "RB3D_DISCARD_SRC_PIXEL_GTE_THRESHOLD", "RB" },
	/* Fieldless 0x4xxx UNDOC 3D-pipe registers (census-driven, indices 42+).
	 * The mesa r300 driver emits none of these; they are read here under the
	 * forced 3D clock, one at a time and boot_id-guarded, so draw-correlation
	 * can separate hardware-updated status registers from reserved/write-only
	 * offsets.  Ordered GA/GB/SU, then SC/RS, then RB3D/ZB/FG, then US/TX,
	 * then PIPE3D last (least characterized). */
	{ 0x400c, "R300_GB_UNDOC_400C", "GB" },
	{ 0x4030, "R300_GB_UNDOC_4030", "GB" },
	{ 0x4034, "R300_GB_UNDOC_4034", "GB" },
	{ 0x4038, "R300_GB_UNDOC_4038", "GB" },
	{ 0x403c, "R300_GB_UNDOC_403C", "GB" },
	{ 0x4040, "R300_GB_UNDOC_4040", "GB" },
	{ 0x4044, "R300_GB_UNDOC_4044", "GB" },
	{ 0x4048, "R300_GB_UNDOC_4048", "GB" },
	{ 0x404c, "R300_GB_UNDOC_404C", "GB" },
	{ 0x4050, "R300_GB_UNDOC_4050", "GB" },
	{ 0x4054, "R300_GB_UNDOC_4054", "GB" },
	{ 0x4058, "R300_GB_UNDOC_4058", "GB" },
	{ 0x405c, "R300_GB_UNDOC_405C", "GB" },
	{ 0x4060, "R300_GB_UNDOC_4060", "GB" },
	{ 0x4064, "R300_GB_UNDOC_4064", "GB" },
	{ 0x4068, "R300_GB_UNDOC_4068", "GB" },
	{ 0x406c, "R300_GB_UNDOC_406C", "GB" },
	{ 0x4124, "R300_GB_UNDOC_4124", "GB" },
	{ 0x4128, "R300_GB_UNDOC_4128", "GB" },
	{ 0x412c, "R300_GB_UNDOC_412C", "GB" },
	{ 0x4130, "R300_GB_UNDOC_4130", "GB" },
	{ 0x4134, "R300_GB_UNDOC_4134", "GB" },
	{ 0x4138, "R300_GB_UNDOC_4138", "GB" },
	{ 0x413c, "R300_GB_UNDOC_413C", "GB" },
	{ 0x4140, "R300_GB_UNDOC_4140", "GB" },
	{ 0x4144, "R300_GB_UNDOC_4144", "GB" },
	{ 0x4148, "R300_GB_UNDOC_4148", "GB" },
	{ 0x414c, "R300_GB_UNDOC_414C", "GB" },
	{ 0x4150, "R300_GB_UNDOC_4150", "GB" },
	{ 0x4154, "R300_GB_UNDOC_4154", "GB" },
	{ 0x4158, "R300_GB_UNDOC_4158", "GB" },
	{ 0x415c, "R300_GB_UNDOC_415C", "GB" },
	{ 0x4160, "R300_GB_UNDOC_4160", "GB" },
	{ 0x4164, "R300_GB_UNDOC_4164", "GB" },
	{ 0x4168, "R300_GB_UNDOC_4168", "GB" },
	{ 0x416c, "R300_GB_UNDOC_416C", "GB" },
	{ 0x4170, "R300_GB_UNDOC_4170", "GB" },
	{ 0x4174, "R300_GB_UNDOC_4174", "GB" },
	{ 0x4178, "R300_GB_UNDOC_4178", "GB" },
	{ 0x417c, "R300_GB_UNDOC_417C", "GB" },
	{ 0x4180, "R300_GB_UNDOC_4180", "GB" },
	{ 0x4184, "R300_GB_UNDOC_4184", "GB" },
	{ 0x4188, "R300_GB_UNDOC_4188", "GB" },
	{ 0x418c, "R300_GB_UNDOC_418C", "GB" },
	{ 0x4190, "R300_GB_UNDOC_4190", "GB" },
	{ 0x4194, "R300_GB_UNDOC_4194", "GB" },
	{ 0x4198, "R300_GB_UNDOC_4198", "GB" },
	{ 0x419c, "R300_GB_UNDOC_419C", "GB" },
	{ 0x41a0, "R300_GB_UNDOC_41A0", "GB" },
	{ 0x41a4, "R300_GB_UNDOC_41A4", "GB" },
	{ 0x41a8, "R300_GB_UNDOC_41A8", "GB" },
	{ 0x41ac, "R300_GB_UNDOC_41AC", "GB" },
	{ 0x41b0, "R300_GB_UNDOC_41B0", "GB" },
	{ 0x41b4, "R300_GB_UNDOC_41B4", "GB" },
	{ 0x41b8, "R300_GB_UNDOC_41B8", "GB" },
	{ 0x41bc, "R300_GB_UNDOC_41BC", "GB" },
	{ 0x41c0, "R300_GB_UNDOC_41C0", "GB" },
	{ 0x41c4, "R300_GB_UNDOC_41C4", "GB" },
	{ 0x41c8, "R300_GB_UNDOC_41C8", "GB" },
	{ 0x41cc, "R300_GB_UNDOC_41CC", "GB" },
	{ 0x41d0, "R300_GB_UNDOC_41D0", "GB" },
	{ 0x41d4, "R300_GB_UNDOC_41D4", "GB" },
	{ 0x41d8, "R300_GB_UNDOC_41D8", "GB" },
	{ 0x41dc, "R300_GB_UNDOC_41DC", "GB" },
	{ 0x41e0, "R300_GB_UNDOC_41E0", "GB" },
	{ 0x41e4, "R300_GB_UNDOC_41E4", "GB" },
	{ 0x41e8, "R300_GB_UNDOC_41E8", "GB" },
	{ 0x41ec, "R300_GB_UNDOC_41EC", "GB" },
	{ 0x41f0, "R300_GB_UNDOC_41F0", "GB" },
	{ 0x41f4, "R300_GB_UNDOC_41F4", "GB" },
	{ 0x41f8, "R300_GB_UNDOC_41F8", "GB" },
	{ 0x41fc, "R300_GB_UNDOC_41FC", "GB" },
	{ 0x4210, "R300_GA_UNDOC_4210", "GA" },
	{ 0x4218, "R300_GA_UNDOC_4218", "GA" },
	{ 0x423c, "R300_GA_UNDOC_423C", "GA" },
	{ 0x426c, "R300_GA_UNDOC_426C", "GA" },
	{ 0x4284, "R300_GA_UNDOC_4284", "GA" },
	{ 0x42bc, "R300_SU_UNDOC_42BC", "SU" },
	{ 0x42cc, "R300_SU_UNDOC_42CC", "SU" },
	{ 0x4308, "R300_RS_UNDOC_4308", "RS" },
	{ 0x430c, "R300_RS_UNDOC_430C", "RS" },
	{ 0x4370, "R300_RS_UNDOC_4370", "RS" },
	{ 0x4374, "R300_RS_UNDOC_4374", "RS" },
	{ 0x4378, "R300_RS_UNDOC_4378", "RS" },
	{ 0x437c, "R300_RS_UNDOC_437C", "RS" },
	{ 0x4380, "R300_RS_UNDOC_4380", "RS" },
	{ 0x4384, "R300_RS_UNDOC_4384", "RS" },
	{ 0x4388, "R300_RS_UNDOC_4388", "RS" },
	{ 0x438c, "R300_RS_UNDOC_438C", "RS" },
	{ 0x4390, "R300_RS_UNDOC_4390", "RS" },
	{ 0x4394, "R300_RS_UNDOC_4394", "RS" },
	{ 0x4398, "R300_RS_UNDOC_4398", "RS" },
	{ 0x439c, "R300_RS_UNDOC_439C", "RS" },
	{ 0x43a0, "R300_RS_UNDOC_43A0", "RS" },
	{ 0x43ac, "R300_SC_UNDOC_43AC", "SC" },
	{ 0x43d4, "R300_SC_UNDOC_43D4", "SC" },
	{ 0x43d8, "R300_SC_UNDOC_43D8", "SC" },
	{ 0x43dc, "R300_SC_UNDOC_43DC", "SC" },
	{ 0x43ec, "R300_SC_UNDOC_43EC", "SC" },
	{ 0x43f0, "R300_SC_UNDOC_43F0", "SC" },
	{ 0x43f4, "R300_SC_UNDOC_43F4", "SC" },
	{ 0x43f8, "R300_SC_UNDOC_43F8", "SC" },
	{ 0x43fc, "R300_SC_UNDOC_43FC", "SC" },
	{ 0x4bdc, "R300_FG_UNDOC_4BDC", "FG" },
	{ 0x4e8c, "R300_RB3D_UNDOC_4E8C", "RB3D" },
	{ 0x4e90, "R300_RB3D_UNDOC_4E90", "RB3D" },
	{ 0x4e94, "R300_RB3D_UNDOC_4E94", "RB3D" },
	{ 0x4e98, "R300_RB3D_UNDOC_4E98", "RB3D" },
	{ 0x4e9c, "R300_RB3D_UNDOC_4E9C", "RB3D" },
	{ 0x4ea8, "R300_RB3D_UNDOC_4EA8", "RB3D" },
	{ 0x4eac, "R300_RB3D_UNDOC_4EAC", "RB3D" },
	{ 0x4eb0, "R300_RB3D_UNDOC_4EB0", "RB3D" },
	{ 0x4eb4, "R300_RB3D_UNDOC_4EB4", "RB3D" },
	{ 0x4eb8, "R300_RB3D_UNDOC_4EB8", "RB3D" },
	{ 0x4ebc, "R300_RB3D_UNDOC_4EBC", "RB3D" },
	{ 0x4ec0, "R300_RB3D_UNDOC_4EC0", "RB3D" },
	{ 0x4ec4, "R300_RB3D_UNDOC_4EC4", "RB3D" },
	{ 0x4ec8, "R300_RB3D_UNDOC_4EC8", "RB3D" },
	{ 0x4ecc, "R300_RB3D_UNDOC_4ECC", "RB3D" },
	{ 0x4ed0, "R300_RB3D_UNDOC_4ED0", "RB3D" },
	{ 0x4ed4, "R300_RB3D_UNDOC_4ED4", "RB3D" },
	{ 0x4ed8, "R300_RB3D_UNDOC_4ED8", "RB3D" },
	{ 0x4edc, "R300_RB3D_UNDOC_4EDC", "RB3D" },
	{ 0x4ee0, "R300_RB3D_UNDOC_4EE0", "RB3D" },
	{ 0x4ee4, "R300_RB3D_UNDOC_4EE4", "RB3D" },
	{ 0x4ee8, "R300_RB3D_UNDOC_4EE8", "RB3D" },
	{ 0x4eec, "R300_RB3D_UNDOC_4EEC", "RB3D" },
	{ 0x4ef0, "R300_RB3D_UNDOC_4EF0", "RB3D" },
	{ 0x4f0c, "R300_ZB_UNDOC_4F0C", "ZB" },
	{ 0x4f2c, "R300_ZB_UNDOC_4F2C", "ZB" },
	{ 0x4f64, "R300_ZB_UNDOC_4F64", "ZB" },
	{ 0x4f78, "R300_ZB_UNDOC_4F78", "ZB" },
	{ 0x4f7c, "R300_ZB_UNDOC_4F7C", "ZB" },
	{ 0x4f80, "R300_ZB_UNDOC_4F80", "ZB" },
	{ 0x4f84, "R300_ZB_UNDOC_4F84", "ZB" },
	{ 0x4f88, "R300_ZB_UNDOC_4F88", "ZB" },
	{ 0x4f8c, "R300_ZB_UNDOC_4F8C", "ZB" },
	{ 0x4f90, "R300_ZB_UNDOC_4F90", "ZB" },
	{ 0x4f94, "R300_ZB_UNDOC_4F94", "ZB" },
	{ 0x4f98, "R300_ZB_UNDOC_4F98", "ZB" },
	{ 0x4f9c, "R300_ZB_UNDOC_4F9C", "ZB" },
	{ 0x4fa0, "R300_ZB_UNDOC_4FA0", "ZB" },
	{ 0x4fa4, "R300_ZB_UNDOC_4FA4", "ZB" },
	{ 0x4fa8, "R300_ZB_UNDOC_4FA8", "ZB" },
	{ 0x4fac, "R300_ZB_UNDOC_4FAC", "ZB" },
	{ 0x4fb0, "R300_ZB_UNDOC_4FB0", "ZB" },
	{ 0x4fb4, "R300_ZB_UNDOC_4FB4", "ZB" },
	{ 0x4fb8, "R300_ZB_UNDOC_4FB8", "ZB" },
	{ 0x4fbc, "R300_ZB_UNDOC_4FBC", "ZB" },
	{ 0x4fc0, "R300_ZB_UNDOC_4FC0", "ZB" },
	{ 0x4fc4, "R300_ZB_UNDOC_4FC4", "ZB" },
	{ 0x4fc8, "R300_ZB_UNDOC_4FC8", "ZB" },
	{ 0x4fcc, "R300_ZB_UNDOC_4FCC", "ZB" },
	{ 0x4108, "R300_TX_UNDOC_4108", "TX" },
	{ 0x410c, "R300_TX_UNDOC_410C", "TX" },
	{ 0x46a0, "R300_US_UNDOC_46A0", "US" },
	{ 0x40b4, "R300_PIPE3D_UNDOC_40B4", "PIPE3D" },
	{ 0x40b8, "R300_PIPE3D_UNDOC_40B8", "PIPE3D" },
	{ 0x40bc, "R300_PIPE3D_UNDOC_40BC", "PIPE3D" },
	{ 0x40c0, "R300_PIPE3D_UNDOC_40C0", "PIPE3D" },
	{ 0x40c4, "R300_PIPE3D_UNDOC_40C4", "PIPE3D" },
	{ 0x40c8, "R300_PIPE3D_UNDOC_40C8", "PIPE3D" },
	{ 0x40cc, "R300_PIPE3D_UNDOC_40CC", "PIPE3D" },
	{ 0x40d0, "R300_PIPE3D_UNDOC_40D0", "PIPE3D" },
	{ 0x40d4, "R300_PIPE3D_UNDOC_40D4", "PIPE3D" },
	{ 0x40d8, "R300_PIPE3D_UNDOC_40D8", "PIPE3D" },
	{ 0x40dc, "R300_PIPE3D_UNDOC_40DC", "PIPE3D" },
	{ 0x40e0, "R300_PIPE3D_UNDOC_40E0", "PIPE3D" },
	{ 0x40e4, "R300_PIPE3D_UNDOC_40E4", "PIPE3D" },
	{ 0x40e8, "R300_PIPE3D_UNDOC_40E8", "PIPE3D" },
	{ 0x40ec, "R300_PIPE3D_UNDOC_40EC", "PIPE3D" },
	{ 0x40f0, "R300_PIPE3D_UNDOC_40F0", "PIPE3D" },
	{ 0x40f4, "R300_PIPE3D_UNDOC_40F4", "PIPE3D" },
	{ 0x40f8, "R300_PIPE3D_UNDOC_40F8", "PIPE3D" },
	{ 0x40fc, "R300_PIPE3D_UNDOC_40FC", "PIPE3D" },
	{ 0x4be4, "R300_PIPE3D_UNDOC_4BE4", "PIPE3D" },
	{ 0x4bec, "R300_PIPE3D_UNDOC_4BEC", "PIPE3D" },
	{ 0x4bf0, "R300_PIPE3D_UNDOC_4BF0", "PIPE3D" },
	{ 0x4bf4, "R300_PIPE3D_UNDOC_4BF4", "PIPE3D" },
	{ 0x4bf8, "R300_PIPE3D_UNDOC_4BF8", "PIPE3D" },
	{ 0x4bfc, "R300_PIPE3D_UNDOC_4BFC", "PIPE3D" },
	{ 0x4fd8, "R300_PIPE3D_UNDOC_4FD8", "PIPE3D" },
	{ 0x4fdc, "R300_PIPE3D_UNDOC_4FDC", "PIPE3D" },
	{ 0x4fe0, "R300_PIPE3D_UNDOC_4FE0", "PIPE3D" },
	{ 0x4fe4, "R300_PIPE3D_UNDOC_4FE4", "PIPE3D" },
	{ 0x4fe8, "R300_PIPE3D_UNDOC_4FE8", "PIPE3D" },
	{ 0x4fec, "R300_PIPE3D_UNDOC_4FEC", "PIPE3D" },
	{ 0x4ff0, "R300_PIPE3D_UNDOC_4FF0", "PIPE3D" },
	{ 0x4ff4, "R300_PIPE3D_UNDOC_4FF4", "PIPE3D" },
};

static int rs480_force_clock_3d_read_show(struct seq_file *m, void *unused)
{
	struct radeon_device *rdev = m->private;
	if (rs480_debugfs_refuse_if_parked(m, rdev))
		return 0;
	const struct rs480_force_clock_3d_reg *e;
	u32 sclk_orig, sclk2_orig, value;
	int idx = radeon_rs480_force_clock_3d_index;

	if (idx < 0 || idx >= (int)ARRAY_SIZE(rs480_force_clock_3d_list)) {
		seq_printf(m, "disarmed (radeon_rs480_force_clock_3d_index = %d): "
			   "forces the whole 3D clock set and reads one 3D control "
			   "register; arm 0..%d for an attended probe.  HAZARD: a "
			   "stalled 3D read needs a physical power cycle.\n",
			   idx, (int)ARRAY_SIZE(rs480_force_clock_3d_list) - 1);
		return 0;
	}
	e = &rs480_force_clock_3d_list[idx];
	sclk_orig  = RREG32_PLL(RS480_SCLK_CNTL_PLL_INDEX);
	sclk2_orig = RREG32_PLL(RS480_SCLK_CNTL2_PLL_INDEX);
	WREG32_PLL(RS480_SCLK_CNTL_PLL_INDEX,  sclk_orig  | RS480_SCLK_3D_FORCE_ALL);
	WREG32_PLL(RS480_SCLK_CNTL2_PLL_INDEX, sclk2_orig | RS480_SCLK2_3D_FORCE_ALL);
	/* Let the forced 3D clock domains settle before the MMIO read. */
	udelay(10);
	value = RREG32(e->offset);
	WREG32_PLL(RS480_SCLK_CNTL2_PLL_INDEX, sclk2_orig);
	WREG32_PLL(RS480_SCLK_CNTL_PLL_INDEX,  sclk_orig);
	seq_printf(m, "index %d: %s (0x%04x) domain=%s sclk2_was=0x%08x = 0x%08x\n",
		   idx, e->name, e->offset, e->domain, sclk2_orig, value);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(rs480_force_clock_3d_read);

/* Gated-state plain-read probe.  The force_clock_validated tier asserts a
 * register is safe to read ONLY with its domain SCLK_CNTL FORCE bit set; the
 * open question is whether a PLAIN read stalls when the clock is genuinely
 * gated.  This node answers it by CLEARING the FORCE bit, plain-reading, then
 * restoring -- the inverse of the force-clock node.
 *
 * HAZARD: reset-less K8.  If the plain read stalls while the FORCE bit is
 * clear, the restore WREG32_PLL never runs and both cores freeze -- a physical
 * power cycle.  The table holds only inactive-DISP2 CRTC2 registers (the second
 * pipe drives no display on this board, so clearing FORCE_DISP2 cannot blank
 * the visible panel), and the node is disarmed by default
 * (radeon_rs480_gated_read_index == -1).  Caveat: with dynamic clock gating
 * disabled (BIOS forces all clocks), clearing one FORCE bit may not gate the
 * clock at all, in which case the read simply completes. */
struct rs480_gated_read_reg {
	u32 clear_bit;
	u32 offset;
	const char *name;
	const char *domain;
};

static const struct rs480_gated_read_reg rs480_gated_read_list[] = {
	{ RS480_SCLK_FORCE_DISP2, 0x03f8, "RADEON_CRTC2_GEN_CNTL",       "DISP2" },
	{ RS480_SCLK_FORCE_DISP2, 0x0324, "RADEON_CRTC2_OFFSET",         "DISP2" },
	{ RS480_SCLK_FORCE_DISP2, 0x032c, "RADEON_CRTC2_PITCH",          "DISP2" },
	{ RS480_SCLK_FORCE_DISP2, 0x0304, "RADEON_CRTC2_H_SYNC_STRT_WID","DISP2" },
	{ RS480_SCLK_FORCE_DISP2, 0x0308, "RADEON_CRTC2_V_TOTAL_DISP",   "DISP2" },
};

static int rs480_gated_read_show(struct seq_file *m, void *unused)
{
	struct radeon_device *rdev = m->private;
	if (rs480_debugfs_refuse_if_parked(m, rdev))
		return 0;
	const struct rs480_gated_read_reg *e;
	u32 sclk_orig, value;
	int idx = radeon_rs480_gated_read_index;

	if (idx < 0 || idx >= (int)ARRAY_SIZE(rs480_gated_read_list)) {
		seq_printf(m, "disarmed (radeon_rs480_gated_read_index = %d): clears a "
			   "DISP2 SCLK_CNTL FORCE bit and PLAIN-reads an inactive CRTC2 "
			   "register to test gated-state read safety.  Set "
			   "radeon_rs480_gated_read_index=0..%d for an attended probe; a "
			   "stall needs a physical power cycle.\n",
			   idx, (int)ARRAY_SIZE(rs480_gated_read_list) - 1);
		return 0;
	}
	e = &rs480_gated_read_list[idx];
	sclk_orig = RREG32_PLL(RS480_SCLK_CNTL_PLL_INDEX);
	WREG32_PLL(RS480_SCLK_CNTL_PLL_INDEX, sclk_orig & ~e->clear_bit);
	mdelay(1);
	value = RREG32(e->offset);
	WREG32_PLL(RS480_SCLK_CNTL_PLL_INDEX, sclk_orig);
	seq_printf(m, "index %d: %s (0x%04x) domain=%s cleared_bit=0x%08x plain_read=0x%08x\n",
		   idx, e->name, e->offset, e->domain, e->clear_bit, value);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(rs480_gated_read);

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
	/* Retained exhausted-state frontier probe.  The active list is empty, so
	 * reads report exhaustion rather than performing an MMIO read.  Any
	 * reinstated nonempty table requires an attended harness to gate physical
	 * presence before opening the node. */
	debugfs_create_file("radeon_rs480_frontier_probe", 0400, root, rdev,
			    &rs480_frontier_probe_fops);
	debugfs_create_file("radeon_rs480_force_clock_read", 0400, root, rdev,
			    &rs480_force_clock_read_fops);
	debugfs_create_file("radeon_rs480_force_clock_3d_read", 0400, root, rdev,
			    &rs480_force_clock_3d_read_fops);
	debugfs_create_file("radeon_rs480_gated_read", 0400, root, rdev,
			    &rs480_gated_read_fops);
	/* Attended vertex-engine probe.  Mode 0400: reading it performs one RREG32
	 * of the vertex control register radeon_rs480_vertex_index selects, which
	 * the operator must hold clocked via a concurrent HB-TCL draw loop. */
	debugfs_create_file("radeon_rs480_vertex_probe", 0400, root, rdev,
			    &rs480_vertex_probe_fops);
	/* PLL-indirect clock-tree read-out.  Read-only and low hazard: the PLL
	 * aperture is always clocked and r100_pll_rreg serializes the index/data
	 * dance under pll_idx_lock. */
	debugfs_create_file("radeon_rs480_pll_regs", 0444, root, rdev,
			    &rs480_pll_regs_fops);
	/* Hazard-tier first-observation read.  Mode 0444: the listed registers
	 * are read-safe name-pattern false-positives, read one at a time as
	 * radeon_rs480_hazard_index selects (default -1 disarmed), so each value
	 * is captured deliberately before promotion to the safe-regs list. */
	debugfs_create_file("radeon_rs480_hazard_read", 0444, root, rdev,
			    &rs480_hazard_read_fops);
	/* CP IB scratch-write baseline oracle.  Mode 0400: reading it submits a
	 * fence-bearing IB scratch write (the r100_ib_test path), root-only, inert
	 * until radeon_rs480_cp_ib_scratch_oracle equals the arm token.  IGP-safe:
	 * the IB fences through the live ring, no CSQ stop/restart. */
	debugfs_create_file("radeon_rs480_cp_ib_scratch_oracle", 0400, root, rdev,
			    &rs480_cp_ib_scratch_oracle_fops);
	/* GPU-reset recovery probe.  Mode 0400: reading it forces a deterministic
	 * radeon_gpu_reset (suspend/resume/cp_init), root-only, inert until
	 * radeon_rs480_gpu_reset_recover_probe equals the arm token, and refused
	 * unless the engine is idle so the hard-locking CP soft-reset is skipped. */
	debugfs_create_file("radeon_rs480_gpu_reset_recover_probe", 0400, root, rdev,
			    &rs480_gpu_reset_recover_probe_fops);
	/* RBBM soft-reset recovery probe (idle, stage 1 of hang-recovery).  Mode
	 * 0400: reading it runs the RBBM_SOFT_RESET sequence on the idle engine,
	 * root-only, inert until radeon_rs480_reset_hang_probe equals the token. */
	debugfs_create_file("radeon_rs480_reset_hang_probe", 0400, root, rdev,
			    &rs480_reset_hang_probe_fops);
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

/*
 * The RS480-family IGP (RS480/RS482/RS485/RC410, all CHIP_RS480 in the
 * radeon family table) instantiates the R400 fragment-shader (US) extended
 * register file -- US_CODE_BANK (0x46b8), US_CODE_EXT (0x46bc), and the
 * 64-entry US_ALU_EXT_ADDR array (0x4ac0-0x4bbc) -- even though the part is
 * R300-class.  The stock r300_reg_safe_bm omits them, so r300_packet0_check
 * rejects a command stream that writes them ("Forbidden register"), which is
 * what blocks the mesa R300_HB_R400_US route from reaching the silicon.  The
 * widened bitmap is a hardware-facing permission change, so keep the stock
 * r300 bitmap unless rs480_r400_us_cs=1 is set at module load for an attended
 * run.  Every other family keeps the stock r300 bitmap.  These are plain value
 * registers (code-bank index, extended-address bits), not BO offsets, so they
 * need no relocation handling once the operator arms the route.
 */
static void rs480_set_reg_safe(struct radeon_device *rdev)
{
	if (rdev->family == CHIP_RS480 && radeon_rs480_r400_us_cs == 1) {
		rdev->config.r300.reg_safe_bm = rs480_reg_safe_bm;
		rdev->config.r300.reg_safe_bm_size = ARRAY_SIZE(rs480_reg_safe_bm);
		dev_info(rdev->dev,
			 "RS480 R400-US CS-checker allowlist armed by rs480_r400_us_cs=1\n");
	} else {
		r300_set_reg_safe(rdev);
	}
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
	rs480_set_reg_safe(rdev);

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
