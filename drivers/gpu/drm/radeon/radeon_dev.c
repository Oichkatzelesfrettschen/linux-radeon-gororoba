// SPDX-License-Identifier: MIT

#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/pci.h>
#include <linux/panic.h>

#include "radeon.h"

struct radeon_dev_profile_name {
	const char *name;
	enum radeon_dev_profile profile;
};

static const struct radeon_dev_profile_name radeon_dev_profile_names[] = {
	{ "off", RADEON_DEV_PROFILE_OFF },
	{ "observe-dev", RADEON_DEV_PROFILE_OBSERVE },
	{ "probe-dev", RADEON_DEV_PROFILE_PROBE },
	{ "mutate-dev", RADEON_DEV_PROFILE_MUTATE },
};

#if RADEON_MUTATE_DEV
#define RADEON_DEV_COMPILED_PROFILE RADEON_DEV_PROFILE_MUTATE
#elif RADEON_PROBE_DEV
#define RADEON_DEV_COMPILED_PROFILE RADEON_DEV_PROFILE_PROBE
#else
#define RADEON_DEV_COMPILED_PROFILE RADEON_DEV_PROFILE_OBSERVE
#endif

static enum radeon_dev_profile radeon_dev_selected_profile =
	RADEON_DEV_PROFILE_OFF;
static char radeon_profile_dev[sizeof("observe-dev")] = "off";

static int radeon_dev_profile_set(const char *value,
				  const struct kernel_param *parameter)
{
	enum radeon_dev_profile profile = RADEON_DEV_PROFILE_OFF;
	bool found = false;
	unsigned int index;

	(void)parameter;
	for (index = 0; index < ARRAY_SIZE(radeon_dev_profile_names); index++) {
		if (!strcmp(value, radeon_dev_profile_names[index].name)) {
			profile = radeon_dev_profile_names[index].profile;
			found = true;
			break;
		}
	}
	if (!found) {
		pr_err("radeon: profile_dev rejects unknown value \"%s\"\n",
		       value);
		return -EINVAL;
	}
	if (profile > RADEON_DEV_COMPILED_PROFILE) {
		pr_err("radeon: profile_dev=%s exceeds the compiled profile\n",
		       value);
		return -EINVAL;
	}

	strscpy(radeon_profile_dev, value, sizeof(radeon_profile_dev));
	radeon_dev_selected_profile = profile;
	return 0;
}

static int radeon_dev_profile_get(char *buffer,
				  const struct kernel_param *parameter)
{
	(void)parameter;
	return scnprintf(buffer, PAGE_SIZE, "%s", radeon_profile_dev);
}

static const struct kernel_param_ops radeon_dev_profile_ops = {
	.set = radeon_dev_profile_set,
	.get = radeon_dev_profile_get,
};

MODULE_PARM_DESC(profile_dev,
	"Development runtime profile: off (default), observe-dev, probe-dev, or mutate-dev. "
	"The selected profile cannot exceed the compiled build profile.");
module_param_cb(profile_dev, &radeon_dev_profile_ops, NULL, 0444);

/* Development arming binds to one device.  The probe-dev and mutate-dev
 * interfaces read module-global selectors (the reset mask, the force-clock
 * and hazard indices, the CP-ME arm tokens, the R400-US boolean, the Palm
 * reset override), so a second bound device would race the first for one
 * armed selection.  The first device to initialize under probe-dev or
 * mutate-dev claims the arming through this pointer; every later device
 * clamps to observe-dev and keeps its read-only surface.  The claim holds
 * for the module lifetime, so a holder that unbinds fails closed rather
 * than migrating armed state to the next device. */
static struct radeon_device *radeon_dev_arm_holder;

void radeon_dev_context_init(struct radeon_device *rdev)
{
	enum radeon_dev_profile profile = radeon_dev_selected_profile;

	if (profile >= RADEON_DEV_PROFILE_PROBE) {
		if (cmpxchg(&radeon_dev_arm_holder, NULL, rdev)) {
			dev_warn(rdev->dev,
				 "profile_dev=%s arms one device and another radeon device holds the arming; this device runs observe-dev\n",
				 radeon_profile_dev);
			profile = RADEON_DEV_PROFILE_OBSERVE;
		} else {
			/* The successful claim is the attestation anchor: the
			 * holder's PCI address in the log ties every armed
			 * operation in a retained bundle to one device. */
			dev_info(rdev->dev,
				 "development arming holder claimed by %s under profile_dev=%s\n",
				 pci_name(rdev->pdev), radeon_profile_dev);
		}
	}
	rdev->dev_context.profile = profile;
	atomic_set(&rdev->dev_context.mutation_tainted, 0);
}

bool radeon_dev_profile_enabled(struct radeon_device *rdev,
				enum radeon_dev_profile required)
{
	return rdev && rdev->dev_context.profile >= required;
}

void radeon_dev_mark_mutation(struct radeon_device *rdev,
			      const char *operation)
{
	if (!radeon_dev_profile_enabled(rdev, RADEON_DEV_PROFILE_MUTATE))
		return;
	if (atomic_cmpxchg(&rdev->dev_context.mutation_tainted, 0, 1))
		return;

	dev_warn(rdev->dev,
		 "development mutation executed: %s; tainting kernel\n",
		 operation);
	add_taint(TAINT_USER, LOCKDEP_STILL_OK);
}

#if RADEON_OBSERVE_DEV
int radeon_rs480_safe_regs = 1;
int radeon_rs480_candidate_regs = 1;
#endif

#if RADEON_PROBE_DEV
int radeon_rs480_cp_me_ram_dump;
int radeon_rs480_cp_me_oracle;
int radeon_rs480_frontier_index = -1;
int radeon_rs480_vertex_index = -1;
int radeon_rs480_hazard_index = -1;
int radeon_rs480_hazard_readers_armed;
int radeon_rs480_cp_status_arm;
int radeon_rs480_status_census_arm;
int radeon_rs480_status_census_records = 256;
int radeon_rs480_status_census_read_order;
#endif

#if RADEON_MUTATE_DEV
int radeon_palm_pci_reset_unsafe;
int radeon_rs480_cp_me_ram_inject;
int radeon_rs480_cp_ib_scratch_oracle;
int radeon_rs480_force_clock_index = -1;
int radeon_rs480_force_clock_3d_index = -1;
int radeon_rs480_gated_read_index = -1;
int radeon_rs480_reset_hang_probe;
int radeon_rs480_r400_us_cs;
#endif

#if RADEON_MUTATE_DEV
bool radeon_palm_dev_pci_reset_unsafe(struct radeon_device *rdev)
{
	if (!radeon_dev_profile_enabled(rdev, RADEON_DEV_PROFILE_MUTATE) ||
	    radeon_palm_pci_reset_unsafe != 1)
		return false;

	return true;
}
#endif

#if RADEON_MUTATE_DEV
MODULE_PARM_DESC(palm_pci_reset_unsafe,
	"Allow evergreen_gpu_pci_config_reset_safe to fire on CHIP_PALM (Wrestler GPU). "
	"Default 0: refuse, because the reset propagates a transient PCIe-fabric stall "
	"to adjacent integrated devices (NIC drops, X session loses output layout). "
	"Set to 1 only for forensic experimentation on a controlled host."
);
module_param_named(palm_pci_reset_unsafe, radeon_palm_pci_reset_unsafe, int, 0644);
#endif

#if RADEON_OBSERVE_DEV
MODULE_PARM_DESC(rs480_safe_regs,
	"Expose the read-only RS480/RS482/RS485 curated MMIO snapshot in debugfs. "
	"Default 1: create radeon_rs480_safe_regs. Set to 0 to keep the DKMS "
	"radeon module active but suppress the extra reverse-engineering debugfs file."
);
module_param_named(rs480_safe_regs, radeon_rs480_safe_regs, int, 0444);

MODULE_PARM_DESC(rs480_candidate_regs,
	"Expose the read-only RS480/RS482/RS485 candidate register snapshot in debugfs. "
	"Default 1: expose radeon_rs480_candidate_regs and block-scoped "
	"candidate files for bounded register validation."
);
module_param_named(rs480_candidate_regs, radeon_rs480_candidate_regs, int, 0444);
#endif

#if RADEON_PROBE_DEV
MODULE_PARM_DESC(rs480_cp_me_ram_dump,
	"Dump the RS480/RS482/RS485 CP MicroEngine instruction memory through the "
	"CP_ME_RAM_RADDR read-back port in debugfs. Default 0 (OFF): this writes a CP "
	"register on reset-less R300-class silicon, so it stays inert until the operator "
	"sets it to 1 AND the engine is idle. CP_ME_RAM_RADDR is 8-bit on RS48x, so the "
	"read pointer wraps mod-256 and the addressable memory is exactly the 256-microword "
	"R300_cp.bin overlay; microwords 0..255 read back the loaded blob (a built-in "
	"calibration) and there is no separately-addressable ROM through this port."
);
module_param_named(rs480_cp_me_ram_dump, radeon_rs480_cp_me_ram_dump, int, 0644);

MODULE_PARM_DESC(rs480_cp_status_arm,
	"Arm the one-shot RBBM/CP status pair reader debugfs node "
	"radeon_rs480_cp_status. Default 0 (OFF); arm with the exact token "
	"0x43505354 ('CPST'), a stray nonzero value does nothing. The armed "
	"read consumes the token atomically, takes the hardware lock, and "
	"performs exactly two plain 32-bit reads -- RBBM_STATUS (0x0e40) then "
	"CP_STAT (0x07c0) -- bracketed by three CLOCK_MONOTONIC_RAW-class "
	"timestamps. RBBM_STATUS is on the promoted read-safe list; CP_STAT "
	"takes its first disciplined RS48x observation through this node. "
	"No writes, no offset selector, one register pair per arming."
);
module_param_named(rs480_cp_status_arm, radeon_rs480_cp_status_arm, int, 0644);

MODULE_PARM_DESC(rs480_status_census_arm,
	"Arm the paired RBBM/CP_STAT census debugfs node "
	"radeon_rs480_paired_status_census. Default 0 (OFF); arm with the "
	"exact token 0x43454E53 ('CENS'). The first read of an armed node "
	"consumes the token atomically, takes the hardware lock once, reads "
	"the RBBM_STATUS (0x0e40) / CP_STAT (0x07c0) pair "
	"rs480_status_census_records times into a little-endian binary "
	"census (transport ABI v1), and releases the lock before copying to "
	"userspace. A private gate admits one live census; a disarmed, busy, "
	"parked, or suspended capture writes a valid header with zero records "
	"and reads no register. Raw words and CLOCK_MONOTONIC_RAW-class "
	"timestamps only; field decoding lives in userspace analysis."
);
module_param_named(rs480_status_census_arm, radeon_rs480_status_census_arm, int, 0644);

MODULE_PARM_DESC(rs480_status_census_records,
	"Records the paired-status census captures per armed read. Default "
	"256; clamped to 1..4096. Each record is one RBBM/CP_STAT read pair "
	"with three timestamps; the whole run holds the hardware lock once."
);
module_param_named(rs480_status_census_records, radeon_rs480_status_census_records, int, 0644);

MODULE_PARM_DESC(rs480_status_census_read_order,
	"Read-order schedule for the paired-status census. Default 0 "
	"(alternating: even records read RBBM then CP_STAT, odd records read "
	"CP_STAT then RBBM). 1 AB-only, 2 BA-only, 3 AA calibration (RBBM "
	"read twice), 4 BB calibration (CP_STAT read twice). An out-of-range "
	"value falls back to alternating."
);
module_param_named(rs480_status_census_read_order, radeon_rs480_status_census_read_order, int, 0644);
#endif

#if RADEON_MUTATE_DEV
MODULE_PARM_DESC(rs480_cp_me_ram_inject,
	"Arm the RS480/RS482/RS485 CP MicroEngine instruction-memory injection "
	"increment 1 (write a microword through CP_ME_RAM_ADDR, read it back, "
	"restore it; the modified word is NEVER executed). Default 0 (OFF). This "
	"writes a CP register on reset-less R300-class silicon, so it is an exact "
	"arm gate, not a boolean: it must equal 0x494e4a31 ('INJ1') AND the "
	"debugfs write to radeon_rs480_cp_me_ram_inject must carry the literal ARM "
	"keyword. A stray nonzero value alone does nothing. The address is bounded "
	"to the 256-microword R300_cp.bin overlay (known-writable, restore "
	"cross-checkable). The execute-the-word increment 2 is the stop-line and is "
	"absent from this build."
);
module_param_named(rs480_cp_me_ram_inject, radeon_rs480_cp_me_ram_inject, int, 0644);
#endif

#if RADEON_PROBE_DEV
MODULE_PARM_DESC(rs480_cp_me_oracle,
	"Arm the CP MicroEngine oracle debugfs node radeon_rs480_cp_me_oracle. "
	"Default 0 (OFF); arm with the exact token 0x4f524331 ('ORC1'), a stray "
	"nonzero value does nothing. On an IGP the live-fire is EXCLUDED: reading "
	"the node prints an exclusion notice, because the CSQ stop/restart + gfx "
	"ring test scratch poll hard-locks the K8 northbridge (no MMIO completion "
	"timeout). Use radeon_rs480_cp_me_ram_inject for safe CP_ME_RAM "
	"read/verify/restore. The live-fire (inject a sentinel into dead microword "
	"0xff, stop/restart the command queue, ring test, restore) is retained for a "
	"future discrete Radeon, where the PCIe completion timeout makes a wedged "
	"poll fail cleanly; root-only, run with the display quiesced."
);
module_param_named(rs480_cp_me_oracle, radeon_rs480_cp_me_oracle, int, 0644);
#endif

#if RADEON_MUTATE_DEV
MODULE_PARM_DESC(rs480_cp_ib_scratch_oracle,
	"Arm the CP IB scratch-write baseline oracle debugfs node "
	"radeon_rs480_cp_ib_scratch_oracle. Default 0 (OFF); arm with the exact "
	"token 0x49425343 ('IBSC'). Reading the armed node submits one "
	"fence-bearing IB that writes a sentinel to a scratch register and reads "
	"it back (the r100_ib_test path the driver runs at every resume): a plain "
	"CS scratch write with NO microcode inject, NO CP_CSQ_CNTL toggle, and NO "
	"r100_ring_test poll. SAFE on the K8 IGP because the IB fences through the "
	"live ring instead of stopping and restarting the command queue, unlike "
	"radeon_rs480_cp_me_oracle. Requires an initialized gfx ring; root-only.");
module_param_named(rs480_cp_ib_scratch_oracle, radeon_rs480_cp_ib_scratch_oracle, int, 0644);

MODULE_PARM_DESC(rs480_reset_hang_probe,
	"Arm the wedged-3D production-reset probe debugfs node "
	"radeon_rs480_reset_hang_probe. Default 0 (OFF); arm with 0x57443341 "
	"('WD3A') for the wedged-3D drainable stage or "
	"0x57443342 ('WD3B') for the wedged-3D hung stage. WD3A and WD3B recover a "
	"userspace-induced VAP/GA frontend stall through the production "
	"radeon_gpu_reset path: ring backup, r300_asic_reset, ring restore or fence "
	"force-completion, then radeon_ib_ring_tests. WD3A admits a busy frontend; "
	"WD3B admits a busy frontend with RB3D and RE idle. Root-only, initialized "
	"gfx ring; run with the display quiesced.");
module_param_named(rs480_reset_hang_probe, radeon_rs480_reset_hang_probe, int, 0644);

MODULE_PARM_DESC(rs480_r400_us_cs,
	"RS480 R400-US CS-checker allowlist: 0 (default) keeps the stock R300 "
	"bitmap.  Set 1 at module load for an attended R300_HB_R400_US run; this "
	"admits PACKET0 writes to US_CODE_BANK, US_CODE_EXT, and "
	"US_ALU_EXT_ADDR_0..63 on CHIP_RS480.");
module_param_named(rs480_r400_us_cs, radeon_rs480_r400_us_cs, int, 0644);
#endif

#if RADEON_PROBE_DEV
MODULE_PARM_DESC(rs480_frontier_index,
	"RS480 attended frontier probe: residual frontier exhausted; no valid "
	"index performs an MMIO read.  -1 (default) remains disarmed."
);
module_param_named(rs480_frontier_index, radeon_rs480_frontier_index, int, 0644);

MODULE_PARM_DESC(rs480_vertex_index,
	"RS480 attended vertex-engine probe: hold the VAP_PVS/SE_TCL engine clocked "
	"with a continuous HB-TCL draw loop, then set N (0..6) to perform one RREG32.  "
	"-1 (default) remains disarmed.");
module_param_named(rs480_vertex_index, radeon_rs480_vertex_index, int, 0644);

MODULE_PARM_DESC(rs480_hazard_index,
	"RS480 hazard-tier first-observation read: index (0..21) that "
	"radeon_rs480_hazard_read reads per open.  The list is read-safe "
	"name-pattern false-positives (BIOS/GUI scratch, SE viewport, "
	"SW_SEMAPHORE, WAIT_UNTIL), NOT wedge hazards.  -1 (default) disarmed."
);
module_param_named(rs480_hazard_index, radeon_rs480_hazard_index, int, 0644);
#endif

#if RADEON_MUTATE_DEV
MODULE_PARM_DESC(rs480_force_clock_index,
	"RS480 per-domain force-clock-then-read: index (0..4) into the VIP/CAP "
	"force-clock table read per open; the domain SCLK_CNTL FORCE bit is set, "
	"the register read, and SCLK_CNTL restored.  -1 (default) disarmed.");
module_param_named(rs480_force_clock_index, radeon_rs480_force_clock_index, int, 0644);

MODULE_PARM_DESC(rs480_force_clock_3d_index,
	"RS480 3D-engine force-clock-then-read (HAZARD): index into the 3D "
	"control-register table.  Forces the whole 3D clock set -- VAP/TX/US/SU/RB "
	"in SCLK_CNTL (PLL 0x0d) and TCL/CBA/GA in SCLK_CNTL2 (PLL 0x1e) -- reads "
	"the register, then restores both PLL registers.  The 3D engine is the "
	"block class whose VAP write wedged the reset-less K8; a stalled read needs "
	"a physical power cycle.  -1 (default) disarmed.");
module_param_named(rs480_force_clock_3d_index, radeon_rs480_force_clock_3d_index, int, 0644);

MODULE_PARM_DESC(rs480_gated_read_index,
	"RS480 gated-state plain-read probe (HAZARD): index into the inactive-DISP2 "
	"CRTC2 table; clears FORCE_DISP2, plain-reads, restores, to test whether a "
	"read stalls when the clock is gated.  A stall needs a physical power cycle.  "
	"-1 (default) disarmed.");
module_param_named(rs480_gated_read_index, radeon_rs480_gated_read_index, int, 0644);
#endif

#if RADEON_PROBE_DEV
MODULE_PARM_DESC(rs480_hazard_readers_armed,
	"RS480 hazard-reader arm gate: 0 (default) makes the wedge-prone "
	"radeon_rs480_candidate_vap_regs and radeon_rs480_candidate_firmware_read_regs "
	"nodes refuse the MMIO read.  VAP/PVS clock-gates at rest and a read can "
	"stall the reset-less K8 northbridge; the firmware_read cohort includes "
	"HOST_PATH_CNTL (0x0130), which gates the HyperTransport host path.  Set 1 "
	"to arm an attended read.");
module_param_named(rs480_hazard_readers_armed, radeon_rs480_hazard_readers_armed, int, 0644);
#endif
