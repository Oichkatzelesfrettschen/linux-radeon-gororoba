// SPDX-License-Identifier: MIT

#include <linux/moduleparam.h>

#include "radeon_dev.h"

int radeon_palm_pci_reset_unsafe;
int radeon_rs480_safe_regs = 1;
int radeon_rs480_candidate_regs = 1;
int radeon_rs480_cp_me_ram_dump;
int radeon_rs480_cp_me_ram_inject;
int radeon_rs480_cp_me_oracle;
int radeon_rs480_cp_ib_scratch_oracle;
int radeon_rs480_gpu_reset_recover_probe;
int radeon_rs480_reset_hang_probe;
int radeon_rs480_r400_us_cs;
int radeon_rs480_frontier_index = -1;
int radeon_rs480_vertex_index = -1;
int radeon_rs480_hazard_index = -1;
int radeon_rs480_force_clock_index = -1;
int radeon_rs480_force_clock_3d_index = -1;
int radeon_rs480_gated_read_index = -1;
int radeon_rs480_hazard_readers_armed;

MODULE_PARM_DESC(palm_pci_reset_unsafe,
	"Allow evergreen_gpu_pci_config_reset_safe to fire on CHIP_PALM (Wrestler GPU). "
	"Default 0: refuse, because the reset propagates a transient PCIe-fabric stall "
	"to adjacent integrated devices (NIC drops, X session loses output layout). "
	"Set to 1 only for forensic experimentation on a controlled host."
);
module_param_named(palm_pci_reset_unsafe, radeon_palm_pci_reset_unsafe, int, 0644);

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

MODULE_PARM_DESC(rs480_gpu_reset_recover_probe,
	"Arm the GPU-reset recovery probe debugfs node "
	"radeon_rs480_gpu_reset_recover_probe. Default 0 (OFF); arm with the exact "
	"token 0x52435652 ('RCVR'). Reading the armed node sets needs_reset and "
	"calls radeon_gpu_reset() directly -- the deterministic reset the stock "
	"radeon_gpu_reset node cannot deliver, since that node only wakes the fence "
	"queue and fires nothing without a blocked waiter. Idle-gated: it refuses "
	"unless RBBM_STATUS reads !GUI_ACTIVE, so r300_asic_reset early-returns and "
	"the RBBM_SOFT_RESET CP reset (the documented R3XX/R4XX hard-locking path) "
	"is skipped. A PASS proves the suspend/resume/cp_init recovery path "
	"survives; it does NOT prove a wedged ring recovers. Requires an "
	"initialized gfx ring; root-only; run with the display quiesced.");
module_param_named(rs480_gpu_reset_recover_probe, radeon_rs480_gpu_reset_recover_probe, int, 0644);

MODULE_PARM_DESC(rs480_reset_hang_probe,
	"Arm the RBBM soft-reset recovery probe debugfs node "
	"radeon_rs480_reset_hang_probe. Default 0 (OFF); arm with 0x53525354 "
	"('SRST') for the idle soft-reset stage, 0x48414E47 ('HANG') for the "
	"2D-blit in-busy stage that busies the E2 engine via r100_copy_blit and resets "
	"while it drains, 0x57443341 ('WD3A') for the wedged-3D drainable stage, or "
	"0x57443342 ('WD3B') for the wedged-3D hung stage. The WD3A/WD3B stages recover "
	"a userspace-induced VAP/GA frontend stall through the production radeon_gpu_reset "
	"path (ring backup, r300_asic_reset, ring restore or fence force-completion, "
	"radeon_ib_ring_tests); WD3A gates on a busy frontend, WD3B on the frontend-wedge "
	"signature (RB3D/RE idle). Reading a soft-reset-scaffold node (SRST/HANG) force-clocks "
	"VAP/GA/E2 and runs the documented RBBM_SOFT_RESET sequence (the half of "
	"r300_asic_reset that radeon_gpu_reset skips on an idle engine), rebuilds the "
	"CP with r100_cp_init, and re-tests it with r100_ib_test. It proves whether the "
	"soft-reset write wedges this reset-less northbridge and whether the CP executes "
	"again, NOT that a hung engine recovers. RBBM_SOFT_RESET (0x0000F0) is low control "
	"space, not the gated VAP aperture. Idle-only, root-only, initialized gfx ring; "
	"run with the display quiesced.");
module_param_named(rs480_reset_hang_probe, radeon_rs480_reset_hang_probe, int, 0644);

MODULE_PARM_DESC(rs480_r400_us_cs,
	"RS480 R400-US CS-checker allowlist: 0 (default) keeps the stock R300 "
	"bitmap.  Set 1 at module load for an attended R300_HB_R400_US run; this "
	"admits PACKET0 writes to US_CODE_BANK, US_CODE_EXT, and "
	"US_ALU_EXT_ADDR_0..63 on CHIP_RS480.");
module_param_named(rs480_r400_us_cs, radeon_rs480_r400_us_cs, int, 0644);

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

MODULE_PARM_DESC(rs480_hazard_readers_armed,
	"RS480 hazard-reader arm gate: 0 (default) makes the wedge-prone "
	"radeon_rs480_candidate_vap_regs and radeon_rs480_candidate_firmware_read_regs "
	"nodes refuse the MMIO read.  VAP/PVS clock-gates at rest and a read can "
	"stall the reset-less K8 northbridge; the firmware_read cohort includes "
	"HOST_PATH_CNTL (0x0130), which gates the HyperTransport host path.  Set 1 "
	"to arm an attended read.");
module_param_named(rs480_hazard_readers_armed, radeon_rs480_hazard_readers_armed, int, 0644);
