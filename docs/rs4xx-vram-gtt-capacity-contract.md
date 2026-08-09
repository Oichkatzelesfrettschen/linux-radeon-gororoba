# RS4xx VRAM and GTT capacity contract

## Boundary

`policy/rs4xx-vram-gtt-capacity-contract.tsv` is the finite Linux source
contract for RS482 capacity, placement, movement, and observation. The fixed
four-state nominal-selector model lives in
`policy/rs482-gtt-capacity-matrix.tsv`, and
`policy/rs482-gtt-capacity-exclusions.tsv` makes the selected nearby
source-supported or invalid selectors explicit.

The 128 MiB VRAM pool and a GTT aperture are different resources. VRAM is a
firmware-reserved physical DRAM interval owned by the integrated GPU. GTT is a
GPU virtual address aperture whose BO backing is committed through TTM. A
larger GTT increases address and migration capacity; it does not create DRAM,
increase memory bandwidth, or prove that every byte can be resident at once.

On x86_64 with 4 KiB CPU and GPU pages, one RS400 aperture entry carries:

* four bytes in the hardware GART table;
* eight bytes in the CPU-page pointer array; and
* eight bytes in the u64 PTE shadow array.

The source-model metadata cost is therefore five bytes per KiB of aperture:
640 KiB for 128 MiB, 1.25 MiB for 256 MiB, 2.5 MiB for 512 MiB, and 5 MiB for
1024 MiB. These are allocation formulas, not retained target memory-use
measurements.

## Existing policy

Linux already contains five capacity controls that an optimization must
measure rather than replace blindly:

1. Multi-domain BO placement tries VRAM, GTT, and CPU in that order.
2. A single BO cannot exceed unpinned GTT capacity because VRAM migration uses
   the GTT path.
3. Pinned VRAM and GTT bytes reduce the GEM_INFO visible-VRAM and GTT fields.
4. Preferred-domain movement per IB starts at one quarter of total VRAM when
   VRAM is empty, decreases linearly with usage, and reaches a one MiB floor
   at or before one-half usage.
5. Usage, moved-byte, TTM extent, and per-BO placement surfaces already exist.

`vramlimit` is not an optimization mechanism for this target. It changes
driver accounting after the firmware-visible VRAM interval is established and
cannot return the reserved DRAM to Linux.

## Finite configuration denominator

The requested denominator contains exactly 128, 256, 512, and 1024 MiB GTT
with the target's 128 MiB VRAM held fixed. Linux source accepts each nominal
selector and the matrix proves its register code, page counts, and static
metadata cost before `radeon_gtt_location()` applies the target-dependent
address-space fit. The matrix marks effective capacity unresolved because that
function can reduce `mc.gtt_size`. It does not prove the board-specific
interval, a successful boot, allocator headroom, or workload performance.

The denominator excludes 32 and 64 MiB because they are below the requested
frontier, 2048 MiB because it lacks exact Vostro address and boot evidence,
non-power-of-two values because Linux replaces them with auto, and reduced
`vramlimit` states because they do not reclaim physical memory.

Capacity captures use `radeon_vram_mm`, `radeon_gtt_mm`, and
`radeon_gem_info`. They exclude the raw `radeon_vram` and `radeon_gtt` files.
Those payload readers bound reads with inode size and VRAM size or GTT page
count, but the VRAM bound is not the visible-VRAM allocator bound and neither
reader proves complete parked-state, suspended-state, or lifetime protection.
They are outside this allocator-only evidence lane.

## Ranked resolution frontier

The implementation order is evidence-ranked, not size-ranked:

1. Close the offline source model for all four sizes and the fixed 128 MiB
   VRAM input.
2. Admit a fresh exact-target module and aperture event for the currently
   loaded configuration.
3. Run a reversible no-submit allocation-pressure sweep on that configuration.
   Retain requested and realized placement, allocation errno, usage deltas,
   cumulative bytes moved, TTM extents, object inventory, cleanup, and process
   identity.
4. Derive the largest successful allocation, largest free extent, fragmentation
   recovery, pinned headroom, and VRAM-to-GTT fallback knee. A fill ratio is a
   diagnostic, not a goal.
5. Prepare the other three module configurations as reboot-gated trials. Each
   trial retains the exact boot, module, aperture, GART-ready, address interval,
   allocation sweep, cleanup, and stability evidence before another size runs.
6. Run submit or application workloads only through Steinmarder's separate
   GPU hazard gate. Compare completed work, bytes moved, copy count, cache-sync
   cost, latency distribution, and fault or reset state.
7. Change Mesa placement or heap reporting only after the exact-target evidence
   selects a policy and proves the payload visibility semantics that policy
   requires.

The winner is the smallest aperture that satisfies the retained workload set
with stable allocation headroom and no worse movement, fragmentation, fault,
or reset outcome than larger candidates. A larger candidate wins only when it
removes a measured constraint without introducing a measured regression.

## Checks

Run the calibrated source contract before module builds:

```sh
python3 scripts/check_rs4xx_vram_gtt_capacity.py --selftest
python3 scripts/check_rs4xx_vram_gtt_capacity.py
```

These checks prove the exact finite row set, matrix arithmetic, exclusions,
source-function identities, dependencies, and nonclaims. They do not contact a
target or turn an offline model into a runtime or silicon result.
