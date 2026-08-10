# RS4xx VRAM and GTT capacity contract

## Authority and boundary

`policy/rs4xx-vram-gtt-capacity-contract.tsv` is the finite Linux source
contract for RS482 capacity admission, placement, allocation, movement, and
observation. The contract has four supporting denominators:

* `policy/rs482-gtt-capacity-matrix.tsv` fixes the four requested nominal GTT
  selectors and their source-derived metadata sizes.
* `policy/rs482-gtt-capacity-exclusions.tsv` closes the nearby input classes
  that do not represent comparable trials.
* `policy/rs482-vram-gtt-capacity-coefficients.tsv` retains each linear or
  piecewise coefficient, its evaluation input, its valid domain, and its
  nonclaim.
* `policy/rs482-vram-gtt-capacity-source-lineage.tsv` binds the reviewed input
  commit, Git blob, and content SHA-256 identities to the projections
  preserved by this contract.

The reviewed source-policy input is signed annotated tag
`rs482-vram-gtt-capacity-source-policy-authority`, tag object
`38c49adcba27a5ddac82b9978683227b91cf3c46`, which peels to commit
`6667d7561617debdc62cf99c62fb47bd67f95043`. It contributes four selector
rows and 14 contract row identifiers. The verifier binds the tag object,
peeled commit, exact `100644` tree entries, blob identities, content hashes,
canonical schemas, row counts, and integrated projections. The integrated
policy preserves the numeric selector fields from `config_id` through
`static_metadata_bytes` for all four rows and preserves every input contract
row identifier. It adds
`RADEON_GTT_MODULE_GLOBAL_REQUEST_STATE`, expands the source observation
surface, and corrects the module-global auto state and address-fit relations
against the current source tree. The input commit is policy authority, not a
driver C change or a runtime result. Signature trust remains a repository
publication property rather than a source or hardware verdict.

This repository owns the source policy and its calibrated verifier. It does
not change driver C behavior in this batch. It does not produce a hardware
verdict. Exact RS482 runtime evidence belongs in `steinmarder-r300`, and Vostro
platform evidence owns the K8, HT, firmware, DRAM, PAT, MTRR, and host address
domain observations.

The source evidence binds to the current Radeon subtree. Hardware promotion
still binds to RS482 device `1002:5974` on an identified target event. The
128 MiB VRAM value is a fixed input to the proposed target denominator, not a
claim that every RS482 boot exposes that capacity.

## Resource decomposition

The model separates four resources that similar names can otherwise blur:

1. Firmware-visible VRAM is a physical DRAM interval reserved for the
   integrated GPU. Linux derives its interval from northbridge and aperture
   state.
2. GTT is a GPU virtual address aperture. It maps GPU addresses through a GART
   table to backing pages. Increasing its size creates address capacity, not
   physical DRAM or bandwidth.
3. GART metadata is host memory for page pointers, the PTE shadow, and the
   coherent hardware table. Its cost exists before ordinary payload pages
   occupy the aperture.
4. TTM allocator capacity is the range-manager address space after address fit
   and initialization. Pinning, fragmentation, placement, and current usage
   determine how much of that capacity an allocation can use.

`vramlimit` only reduces driver-visible `real_vram_size` after Linux establishes
the physical VRAM interval. It cannot return firmware-reserved DRAM to the
operating system, so this contract excludes it as a memory-reclamation
mechanism.

## Capacity state machine

The source implements a four-stage state machine:

```text
module-global request R
  -> per-device normalized selector S
  -> address-fit effective aperture E
  -> allocator and observation capacity C
```

`radeon_gart_size` starts at minus one and remains one writable module-global
integer. `radeon_check_arguments()` can replace that shared value with the
family default when it sees auto, a value below 32 MiB, or a non-power-of-two
value. It then copies the result into `rdev->mc.gtt_size`. The first probed
Radeon device can therefore change the auto value seen by every later device
in the same module lifetime.

Comparable trials use an explicit valid `gartsize=` value at module load and
retain PCI probe order. A later sysfs parameter write only changes the shared
request. It does not rerun RS400 selector normalization, memory placement,
metadata allocation, TTM setup, or register programming for an initialized
device.

RS400 normalizes `S` to one of 32, 64, 128, 256, 512, 1024, or 2048 MiB.
`radeon_gtt_location()` then derives `E` from the address regions before and
after VRAM. TTM and GART initialization consume `E`. A successful GART enable
programs the corresponding selector and enable bit. Observed free capacity is
smaller than `E` when pinned objects consume GTT or allocator fragmentation
prevents a contiguous extent.

## Structural source path

The source-map policy treats this graph as lexical and structural evidence. It
does not claim runtime reachability or a completed callback invocation.

```text
radeon_driver_load_kms
  -> radeon_device_init
     -> radeon_check_arguments
        -> radeon_gart_size_auto
        -> rdev->mc.gtt_size
     -> radeon_asic_init
        -> CHIP_RS480 selects rs400_asic
     -> radeon_init
        -> rdev->asic->init
           -> rs400_init
              -> rs400_mc_init
                 -> rs400_gart_adjust_size
                 -> r100_vram_init_sizes
                 -> radeon_vram_location
                 -> radeon_gtt_location
              -> radeon_bo_init
                 -> radeon_ttm_init
                    -> radeon_ttm_init_vram
                    -> radeon_ttm_set_active_vram_size
                    -> radeon_ttm_init_gtt
                    -> radeon_ttm_debugfs_init
              -> rs400_gart_init
                 -> radeon_gart_init
                 -> radeon_gart_table_ram_alloc
              -> rs400_startup
                 -> rs400_gart_enable
```

The policy also binds `RADEON_GEM_INFO` to `radeon_gem_info_ioctl()`,
`RADEON_INFO` to `radeon_info_ioctl()`, GEM debugfs registration to
`radeon_debugfs_gem_info_show()`, and the raw VRAM and GTT debugfs nodes to
their file-operation readers. The raw readers remain excluded from the
allocator-only capture because a structural binding does not prove safe
payload visibility.

The retained source-only capture for commit `c4f4177` closes 73 roots, 219
raw cscope queries, 1,053 parsed cscope rows, 246 commands, 55 declared
bindings, 13 hazards, six contextual witnesses, and 15,643 call candidates.
Its driver tree remains
`6fd8d3c6ec245c31f195ef86c15fadf5e206642d`. The source-intelligence contract
records its complete path and hashes. This capture has no kernel lanes and
does not change any runtime or silicon status.

## Finite selector denominator

The requested denominator contains exactly 128, 256, 512, and 1024 MiB GTT
with a fixed 128 MiB VRAM input. Each row states
`explicit-module-load-gartsize`; none relies on auto selection.

| GTT MiB | Size code | Enabled value | 4 KiB pages | Metadata bytes |
| ---: | ---: | ---: | ---: | ---: |
| 128 | `0x00000004` | `0x00000005` | 32,768 | 655,360 |
| 256 | `0x00000006` | `0x00000007` | 65,536 | 1,310,720 |
| 512 | `0x00000008` | `0x00000009` | 131,072 | 2,621,440 |
| 1024 | `0x0000000a` | `0x0000000b` | 262,144 | 5,242,880 |

Every family below `CHIP_RV770` resolves an auto request to 512 MiB. A shared
512 MiB value therefore does not identify RS482 as the first probed device and
does not establish an optimum.

The exclusion ledger closes ten classes. It distinguishes supported selectors
below the requested frontier, generic validation fallbacks, the supported but
unadmitted 2048 MiB selector, values above 2048 MiB that RS400 forces to 32
MiB, post-probe parameter writes, `vramlimit`, and raw debugfs payload readers.
An excluded class returns only through its named reactivation condition.

## Address-fit derivation

Let `S` be a valid normalized selector in bytes. RS400 sets
`gtt_base_align = S - 1`. The two candidate regions are:

```text
before = vram_start & ~(S - 1)
after  = (mc_mask - vram_end + S - 1) & ~(S - 1)
```

Both results are nonnegative integer multiples of `S`. The placement function
selects the larger candidate. If the requested `S` fits, it remains unchanged.
If `S` exceeds the selected candidate, that candidate is a multiple of `S`
strictly smaller than `S`, so it equals zero. For an admitted power-of-two
selector, the effective source result is therefore:

```text
E is S or 0
```

A zero result later fails the RS400 selector switch with `EINVAL`. The source
does not silently produce an arbitrary intermediate aperture for the admitted
selectors. This derivation does not identify the target address interval or
prove a successful boot.

## Metadata coefficients

Let `A` be the effective GTT aperture in MiB. On x86_64 with 4 KiB CPU pages,
4 KiB GPU pages, eight-byte pointers, and eight-byte `u64` values:

```text
cpu_pages(A)       = 256 * A
gpu_pages(A)       = 256 * A
hardware_table(A)  = 4 * gpu_pages(A) = 1024 * A bytes
cpu_pointer_array  = 8 * cpu_pages(A) = 2048 * A bytes
pte_shadow(A)      = 8 * gpu_pages(A) = 2048 * A bytes
static_metadata(A) = 5120 * A bytes
```

The coefficient ledger stores each component rather than only the combined
slope. That decomposition makes page-size and pointer-width changes
falsifiable. The combined result excludes the dummy page, allocator metadata,
host page tables, alignment waste, coherent-allocation metadata, and payload
backing. It is a source allocation formula, not a target memory measurement.

## Movement coefficients

Let `V` be `real_vram_size`, `U` be current VRAM manager usage, and `F` be one
MiB. `radeon_bo_get_threshold_for_moves()` computes:

```text
T(V, U) = max(floor(max(floor(V / 2) - U, 0) / 2), F)
```

For `V = 128 MiB`, the nonfloor segment is:

```text
T(128 MiB, U) = 32 MiB - ceil(U / 2)
```

The intercept is 32 MiB. The usage slope is minus one half over each two-byte
usage increment. Odd usage values add a one-byte downward rounding term. The
one MiB floor first equals the raw threshold at 65,011,711 bytes in the full
integer-byte domain. For page-aligned Radeon BO usage, the first reachable
4 KiB-aligned value at the floor is 62 MiB, or 65,011,712 bytes. The validator
rederives the coefficients and the byte-domain knee from the retained inputs.

`radeon_bo_list_validate()` compares the already accumulated movement against
the threshold with a strict `bytes_moved > threshold` test before it validates
the next BO. The next whole BO can therefore overshoot the threshold. Every
comparison retains the BO-size distribution and cumulative movement rather
than interpreting the threshold as a hard byte cap.

## Single-BO and pinned-capacity coefficients

GEM creation applies this single-BO ceiling:

```text
max_bo_size = effective_gtt_bytes - gart_pin_size
```

The relation is valid when effective GTT is at least the pinned debit. It
applies even to an initial VRAM request because VRAM-to-system migration uses
the GTT path. A larger ceiling does not prove a free extent, physical backing,
or successful placement.

Linux increments pin counters only after successful realized placement and
unwinds them on unpin. `RADEON_GEM_INFO` subtracts `vram_pin_size` from visible
VRAM and `gart_pin_size` from effective GTT. Unpinned bytes still differ from
the largest allocatable extent because fragmentation remains independent.

## Observation surfaces

The minimum allocator capture uses these read-only query surfaces:

* `RADEON_GEM_INFO` reports active VRAM manager size, visible VRAM minus pinned
  VRAM, and effective GTT minus pinned GTT.
* `RADEON_INFO_VRAM_USAGE` and `RADEON_INFO_GTT_USAGE` report current manager
  usage.
* `RADEON_INFO_NUM_BYTES_MOVED` reports the cumulative movement counter.
* `radeon_vram_mm` and `radeon_gtt_mm` report TTM range-manager extents.
* `radeon_gem_info` lists tracked BO sizes and realized VRAM, GTT, or CPU
  placement under `gem.mutex`.

These surfaces do not prove the firmware carveout, payload correctness,
largest free extent across a concurrent mutation, or end-to-end performance.
The raw `radeon_vram` and `radeon_gtt` files access mapped payload or backing
pages. The VRAM reader writes the MMIO index selector before reading the data
register. The GTT reader copies present host backing pages and clears ranges
whose page pointer is absent. Two contextual source-map witnesses separate
node registration from a later read event and classify each path by its
maximum source-visible side effect. Their bounds do not establish the
visible-VRAM, parked, suspended, and lifetime contract required by this
allocator-only lane, so the exclusion ledger keeps them out.

## Research-quality selection method

The trial program applies a feasibility gate before it ranks performance. A
candidate fails feasibility when any retained event shows selector fallback,
zero address fit, GART initialization failure, incomplete cleanup, allocator
corruption, fault, hang, reset, or unexplained identity drift.

Each feasible candidate then enters a Pareto comparison across:

* largest successful BO and largest free GTT extent;
* pinned headroom and fragmentation recovery;
* requested and realized placement;
* cumulative movement, copy count, and BO-size distribution;
* latency distribution and completed work;
* static metadata and observed host-memory pressure;
* faults, resets, kernel warnings, and post-trial recovery.

The target plan prespecifies at least three independent boot events per
candidate and applies the same allocation sequence to every event. It rotates
candidate order across replicate blocks, retains all raw trials, and reports
the median and full range. A larger sample can add quantiles and confidence
intervals without replacing raw data. Every trial records kernel, module,
package, source commit, boot, device, firmware, command, probe order, requested
selector, effective interval, GART-ready state, process, cleanup, and log
identity.

The smallest feasible aperture wins only when all measured outcomes are
equivalent within the prespecified comparison bounds. A larger aperture wins
when it removes a measured capacity or movement constraint without introducing
a measured safety, stability, memory-pressure, or latency regression. The
largest aperture and the highest fill ratio never win by definition.

## Resolution roadmap

The work proceeds through explicit gates:

1. The source checker closes the 15 contract rows, four selector rows, ten
   exclusion rows, ten coefficient rows, two lineage rows, 36 source
   functions, module request, two ioctl bindings, and eight register
   encodings.
2. The capacity contract contributes exactly 73 partition bound roots, 13
   hazards, 55 declared bindings, and six contextual witnesses across the
   request, selector, address fit, allocator, GART, ioctl, debugfs, and raw
   reader structural boundaries. The integrated live policy closes 119 roots,
   30 hazards, 63 bindings, and eight witnesses. A fresh source map remains a
   lexical candidate graph rather than runtime proof.
3. A read-only exact-target production baseline records the loaded request,
   effective GTT interval, GART state, allocator counters, device identity,
   module identity, boot identity, and logs before any pressure trial.
4. A no-submit allocation-pressure campaign runs on the loaded configuration.
   It retains allocation errno, placement, pinning, movement, extents,
   fragmentation, BO inventory, cleanup, and stability.
5. The other selectors run as reboot-gated explicit module-load trials under
   the same capture contract and balanced replicate order.
6. Submit and application workloads run only through Steinmarder's separate
   GPU hazard gate after the no-submit lane closes.
7. Mesa placement or heap reporting changes only after the retained target
   evidence selects a capacity policy and proves the payload visibility
   semantics that userspace needs.
8. `radeon-custom` advances its signed source pin only when the driver source
   subtree identity changes. This policy-only batch does not change that
   subtree.

## Verification

Run the calibrated source contract before module builds:

```sh
python3 scripts/check_rs4xx_vram_gtt_capacity.py --selftest
python3 scripts/check_rs4xx_vram_gtt_capacity.py
```

The self test includes a known-good fixture and mutations for row order,
serialization aliases, changed arithmetic, inactive source twins, local macro
overrides, callback drift, and bounded-input failures. The live check proves
the exact finite source-policy denominator. It does not contact a target, load
a module, allocate a BO, submit work, or promote runtime or silicon status.
