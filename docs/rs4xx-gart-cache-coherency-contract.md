# RS4xx GART cache and coherency source contract

## Scope and canonical owner

This contract interprets the coupled cache controls used by RS400 and RS480
GART mappings. `policy/rs4xx-gart-memory-path.tsv` is the canonical finite
ledger. `docs/rs4xx-gart-bo-lifecycle-contract.md` describes its complete
35-row lifecycle and its four open boundaries.

The cache policy checker retains seven calibrated source relationships as a
focused diagnostic subset. The lifecycle ledger splits coherent table
allocation from the UC alias attempt, so those seven checks correspond to
these eight canonical rows:

* `NON_PCIE_GTT_ATTRIBUTE_NORMALIZATION`
* `TTM_DEFAULT_CACHED_SELECTION`
* `CACHED_TTM_SNOOP_FLAG_PROPAGATION`
* `RS400_PTE_PERMISSION_AND_SNOOP_ENCODING`
* `RS480_GLOBAL_REQUEST_SNOOP_DISABLE`
* `GART_TABLE_DMA_COHERENT_ALLOCATION_API`
* `RS4XX_GART_TABLE_UC_ALIAS_ATTEMPT`
* `RS4XX_GART_TABLE_WB_RESTORE_ATTEMPT`

`scripts/check_radeon_gart_lifecycle.py` proves the finite ledger and invokes
`scripts/check_rs4xx_gart_cache_policy.py` as a required subcontract. A direct
cache checker run remains useful for a focused failure, but it does not own a
second policy table.

## Coupled source state

The non PCIe BO constructor removes `RADEON_GEM_GTT_WC` and
`RADEON_GEM_GTT_UC`. TTM therefore selects `ttm_cached`. Backend bind adds
`RADEON_GART_PAGE_SNOOP`, and the RS400 PTE encoder omits
`RS400_PTE_UNSNOOPED` for that request. At the same time, the sole
`RS480_AGP_MODE_CNTL` write in GART enable retains
`RS480_REQ_TYPE_SNOOP_DIS`.

The checker deliberately accepts this combined source state. Linux source does
not define whether the global setting or the per PTE request controls an
RS482 transaction. `EFFECTIVE_PER_PTE_SNOOP_SEMANTICS` therefore remains open
in the lifecycle ledger and belongs to exact target authority in Steinmarder.

The GART page table uses `dma_alloc_coherent`. The x86 RS400 and RS480 path
then calls `set_memory_uc`, and release calls `set_memory_wb` before
`dma_free_coherent`. The source ignores both integer results. Allocation API
terminology and call order establish neither an effective CPU alias page type
nor CPU and GPU payload coherence.

## Ordering boundary

`radeon_gart_bind` and `radeon_gart_unbind` write PTEs, execute `mb()`, and
then call the ASIC TLB flush. This is address publication order. The callback
has a void result, so its bounded poll cannot report completion to its callers.
`RS400_TLB_FLUSH_COMPLETION` remains open.

The root-only GART table reader enters one hardware transaction and holds
`rdev->gart.lock` across metadata and PTE reads. Bind, unbind, and common
finalization hold the same table lock. Lifecycle transitions close and drain
ordinary reader admission before RS400 disables the aperture or releases table
storage. The emitted rows therefore form one source-defined table snapshot
relative to those writers. The reader does not provide a payload-cache action
or a synchronization surface for Mesa.

Reservation fences and the r300 fence command sequence add execution order.
They do not add CPU payload cache maintenance. CPU to GPU publication and GPU
to CPU invalidation remain separate open target rows in the GART lifecycle and
command submission ledgers.

## Excluded historical experiment

The physical denominator is the 73 paths matching
`^patches/rs480/[0-9]{4}-[^/]+[.]patch$` at the pinned radeon-custom commit.
`docs/legacy-rs480-patch-set.tsv` also retains the full 74-path recursive
patch inventory and identifies the nested non-numeric draft that the selector
excludes.

`docs/legacy-patch-denominator-supersession.tsv` records two physical patch
files with numeric ID 0023. Both pinned files use K8 F3x40 offset 0x40 and
explicitly distinguish it from F3x44. The later file rebases the experiment to
the deployed 0.3 source layout and wires `rs480_snoop_status_debugfs_init` into
`rs400_init`; its header's claim that the pinned original used F3x44 is false.
Neither file belongs to the 70 declared transition series or the 124 allocated
transition effect atoms.

Both files propose the same two behavior changes that remain unported:

1. It conditionally removes `REQ_TYPE_SNOOP_DIS` from global GART setup.
2. It exposes a path that can write K8 F3x40 AtomicRMW reporting state.

The Steinmarder finding pinned by the lifecycle ledger at
`steinmarder-r300/src/re/r300/findings/resolved/canonical/2026-06-21-rs482-global-gart-snoop-gart-binding-outcome.md`
is a reported operational negative. It reports that clearing
`REQ_TYPE_SNOOP_DIS` produced `AGP_MODE_CNTL = 0x00400000`, left the GART not
ready, and made GTT and GEM allocations fail. Its
`AGP_MODE_CNTL = 0x01400000` control reports no GART or GEM errors. That result
is sufficient to keep the global-snoop mutation excluded. The finding's
`linked_results` list is empty, however, so raw decision-grade replay remains
unavailable. This repository does not independently prove the reported silicon
behavior, and the report says nothing about the still untested per PTE snoop
path. The policy ledger pins the external commit and row that carry this
boundary.

The retained K8 finding at
`steinmarder-r300/src/re/r300/findings/archive/2026-06-18-rs482-ht-mediated-gart-atomic-rmw-coherency-latch-falsified.md`
reports `F3x40 = 0x00043bff`, so `AtomicRMWEn` is already set. It identifies
the bit as MCA error reporting for unsupported Atomic RMW commands, not as an
enable for atomic execution. Writing the already set reporting bit adds no
atomic capability or required state transition. The source denominator also
assigns neither experiment a native owner, so active source retains the global
snoop disable setting and contains no K8 AtomicRMW reporter.

## Falsifiers and checks

This contract fails if the finite lifecycle ledger changes denominator,
dependency, status, or external authority without a matching checker update.
It also fails if a source mutation escapes the calibrated fixtures or if the
legacy denominator no longer agrees with the pinned migration inputs.

```sh
python3 scripts/check_radeon_gart_lifecycle.py --selftest
python3 scripts/check_radeon_gart_lifecycle.py
python3 scripts/check_rs4xx_gart_cache_policy.py --selftest
python3 scripts/check_rs4xx_gart_cache_policy.py
python3 scripts/check_legacy_patch_denominator.py --selftest
python3 scripts/check_legacy_patch_denominator.py
```

The lifecycle checker is authoritative for the active finite ledger. The cache
checker is its diagnostic subset, and the denominator checker proves the
excluded historical input set. These commands prove source and reconstruction
facts only. They do not prove runtime reachability, silicon coherence,
performance, or hazard clearance.
