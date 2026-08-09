# RS4xx GART cache and coherency source contract

## Scope

This contract records the coupled source state that governs RS400 and RS480
GART mappings. It separates source relationships from effective CPU and GPU
coherency. The source relationships are known. Effective coherency on RS482 is
unresolved.

## Coupled source state

| Owner | Input | Source transition |
| --- | --- | --- |
| `radeon_bo_create` | A buffer object on a non-PCIe Radeon device | The constructor removes `RADEON_GEM_GTT_WC` and `RADEON_GEM_GTT_UC`. |
| `radeon_ttm_tt_create` | GTT flags with neither UC nor WC selected | TTM selects `ttm_cached`. |
| `radeon_ttm_backend_bind` | A cached TTM translation table | The bind flags include `RADEON_GART_PAGE_SNOOP` before `radeon_gart_bind`. |
| `rs400_gart_get_page_entry` | A bind with `RADEON_GART_PAGE_SNOOP` | The encoded PTE omits `RS400_PTE_UNSNOOPED`. |
| `rs400_gart_enable` | RS4xx GART initialization | `RS480_AGP_MODE_CNTL` retains `RS480_REQ_TYPE_SNOOP_DIS`. |
| `radeon_gart_table_ram_alloc` | The system-memory GART table | The table uses `dma_alloc_coherent`; the x86 RS400 and RS480 path then calls `set_memory_uc`. |
| `radeon_gart_table_ram_free` | GART table release | The same path calls `set_memory_wb` before `dma_free_coherent`. |

`scripts/check_rs4xx_gart_cache_policy.py` proves these seven relationships and
rejects mutations to each relationship. The checker deliberately accepts the
combined state in which a cached bind requests per-PTE snoop while the global
mode retains `REQ_TYPE_SNOOP_DIS`. It reports the source contract and does not
interpret which setting controls effective traffic.

The active source ignores the integer returns from `set_memory_uc` and
`set_memory_wb`. Call presence and order therefore do not establish that the
CPU alias page-attribute transitions succeed on a running kernel.

## Ordering boundary

`radeon_gart_bind` and `radeon_gart_unbind` write PTEs, execute `mb()`, and
then call the ASIC TLB flush. This source order is the available publication
contract.

The root-only GART table reader holds `rs400_gart_page_table_lock`.
`rs400_gart_fini` holds the same lock, but bind and unbind do not. `READ_ONCE`
protects each scalar read and does not make the multi-entry output one
generation-consistent snapshot. A future snapshot claim requires either
serialization with PTE writers or a generation and retry protocol.

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

The canonical Steinmarder finding at
`steinmarder-r300/src/re/r300/findings/active/2026-06-21-rs482-global-gart-snoop-breaks-gart-binding-measured.md`
is a reported operational negative. It reports that clearing
`REQ_TYPE_SNOOP_DIS` produced `AGP_MODE_CNTL = 0x00400000`, left the GART not
ready, and made GTT and GEM allocations fail. Its
`AGP_MODE_CNTL = 0x01400000` control reports no GART or GEM errors. That result
is sufficient to keep the global-snoop mutation excluded. The finding's
`linked_results` list is empty, however, so raw decision-grade replay remains
unavailable. This repository does not independently prove the reported silicon
behavior, and the report says nothing about the still-untested per-PTE snoop
path.

The retained K8 finding at
`steinmarder-r300/src/re/r300/findings/archive/2026-06-18-rs482-ht-mediated-gart-atomic-rmw-coherency-latch-falsified.md`
reports `F3x40 = 0x00043bff`, so `AtomicRMWEn` is already set. It identifies
the bit as MCA error reporting for unsupported Atomic RMW commands, not as an
enable for atomic execution. Writing the already-set reporting bit adds no
atomic capability or required state transition. The source denominator also assigns
neither experiment a native owner, so active source retains the global
snoop-disable setting and contains no K8 AtomicRMW reporter.

## Falsifiers and checks

This contract fails if any source relationship above changes without a matching
policy update, if the mutation fixtures accept a changed relationship, or if
the denominator ledger no longer agrees with the pinned migration inputs.

```sh
python3 scripts/check_rs4xx_gart_cache_policy.py --selftest
python3 scripts/check_rs4xx_gart_cache_policy.py
python3 scripts/check_legacy_patch_denominator.py --selftest
python3 scripts/check_legacy_patch_denominator.py
```

These commands prove source and reconstruction facts only. They do not prove
runtime reachability, silicon coherency, performance, or hazard clearance.
