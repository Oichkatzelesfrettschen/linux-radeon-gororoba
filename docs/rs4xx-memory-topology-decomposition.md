# RS4xx memory topology decomposition

The RS485M (Radeon Xpress 1150, `CHIP_RS480`, PCI `1002:5974`) has no
dedicated memory. Every byte the GPU reads or writes is host DRAM reached
through one of five mechanisms that the driver source keeps distinct, and a
claim about "memory management" on this part resolves to exactly one of
them. This document names each mechanism, the source symbol that owns it,
the invariant the source holds, and the ledger row that carries its evidence
state. Behavior is described; nothing here changes it.

## The five mechanisms

| Mechanism | Owner symbol | What it establishes |
| --- | --- | --- |
| Physical carveout | `rs400_mc_init`, `r100_vram_init_sizes` (`r100.c`) | The DRAM interval the northbridge reserved for the GPU, read from `RADEON_NB_TOM`, becomes `mc.real_vram_size` and `mc.mc_vram_size`; `radeon_vram_location` places it in GPU address space at the `NB_TOM` base. |
| GPU aperture addresses | `radeon_gtt_location` (`radeon_device.c`), `rs400_gart_adjust_size`, `rs400_gart_enable` (`rs400.c`) | A GTT window of `mc.gtt_size` bytes, aligned to its own size, placed in the larger free region before or after VRAM; `RS480_AGP_ADDRESS_SPACE_SIZE` carries the size code and `RS480_GART_EN`. |
| Page-table mappings | `radeon_gart_init`, `radeon_gart_bind`, `radeon_gart_unbind` (`radeon_gart.c`), `rs400_gart_get_page_entry`, `rs400_gart_set_page`, `rs400_gart_tlb_invalidate` (`rs400.c`) | One 4-byte hardware PTE per GPU page carrying `RS400_PTE_READABLE`, `RS400_PTE_WRITEABLE`, and `RS400_PTE_UNSNOOPED`; a u64 shadow per GPU page; a page pointer per CPU page; a coherent table allocation whose CPU alias is attempted uncached. |
| Placement policy | `radeon_ttm_placement_from_domain`, `radeon_bo_get_threshold_for_moves` (`radeon_object.c`), `radeon_gem_object_create` (`radeon_gem.c`) | VRAM, then GTT, then CPU for a multi-domain request; GTT objects at or below `RADEON_GTT_TOPDOWN_LIMIT` (512 KiB) insert top-down; the per-IB move budget is the larger of 1 MiB and half the free lower half of VRAM; one object is bounded by `gtt_size - gart_pin_size`. |
| Compaction | `radeon_gtt_compact` (`radeon_object.c`), invoked from `radeon_gem_object_create` | When no hole is wide enough, unpinned, unreserved GTT objects are re-bound at new aperture offsets by rewriting their page-table entries; no payload byte is copied. |

## Ordering contracts between the mechanisms

1. Carveout before aperture. `rs400_mc_init` calls `rs400_gart_adjust_size`,
   reads `NB_TOM`, calls `radeon_vram_location`, then `radeon_gtt_location`.
   The aperture is placed against a VRAM interval that already exists, so
   `mc.gtt_start` and `mc.gtt_end` never overlap `mc.vram_start` to
   `mc.vram_end`.
2. Aperture before table. `radeon_gart_init` derives `num_cpu_pages` and
   `num_gpu_pages` from the effective `mc.gtt_size`, so the table is sized by
   the aperture that address fit produced, never by the requested selector.
3. Table before enable, invalidation before ready. `rs400_gart_enable`
   programs `RS480_GART_BASE` from `gart.table_addr`, sets the size code and
   `RS480_GART_EN`, then calls `rs400_gart_tlb_invalidate`; `gart.ready`
   becomes true only when that invalidation returned zero. A timed-out
   invalidation clears `RS480_AGP_ADDRESS_SPACE_SIZE` and returns
   `-ETIMEDOUT`, so no translation from before the enable can be served
   through a published aperture.
4. Bind publishes through the same invalidation. `radeon_gart_bind` writes
   the shadow and hardware entries, executes `mb()`, then calls the ASIC
   `tlb_flush`; on RS4xx that is `rs400_gart_tlb_flush`, whose poll
   disposition is counted in `rs4xx_gart_tlb_flush_timeouts`. The bind path
   carries no per-call result to its caller, which is the remaining source
   boundary of `RS400_TLB_FLUSH_COMPLETION`.
5. Placement inside the published aperture. TTM's GTT manager is initialized
   from the effective `mc.gtt_size` after the aperture is published, so every
   placement the manager hands out is a translation the table can carry.
6. Compaction under the same locks as placement. `radeon_gtt_compact` holds
   `gem.mutex`, reserves each candidate, and skips a pinned or externally
   reserved object, so a rewrite never races a binding the GPU may be using.

## Ownership of each byte

| Byte class | Owner | Lifetime rule |
| --- | --- | --- |
| Carveout DRAM | Firmware, through `NB_TOM` | Fixed for the boot; `vramlimit` only narrows the driver's accounting of it. |
| GART hardware table | `radeon_gart_table_ram_alloc` | Coherent DMA allocation; freed by `radeon_gart_table_ram_free` after `radeon_gart_fini` unbinds every page; the WB restore of the CPU alias is attempted, not proven. |
| PTE shadow and page pointers | `radeon_gart_init` | Virtual allocations sized by the page counts; released in `radeon_gart_fini`. |
| GTT-placed object pages | TTM through `radeon_ttm_backend_bind` | Bound while placed; unbound before the pages are released; a userptr object pins and DMA-maps its pages transactionally. |
| VRAM-placed objects | TTM VRAM manager | Inside `real_vram_size`; CPU access limited to `visible_vram_size`. |

## Invariants the source holds

* `gtt_start` is a multiple of `gtt_size`, and `gtt_size` is a power of two
  between 32 MiB and 2 GiB, because `rs400_gart_adjust_size` forces every
  other selector to 32 MiB and `radeon_gtt_location` aligns to
  `gtt_base_align = gtt_size - 1`.
* The table holds exactly `gtt_size / RADEON_GPU_PAGE_SIZE` entries, each 4
  bytes, so the hardware table is `gtt_size / 1024` bytes and the static
  metadata is `5120 * (gtt_size / MiB)` bytes.
* A bound entry carries the snoop request the placement asked for
  (`RS400_PTE_UNSNOOPED` clear for a cached TTM page), while the global mode
  keeps `RS480_REQ_TYPE_SNOOP_DIS`; which of the two the hardware honors is
  the open row `EFFECTIVE_PER_PTE_SNOOP_SEMANTICS`.
* No object larger than `gtt_size - gart_pin_size` is created, because a
  VRAM-to-system move travels the GTT.
* Compaction changes GPU addresses of unpinned objects and no payload, so a
  submission that captured an address before compaction is the caller's
  hazard; the reservation it holds excludes the object from compaction.

## What remains open, and who closes it

| Row | State | Closure |
| --- | --- | --- |
| `RS400_TLB_FLUSH_COMPLETION` | repaired in source | A target trial that forces the poll to time out and observes the counter and the enable refusal. |
| `EFFECTIVE_PER_PTE_SNOOP_SEMANTICS` | open, target-owned | Directional CPU and GPU visibility trials under the retained cache-action controls in `steinmarder-r300`. |
| `CPU_GTT_GPU_PAYLOAD_PUBLICATION` | open, target-owned | The same trials, producer side. |
| `GPU_GTT_CPU_PAYLOAD_INVALIDATION` | open, target-owned | The same trials, consumer side. |

The ledger of record is `policy/rs4xx-gart-memory-path.tsv`, verified by
`scripts/check_radeon_gart_lifecycle.py`; the capacity contract is
`policy/rs4xx-vram-gtt-capacity-contract.tsv`, verified by
`scripts/check_rs4xx_vram_gtt_capacity.py`. This document restates their rows
in topology order and adds no row of its own.
