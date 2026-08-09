# RS4xx GART and buffer object lifecycle contract

## Scope and authority

`policy/rs4xx-gart-memory-path.tsv` is the canonical finite ledger for the
Linux Radeon GART, TTM, buffer object, CPU mapping, and teardown path. Its 29
rows use one 19 field schema and one acyclic dependency graph. The denominator
contains 18 `proven` rows, 4 `repaired` rows, and 7 `open` rows.

The status in `source_status` describes the bounded source relation. Runtime
and silicon status remain separate fields. A source proof cannot promote a
runtime or silicon row. The external repository, commit, artifact, and row
fields identify the exact authority for facts that Linux does not own.

`scripts/check_radeon_gart_lifecycle.py` enforces the complete row set, field
schema, exact dependencies, acyclic graph, external authority identities, and
the source relations named by the ledger. Its selftest must reject known bad
source and policy mutations before a tree result has authority.

## Mechanism ownership

* Build and callback reachability owns
  `GART_SOURCE_BUILD_REACHABILITY` and
  `RS400_ASIC_GART_CALLBACK_SELECTION`. Kbuild links each owner once.
  `radeon_asic_init` selects `rs400_asic` for RS400 and RS480, and that table
  supplies the GART callbacks. This is source reachability, not live callback
  execution.
* Aperture and page table allocation owns `GTT_APERTURE_SIZE_DERIVATION`,
  `GART_TABLE_DMA_COHERENT_ALLOCATION_API`, and
  `RS4XX_GART_TABLE_UC_ALIAS_ATTEMPT`. `radeon_gart_init` derives both page
  counts from the event specific `mc.gtt_size`. `radeon_gart_table_ram_alloc`
  owns the coherent DMA allocation and the unchecked x86 UC alias attempt.
  The allocation API and call order do not establish an effective CPU page
  type or payload coherence.
* Buffer object and TTM cache selection owns
  `NON_PCIE_GTT_ATTRIBUTE_NORMALIZATION`, `TTM_DEFAULT_CACHED_SELECTION`,
  `USERPTR_TT_EXTERNAL_POPULATION`, `USERPTR_PIN_DMA_MAP_TRANSACTION`, and
  `CACHED_TTM_SNOOP_FLAG_PROPAGATION`. `radeon_bo_create` removes userspace GTT
  UC and WC requests on non PCIe devices. TTM selects `ttm_cached`. Ordinary
  and userptr translation tables remain distinct ownership paths. A cached
  bind requests `RADEON_GART_PAGE_SNOOP`, but Linux does not own the effective
  RS482 result.
* PTE admission and publication owns `GART_BIND_RANGE_ADMISSION`,
  `RS400_PTE_PERMISSION_AND_SNOOP_ENCODING`,
  `RS480_GLOBAL_REQUEST_SNOOP_DISABLE`, and
  `GART_BIND_PTE_MB_TLB_PUBLICATION`. Linux validates the mapping interval,
  encodes permission and snoop request bits, stores shadows and table entries,
  executes `mb()`, and dispatches the ASIC TLB callback. The global mode
  retains `RS480_REQ_TYPE_SNOOP_DIS`. Source order does not establish global
  and per PTE precedence, payload visibility, or completed invalidation.
* Unbind and sparse teardown owns `GART_UNBIND_RANGE_ADMISSION`,
  `GART_UNBIND_SPARSE_CURSOR`, and `GART_UNBIND_PTE_MB_TLB_PUBLICATION`.
  Linux validates the interval, derives every GPU PTE cursor from its CPU page
  index, writes dummy entries for populated pages, executes `mb()`, and
  dispatches the TLB callback. A returned void call does not report whether
  invalidation completed.
* CPU access and bounded observation owns `KERNEL_BO_MAP_RESERVATION_WAIT`,
  `USER_MMAP_FAULT_RESERVATION`, and `GART_TABLE_READER_SNAPSHOT_BOUNDARY`.
  Kernel mapping waits kernel reservation users. The userspace fault path
  reserves the BO before placement inspection. The debug reader protects
  table lifetime against finalization, but ordinary bind and unbind writers do
  not share its lock. These relations order software access and lifetime; they
  do not perform payload cache maintenance.
* Common release owns `RS4XX_GART_TABLE_WB_RESTORE_ATTEMPT` and
  `GART_COMMON_TEARDOWN`. Common GART finalization unbinds the ready aperture
  before releasing shadows and the dummy page. The RS4xx table release
  attempts WB restoration before coherent DMA release and ignores the page
  attribute result. Common GART and RS400 table release are separate owners.
* Target semantics owns `EFFECTIVE_PER_PTE_SNOOP_SEMANTICS`,
  `CPU_GTT_GPU_PAYLOAD_PUBLICATION`, and
  `GPU_GTT_CPU_PAYLOAD_INVALIDATION`. Steinmarder owns exact target silicon and
  payload verdicts. Linux records the source controls and order that an
  admitted trial must retain. No source checker can close these rows.
* Unresolved Linux lifecycle owns `RS400_TLB_FLUSH_COMPLETION`,
  `GART_SUSPEND_READY_STATE`, `GART_BACKEND_NOT_READY_UNBIND_STATE`, and
  `GART_TTM_TEARDOWN_OWNERSHIP`. Linux owns the missing result and state
  contracts. These rows remain open until source accounts for every local
  disposition and the checker calibrates the completed mechanism.

The Vostro repository supplies event scoped aperture and page table
observations. Steinmarder supplies RS482 silicon and payload authority. Their
full commit identities and row names live in the policy ledger so an adjacent
repository cannot silently replace the evidence bound by this contract.

## Lifecycle sequence

The bounded source path has these ownership transfers:

1. BO creation normalizes non PCIe GTT cache flags.
2. TTM selects a cache mode and creates the translation table.
3. Userptr population allocates only its external SG table container.
4. Backend bind pins userptr pages when applicable, creates and maps SG
   entries, extracts DMA addresses, requests PTE flags, and binds the range.
5. GART bind updates software shadows and the mapped page table before its
   barrier and TLB callback.
6. Kernel maps and userspace faults use reservation ordering around CPU
   access. This ordering is not a cache visibility operation.
7. Backend unbind removes PTEs before it releases userptr DMA and page
   ownership.
8. Common finalization unbinds the ready aperture before it releases common
   shadows. RS400 finalization later releases the page table allocation.

Every step names a source relation. None of the steps asserts that CPU cache
lines reached the GPU, that GPU writes reached the CPU, or that RS482 honored
the requested per PTE snoop state.

## Repaired source defects

The four `repaired` rows preserve the defects and the replacement mechanisms
as distinct evidence:

* `USERPTR_PIN_DMA_MAP_TRANSACTION` makes the ownership prefix transactional.
  A zero progress page pin now fails. The backend propagates pin failures. SG
  entries use `sg_free_table` after DMA map failure, and the SG container is
  cleared so later teardown cannot treat released entries as mapped. A
  completed pin rolls back after GART bind failure. Unbind removes PTEs before
  DMA unmap and page release, then clears the released SG ownership state.
* `GART_BIND_RANGE_ADMISSION` rejects a zero page count, a misaligned offset, a
  null DMA address array, and any interval outside `num_cpu_pages` before an
  array or page table access.
* `GART_UNBIND_RANGE_ADMISSION` applies the same nonzero, alignment, overflow,
  and containment contract before teardown changes any entry.
* `GART_UNBIND_SPARSE_CURSOR` derives the GPU PTE cursor on every outer CPU page
  iteration. A sparse hole cannot shift a later dummy write into an earlier
  PTE range.

These repairs close source defects only. They do not make userptr a preferred
Mesa sharing ABI, establish payload visibility, or prove a live TLB outcome.

## Open boundaries and completion evidence

* `EFFECTIVE_PER_PTE_SNOOP_SEMANTICS` belongs to Steinmarder. Linux requests
  per PTE snoop while global request snoop disable remains set. Source does not
  define effective precedence. One admitted exact target trial must retain
  both controls, the same BO, completed submission, and exact PTE bytes.
* `CPU_GTT_GPU_PAYLOAD_PUBLICATION` belongs to Steinmarder. The mapped submit
  path has no CPU payload cache maintenance or target digest observation. A
  CPU producer and GPU consumer trial must retain the cache action, PTE state,
  submission, completed fence, and both digests.
* `GPU_GTT_CPU_PAYLOAD_INVALIDATION` belongs to Steinmarder. Fence retirement
  and GART unbind do not invalidate CPU payload cache lines. A GPU producer and
  CPU consumer trial must retain the completed fence, cache action, PTE state,
  and both digests.
* `RS400_TLB_FLUSH_COMPLETION` belongs to Linux. The callback issues
  invalidation and polls, but its void signature discards timeout disposition.
  A result channel and calibrated success and timeout paths must account for
  every caller.
* `GART_SUSPEND_READY_STATE` belongs to Linux. Suspend disables hardware while
  `gart.ready` continues to represent allocated state. Separate allocated and
  enabled state, or an executable quiescence invariant, must prevent live bind
  and unbind ambiguity.
* `GART_BACKEND_NOT_READY_UNBIND_STATE` belongs to Linux. Common unbind can
  return for not ready while the backend clears `bound` without a disposition
  result. A result and state contract must distinguish global teardown from a
  live mismatch.
* `GART_TTM_TEARDOWN_OWNERSHIP` belongs to Linux. RS400 and TTM finalization
  both invoke common GART finalization across separate object and table owners.
  One owner or an executable ordering invariant must account for every object,
  callback, table, and common allocation.

The global snoop enable mutation remains excluded. The retained negative sits
in Steinmarder and does not authorize another live mutation from this source
repository. K8 F3x40 AtomicRMW reporting state is also not a cache coherence
enable and does not close a ledger row.

## Build priorities

1. Admit the repaired source only after the lifecycle checker classifies its
   good tree and all known bad fixtures, then link `radeon.ko` with zero
   warnings against both declared kernel roots. Production and relevant
   development profiles remain load bearing.
2. Close Linux owned open rows in dependency order. A TLB completion result, a
   hardware enabled state, a backend unbind disposition, and consolidated
   teardown ownership each require one final safe mechanism and calibrated
   negative fixtures.
3. Run exact target snoop and payload trials only in Steinmarder after the
   Linux source and build identities are pinned. The trial must preserve raw
   controls, cache actions, producer and consumer digests, submission, and
   fence evidence.
4. Keep Mesa zero copy and reduced cache synchronization paths blocked until
   both payload directions close for the exact mapping state they use.

## Checks

Run the calibrated finite contract before a module build:

```sh
python3 scripts/check_radeon_gart_lifecycle.py --selftest
python3 scripts/check_radeon_gart_lifecycle.py
```

The lifecycle checker invokes the cache policy checker as a required
subcontract. Direct runs remain useful when a cache relation fails:

```sh
python3 scripts/check_rs4xx_gart_cache_policy.py --selftest
python3 scripts/check_rs4xx_gart_cache_policy.py
```

Then run the module build harness against both declared kernel roots as
documented in `README.md`. A green checker and two green builds establish a
bounded source and compile result only. They do not establish runtime
reachability, silicon coherence, performance, or hazard clearance.
