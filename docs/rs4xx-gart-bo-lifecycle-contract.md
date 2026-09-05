# RS4xx GART and buffer object lifecycle contract

## Scope and authority

`policy/rs4xx-gart-memory-path.tsv` is the canonical finite ledger for the
Linux Radeon GART, TTM, buffer object, CPU mapping, and teardown path. Its 35
rows use one 19 field schema and one acyclic dependency graph. The denominator
contains 15 `proven` rows, 17 `repaired` rows, and 3 `open` rows.

The status in `source_status` describes the bounded source relation. Runtime
and silicon status remain separate fields. A source proof cannot promote a
runtime or silicon row. The external repository, commit, artifact, and row
fields identify the exact authority for facts that Linux does not own.

`scripts/check_radeon_gart_lifecycle.py` enforces the complete row set, causal
row order, field schema, exact dependencies, acyclic graph, every external
authority identity, every nonclaim, and a length-framed exact identity for all
18 fields after each `row_id`. Field-specific semantic checks run before the
full-row identity check so rebound mutants must fail for their declared reason.
The three repaired range admission guards use exact tokenized `if`
conditions, fixed direct function-body statement indexes, and a length-framed
token digest of every direct statement from function entry through the guarded
successor. The rejection remains the final top-level statement in each exact
guard body. Common finalization separately requires the exact adjacent direct
sequence from common GART finalization through hardware disable and table
release. The selftest rejects disabled, negated, comment-shadowed, inactive
preprocessor, outer-controlled, nested-action, early-return, declaration-level
statement-expression, teardown-order, and policy mutations. Each policy mutant
is rebound to its own test digest and must fail with its declared semantic error
before a tree result has authority.

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
  reserves the BO before transaction admission and placement inspection. The
  debug reader holds hardware transaction admission and `gart.lock` across its
  metadata and PTE snapshot. Bind, unbind, and finalization writers use the
  same lock. These relations order software access and lifetime; they do not
  perform payload cache maintenance.
* Common release owns `GART_COMMON_TEARDOWN` and
  `RS4XX_GART_TABLE_WB_RESTORE_ATTEMPT`. Common GART finalization unbinds the
  ready aperture before releasing shadows and the dummy page. RS400
  finalization then disables GART hardware. Table release then attempts WB
  restoration before coherent DMA release and ignores the page attribute
  result. Common GART and RS400 table release are separate owners.
* Target semantics owns `EFFECTIVE_PER_PTE_SNOOP_SEMANTICS`,
  `CPU_GTT_GPU_PAYLOAD_PUBLICATION`, and
  `GPU_GTT_CPU_PAYLOAD_INVALIDATION`. Steinmarder owns exact target silicon and
  payload verdicts. Both directional rows depend on the bound translation, not
  on a snoop verdict. Linux records the source controls and order that an
  admitted trial must retain. No source checker can close these rows or
  attribute a directional result to snooping.
* Terminal lifecycle owns `GART_SUSPEND_READY_STATE`,
  `GART_BACKEND_NOT_READY_UNBIND_STATE`, `GART_TTM_TEARDOWN_OWNERSHIP`,
  `RS4XX_GART_COMPLETION_RELEASE`, `TTM_BO_MOVE_BIND_ROLLBACK`,
  `RS4XX_BO_LIFETIME_ACCOUNTING`, `RS4XX_BO_TRANSACTION_ROOTS`, and
  `RS4XX_TTM_FINI_LIVE_DENOMINATOR`. These repaired rows distinguish allocated
  GART storage from enabled hardware, propagate common teardown refusal,
  retain complete BO, table, and page ownership, roll back a move-installed
  binding, and veto final TTM destruction while any counted owner remains.
* `RS400_TLB_FLUSH_COMPLETION` is repaired in source. `rs400_gart_tlb_invalidate`
  returns the poll disposition, the void ASIC callback counts a timeout in
  `rs4xx_gart_tlb_flush_timeouts` and warns once, and `rs400_gart_enable`
  refuses to publish `gart.ready` after a timed-out invalidation. Every
  remaining open row is target-owned.

The Vostro repository supplies event scoped aperture and page table
observations. Steinmarder supplies RS482 silicon and payload authority. Their
full commit identities and row names live in the policy ledger so an adjacent
repository cannot silently replace the evidence bound by this contract.

## Fault-injection contract

`rs400_gart_tlb_invalidate` consumes `rdev->rs4xx_gart_tlb_fault_inject` with
`atomic_xchg` as its first statement, so an armed one-shot returns `-ETIMEDOUT`
before `radeon_rs4xx_hardware_access_begin` opens a hardware transaction. The
injected call writes no memory-controller register, holds no admission, and
clears the arm in the operation that reads it, so exactly one invalidation
carries the injected disposition and the next call reaches hardware.

Every consequence below the injected call is the disposition the poll would
have produced. `rs400_gart_tlb_flush` increments
`rs4xx_gart_tlb_flush_timeouts` and warns once; an enable-time invalidation
clears `RS480_AGP_ADDRESS_SPACE_SIZE`, leaves `gart.ready` false, and returns
`-ETIMEDOUT`, so `radeon_gart_bind_locked` and `radeon_gart_unbind_locked`
refuse with `-EINVAL` until an enable publishes the aperture again.

The mutate profile arms the one-shot through the write-only debugfs node
`radeon_rs400_gart_tlb_fault_inject`, which accepts the exact value 1 and
returns `-EINVAL` for every other value and `-ENODEV` off `CHIP_RS400` and
`CHIP_RS480`. The observe profile reads the counter, the arm, and `gart.ready`
through `radeon_rs400_gart_tlb_disposition`, which serves driver memory and
therefore answers while the device is parked.
`scripts/run_rs400_gart_tlb_fault_injection.sh` drives the arm on the target
through a GTT-domain GEM allocation, whose bind calls the ASIC `tlb_flush`
callback recorded by `GART_BIND_PTE_MB_TLB_PUBLICATION`.

## Lifecycle sequence

The bounded source path has these ownership transfers:

1. BO creation normalizes non PCIe GTT cache flags.
2. BO creation rejects an imported SG table on the AGP backend before
   allocation and TTM construction.
3. TTM selects a cache mode and creates the backend-specific translation
   table.
4. Userptr population allocates only its external SG table container.
5. Backend bind pins userptr pages when applicable, creates and maps SG
   entries, extracts DMA addresses, requests PTE flags, and binds the range.
6. GART bind updates software shadows and the mapped page table before its
   barrier and TLB callback.
7. Kernel maps and userspace faults use reservation ordering around CPU
   access. This ordering is not a cache visibility operation.
8. Backend unbind removes PTEs before it releases userptr DMA and page
   ownership.
9. Common finalization unbinds the ready aperture before it releases common
   shadows. RS400 finalization then disables GART hardware and releases the
   page table allocation through the WB restore attempt.
10. A terminal unbind refusal retains the complete BO, its translation table,
    and pages that leave generic TTM accounting before generic cleanup releases
    the resource range or clears the translation-table pointer.

Every step names a source relation. None of the steps asserts that CPU cache
lines reached the GPU, that GPU writes reached the CPU, or that RS482 honored
the requested per PTE snoop state.

## Repaired source defects

The 17 `repaired` rows preserve the defects and replacement mechanisms as
distinct evidence:

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
* `USER_MMAP_FAULT_RESERVATION` reserves the BO before transaction admission,
  placement changes, and CPU aperture PTE installation.
* `GART_TABLE_READER_SNAPSHOT_BOUNDARY` holds hardware admission and
  `gart.lock` across metadata and every PTE read.
* `GART_COMMON_TEARDOWN`, `RS4XX_GART_TEARDOWN_ERROR_PROPAGATION`,
  `GART_SUSPEND_READY_STATE`, `GART_BACKEND_NOT_READY_UNBIND_STATE`, and
  `RS4XX_GART_COMPLETION_RELEASE` preserve exact common-teardown disposition,
  separate allocated from enabled state, and publish completion only after
  aperture disable and coherent table release.
* `GART_TTM_TEARDOWN_OWNERSHIP` transfers complete BO, translation-table, and
  retained-page ownership before the void callbacks return. The retained and
  detached GEM debugfs classifications precede resource dereference.
* `TTM_BO_MOVE_BIND_ROLLBACK` removes any binding installed by a failed move.
  `RS4XX_BO_LIFETIME_ACCOUNTING` and `RS4XX_BO_TRANSACTION_ROOTS` keep each BO
  counted and admitted through true final destruction.
* `RS4XX_TTM_FINI_LIVE_DENOMINATOR` vetoes range-manager and TTM destruction
  for a live BO, retained BO, retained table, retained accounted page,
  transaction, or reader.

These repairs close source defects only. They do not make userptr a preferred
Mesa sharing ABI, establish payload visibility, or prove a live TLB outcome.

## Open boundaries and completion evidence

* `EFFECTIVE_PER_PTE_SNOOP_SEMANTICS` belongs to Steinmarder. Linux requests
  per PTE snoop while global request snoop disable remains set. Source does not
  define effective precedence. One admitted exact target trial must retain
  both controls, the same BO, completed submission, and exact PTE bytes.
* `CPU_GTT_GPU_PAYLOAD_PUBLICATION` belongs to Steinmarder. The mapped submit
  path has no CPU payload cache maintenance or target digest observation. A
  CPU producer and GPU consumer trial keeps the same BO bound and retains raw
  PTE bytes and decoded bits, raw global snoop control, BO and cache mapping,
  module and target identity, command stream, an observed completed fence,
  maintenance-on and maintenance-off arms, and both digests.
* `GPU_GTT_CPU_PAYLOAD_INVALIDATION` belongs to Steinmarder. Linux establishes
  the bound translation but performs no CPU payload invalidation after GPU
  completion. A GPU producer and CPU consumer trial observes a completed fence
  before the CPU cache action and digest while the same BO remains bound. It
  retains the same raw controls, identities, command stream, maintenance arms,
  and both digests as the CPU-to-GPU direction.

Each directional trial can close visibility only for its exact retained state.
It cannot establish that snooping caused the result or generalize cache
coherence to another mapping state. Maintenance off failing while maintenance
on passes supports maintenance-required visibility only for that exact state.
Both arms passing supports only that no maintenance effect was observed in the
tested trials. Both arms failing leaves visibility open.

* `RS400_TLB_FLUSH_COMPLETION` belongs to Linux and carries its result
  channel: the invalidation returns 0, `-ETIMEDOUT`, or `-EBUSY`, GART enable
  consumes it before ready publication, and the bind and unbind flushes count
  it. The runtime status stays `not-run` until a target trial observes the
  counter and the enable refusal on a forced timeout.

The global snoop enable mutation remains excluded. The retained negative sits
in Steinmarder and does not authorize another live mutation from this source
repository. K8 F3x40 AtomicRMW reporting state is also not a cache coherence
enable and does not close a ledger row.

## Failed reset terminal retention

The RS4xx admission state assigns every delayed translation-table destructor
one stable disposition. A destructor waits while reset, suspend, or resume owns
the hardware transition. A running result admits the GART unbind. A parked or
shutdown result retains the binding, translation table, backing pages, buffer
object, TTM device, DRM device, PCI parent, and module until reboot. Shutdown
returns its disposition immediately because `ttm_device_fini` can wait for the
same delayed destructor.

The GEM destructor enters a wait-capable hardware transaction before TTM
finalization. Reset closes transaction admission and drains admitted
destructors before it publishes `RESETTING`. The lower GART unbind uses a
wait-capable reader when no transaction already owns the complete move or
destruction. A reader enclosing the wait-capable unbind creates a cycle: reset
can wait for the outer reader while the unbind waits for reset. The transaction
root removes the cycle and preserves one stable disposition
for the complete buffer object.

Linux v7.1 `ttm_tt_unpopulate` invokes the driver
`ttm_tt_unpopulate` callback through a `void` interface, then clears populated
state and releases global accounting. `ttm_bo_tt_destroy` invokes the driver
destroy callback, then clears the buffer object's translation-table pointer.
The Radeon callback therefore has no result channel that preserves an RS4xx
GART unbind refusal in TTM core state. The terminal callback transfers the
complete Radeon BO and its bound translation table into per-device retention
before returning. It also transfers every page that leaves generic TTM
allocation accounting into an exact retained-page denominator. The later
driver BO destructor observes the retained flag and leaves the BO allocated.
The retained TTM device keeps the associated workqueue and callback code alive.

Generic TTM cleanup can release the resource-manager range and clear
`rbo->tbo.resource` after that transfer. Hardware admission remains closed, so
no later BO allocation, movement, or binding can reuse the released range on
the terminal device. The GEM debugfs reader reports `RETAINED` before resource
inspection and reports `DETACHED` for a nonretained BO without a resource.

The terminal retention is a host-safety result and a resource-lifetime
boundary. It establishes that teardown issues no RS4xx GART write or TLB flush
after failed reset. It preserves complete Radeon ownership and accounts for
pages that generic TTM no longer counts. It does not reclaim memory before
reboot, restore the device, or add a result channel to the generic callback ABI.

## Build priorities

The retained declared build identities remain `6.18.38-2-cachyos-lts` and
`7.1.4-1-cachyos`. At source commit
`df6f5cf10024ee20cc5db66e5c891f9207f24f7a`, the exact-root matrix passed
`prod`, `observe-dev`, `probe-dev`, and `mutate-dev` with zero warnings on both
roots. The 6.18 root used the signed Clang and LLD 22.1.6 package set; the 7.1
root used the signed 22.1.8 set. Their exact package and signature identities
live in `ci/kernel-toolchains/`. The built Radeon driver tree was
`bc05af9ebe11efd046b99359fd063f38a6b1e2ce`. The result proves bounded source
reachability, link, metadata, and profile projection, not module loading,
runtime reachability, or silicon behavior.

1. Preserve the lifecycle checker's known-good and known-bad calibration and
   the eight-lane exact-root, exact-toolchain, zero-warning build matrix on
   every change to the repaired source or its build contract.
2. Move `RS400_TLB_FLUSH_COMPLETION` from `repaired` to a runtime verdict only
   through a target trial that forces the timeout path and observes the
   counter and the enable refusal.
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

The lifecycle checker admits 35 rows with 15 proven, 16 repaired, and 4 open
statuses. Its selftest rejects 144 known-bad source, ownership, authority,
dependency, and evidence mutations.

Then run the module build harness against both exact declared kernel roots as
documented in `README.md`. The matrix recorded for driver tree
`bc05af9ebe11efd046b99359fd063f38a6b1e2ce` satisfies this gate. A driver or
build-contract change requires a new exact-root matrix. A green checker and
exact-root profile matrix establish a bounded source and compile result only.
They do not establish runtime reachability, silicon coherence, performance, or
hazard clearance.
