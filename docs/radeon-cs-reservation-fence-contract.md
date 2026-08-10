# Radeon command submission, reservation, and fence contract

## Scope and authority

`policy/radeon-cs-reservation-fence-contract.tsv` is the canonical finite
ledger for Radeon command submission admission, BO reservation, dependency
import, IB scheduling, fence command emission, and reservation fence
publication. Its 14 rows use the same 19 field schema as the GART lifecycle
ledger. The denominator contains 7 `proven` rows, 3 `repaired` rows, and 4
`open` rows.

The source ledger proves software ownership and order. It does not infer fence
completion from fence publication, payload coherence from reservation order,
or executed cache control from emitted ring dwords. Steinmarder owns future
exact RS482 replay work and retained payload evidence.

`scripts/check_radeon_cs_reservation_fence_contract.py` enforces the complete
row set, causal row order, exact dependency graph, callback bindings, parked
refusal, relocation geometry, BO reservation order, dependency import, ring
schedule, r300 fence command order, reservation fence publication, every
external identity, every nonclaim, every bounded source path and symbol, and a
length-framed exact identity for all 18 fields after each `row_id`.
Field-specific semantic checks run before the full-row identity check so
rebound mutants must fail for their declared reason.
The four guarded relations that carry the two repaired admission rows use exact
tokenized `if` conditions,
fixed direct function-body statement indexes, and a length-framed token digest
of every direct statement from function entry through the guarded successor.
The rejection remains the final top-level statement in each exact guard body.
The selftest rejects disabled, negated, outer-controlled, nested,
later-overridden, jump-bypassed, declaration-level statement-expression, and
policy mutations. It also rejects a hardware transaction root that bypasses
admission or release, parser cleanup that ends the transaction before
`drm_exec_fini`, relocation reference release that precedes transaction end,
ring scheduling that omits either rollback, dependency waits that swallow an
error, reservation preparation that ignores an error, and failed-reset
publication that reaches direct hardware access. The final CS cleanup suffix
and the reservation-release function carry exact tokenized control flow, so a
retained token behind a `goto` cannot satisfy the checker. Each policy mutant
is rebound to its own test digest and must fail with its declared semantic
error before the tree result has authority.

## Mechanism ownership

* ASIC and ring callback ownership uses
  `RS482_ASIC_COMMAND_CALLBACK_BINDING`. RS400 and RS480 select `rs400_asic`.
  Its graphics ring reaches `r100_ring_ib_execute`, `r300_fence_ring_emit`,
  and `r300_cs_parse`. This proves source binding, not live callback execution.
* Parked admission uses `CS_PARKED_EARLY_REFUSAL`. `radeon_cs_ioctl` enters
  `radeon_device_lock_hardware`, which increments and revalidates the RS4xx
  transaction admission count before the helper takes the shared
  `exclusive_lock` reader. The ioctl returns `EIO` on `gpu_parked` before
  parser, relocation, or ring work. Reset uses the writer side. Current target
  execution is not run, and the row binds no external authority. Steinmarder
  commit `baa6b2d496c52392c0ecb5e18306db02e9dfd6cf` retains the older 0.6
  parked-entry directory bundle as historical adjacent context only. That
  bundle observed the separate `!accel_working` refusal with `EBUSY`, not the
  current direct `gpu_parked` refusal with `EIO`.
* Pre-BO topology uses `CS_RELOCATION_RECORD_GEOMETRY`. Parser admission rejects
  relocation metadata without an IB, requires complete four dword records, and
  validates every relocation index before BO lookup or reservation.
* BO ownership uses `CS_BO_RESERVATION_LOCKS`. Every command submission keeps
  the hardware transaction active through parser initialization, relocation
  parsing, ring scheduling, and `drm_exec_fini`. Every relocation holds its GEM
  reference, enters the validation list, and reaches `drm_exec_prepare_obj`
  before TTM validation and GPU offset capture. The transaction ends before
  `radeon_cs_parser_release_storage` drops the final parser relocation
  references. Reservation ownership protects placement and metadata; it does
  not maintain payload caches.
* Prior dependency import uses `CS_RESERVATION_DEPENDENCY_IMPORT`. Same device
  Radeon fences become per ring dependencies. Foreign or different device
  fences receive a CPU wait. Any error aborts target ring scheduling while BO
  reservations remain held.
* IB scheduling uses `CS_RING_DEPENDENCY_AND_IB_SCHEDULE`. The scheduler locks
  the ring, resolves ring dependencies, dispatches the IB, emits its fence, and
  commits the ring. A successful return reports committed work and a completion
  token, not completed work.
* Post-schedule completion state uses `CS_SUCCESS_FENCE_INVARIANT`. After both
  scheduling calls return success, validated BOs require `parser.ib.fence`
  before cleanup. The current scheduler cannot return success before assigning
  the fence because fence emission precedes commit and every earlier error
  exits. The guard remains a last-ditch invariant assertion and null-dereference
  barrier. It is not rollback for a future broken scheduler that commits work
  without a fence.
* r300 fence command ownership uses `R300_FENCE_COMMAND_SEQUENCE`. The bound
  emitter writes 3D and Z cache flush commands, an idle and clean wait, HDP
  read buffer invalidation, the scratch sequence, and the software interrupt
  before ring commit. The void emitter has no local execution result.
* Reservation fence publication uses `CS_RESERVATION_FENCE_PUBLICATION`.
  Successful cleanup adds the IB fence with READ or WRITE usage before
  `drm_exec_fini` releases reservations. `radeon_cs_ioctl` ends the hardware
  transaction only after this cleanup returns, then releases parser relocation
  references. Error cleanup adds no new fence. Publication orders later users
  but does not report completion or payload visibility.
* Linux trust and waiter ownership uses `CS_RELOCATION_ACCESS_DIRECTION` and
  `CS_SUSPEND_FENCE_LOCK_CONTEXT`. Linux owns the missing packet role
  validation and suspend lock proof. Each row stays open until source and
  calibrated fixtures account for its full local contract.
* Failed-reset waiter ownership uses `FENCE_FORCE_COMPLETION_PUBLICATION`.
  `radeon_rs4xx_publish_parked_state` latches `gpu_parked` before it calls
  `radeon_fence_driver_force_completion_parked`. The helper cancels delayed
  lockup work, takes `fence_queue.lock`, clears delayed IRQ demand, wakes the
  queue, and leaves `last_seq` unchanged. Awakened terminal fence paths publish
  `-EIO` or `-ESHUTDOWN` before signaling and perform no MMIO. Queue wake
  callbacks release logical fence IRQ references.
  Retained page-flip completion releases logical page-flip IRQ references.
  `radeon_irq_hardware_update_allowed` requires an installed IRQ path with
  neither reset nor parking active before either release path calls
  `radeon_irq_set`. This is a repaired source contract; runtime and silicon
  status remain unproved.
* RS482 execution and payload semantics uses
  `RS482_RESET_RING_REPLAY_SEMANTICS` and
  `RS482_CACHED_GTT_PAYLOAD_VISIBILITY`. No exact reset-replay owner artifact is
  materialized, so the reset row carries no external authority. Steinmarder
  owns future exact target replay count and current payload evidence. Linux
  supplies source order and the commit identity that an admitted trial must
  bind. Successful ring replay and failed-reset force completion are sibling
  outcomes in `radeon_gpu_reset_internal`; the public `radeon_gpu_reset`
  entry delegates to that serialized implementation. Neither outcome is a
  prerequisite for the other.

## Submission sequence

The successful source path has these ordered ownership steps:

1. `radeon_cs_ioctl` admits one hardware transaction, acquires the shared
   exclusion, and refuses a parked device.
2. Parser initialization discovers chunk topology and rejects relocation data
   without an IB.
3. Relocation parsing validates record geometry, acquires GEM references, and
   builds the BO validation list.
4. `drm_exec` locks each BO reservation before TTM placement validation and GPU
   offset capture.
5. Reservation fences become local ring dependencies or complete through a
   CPU wait for a foreign owner.
6. `radeon_ib_schedule` locks the target ring, resolves dependencies, dispatches
   the IB, emits its fence, and commits the ring.
7. The r300 fence callback emits cache and idle commands, a sequence store, and
   an interrupt request into that pending ring stream.
8. The post-schedule invariant requires a fence for every validated BO before
   cleanup can enter successful publication.
9. Successful parser cleanup attaches the IB fence to each BO reservation with
   the declared access usage, calls `drm_exec_fini`, and returns while the
   hardware transaction remains active.
10. `radeon_cs_ioctl` ends the hardware transaction, then releases parser
    relocation references and storage.

This path provides execution dependency and lifetime order. It carries no CPU
payload cache action and no exact target digest. The emitted r300 sequence is
not evidence that RS482 executed the commands or that either payload direction
became coherent.

## Repaired source defects

The three `repaired` rows retain the original unsafe shapes and their replacement
contracts:

* `CS_RELOCATION_RECORD_GEOMETRY` rejects a relocation chunk when no IB chunk
  is present and requires the chunk length to be divisible by four. Every
  packet relocation index must be four dword aligned, remain inside the chunk,
  and leave one complete record before `p->relocs` or `kdata` access. Invalid
  topology returns `EINVAL` before BO reservation.
* `CS_SUCCESS_FENCE_INVARIANT` rejects a post-schedule success path that has
  validated BOs but no `parser.ib.fence`. This prevents cleanup from
  dereferencing and publishing a null completion token. It cannot cancel or
  make safe work that a future broken scheduler already committed without a
  fence.
* `FENCE_FORCE_COMPLETION_PUBLICATION` repairs the failed-reset path for
  RS400 and RS480. The parked-state publisher sets `gpu_parked` before it
  cancels lockup work and calls the CPU-only helper. The helper publishes each
  initialized ring sequence under `fence_queue.lock` and wakes the queue. It
  performs no register access after the terminal park. Fence and retained
  page-flip completion may release logical IRQ references, while the shared
  IRQ hardware predicate prevents an interrupt register update during reset
  and after parking.

The repairs do not validate the truth of a userspace access domain declaration
and do not prove that an emitted fence completed.

## Open boundaries and completion evidence

* `CS_RELOCATION_ACCESS_DIRECTION` belongs to Linux. READ or WRITE reservation
  usage derives from userspace `write_domain`. The bounded r300 parser does not
  bind every supported packet write site to that declaration. A finite packet
  resource role map and negative command stream corpus must cover every
  supported write site and reject an inaccurate domain.
* `FENCE_FORCE_COMPLETION_PUBLICATION` is source-repaired in Linux. Failed
  reset latches `gpu_parked` before CPU-only sequence publication. The helper
  advances `last_seq` under `fence_queue.lock`, wakes the queue, cancels
  delayed lockup work, and performs no MMIO. Logical fence and page-flip IRQ
  release remains CPU-side because the hardware update predicate rejects both
  reset and parked state. Runtime and silicon completion remain unproved. This
  failed-reset branch is not a causal prerequisite for successful ring replay.
* `RS482_RESET_RING_REPLAY_SEMANTICS` belongs to Steinmarder. Successful reset
  can recommit backed up ring dwords after partial execution. Source does not
  establish exactly once payload effects. No exact retained artifact owns this
  question. An admitted marker and fence harness must materialize an owner that
  distinguishes not executed, executed once, and repeated effects on RS482.
  This successful-reset branch does not traverse failed-reset force completion.
* `CS_SUSPEND_FENCE_LOCK_CONTEXT` belongs to Linux. `radeon_fence_wait_empty`
  documents a ring lock requirement, while the bounded suspend caller has no
  adjacent lock proof. A complete caller exclusion proof or a repaired lock
  invariant must close the local precondition.
* `RS482_CACHED_GTT_PAYLOAD_VISIBILITY` belongs to Steinmarder. Reservations,
  fences, barriers, and emitted GPU cache commands contain no CPU payload
  cache maintenance or target digest observation. Both exact target directions
  retain raw PTE bytes and decoded bits, raw global snoop control, BO and cache
  mapping, module and target identity, command stream, an observed completed
  fence, maintenance-on and maintenance-off arms, and producer and consumer
  digests. Maintenance off failing while maintenance on passes supports
  maintenance-required visibility only for the exact state. Both arms passing
  supports only that no maintenance effect was observed in the tested trials.
  Both arms failing leaves visibility open.

`RS482_CACHED_GTT_PAYLOAD_VISIBILITY` depends on both the r300 fence command
sequence and reservation fence publication. It also joins the directional
payload rows in `policy/rs4xx-gart-memory-path.tsv`. Neither ledger may promote
the shared target question from the other ledger's source status.

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

1. Preserve the CS and parked guard known-good and known-bad calibration and
   the eight-lane exact-root, exact-toolchain, zero-warning build matrix on
   every change to the repaired source or its build contract.
2. Build the finite packet resource role map before changing reservation usage.
   The corpus must cover every supported r300 write site and include negative
   domain declarations that compile but fail admission.
3. Keep failed reset waiter publication bounded to the source contract until
   target evidence observes fence completion. The mechanism accounts for
   generic fence sequence state, the wait queue, delayed work, and parked MMIO
   refusal together.
4. Close the suspend caller proof or repair its lock invariant as one source
   mechanism. Do not infer the missing exclusion from a comment.
5. Run reset replay and cached payload oracles only in Steinmarder against a
   pinned Linux commit. Keep Mesa exactly once, zero copy, and reduced cache
   synchronization assumptions blocked until those target rows close.

## Checks

Run the calibrated CS contract and parked refusal gates before a module build:

```sh
python3 scripts/check_radeon_cs_reservation_fence_contract.py --selftest
python3 scripts/check_radeon_cs_reservation_fence_contract.py
python3 scripts/check_parked_admission_guards.py --selftest
python3 scripts/check_parked_admission_guards.py
```

Run the GART lifecycle checker when a change affects cached GTT payload
language or the shared target rows:

```sh
python3 scripts/check_radeon_gart_lifecycle.py --selftest
python3 scripts/check_radeon_gart_lifecycle.py
```

Then run the module build harness against both exact declared kernel roots as
documented in `README.md`. The matrix recorded for driver tree
`bc05af9ebe11efd046b99359fd063f38a6b1e2ce` satisfies this gate. A driver or
build-contract change requires a new exact-root matrix. These checks prove a
bounded source and compile contract only. They do not prove live submission,
reset replay count, fence completion, payload visibility, performance, or
hazard clearance.
