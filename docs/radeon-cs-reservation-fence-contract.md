# Radeon command submission, reservation, and fence contract

## Scope and authority

`policy/radeon-cs-reservation-fence-contract.tsv` is the canonical finite
ledger for Radeon command submission admission, BO reservation, dependency
import, IB scheduling, fence command emission, and reservation fence
publication. Its 14 rows use the same 19 field schema as the GART lifecycle
ledger. The denominator contains 7 `proven` rows, 2 `repaired` rows, and 5
`open` rows.

The source ledger proves software ownership and order. It does not infer fence
completion from fence publication, payload coherence from reservation order,
or executed cache control from emitted ring dwords. Steinmarder owns exact
RS482 replay and payload verdicts.

`scripts/check_radeon_cs_reservation_fence_contract.py` enforces the complete
row set, exact dependency graph, callback bindings, parked refusal, relocation
geometry, BO reservation order, dependency import, ring schedule, r300 fence
command order, reservation fence publication, external identities, and the
recorded open boundaries. Its selftest must reject known bad source and policy
mutations before the tree result has authority.

## Mechanism ownership

* ASIC and ring callback ownership uses
  `RS482_ASIC_COMMAND_CALLBACK_BINDING`. RS400 and RS480 select `rs400_asic`.
  Its graphics ring reaches `r100_ring_ib_execute`, `r300_fence_ring_emit`,
  and `r300_cs_parse`. This proves source binding, not live callback execution.
* Parked admission uses `CS_PARKED_EARLY_REFUSAL`. `radeon_cs_ioctl` holds
  `exclusive_lock` for reading and returns `EIO` on `gpu_parked` before parser,
  relocation, or ring work. Reset uses the writer side.
* Relocation topology uses `CS_RELOCATION_RECORD_GEOMETRY` and
  `CS_SUCCESS_FENCE_INVARIANT`. Parser admission requires complete four dword
  relocation records and rejects relocation metadata without an IB. Before
  cleanup, ioctl success with validated BOs also requires `parser.ib.fence`.
  Malformed topology or missing completion state cannot publish reservation
  fences.
* BO ownership uses `CS_BO_RESERVATION_LOCKS`. Every relocation holds its GEM
  reference, enters the validation list, and reaches `drm_exec_prepare_obj`
  before TTM validation and GPU offset capture. Reservation ownership protects
  placement and metadata; it does not maintain payload caches.
* Prior dependency import uses `CS_RESERVATION_DEPENDENCY_IMPORT`. Same device
  Radeon fences become per ring dependencies. Foreign or different device
  fences receive a CPU wait. Any error aborts target ring scheduling while BO
  reservations remain held.
* IB scheduling uses `CS_RING_DEPENDENCY_AND_IB_SCHEDULE`. The scheduler locks
  the ring, resolves ring dependencies, dispatches the IB, emits its fence, and
  commits the ring. A successful return reports committed work and a completion
  token, not completed work.
* r300 fence command ownership uses `R300_FENCE_COMMAND_SEQUENCE`. The bound
  emitter writes 3D and Z cache flush commands, an idle and clean wait, HDP
  read buffer invalidation, the scratch sequence, and the software interrupt
  before ring commit. The void emitter has no local execution result.
* Reservation fence publication uses `CS_RESERVATION_FENCE_PUBLICATION`.
  Successful cleanup adds the IB fence with READ or WRITE usage before
  `drm_exec_fini` releases reservations. Error cleanup adds no new fence.
  Publication orders later users but does not report completion or payload
  visibility.
* Linux trust and waiter ownership uses `CS_RELOCATION_ACCESS_DIRECTION`,
  `FENCE_FORCE_COMPLETION_PUBLICATION`, and `CS_SUSPEND_FENCE_LOCK_CONTEXT`.
  Linux owns the missing packet role validation, failed reset waiter
  publication, and suspend lock proof. Each row stays open until source and
  calibrated fixtures account for its full local contract.
* RS482 execution and payload semantics uses
  `RS482_RESET_RING_REPLAY_SEMANTICS` and
  `RS482_CACHED_GTT_PAYLOAD_VISIBILITY`. Steinmarder owns exact target replay
  count and payload visibility. Linux supplies source order and the commit
  identity that an admitted trial must bind.

## Submission sequence

The successful source path has these ordered ownership steps:

1. `radeon_cs_ioctl` acquires the shared exclusion and refuses a parked device.
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
8. Successful parser cleanup attaches the IB fence to each BO reservation with
   the declared access usage before it releases reservation locks.

This path provides execution dependency and lifetime order. It carries no CPU
payload cache action and no exact target digest. The emitted r300 sequence is
not evidence that RS482 executed the commands or that either payload direction
became coherent.

## Repaired source defects

The two `repaired` rows retain the original unsafe shapes and their replacement
contracts:

* `CS_RELOCATION_RECORD_GEOMETRY` requires the relocation chunk length to be
  divisible by four. Every packet relocation index must be four dword aligned,
  remain inside the chunk, and leave one complete record before `p->relocs` or
  `kdata` access. Truncated and misaligned metadata now returns `EINVAL`.
* `CS_SUCCESS_FENCE_INVARIANT` rejects a relocation chunk when no IB chunk is
  present. It also rejects a successful scheduling path that has validated BOs
  but no `parser.ib.fence`. These two checks prevent cleanup from publishing a
  missing completion token into BO reservations.

The repairs do not validate the truth of a userspace access domain declaration
and do not prove that an emitted fence completed.

## Open boundaries and completion evidence

* `CS_RELOCATION_ACCESS_DIRECTION` belongs to Linux. READ or WRITE reservation
  usage derives from userspace `write_domain`. The bounded r300 parser does not
  bind every supported packet write site to that declaration. A finite packet
  resource role map and negative command stream corpus must cover every
  supported write site and reject an inaccurate domain.
* `FENCE_FORCE_COMPLETION_PUBLICATION` belongs to Linux. Failed reset writes
  the latest sequence through the ASIC callback, but the local function does
  not advance `last_seq`, signal generic fences, or wake the fence queue. A
  source proof or repair must account for the sequence, generic signaling,
  wakeup, ordering, and absence of post park MMIO.
* `RS482_RESET_RING_REPLAY_SEMANTICS` belongs to Steinmarder. Successful reset
  can recommit backed up ring dwords after partial execution. Source does not
  establish exactly once payload effects. An admitted marker and fence harness
  must distinguish not executed, executed once, and repeated effects on RS482.
* `CS_SUSPEND_FENCE_LOCK_CONTEXT` belongs to Linux. `radeon_fence_wait_empty`
  documents a ring lock requirement, while the bounded suspend caller has no
  adjacent lock proof. A complete caller exclusion proof or a repaired lock
  invariant must close the local precondition.
* `RS482_CACHED_GTT_PAYLOAD_VISIBILITY` belongs to Steinmarder. Reservations,
  fences, barriers, and emitted GPU cache commands contain no CPU payload
  cache maintenance or target digest observation. Both exact target directions
  must retain cache actions, PTE and global state, submission, completed fence,
  and producer and consumer digests.

`RS482_CACHED_GTT_PAYLOAD_VISIBILITY` depends on both the r300 fence command
sequence and reservation fence publication. It also joins the directional
payload rows in `policy/rs4xx-gart-memory-path.tsv`. Neither ledger may promote
the shared target question from the other ledger's source status.

## Build priorities

1. Admit the relocation repairs only after the CS checker classifies its good
   tree and every known bad fixture, the parked guard checker remains
   calibrated, and `radeon.ko` links with zero warnings against both declared
   kernel roots.
2. Build the finite packet resource role map before changing reservation usage.
   The corpus must cover every supported r300 write site and include negative
   domain declarations that compile but fail admission.
3. Define failed reset waiter publication before using force completion as a
   recovery guarantee. The mechanism must account for generic fences, the
   sequence cache, the wait queue, and parked MMIO refusal together.
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

Then run the module build harness against both declared kernel roots as
documented in `README.md`. These checks prove a bounded source and compile
contract only. They do not prove live submission, reset replay count, fence
completion, payload visibility, performance, or hazard clearance.
