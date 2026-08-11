# RS4xx failed reset hardware containment

RS400 and RS480 use a shared hardware admission state machine for reset,
suspend, resume, shutdown, debugfs, display, command submission, GART, TTM,
GEM, and low-level register access. A lifecycle transition closes hardware
access and drains every admitted operation before it changes hardware state. A
latch-only refusal closes later admission and retains software ownership when
destruction would require unavailable hardware.

The implementation is kernel-source evidence. A successful module build proves
compilation, linkage, symbol projection, and metadata. Target behavior requires
a retained RS482 bundle in `steinmarder-r300`. The retained parked-device
bundle
`cachyos_vostro1000_rs482_parked_entry_contract_matrix_20260805T055406Z`
proves that a measured RS482 park rejects later GEM, USERPTR, PRIME, and
WAIT_IDLE operations. It does not prove the admission state machine, terminal
retention, or interleaving behavior in the source described here.

## Failure mechanism

The `vostro1000-re` crash-capture authority at
`systems/dell-vostro-1000/host-config/rad05-crash-capture/README.md` records the
RS482 hazard model: a GA-wedged 3D register read becomes a non-posted access
with no K8 northbridge timeout. The CPU load does not return control to a
driver timeout while the integrated GPU register bus remains unresponsive.
This source contract therefore treats every post-failure MMIO access as a host
safety violation.

A parked flag closes only code that reads the flag after the reset
failure. Four classes remain outside that guarantee:

* A callback can pass a flag test before reset failure and reach MMIO after the
  failure.
* A debugfs reader can enter an indirect register path without the reset writer
  lock.
* A GEM fault can install a CPU aperture PTE before the flag changes and use the
  mapping after reset begins.
* A finalizer can release its last software reference while TTM unbind still
  requires GART register access.

`radeon_gpu_reset_internal` also performs BIOS scratch restoration, fence
completion, ring cleanup, display restoration, and power-management work after
`radeon_asic_reset`. Publishing `gpu_parked` after those operations leaves a
failed-reset interval in which the shared state still advertises hardware
availability.

The state machine closes that interval. It makes hardware admission a counted
epoch and publishes the transition before reset cleanup reaches any
post-failure register path.

## State model

`enum radeon_rs4xx_hardware_state` has eight states. The table records the
ordinary caller result for a state that does not admit access.

<!-- markdownlint-disable MD013 -->

| State | Meaning | Ordinary admission result |
| --- | --- | --- |
| `RUNNING` | Hardware accepts ordinary reader and transaction roots. | admitted |
| `RESETTING` | Reset owns hardware while prior work remains drained. | `-EBUSY` |
| `SUSPENDING` | Suspend owns hardware while prior work remains drained. | `-EBUSY` |
| `SUSPENDED` | The ASIC is powered down and resume remains possible. | `-EHOSTDOWN` |
| `RESUMING` | Resume owns hardware while prior work remains drained. | `-EBUSY` |
| `SHUTTING_DOWN` | Unload owns hardware and final ownership is unresolved. | `-ESHUTDOWN` |
| `SHUTDOWN` | Hardware teardown reaches a terminal software state. | `-ESHUTDOWN` |
| `PARKED` | Failed recovery leaves hardware access terminally unsafe. | `-EIO` |

<!-- markdownlint-enable MD013 -->

`RUNNING` maps to `-EALREADY` when a transition expects another state. That
mapping makes an expectation mismatch fail closed. `radeon_resume_kms` accepts
the one explicit no-owner case in which a resume request observes `RUNNING`.
The caller returns success without ending a transition it does not own.

The transition owner is the task stored in `rs4xx_hardware_owner`. Reset,
suspend, resume, and shutdown helpers called by that task retain nested access
to bounded hardware operations. Every other task receives the state-specific
refusal. The owner identity is a narrow capability, not a family-wide bypass.

## Admission classes

Two counters distinguish operations by lifetime and call topology.

### Hardware readers

`rs4xx_hardware_readers` covers bounded leaf access. Register helpers, IRQ
status access, encoder reads, connector reads, clock reads, and similar leaves
enter through `radeon_rs4xx_hardware_access_begin` and leave through
`radeon_rs4xx_hardware_access_end`.

A reader performs these operations in order:

1. It reads the state with acquire ordering and rejects `gpu_parked`.
2. It increments `rs4xx_hardware_readers`.
3. It executes `smp_mb__after_atomic`.
4. It revalidates the state and parked latch.
5. It decrements the counter and wakes the transition waiter on a failed
   revalidation.

The post-increment barrier prevents a reader from hiding on the wrong side of
transition publication. The transition observes the reader count, or the
reader observes the closed state.

### Hardware transactions

`rs4xx_hardware_transactions` covers callback-bearing or lock-bearing work
whose interior can invoke several hardware leaves. CS parsing, modeset,
cursor replacement, framebuffer allocation, PRIME ownership changes, TTM BO
movement, GEM faults, and finalizers use transaction admission directly or
through `radeon_device_lock_hardware`.

A transaction performs these operations in order:

1. It rejects `gpu_parked`, a non-running state, and `rs4xx_hardware_closing`.
2. It increments `rs4xx_hardware_transactions`.
3. It executes `smp_mb__after_atomic`.
4. It revalidates state, parked state, and closing state.
5. It decrements and wakes the transition waiter on failed revalidation.

`radeon_device_lock_hardware` adds the legacy `exclusive_lock` reader after
transaction admission. A transition owner skips the reader lock because reset
already owns its writer. `radeon_device_unlock_hardware` releases the reader
lock when present and ends the transaction.

The split between readers and transactions is load-bearing. A low-level MMIO
helper can nest inside a transaction without acquiring callback locks. A
callback-bearing root cannot disappear from the transition denominator merely
because its final MMIO leaf has its own short reader guard.

## Transition ordering

`radeon_rs4xx_hardware_transition_start_locked` owns the common closure
sequence:

1. It sets `rs4xx_hardware_closing`.
2. It executes a full barrier.
3. It waits for `rs4xx_hardware_transactions` to reach zero.
4. It publishes the owner task.
5. It publishes the transition state with release ordering.
6. It executes a full barrier.
7. It waits for `rs4xx_hardware_readers` to reach zero.

`radeon_rs4xx_hardware_transition_end` waits for both counters, clears the
owner, publishes the final state with release ordering, clears closing only for
`RUNNING`, wakes waiters, and releases the transition mutex.

`radeon_rs4xx_latch_teardown_refusal` is a terminal admission latch, not a
lifecycle transition. It sets `gpu_parked`, clears acceleration and ring
readiness, and closes every later reader or transaction admission. It does not
retroactively drain an operation that already passed admission. Reset,
suspend, resume, and unload use the transition helpers when they require a
drained hardware epoch. A GART or TTM invariant refusal in `RUNNING` retains
the affected ownership and closes new admission; the source does not claim an
instant drain for already admitted work on that latch-only path.

The latch publishes `rs4xx_parked_publish_pending` through a fully ordered
exchange. The process-context worker clears pending before it drains the
transaction and reader counters, performs CPU-only containment, clears running
through a second fully ordered exchange, and executes one final queue check. A
refusal concurrent with the worker either leaves pending set for that final
check or observes running clear and queues another worker. This ordering keeps
a refusal from disappearing between the worker's last publication and return.

`policy/rs4xx-hardware-transition-contract.tsv` declares every transition
owner. `scripts/check_rs4xx_hardware_transition_contract.py` proves the exact
five-row call-site denominator and the eight-state denominator.

<!-- markdownlint-disable MD013 -->

| Owner | Expected state | Transition | Terminal states |
| --- | --- | --- | --- |
| `rs400_init` | `RUNNING` | `RESETTING` | `RUNNING`, `PARKED` |
| `radeon_suspend_kms` | `RUNNING` | `SUSPENDING` | `RUNNING`, `SUSPENDED` |
| `radeon_resume_kms` | `SUSPENDED` | `RESUMING` | `SUSPENDED`, `RUNNING`, `PARKED` |
| `radeon_gpu_reset_internal` | `RUNNING` | `RESETTING` | `RUNNING`, `PARKED` |
| `radeon_driver_unload_kms` | any stable state | `SHUTTING_DOWN` | `SHUTDOWN` |

<!-- markdownlint-enable MD013 -->

## Reset path

The source call path has this mechanism order:

```text
radeon_gpu_reset or radeon_gpu_reset_forced
  -> radeon_gpu_reset_internal
  -> radeon_rs4xx_hardware_transition_begin
  -> close transaction admission and drain transactions
  -> publish RESETTING and drain readers
  -> down_write(exclusive_lock)
  -> unmap_mapping_range(anonymous GEM mapping)
  -> synchronize_irq and drain work
  -> radeon_asic_reset
  -> radeon_rs4xx_publish_parked_state on failure
  -> CPU-only failed-reset cleanup
  -> radeon_rs4xx_hardware_transition_end(PARKED or RUNNING)
```

`unmap_mapping_range` revokes already installed anonymous GEM aperture PTEs.
The admission state stops future fault and callback work. Both mechanisms are
required because a state flag cannot retract a CPU page-table entry.

`radeon_fbdev_fb_mmap` owns a separate persistent mapping boundary. Linux 6.18
and 7.1 `drivers/video/fbdev/core/fb_chrdev.c:fb_mmap` call
`info->fbops->fb_mmap` under `info->mm_lock`. The Radeon callback derives
`rdev` through `info->par`, `fb_helper->dev`, and `dev_private`. RS400 and
RS480 then return `-ENODEV` before `fb_io_mmap`. Linux
`drivers/video/fbdev/core/fb_io_fops.c:fb_io_mmap` selects either framebuffer
memory or the exported MMIO range from `vm_pgoff`, then passes the selected
address range to `vm_iomap_memory`. This source proof closes the admitted
Radeon callback before mapping selection. Runtime framework dispatch and the
denominator of mappings established by other source or an earlier module stay
outside this source-static claim.

`radeon_rs4xx_publish_parked_state` executes before BIOS scratch restoration
and failed-reset fence cleanup. It latches `gpu_parked`, disables acceleration,
clears reset demand, marks every ring unready, disables IRQ hardware without
MMIO, drains power work, publishes fences through CPU state, and retains page
flip ownership that cannot be released safely.

The display reprogramming path records the expected CRTC count. A missing or
failed reprogramming completion publishes `PARKED` before the reset reader lock
is released. Successful reset reaches `RUNNING` only after the display and ring
restoration contract completes.

`rs400_startup` owns one hardware-access reader epoch from common register and
memory-controller programming through clock, GART, writeback, fence, IRQ,
host-path, command-processor, and indirect-buffer initialization. Every
post-admission error reaches one release label. The host-path register read and
each initialization callback therefore execute under the same reader epoch.
`rs400_init` unwinds command processor, writeback, indirect-buffer, GART, and
IRQ ownership after a startup error, clears `accel_working`, and returns the
startup error. Device load therefore stops before debugfs materialization and
ring tests can admit a degraded RS400 device. A GART unwind error retains its
exact terminal ownership result.

## Suspend and resume

Suspend closes admission before display power-down and BO eviction. A display
or scanout release failure restores `RUNNING`. Successful power-down publishes
`SUSPENDED`.

Wait-capable destructors treat `SUSPENDED` as a reversible unavailable state.
They wait for resume instead of retaining an object until reboot. `PARKED`,
`SHUTTING_DOWN`, and `SHUTDOWN` are stable dispositions, so the same wait ends
and the caller chooses release or terminal retention.

Resume owns `RESUMING` through PCI restoration, ASIC resume, ring tests, cursor
pinning, encoder state, HPD, modeset, and power state. An RS4xx PCI enable
failure clears bus mastering, saves the cleared PCI command state, restores
`PCI_D3hot`, publishes `SUSPENDED`, and returns the exact enable error. A later
successful retry calls `pci_set_master` only after `pci_enable_device`
succeeds. ASIC resume failure publishes `PARKED`. Complete resume publishes
`RUNNING` before asynchronous flip cleanup restarts.

Runtime resume checks terminal ownership before `pci_set_power_state`,
`pci_restore_state`, `pci_enable_device`, and `pci_set_master`. A terminal retry
disables polling, publishes `DRM_SWITCH_POWER_OFF`, preserves PCI ownership,
and returns `-EIO`. A nonterminal failure disables polling, clears bus master,
disables the PCI device only when enablement succeeded, saves the cleaned PCI
state, restores the ATPX-derived D3cold or D3hot state, and publishes
`DRM_SWITCH_POWER_DYNAMIC_OFF` for a valid retry. Both failure branches return
their original error. `policy/pci-runtime-resume-rollback-authority.toml` pins
the Linux 6.18 and 7.1 PCI and runtime-PM sources that define this ownership
split.

## Unload and ownership retention

`radeon_driver_unload_kms` serializes through `rs4xx_unload_lock` and
`rs4xx_unload_completed`. Each successful shutdown begin has one transition
end. Repeated unload calls observe the completed flag and return without a
second teardown.

Unload retains terminal ownership when any of these conditions holds:

* The prior hardware state is `PARKED` or `SUSPENDED`.
* The prior state is another state that does not license ordinary teardown.
* Display teardown cannot release every scanout owner.
* Open DRM files retain GEM ownership.
* Common RS4xx GART teardown returns a hardware refusal.
* TTM finalization returns `-EBUSY` for a nonzero ownership denominator.

`radeon_rs4xx_finish_terminal_shutdown` publishes `SHUTDOWN`, quiesces
hardwareless work, and marks unload complete. It retains the BAR mapping,
memory manager, DRM device, parent device, and module ownership until reboot.
That retention is containment. A destructor that requires dead MMIO makes
ordinary release unsafe.

`radeon_pci_remove` takes a DRM reference before unplug. A retained terminal
device enters a global identity list, clears PCI bus mastering, and keeps its
DRM and module references. A later probe of the same PCI device returns
`-ENODEV`. A fully released device drops both retained references.

## Memory and command lifetime

`gart.lock` serializes the GART CPU shadow, page array, hardware page table,
and TLB flush. Bind and fini use hardware reader admission. Unbind uses
wait-capable reader admission so reversible lifecycle transitions complete
before cleanup selects a disposition.

A `RUNNING` unbind with an invalid GART state or range returns `-EINVAL`.
Backend unbind latches teardown refusal and retains the binding, page, DMA, and
SG ownership. The invalid operation changes no PTE or backing ownership.

`radeon_gem_object_free` uses wait-capable transaction admission. A terminal
refusal increments `rs4xx_retained_gem_objects`, unregisters the memory
notifier, and leaves the complete BO on `rdev->gem.objects`. RS400 finalization
completes common GART disposition before GEM force deletion. It disables the
aperture, releases coherent table storage, and then release-publishes
`rs4xx_gart_teardown_complete`, so later TTM unbind callbacks release bound and
userptr software ownership without touching disabled hardware.

A failed TTM backend unbind keeps `bound`, page, DMA, and SG ownership and
latches the RS4xx hardware fault. The void TTM unpopulate and destroy callbacks
retain the complete Radeon BO and its `radeon_ttm_tt` before returning to TTM.
The translation table enters `rs4xx_retained_ttm_tables_list`; pages that leave
generic TTM allocation accounting enter
`rs4xx_retained_ttm_accounted_pages`. Each ownership transfer is idempotent.
The complete BO remains the primary lifetime anchor, while the per-device table
list preserves the detached translation table after generic cleanup clears
`bo->ttm`.

Generic TTM cleanup releases the resource-manager range and clears
`rbo->tbo.resource` after terminal retention. Closed hardware admission forbids
later allocation, movement, or rebinding through that released range. The GEM
debugfs reader prints `RETAINED` before inspecting the resource pointer and
prints `DETACHED` for a nonretained BO with no resource. It dereferences
`resource->mem_type` only when the resource exists.

An imported SG table supplies DMA addresses for the Radeon GART backend, while
the AGP backend consumes a page-pointer array. `radeon_bo_create` rejects an SG
import on `RADEON_IS_AGP` with `-EOPNOTSUPP` before allocation and TTM
construction. `radeon_ttm_tt_populate` also rejects an external SG table that
lacks a Radeon GTT wrapper. This boundary avoids interpreting one backend's
translation storage as the other backend's representation.

`radeon_bo_create` enters transaction admission and increments
`rs4xx_live_bos` immediately before `ttm_bo_init_validate` transfers
destruction ownership. `radeon_ttm_bo_destroy` decrements the count only after
final `kfree` and wakes teardown waiters. Terminal retention returns before the
decrement. The count therefore covers delayed BO deletion and failed
construction after TTM accepts the destroy callback.

`radeon_ttm_fini` acquire-reads the live BO count and checks retained BOs,
retained translation tables, retained accounted pages, transactions, and
readers. Any nonzero value stores `-EBUSY` and returns before range-manager or
TTM device destruction. It does not pre-drain the delayed-deletion workqueue
because an imported external fence can remain pending indefinitely. A zero
denominator lets `ttm_device_fini` drain the already empty BO deletion queue.

`rs400_gart_fini` stores the exact common GART result in
`rs4xx_gart_fini_error`. `radeon_device_fini` returns that result before GEM,
TTM, interface, BAR, or MMIO release. `radeon_driver_unload_kms` converts the
result into terminal shutdown retention. This path intentionally retains
memory until reboot. It is neither retryable cleanup nor device recovery.

`radeon_bo_move` holds a transaction across reservation wait, binding, copy or
memcpy movement, unbind, placement notification, and statistics. The
reservation wait precedes binding. A move that installs a new binding removes
it synchronously before a later move error returns. A GEM fault reserves the BO
before transaction admission, then holds the transaction through placement
notification and CPU PTE installation. It returns `VM_FAULT_SIGBUS` when
admission closes.

`radeon_cs_ioctl` holds `radeon_device_lock_hardware` through parser setup,
reservation, validation, dependency import, IB scheduling, fence publication,
and `drm_exec_fini`. Every exec object retains an independent parser relocation
reference or VM ownership reference. The parser releases relocation references
after the hardware transaction ends, so `drm_exec_fini` cannot invoke a final
destructor under the transaction root.

## Display, IRQ, and debugfs paths

Display callbacks use short reader admission for hardware leaves and
transaction admission for callback-bearing operations. Page-flip quiescence
synchronizes the IRQ, detaches queued work, and moves unreleasable flip
ownership into `rs4xx_retained_flips`. CPU-only completion publishes the event
and fence state without touching the engine.

IRQ initialization establishes software locks before registration can fail.
Hardwareless IRQ teardown masks PCI delivery, frees the handler, cancels IRQ
work, and avoids register access. Fence and ring debugfs readers enter through
`radeon_device_lock_hardware` before callbacks or scratch-register reads.

RS4xx development readers share `rs480_debugfs_lock_hardware`. The helper emits
the schema, starts a hardware transaction, adds the legacy reader lock when the
caller is not the transition owner, and reports the state-specific refusal.
Each admitted data path calls `radeon_device_unlock_hardware`. CPU-only schema
and terminal records remain available without an MMIO claim.

## Source intelligence and verification

`policy/radeon-driver-source-map.toml` declares the
`rs4xx-hardware-admission` partition. The capture includes GNU cflow, cscope,
Universal Ctags and readtags, GNU Global, lizard, SCC, declared callback edges,
contextual path witnesses, and Graphviz input. The capture labels its graph as
a research candidate. Lexical and declared edges do not prove runtime
reachability, preprocessor activation, framework order, or hardware behavior.
Bounded lexical queries record the exact fbops assignment count and use a
brace-scoped function query to bind that assignment to
`radeon_fbdev_driver_fbdev_probe`. Declared edges record Linux
`drivers/video/fbdev/core/fb_chrdev.c:fb_mmap` callback selection and the
guarded `fb_io_mmap` terminal call. Linux 6.18 and 7.1
`drivers/pci/pci-driver.c:pci_device_remove` call `drv->remove`; the declared
PCI removal edge uses that framework symbol and the exact Radeon callback
target.

`policy/rs4xx-ttm-retention-authority.toml` pins the Linux 6.18 and 7.1 TTM,
GEM, PRIME, and AGP sources that define callback return types, cleanup order,
resource release, SG ownership, and accounting. The PCI runtime authority file
pins the matching PCI core and runtime-PM implementations. Its PCI core rows
also ground the enable counter, restored command register, disable
precondition, and saved retry image used by the system resume rollback. The
source checkers verify every declared commit and file digest before admitting
their derived contracts.

The local source gates run with these commands:

```sh
python3 scripts/check_rs4xx_hardware_transition_contract.py --selftest
python3 scripts/check_rs4xx_hardware_transition_contract.py
python3 scripts/check_rs4xx_hardware_admission_contract.py --selftest
python3 scripts/check_rs4xx_hardware_admission_contract.py
python3 scripts/check_radeon_debugfs_registration.py --selftest
python3 scripts/check_radeon_debugfs_registration.py
python3 scripts/capture_radeon_driver_source_map.py --self-test
python3 scripts/check_build_features.py --self-test
python3 scripts/check_build_features.py
python3 scripts/check_all_dev_interfaces.py --self-test
python3 scripts/check_all_dev_interfaces.py
python3 scripts/check_parked_admission_guards.py --selftest
python3 scripts/check_parked_admission_guards.py
python3 scripts/check_parked_entry_policy.py --selftest
python3 scripts/check_parked_entry_policy.py
python3 scripts/check_radeon_gart_lifecycle.py --selftest
python3 scripts/check_radeon_gart_lifecycle.py
python3 scripts/check_radeon_cs_reservation_fence_contract.py --selftest
python3 scripts/check_radeon_cs_reservation_fence_contract.py
```

The transition checker admits 38 policy rows and calibrates 41 verdicts. The
admission checker proves 12 operational callers, 31 direct call-site shapes,
34 direct call occurrences, and 53 known-bad mutations. The GART lifecycle
checker classifies 35 rows and rejects 144 known-bad mutations. The debugfs
registration checker proves 18 static components, 8 ring slots, and 2 TTM
managers while rejecting 12 topology mutations. These finite denominators bind
the current source-static contract; they remain distinct from a compiler proof
or a hardware verdict.

## Evidence boundary and falsifiers

The source proves declared ordering and finite call-site structure. It does not
prove scheduler interleavings, target hardware survival, warm reboot recovery,
or package deployment.

The containment model fails when any observation satisfies one of these
falsifiers:

* A hardware-bearing callback reaches MMIO without reader or transaction
  admission.
* A transition begins hardware access while an ordinary transaction remains
  active.
* A reader increments after transition publication and still observes
  `RUNNING`.
* A failed `radeon_asic_reset` reaches a register access before
  `radeon_rs4xx_publish_parked_state` closes admission, or the later CPU-only
  containment path reaches hardware before `PARKED` publication.
* An installed GEM aperture PTE survives reset invalidation and permits CPU
  access during reset.
* `drm_exec_fini` or another reference drop invokes a final hardware destructor
  inside its enclosing transaction.
* TTM core detaches `bo->ttm` without a complete BO or per-device retained
  translation-table ownership anchor after an unbind refusal.
* Generic TTM clears `rbo->tbo.resource` and a retained-object reader
  dereferences it before classifying the retained or detached state.
* An imported SG table reaches the AGP backend and is interpreted as a Radeon
  GART DMA-address array or an AGP page-pointer array.
* TTM binding begins before the reservation wait, or a later move error leaves
  a binding that the failed move installed.
* A counted BO leaves `rs4xx_live_bos` before final destruction, or TTM
  finalization reaches `ttm_device_fini` with a nonzero live, retained, or
  retained-page denominator.
* RS400 publishes completed GART teardown before aperture disable and coherent
  table release.
* Runtime resume reaches PCI restoration after terminal ownership is retained,
  or a nonterminal failure leaves bus mastering, enablement, polling, or the
  retry state inconsistent with its acquisition point.
* System resume enable failure leaves bus mastering set, remains in D0, loses
  the cleaned retry image, replaces the PCI error, or a successful retry omits
  explicit bus-master restoration.
* RS400 acceleration startup failure returns success and permits later device,
  debugfs, or ring-test admission with `accel_working` cleared.
* Unload or remove releases a BO, BAR, DRM device, parent device, or module
  reference after hardware-safe destruction fails.
* A second probe binds the same terminally retained PCI identity before reboot.

Target promotion requires a package that pins the reviewed source commit, a
clean dual-kernel module build, a safe read-only deployment identity check, and
an attended RS482 run with boot-persistent logging. A failed-reset injection
remains a hazardous hardware mutation. It requires explicit preflight,
netconsole, boot identity capture, manual recovery, and a sealed result bundle.
The source-static and build gates run before that mutation and do not substitute
for it.
