# Radeon driver source intelligence contract

## Scope and authority

`scripts/capture_radeon_driver_source_map.py` produces the finite source
intelligence contract for the tracked Radeon subtree. The policy in
`policy/radeon-driver-source-map.toml` bounds the source denominator, tool set,
kernel lanes, graph roots, declared bindings, contextual path witnesses,
hazard identifier censuses, and coefficient symbols. The capture exports a
named Git commit and never reads a mutable working tree as source authority.

This repository owns source structure, build profile projection, and semantic
source checks. `radeon-custom` owns package selection and deployment identity.
`steinmarder-r300` owns exact RS482 hardware evidence and retained runtime
verdicts. `mesa-26-gororoba` owns userspace behavior. The source map does not
promote a source edge, a linked symbol, or a successful module build into a
runtime or hardware claim.

The evidence ranks remain separate:

1. Git commit, tree, and blob objects identify admitted source bytes.
2. Analyzer output describes lexical structure over those bytes.
3. Declared bindings represent policy checked macro, callback, table, and
   framework edges that lexical tools do not resolve.
4. Preprocessed translation units and linked modules prove named build lane
   inclusion.
5. Mutation calibrated source checkers prove the exact source invariants that
   they declare under their documented lexical assumptions.
6. A retained target bundle proves only the exact runtime observation it
   records.

## Capture architecture

The producer separates source identity, analysis, semantic joins, build
projection, and verification:

```text
named Git commit
  -> raw commit and tree object proofs
  -> tracked source closure
  -> 222 admitted source files
     -> ctags, readtags, GNU Global, and cscope indexes
     -> GNU cflow lexical edges and partition trees
     -> extracted callback candidates
     -> policy declared indirect bindings
     -> bounded code masked queries
     -> lizard and scc measurements
  -> 21 selected translation units per declared profile lane
     -> exact kernel root
     -> 7,174 entry LLVM prefix tree and 19 row semantic closure
     -> fixed make, shell, LLVM, PATH, and resource directory inputs
     -> normalized preprocessor output
     -> linked radeon.ko
     -> raw and canonical module symbol sets
  -> replayed call candidates, path witnesses, and coefficients
  -> independently derived file denominator and SHA-256 ledger
```

The captured directory has six fixed top level files and eleven fixed top
level directories. The verifier derives every expected recursive path from
policy, source membership, Git proofs, command records, analysis products, and
kernel lanes. A manifest supplied file list cannot widen that denominator.

<!-- markdownlint-disable MD013 -->

| Surface | Canonical bundle artifacts | Contract |
| --- | --- | --- |
| Identity | `capture-manifest.json`, `UPSTREAM_BASE.toml`, `source-closure.toml`, `metadata/git-*-proof/` | Raw Git objects bind the source commit through the Radeon driver subtree and bind retained producer inputs. |
| Source | `source/`, `metadata/file-list.tsv`, `inputs/c-and-header-files.txt` | Every admitted path has a type, size, SHA-256 digest, and Git object identity. The 207 C and header paths form the complete analyzer denominator. |
| Cross references | `indexes/ctags/`, `indexes/global/`, `indexes/cscope/`, `queries/` | Retained indexes, exact query inputs, raw query outputs, diagnostics, and summaries preserve replay inputs and results. |
| Lexical graph | `radeon-driver-lexical-map.tsv`, `analysis/cflow-lexical-edges.tsv`, `cflow/` | GNU cflow provides the full lexical graph and seven bounded partition trees in text and DOT form. |
| Indirect graph | `radeon-driver-declared-bindings.tsv`, `analysis/extracted-binding-candidates.tsv` | Brace bounded policy bindings and syntax extracted candidates preserve callback, macro, table, and file operation discontinuities. |
| Unified graph | `analysis/call-candidates.tsv` | The exact union keeps edge kind, caller, callee, partition, provenance, and classification. |
| Contextual paths | `analysis/contextual-path-witnesses.tsv`, `analysis/contextual-path-joins.tsv` | Ordered axes and typed joins preserve required family, profile, ring, token, and event context. |
| Hazard census | `analysis/hazard-guard-identifier-census.tsv` | Policy named identifiers occur in bounded owner functions. The product is not a control flow proof. |
| Complexity | `analysis/lizard.csv`, `analysis/scc.json`, `analysis/coefficient-vectors.tsv` | Function NLOC, CCN, graph degree, indirect edges, side effect class, guard census, and evidence rank remain separately inspectable. |
| Build lanes | `preprocessed/<release>/<profile>/` | Every declared lane retains 21 normalized translation units, one linked module, raw symbols, canonical symbols, and build metadata. |
| Profile deltas | `analysis/profile-symbol-delta-summary.tsv`, `analysis/profile-symbol-delta-members.tsv` | Canonical symbols strip only a terminal `.llvm.<digits>` suffix, reject collisions, and preserve exact additions and removals. |
| Tool provenance | `metadata/tool-versions.tsv`, `metadata/kernel-toolchains.tsv`, `metadata/kernel-toolchain-closures/`, `metadata/toolchain-runtime-libraries.tsv` | Required analyzer executables carry exact hashes. Each LLVM lane retains the 7,174 entry prefix tree, the 19 row semantic execution closure, resource paths, and recorded host runtime rows. |
| Execution record | `metadata/command-metadata.tsv`, `diagnostics/` | Every producer command has an exact identifier, tool, working directory, status, output ownership, argument vector, and environment. |
| Seal | `capture-hashes.sha256` | Every expected regular file except the ledger itself has one content digest. |

<!-- markdownlint-enable MD013 -->

## Reference capture attestation

The complete reference capture identifies source and producer commit
`7a353a84d863a4ef2326a81cc837fb3d03408665`. Its local bundle name is
`radeon-driver-lifecycle-admission-reset-source-map/7a353a8-complete-kernel-lanes`.
The name is a convenience label. The Git proofs and manifest identify the
content.

<!-- markdownlint-disable MD013 -->

| Property | Value |
| --- | --- |
| Capture schema | `gororoba-radeon-driver-source-map-v2` |
| Source files | 222 |
| Source bytes | 6,907,264 |
| Regular files | 897 |
| Ledger rows | 896 |
| Bundle size | 958 MiB on the capture filesystem |
| Lexical rows | 98,353 |
| Call candidates | 15,616 |
| Declared indirect bindings | 45 |
| Contextual witnesses | 4 |
| Contextual witness edges | 29 |
| Typed joins | 4 |
| Profile comparisons | 7 |
| Profile delta members | 178 |
| Producer commands | 176 |
| Manifest SHA-256 | `3e2ce7b4d4be3ea38dad4d0e0b78d873acf8eddc2021d0c032b056a941eac92b` |
| Ledger SHA-256 | `1c52018a227921a67eab061cc518d8796d50a3ead35d5908448ecb88d44c17b2` |

<!-- markdownlint-enable MD013 -->

The 896 ledger rows cover every regular file except
`capture-hashes.sha256`. The independent verifier passes with
`--require-all-kernel-lanes`. The producer self test rejects changed content,
extra top level and nested files, incomplete command records, changed raw
cscope queries, and forged call witnesses. The full verifier independently
derives coefficient rows from lizard, cflow, and binding replay. These checks
prove that verification does not reduce to self consistent hashing.

## Graph decomposition

The unified candidate graph has the exact decomposition:

```text
15,475 GNU cflow lexical edges
    96 syntax extracted indirect candidates
    45 policy declared indirect bindings
------
15,616 total call candidates
```

The lexical portion classifies 6,760 callees as driver symbols and 8,715 as
external symbols. The remaining rows carry precise callback, table, macro,
wrapper, registration, family selection, reset mode, and event classifications.
The 96 extracted rows remain candidates. The 45 declared rows pass exact
policy and brace containment checks.

The seven focused partitions contain 3,146 lexical rows:

<!-- markdownlint-disable MD013 -->

| Partition | Lexical rows | Architecture surface |
| --- | ---: | --- |
| Module lifecycle | 1,344 | Module load, PCI probe, KMS load, device initialization, unload, and module exit. |
| Reset and park | 846 | Detected reset, forced reset, ASIC reset dispatch, lockup work, parked containment, and reset probes. |
| Command submission | 674 | DRM ioctl entry, parser initialization, IB chunks, ring parser selection, and packet zero validation. |
| GART and memory | 102 | TTM initialization, common GART ownership, RS400 table setup, PTE writes, and TLB flush. |
| KMS and debugfs | 85 | DRM minor debugfs registration, RS480 development nodes, and Palm reset node ownership. |
| Profile and admission | 57 | Runtime profile selection, hardware availability, GEM creation, PRIME import, and dumb creation. |
| Register policy generation | 38 | Register source parsing, safe bitmap generation, and RS4xx runtime policy application. |

<!-- markdownlint-enable MD013 -->

`cflow/full-call-candidates.txt` and
`cflow/full-call-candidates.dot` retain the full lexical tree. Each partition
has corresponding text and DOT output under `cflow/partitions/`.
`queries/cscope-root-symbols.tsv` retains 696 parsed rows for 43 root symbols
across definition, calls, and callers queries. The verifier reruns all 129
queries against the retained cscope database and requires byte exact raw
output plus exact parsed summary equality.

## Contextual path witnesses

The four witnesses preserve source order without claiming runtime
reachability. Each witness splits discontinuous mechanisms into axes and joins
the axes with an explicit callback selection or later debugfs event.

### RS480 command submission and packet validation

The ioctl execution axis is:

```text
drm_ioctl_dispatch
  -> radeon_cs_ioctl
  -> radeon_cs_ib_chunk
  -> radeon_cs_parse
  -> rdev->asic->ring[ring]->cs_parse
```

The RS480 ring selection axis is:

```text
CHIP_RS480
  -> rs400_asic
  -> r300_gfx_ring
  -> r300_cs_parse
  -> r100_cs_parse_packet0
  -> r300_packet0_check
```

A `callback-selection` join connects the parser dispatch slot to the family
selected ring table. The path requires `CHIP_RS480`, the graphics ring index,
and the selected callback table. This witness does not prove that a live ioctl
contains an accepted packet.

### RS480 debugfs WD3 reset request

The registration axis reaches the
`radeon_rs480_reset_hang_probe` node through the DRM primary minor and Radeon
device debugfs registration. A distinct `debugfs-read-event` join begins the
later file operation dispatch. The read axis reaches
`rs480_reset_hang_probe_show` and then `rs480_wedged_3d_reset`.

The path requires the mutate capable compiled ceiling and runtime profile,
working acceleration, a ready graphics ring, a nonzero candidate register
selector, and an admitted WD3A or WD3B token. Registration does not invoke the
reset helper.

### RS480 WD3 forced reset and ASIC selection

The forced reset axis is:

```text
rs480_wedged_3d_reset
  -> radeon_gpu_reset_forced
  -> radeon_gpu_reset_internal
  -> radeon_asic_reset
  -> rdev->asic->asic_reset
```

The family selection axis is `CHIP_RS480 -> rs400_asic -> r300_asic_reset`.
A `callback-selection` join connects the ASIC reset slot to the RS480 family
table. The path requires the WD3 helper to pass its profile, token, ring, and
availability admission checks.

### Palm debugfs PCI configuration reset

The registration axis reaches `radeon_force_pci_reset_safe` through the DRM
primary minor, Radeon device debugfs registration, and the Palm scoped
Evergreen development registration. A distinct `debugfs-write-event` join
begins the later file operation dispatch:

```text
radeon_force_pci_reset_safe
  -> radeon_force_pci_reset_safe_fops
  -> radeon_force_pci_reset_safe_write
  -> evergreen_gpu_pci_config_reset_safe
  -> radeon_pci_config_reset
```

The path requires the mutate capable compiled ceiling and runtime profile,
`CHIP_PALM`, unavailable hardware state, the exact unsafe module parameter
value `1`, file position zero, and the exact command `1`. Its maximum side
effect remains a PCI configuration reset. The exact gates constrain entry but
do not lower the side effect classification.

## Coefficient derivation

The coefficient product selects eleven policy named functions. It replays
lizard NLOC and CCN, lexical fan in and fan out, declared indirect edges,
maximum side effect class, guard census ownership, required identifiers, and
evidence rank. The selected denominator totals 938 NLOC and 308 CCN.

<!-- markdownlint-disable MD013 -->

| Symbol | NLOC | CCN | CCN share | Lexical fan in | Lexical fan out | Declared edges | Maximum side effect |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `r300_packet0_check` | 530 | 222 | 72.08% | 1 | 7 | 1 | Command validation |
| `radeon_gpu_reset_internal` | 155 | 33 | 10.71% | 2 | 37 | 2 | Engine reset |
| `radeon_cs_ioctl` | 67 | 14 | 4.55% | 0 | 16 | 1 | Command submit |
| `radeon_force_pci_reset_safe_write` | 28 | 10 | 3.25% | 0 | 7 | 2 | PCI configuration reset |
| `evergreen_gpu_pci_config_reset_safe` | 42 | 8 | 2.60% | 1 | 16 | 0 | PCI configuration reset |
| `rs480_wedged_3d_reset` | 52 | 8 | 2.60% | 1 | 13 | 2 | Engine reset |
| `radeon_gem_object_create` | 41 | 7 | 2.27% | 4 | 8 | 0 | Software state write |
| `radeon_dev_hardware_available` | 9 | 3 | 0.97% | 4 | 0 | 0 | State read |
| `radeon_gpu_reset` | 4 | 1 | 0.32% | 4 | 1 | 1 | Engine reset |
| `radeon_gpu_reset_forced` | 4 | 1 | 0.32% | 1 | 1 | 2 | Engine reset |
| `rs400_gart_set_page` | 6 | 1 | 0.32% | 0 | 2 | 1 | Memory translation write |

<!-- markdownlint-enable MD013 -->

CCN is a review pressure coefficient, not a defect probability. Fan in and
fan out are lexical measurements, so zero fan in at a framework entry marks a
lexical discontinuity rather than absence of a caller.

## Profile symbol derivation

The six complete lanes are:

<!-- markdownlint-disable MD013 -->

| Kernel release | Profile | Defined symbols | Translation units |
| --- | --- | ---: | ---: |
| `6.18.38-2-cachyos-lts` | `prod` | 3,057 | 21 |
| `6.18.38-2-cachyos-lts` | `mutate-dev` | 3,100 | 21 |
| `7.1.4-1-cachyos` | `prod` | 3,054 | 21 |
| `7.1.4-1-cachyos` | `observe-dev` | 3,069 | 21 |
| `7.1.4-1-cachyos` | `probe-dev` | 3,075 | 21 |
| `7.1.4-1-cachyos` | `mutate-dev` | 3,097 | 21 |

<!-- markdownlint-enable MD013 -->

Every declared profile comparison has zero removals. The 7.1 profile order
adds 15 symbols from production to observation, 6 symbols from observation to
probe, and 22 symbols from probe to mutation. Both kernel releases add the
same 43 canonical symbols from production to mutation. Their shared added set
has SHA-256
`33f52ed8207f0e240d49925ce726dd3151f2c51b70d367fb8be9b9a95d325495`.
Each 43 symbol set contains 13 `__pfx_` entries and 30 other entries.

This equality proves that the declared development projection has a stable
linked symbol surface across the two measured kernel releases. It does not
prove equal machine code, runtime profile selection, interface registration,
or hardware behavior.

## Derived insights and falsifiers

### Lexical and framework complexity require separate review regimes

`r300_packet0_check` carries 72.08 percent of the selected CCN and exposes a
large in function decision surface. Parser changes therefore require focused
packet and register policy mutation tests. In contrast, `radeon_cs_ioctl` and
`radeon_force_pci_reset_safe_write` have zero lexical fan in because their
entries cross ioctl or file operation framework tables. Those paths require
declared bindings, lifecycle checks, and event joins even when their CCN stays
small.

This insight fails if a compiler aware whole program graph resolves the same
framework entries and removes the measured discontinuity, or if the selected
function denominator changes enough to move the concentration.

### Reset policy and reset execution occupy different functions

The four line reset wrappers encode detected versus forced policy identity.
`radeon_gpu_reset_internal` carries 33 CCN and 37 lexical outgoing edges. A
review that inspects only the wrappers misses execution breadth. A review that
inspects only the internal function misses the policy mode entering it. The
source check therefore binds both wrapper mode and internal transaction order.

This insight fails if reset mode ownership moves into the internal function or
if a new caller bypasses the checked wrappers.

### Debugfs registration and operation dispatch occupy different times

The RS480 read path and Palm write path each need two axes. A registration
edge creates a node under one DRM minor. A later user event selects the file
operation. Treating those edges as one ordinary call chain falsely states that
device registration performs a reset.

This insight fails if the framework changes to invoke the operation during
registration, or if a node moves outside the checked DRM minor lifecycle.

### Build profile nesting remains stable at the linked symbol boundary

The 7.1 profiles form a strict monotone symbol sequence and both kernels expose
the same production to mutation addition set. This result supports one shared
development capability policy across the measured kernels. It does not
authorize a shared runtime or hardware verdict.

This insight fails on any removal, canonical symbol collision, nonnested
adjacent set, or different production to mutation added set in a future
capture.

### Maximum side effect remains independent from admission strength

The Palm path has profile, family, availability, parameter, position, command,
and writer lock constraints. Its terminal still performs a PCI configuration
reset. The path remains mutation capable because classification follows the
maximum hardware effect rather than interface mode, gate count, or expected
self restoration.

This insight fails only when the terminal hardware operation changes. A new
guard does not falsify the classification.

## Bounded absence results

The code masked bounded queries record six finite statements:

1. The legacy global Palm debugfs initialization symbol has zero matches in
   all 207 C and header inputs.
2. The admitted PCI driver table has zero explicit remove callback matches.
3. The admitted debugfs creation sites have zero NULL parent matches.
4. The reset entry symbol query has exactly 10 matches.
5. The forced reset C symbol query has exactly 2 matches.
6. The Palm PCI reset C symbol query has exactly 2 matches.

Each statement is lexical and bound to its selected path set, code masking
algorithm, pattern digest, expected count, and retained match rows. A zero does
not prove global absence outside the 222 file source closure.

## Reproduction

The source only capture runs without kernel roots:

```sh
source_commit=$(git rev-parse HEAD)
capture_parent="/var/tmp/linux-radeon-gororoba-source-intelligence"
mechanism="radeon-driver-lifecycle-admission-reset-source-map"
output="${capture_parent}/${mechanism}/${source_commit}-source-only"
python3 scripts/capture_radeon_driver_source_map.py \
  --treeish "$source_commit" \
  --output "$output"
python3 scripts/capture_radeon_driver_source_map.py --verify "$output"
```

The complete capture uses the two declared read only kernel roots and their
root owned toolchain closures:

```sh
source_commit=$(git rev-parse HEAD)
capture_parent="/var/tmp/linux-radeon-gororoba-source-intelligence"
mechanism="radeon-driver-lifecycle-admission-reset-source-map"
output="${capture_parent}/${mechanism}/${source_commit}-complete-kernel-lanes"
python3 scripts/capture_radeon_driver_source_map.py \
  --treeish "$source_commit" \
  --output "$output" \
  --kernel-build-root /opt/gororoba/kernel-builds/6.18.38-2-cachyos-lts \
  --kernel-build-root /opt/gororoba/kernel-builds/7.1.4-1-cachyos \
  --kernel-toolchain-bin \
    6.18.38-2-cachyos-lts=/opt/gororoba/toolchains/llvm-22.1.6/usr/bin \
  --kernel-toolchain-bin \
    7.1.4-1-cachyos=/opt/gororoba/toolchains/llvm-22.1.8/usr/bin
python3 scripts/capture_radeon_driver_source_map.py \
  --verify "$output" \
  --require-all-kernel-lanes
(cd "$output" && sha256sum --check capture-hashes.sha256)
```

Long captures and verification runs execute inside tmux. The output stays
outside Git because the complete reference bundle occupies 958 MiB and
contains build products.

Two sealed captures compare through normalized products:

```sh
python3 scripts/capture_radeon_driver_source_map.py \
  --compare "$left_capture" "$right_capture" \
  --output "$comparison_output"
```

## Trust boundaries

- GNU cflow, cscope, ctags, and Global describe source structure. They do not
  prove runtime reachability, framework scheduling, or indirect binding
  completeness.
- Contextual witnesses prove ordered source evidence and typed joins. Their
  context strings describe requirements and assumptions, not observed events.
- The hazard identifier product is a lexical census. It does not prove control
  flow, unconditional execution, lock state, or refusal efficacy.
- `scripts/check_all_dev_interfaces.py`,
  `scripts/check_parked_admission_guards.py`, and
  `scripts/check_parked_entry_policy.py` own their declared semantic source
  invariants through calibrated positive and negative fixtures.
- The reset source checks bind exact primary source intervals, enclosing
  condition identifiers, return sets, lock transitions, and a finite kernel
  nonlocal exit and inline assembly denominator. They assume other intervening
  calls return. They do not prove a compiler control flow graph, included
  header macro state, or runtime execution.
- A linked module proves compilation, link, metadata, and selected symbol
  projection. It does not prove module loading or target behavior.
- Every LLVM prefix descendant has an exact retained identity. Admission
  rejects effective runner writes, special modes, extended attributes, path
  escapes, and changed symlink resolution before execution. The semantic
  command and library rows join to that tree during capture and offline
  verification.
- Kbuild uses `/usr/bin/make`, `/usr/bin/sh`, an absolute LLVM bin prefix, and
  `PATH=/usr/bin:/bin`. The capture does not trace every child host helper that
  kernel Makefiles execute. Host runtime library rows remain recorded capture
  facts, and offline verification does not reconstruct the original host
  package state.
- The bundle is sealed, not immutable. Any writer can alter the directory, and
  the ledger plus verifier detect rather than prevent that alteration.
- The capture contains no RS482 or Palm hardware verdict. Those verdicts
  require exact target bundles in the owning evidence repository.

## Roadmap and completion gates

The source intelligence program advances through these concrete gates:

1. The protected branch defines
   `RADEON_LLVM_TOOLCHAIN_BIN_618` and `RADEON_LLVM_TOOLCHAIN_BIN_71` as the
   two `/opt/gororoba/toolchains/` bin directories. The
   `source-map-kernel-lanes` job passes before it becomes a required status.
2. The active ruleset requires the green `source-map-kernel-lanes` status so a
   source map regression blocks integration.
3. A future capture retains raw `ldd`, ELF dependency, SONAME, and package
   owner command outputs when it claims portable replay of host runtime
   closure. Until then, the manifest states the recorded host boundary.
4. Parser safety work adds a hardware free packet corpus and calibrated
   mutations around `r300_packet0_check` before changing its command policy.
5. Any new ioctl, callback, work item, debugfs node, file operation, ASIC
   table, or passed function expands the declared indirect edge denominator
   and the self test mutation matrix.
6. Any new hazardous path gains an exact contextual witness, maximum side
   effect class, semantic checker owner, and explicit runtime nonclaim.
7. `steinmarder-r300` records a read only Vostro production baseline with
   module, package, boot, device, and log identity before any attended runtime
   escalation.
8. `radeon-custom` advances its signed source pin and package attestation only
   after the source branch merges. Deployment identity remains separate from
   source and hardware acceptance.
9. A completion claim requires a clean full verifier, all semantic checkers,
   both exact kernel roots, the required CI status, merged pull request, synced
   main checkout, and an explicit ledger of runtime checks that remain not run.
