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
| Guard census | `analysis/hazard-guard-identifier-census.tsv` | Policy named guard identifiers occur in bounded owner functions. The product is not a control flow proof. |
| Effect census | `policy/radeon-driver-source-map.toml` | Policy named effect identifiers replay against bounded owner functions without entering the guard product. The census is not a side effect proof. |
| Complexity | `analysis/lizard.csv`, `analysis/scc.json`, `analysis/coefficient-vectors.tsv` | Function NLOC, CCN, graph degree, indirect edges, side effect class, guard census, and evidence rank remain separately inspectable. |
| Build lanes | `preprocessed/<release>/<profile>/` | Every declared lane retains 21 normalized translation units, one linked module, raw symbols, canonical symbols, and build metadata. |
| Profile deltas | `analysis/profile-symbol-delta-summary.tsv`, `analysis/profile-symbol-delta-members.tsv` | Canonical symbols strip only a terminal `.llvm.<digits>` suffix, reject collisions, and preserve exact additions and removals. |
| Tool provenance | `metadata/tool-versions.tsv`, `metadata/kernel-toolchains.tsv`, `metadata/kernel-toolchain-closures/`, `metadata/toolchain-runtime-libraries.tsv` | Required analyzer executables carry exact hashes. Each LLVM lane retains the 7,174 entry prefix tree, the 19 row semantic execution closure, resource paths, and recorded host runtime rows. |
| Execution record | `metadata/command-metadata.tsv`, `diagnostics/` | Every producer command has an exact identifier, tool, working directory, status, output ownership, argument vector, and environment. |
| Seal | `capture-hashes.sha256` | Every expected regular file except the ledger itself has one content digest. |

<!-- markdownlint-enable MD013 -->

## Reference capture attestation

The complete reference capture identifies source and producer commit
`8158297e70cdea90b69149d700c25957a91f764d`. Its local bundle name is
`radeon-driver-source-map-control-admission/8158297-complete-kernel-lanes`.
The name is a convenience label. The Git proofs and manifest identify the
content.

<!-- markdownlint-disable MD013 -->

| Property | Value |
| --- | --- |
| Capture schema | `gororoba-radeon-driver-source-map-v2` |
| Source files | 222 |
| Source bytes | 6,909,890 |
| Regular files | 901 |
| Ledger rows | 900 |
| Bundle size | 961 MiB on the capture filesystem |
| Lexical rows | 98,390 |
| Call candidates | 15,633 |
| Declared indirect bindings | 45 |
| Contextual witnesses | 4 |
| Contextual witness edges | 29 |
| Typed joins | 4 |
| Profile comparisons | 7 |
| Profile delta members | 178 |
| Producer commands | 176 |
| Manifest SHA-256 | `47d61a02e7df2718ca80e971accad2ab67237836c8a0b383253c8d10208c0363` |
| Ledger SHA-256 | `8bc55ea31649a7c76f813288c277acd45842ca3870fcac81f1d660b96e91f20c` |

<!-- markdownlint-enable MD013 -->

The 900 ledger rows cover every regular file except
`capture-hashes.sha256`. The independent verifier passes with
`--require-all-kernel-lanes`. The producer self test rejects changed content,
extra top level and nested files, incomplete command records, changed raw
cscope queries, and forged call witnesses. The full verifier independently
derives coefficient rows from lizard, cflow, and binding replay. These checks
prove that verification does not reduce to self consistent hashing.

## Graph decomposition

The unified candidate graph has the exact decomposition:

```text
15,492 GNU cflow lexical edges
    96 syntax extracted indirect candidates
    45 policy declared indirect bindings
------
15,633 total call candidates
```

The lexical portion classifies 6,774 edge rows as calls to driver symbols and
8,718 edge rows as calls to external symbols. The remaining call candidate
rows carry precise callback, table, macro, wrapper, registration, family
selection, and reset mode classifications. The four event joins remain in the
separate contextual path product. The 96 extracted rows remain candidates.
All 45 declared rows pass exact matching, and the 28 brace scoped rows also
pass containment checks.

The seven focused partitions contain 3,149 lexical rows:

<!-- markdownlint-disable MD013 -->

| Partition | Lexical rows | Architecture surface |
| --- | ---: | --- |
| Module lifecycle | 1,344 | Module load, PCI probe, KMS load, device initialization, unload, and module exit. |
| Reset and park | 849 | Detected reset, forced reset, ASIC reset dispatch, lockup work, parked containment, and reset probes. |
| Command submission | 674 | DRM ioctl entry, parser initialization, IB chunks, ring parser selection, and packet zero validation. |
| GART and memory | 102 | TTM initialization, common GART ownership, RS400 table setup, PTE writes, and TLB flush. |
| KMS and debugfs | 85 | DRM minor debugfs registration, RS480 development nodes, and Palm reset node ownership. |
| Profile and admission | 57 | Runtime profile selection, hardware availability, GEM creation, PRIME import, and dumb creation. |
| Register policy generation | 38 | Register source parsing, safe bitmap generation, and RS4xx runtime policy application. |

<!-- markdownlint-enable MD013 -->

`cflow/full-call-candidates.txt` and
`cflow/full-call-candidates.dot` retain the full lexical tree. Each partition
has corresponding text and DOT output under `cflow/partitions/`.
`queries/cscope-root-symbols.tsv` retains 689 parsed rows for 43 root symbols
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
`CHIP_PALM`, `radeon_dev_hardware_available` to return zero, the exact unsafe
module parameter value `1`, file position zero, and the exact command `1`. Its
maximum side effect remains a PCI configuration reset. The exact gates
constrain entry but do not lower the side effect classification.

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
mechanism="radeon-driver-source-map-control-admission"
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
mechanism="radeon-driver-source-map-control-admission"
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
outside Git because the complete reference bundle occupies 961 MiB and
contains build products.

Two sealed captures compare through normalized products:

```sh
python3 scripts/capture_radeon_driver_source_map.py \
  --compare "$left_capture" "$right_capture" \
  --output "$comparison_output"
```

## Matched-generation source comparison

The reference comparison uses two captures produced by commit
`8158297e70cdea90b69149d700c25957a91f764d`. Their producer tree, source-map
policy, build-feature policy, tool versions, kernel build-root evidence,
toolchain closure evidence, and retained producer inputs are byte identical.
Among admitted identities, only the source commit, source tree, and driver
subtree differ. Derived source products differ accordingly. Every
producer-side admission field listed above is equal. This equality is an
explicit admission check because comparison schema v3 records input source
commits and ledger hashes but does not record or enforce producer and policy
equality. The v3 verifier authenticates retained comparison-v2 capture
policies through the exact supported set of v2 and v3. New capture production
accepts only comparison v3, and retained comparison v1 remains rejected.

The left input recaptures source commit
`7a353a84d863a4ef2326a81cc837fb3d03408665` under the admitted producer. Its
bundle name is
`radeon-driver-source-map-control-admission/7a353a8-source-under-8158297-producer-complete-kernel-lanes`.
It contains 901 regular files and 900 ledger rows. Its manifest SHA-256 is
`599d5f31f80f06f8f5da8df0a593d6bc6de8c884049ea6eebe37f8fa254c01bc`,
and its ledger SHA-256 is
`15bed05438b9e06847b5bcf6a4e97f179301b04c68d1d5eda07fd369467cf42d`.
The all-lane verifier passes independently.

The comparison bundle name is
`radeon-driver-source-map-unique-tsv-columns/7a353a8-to-8158297-matched-capture-v3-comparison`.
The comparison producer uses Git blob
`b417ab2411527be82e58cb077171c02fa3dbb92d`, whose file SHA-256 is
`45a8a4b02c807701e58a53a326d0d29b1acf8c2e4b6d46d8d1c91c2e3f414317`.
Its manifest SHA-256 is
`f57596bd6ee90c763e5f35bc65a386d29c375cd31a8f31f85cba4ffd4485227a`,
and its nine-row ledger SHA-256 is
`932ca33e4c26dbe87c79c842b25096c184a90a94b403ce38c9ee8cf0b4691dc3`.
Independent `sha256sum --check` verification passes.
The profile member product uses schema
`radeon-driver-profile-symbol-delta-member-delta-v2` and keeps the outer
`capture_change` column distinct from the inner profile `change` column.

<!-- markdownlint-disable MD013 -->

| Product | Removed | Added | Changed | Result |
| --- | ---: | ---: | ---: | --- |
| Source files | 0 | 0 | 1 | One file changes in place: `drivers/gpu/drm/radeon/radeon_rs4xx_dev.c`, from 117,969 to 120,595 bytes. |
| Call candidates | 3 | 20 | 0 | The candidate graph grows by 17 edges. |
| Declared binding evidence | 5 | 5 | 0 | Five stable binding IDs retain their matched text and move with the changed file identity and line positions. |
| Contextual path edges | 0 | 0 | 0 | The four contextual witness topologies remain unchanged. |
| Contextual path joins | 0 | 0 | 0 | The four typed event and callback joins remain unchanged. |
| Profile delta summaries | 0 | 0 | 0 | All seven within-capture profile comparisons retain their canonical counts and set hashes. |
| Profile delta members | 4 | 4 | 0 | Only the raw terminal LLVM suffix for `rs400_gart_page_table_lock` changes in four profile pairs. |
| Coefficient vectors | 1 | 1 | 0 | `rs480_wedged_3d_reset` moves from line 1788 to 1876 with every numeric and categorical coefficient unchanged. |

<!-- markdownlint-enable MD013 -->

The source grows by 2,626 bytes. The lexical index grows from 98,353 to
98,390 rows. The cscope root-query product changes from 696 to 689 rows while
retaining the same 43-symbol and 129-query denominator. The call graph makes
schema emission, parked or suspended refusal, and CP-ME terminal selection
explicit through `rs480_debugfs_emit_schema`,
`rs480_debugfs_refuse_hardware_access`,
`rs480_cp_me_ram_seq_terminal_position`,
`rs480_cp_me_ram_seq_is_terminal`, and
`rs480_cp_me_ram_seq_emit_terminal`. This decomposition adds structural edges
without changing the selected reset coefficient vector. It does not establish
runtime reachability or target behavior.

The native `7a353a8` bundle remains valid under its retained native verifier,
with ledger SHA-256
`1c52018a227921a67eab061cc518d8796d50a3ead35d5908448ecb88d44c17b2`.
The `8158297` verifier rejects it because its schema v1 lane policy lacks the
full LLVM prefix manifests. All 176 native command rows also differ from the
admitted command contract. The native bundle therefore supplies legacy
producer evidence, not a source-comparison endpoint.

The same-source producer control compares that native bundle with the
`7a353a8` recapture. Every one of the six module hashes changes. The raw
defined-symbol name sets replace 30 names in each production lane, 31 names
in the 7.1 observe and probe lanes, and 33 names in each mutate lane. Every
replacement changes only a terminal `.llvm.<digits>` suffix. Removing only
that suffix produces zero added names, zero removed names, and zero canonical
collisions in all six lanes. Module bytes and raw LLVM suffixes are therefore
producer-sensitive evidence even when source and compiler executables match.
The matched-generation comparison keeps that producer effect outside the
source delta.

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

## Live RS482 capacity-policy extension

The sealed `8158297` reference remains an attestation of its original 43 roots
and 45 declared bindings. The live policy extends the next capture to 73 roots,
13 hazards, and 55 exact declared bindings. It adds request normalization,
RS400 ASIC initialization, selector adjustment, address fit, TTM managers,
allocator movement, pin accounting, capacity ioctls, GEM observation, and the
excluded raw VRAM and GTT reader boundary.

The producer pins every partition and root pair with SHA-256
`a680ddd050ac81de5cbc82263d87e158498e267091a3a6d5eb93b087bbb97814`,
every hazard record with SHA-256
`79221ccd7fd2d9e8070d9ca957f8645b927ccfe79191c2b86e65059df0f62be5`,
and every normalized binding record with SHA-256
`e6c66efadb75917286117ed984ec52a90d108ae347d8cee603bbafff17c9df77`.
Policy loading rejects a missing, added, moved, or changed member before
capture.

Policy schema 2 owns these exact live denominators and the separate effect
identifier census. New capture production accepts schema 2 only. Retained
capture verification also accepts schema 1 and replays its original product
set without applying schema 2 counts or adding a new analysis file.
The live topology carries six contextual witnesses. The two added witnesses
separate TTM debugfs registration from later `radeon_vram` and `radeon_gtt`
read dispatch. The VRAM reader carries an MMIO index write plus a data read;
the GTT reader copies host backing-page content. Neither path is promoted to a
runtime event or admitted capacity-trial input.

The root expansion changes the producer-derived cscope denominator from 129 to
219 raw queries. It changes the source-only command contract from 156 to 246
rows and the complete kernel-lane command contract from 176 to 266 rows. The
90 added rows are the three cscope queries for each of 30 new roots. The
analyzer, kernel build, and profile command sets otherwise remain unchanged.

`scripts/check_rs4xx_vram_gtt_capacity.py` owns the semantic source contract.
The source map owns structural candidates only. The source-only attestation
below reproduces the expanded denominator. It does not replace the sealed
six-lane reference figures.

### RS482 capacity source-only attestation

The retained bundle uses this mechanism path beneath the source-intelligence
root:

```text
rs482-vram-gtt-capacity-source-map/7d4ba8ae75d94d0e608de56762ee97cb1d9c4188-source-only
```

The producer creates the bundle and then verifies it offline with exit zero.
The capture contains 779 regular files. Its ledger covers the other 778 files.

<!-- markdownlint-disable MD013 -->

| Field | Exact value |
| --- | --- |
| Source commit | `7d4ba8ae75d94d0e608de56762ee97cb1d9c4188` |
| Source tree | `f10cd2f5fbe4715cf13aae0546a4b9e650bf7e99` |
| Driver tree | `6fd8d3c6ec245c31f195ef86c15fadf5e206642d` |
| Driver-source inputs | 222 files and 6,909,890 bytes |
| Lexical map | 98,390 rows |
| Cscope denominator | 73 root symbols, 219 raw queries, and 1,053 parsed rows |
| Command denominator | 246 rows: 226 bwrap, 16 cflow, and one each for ctags, readtags, lizard, and scc |
| Declared bindings | 55 total and 14 in GART and memory |
| Unified call candidates | 15,643 rows |
| Manifest SHA-256 | `fb65e6d3999ff0b2d8350f89f9cf491d465dff1a52f74ec14a8a3a805f222704` |
| Ledger SHA-256 | `2713ff2fb983294a3af6ca40220b38ef7902ee9134137993dbb73b197810bf89` |

<!-- markdownlint-enable MD013 -->

The driver tree equals the sealed six-lane reference driver tree. The ten-row
call-candidate increase comes from the ten new declared bindings. The source
capture carries no kernel lane, linked module, profile delta, runtime event, or
hardware verdict. Required CI still runs the complete two-kernel, six-profile
producer after publication.

## Roadmap and completion gates

The source intelligence program advances through these concrete gates:

1. The protected branch defines
   `RADEON_LLVM_TOOLCHAIN_BIN_618` and `RADEON_LLVM_TOOLCHAIN_BIN_71` as the
   two `/opt/gororoba/toolchains/` bin directories. The active ruleset requires
   the green `source-map-kernel-lanes` status, so a source map regression blocks
   integration.
2. The complete reference capture and matched-generation comparison retain
   the six lane modules, profile deltas, source graph deltas, and exact hash
   ledgers described above. The retained native bundle and admitted recapture
   supply the separate same-source producer control.
3. The comparison command next rejects unequal producer commits, producer
   trees, policy hashes, analyzer identities, kernel-root evidence, or
   toolchain closures and records those identities in its manifest.
4. A future capture retains raw `ldd`, ELF dependency, SONAME, and package
   owner command outputs when it claims portable replay of host runtime
   closure. Until then, the manifest states the recorded host boundary.
5. Parser safety work adds a hardware free packet corpus and calibrated
   mutations around `r300_packet0_check` before changing its command policy.
6. Any new ioctl, callback, work item, debugfs node, file operation, ASIC
   table, or passed function expands the declared indirect edge denominator
   and the self test mutation matrix.
7. The RS482 capacity source checker closes its four selectors, ten exclusions,
   ten coefficients, 36 source functions, module request, ioctl table, and
   register encodings before any target trial. A fresh source-only capture and
   the required complete kernel-lane CI job close the 73-root, 13-hazard,
   55-binding, six-witness graph.
8. Any new hazardous path gains an exact contextual witness, maximum side
   effect class, semantic checker owner, and explicit runtime nonclaim.
9. `steinmarder-r300` records a read only Vostro production baseline with
   module, package, boot, device, effective GTT interval, allocator counters,
   and log identity before any allocation-pressure or submit trial.
10. `radeon-custom` advances its signed source pin and package attestation only
    when the driver source subtree identity changes. A policy-only batch does
    not advance that pin. Deployment identity remains separate from source and
    hardware acceptance.
11. A completion claim requires a clean full verifier, all semantic checkers,
   both exact kernel roots, the required CI status, merged pull request, synced
   main checkout, and an explicit ledger of runtime checks that remain not run.
