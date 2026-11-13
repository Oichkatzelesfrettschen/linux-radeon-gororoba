# Declared kernel toolchains

Each SHA-256 manifest binds the four distribution packages used to compile one
retained kernel root: `llvm-libs`, `llvm`, `clang`, and `lld`. It also binds
the detached signature for every package. The source workflow verifies all
sixteen file identities, asks `pacman-key` to verify each selected package,
and extracts the packages into a new directory under `RUNNER_TEMP`.
The 22.1.6 manifest selects the signed Arch Linux archive packages because the
matching CachyOS packages left every configured mirror after cache eviction.
Their signatures identify Arch Linux key
`D2E95FEC015CF1F911AAAB0C3D4C5008BB5C8D29`. The 22.1.8 manifest selects
CachyOS packages signed by key
`882DCFE48E2051D48E2562ABF3B607488DB35A47`.

The 6.18.38 root uses Clang and LLD 22.1.6. The 7.1.4 root uses Clang and LLD
22.1.8. The module build jobs place each package supplied `usr/bin` first in
`PATH` and its `usr/lib` in `LD_LIBRARY_PATH`. The module harness rejects every
warning, including a compiler version mismatch.

The `steinmarder-r300` source map lanes use the root owned prefixes under
`/opt/gororoba/toolchains`. Each schema 2 declaration binds a 19 row semantic
execution closure and a separate full prefix manifest with 7,174 descendants.
The producer verifies the exact tree, ownership, modes, effective runner
writes, extended attributes, symlink targets, and Clang resource directory
before it executes a tool. Kbuild uses `/usr/bin/make`, `/usr/bin/sh`, the
absolute LLVM bin prefix, and `PATH=/usr/bin:/bin`. A second scan uses the same
in-memory prefix entries admitted before compilation.

The package cache is an explicit offline input. The detailed 22.1.6 prefix
closure manifests retain the earlier CachyOS package observation and do not
describe the replacement Arch package bytes. A missing package, changed
package byte, changed signature byte, failed signature, compiler warning, or
module build failure stops the job. This contract proves compiler and linker
identity plus bounded module compilation. It does not prove module loading,
runtime reachability, or hardware behavior.

## Consumers

No workflow or script reads these manifests since the module builds moved to
hosted runners inside the pinned CachyOS container (`rg -n
'kernel-toolchains|kernel-build-closure|clang-lld-'` over the tree matches only
documentation and the manifests themselves). They retain the toolchain
identity of the 6.18.38 and 7.1.4 roots in `ci/kernel-build-roots` and the
evidence cited by `README.md` and the two contract documents under `docs/`.

The `source-static` module builds take their compiler from the kernel instead:
`scripts/match_kernel_toolchain.py` reads `CONFIG_CC_VERSION_TEXT` and
`CONFIG_PAHOLE_VERSION` from each lane's headers package and installs the exact
signed build from the Arch Linux Archive when the repository serves a different
one, so the two lanes follow their kernels when CachyOS rebuilds them.
