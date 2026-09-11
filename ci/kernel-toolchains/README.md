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
