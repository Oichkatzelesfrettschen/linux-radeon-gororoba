# Declared kernel toolchains

Each SHA-256 manifest binds the four CachyOS packages used to compile one
retained kernel root: `llvm-libs`, `llvm`, `clang`, and `lld`. It also binds
the detached signature for every package. The source workflow verifies all
sixteen file identities, asks `pacman-key` to verify each selected package,
and extracts the packages into a new directory under `RUNNER_TEMP`.
The pinned signatures identify CachyOS key
`882DCFE48E2051D48E2562ABF3B607488DB35A47`.

The 6.18.38 root uses Clang and LLD 22.1.6. The 7.1.4 root uses Clang and LLD
22.1.8. The workflow places the selected `usr/bin` first in `PATH` and its
`usr/lib` in `LD_LIBRARY_PATH` before it invokes the module harness. The
harness rejects every warning, including a compiler version mismatch.

The package cache is an explicit offline input. A missing package, changed
package byte, changed signature byte, failed signature, compiler warning, or
module build failure stops the job. This contract proves compiler and linker
identity plus bounded module compilation. It does not prove module loading,
runtime reachability, or hardware behavior.
