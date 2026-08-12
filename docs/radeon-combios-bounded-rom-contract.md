# Radeon COMBIOS bounded ROM contract

The Radeon BIOS loader now preserves the byte extent returned by every
acquisition mechanism. The parser admits one declared x86 PCI image, contracts
the accessible extent to that image, and rejects any BIOS header or table span
outside it. A failed read latches `bios_parse_failed` until the image is freed
or replaced.

This contract targets the COMBIOS path used by RS400 and RS480 devices. The
retained Dell Vostro 1000 firmware identifies a COMBIOS image for the RS482
device `1002:5974`. It does not identify an ATOM image, so the ATOM bounds carry
source and compile evidence without an RS482 firmware replay or hardware
promotion.

## Acquisition boundary

The loader records the actual copied extent for each source:

* PCI ROM mapping records the mapping size.
* Platform ROM mapping records `romlen`.
* ATRM records each returned buffer length and rejects a response longer than
  the requested destination span.
* VFCT checks the image header and content length with subtraction before it
  duplicates the image.
* Integrated graphics VRAM recovery records its fixed copied extent.

`radeon_get_bios` then validates the `PCIR` structure, its 512 byte image length
units, its x86 code type, and the Radeon BIOS header. The recorded size becomes
the declared first PCI image size. Later images and bytes after that boundary
are not parser input.

All teardown paths call `radeon_bios_fini`. The helper clears the pointer,
extent, and failure latch together, so a later acquisition cannot inherit a
stale bound.

## COMBIOS execution boundary

`RBIOS8`, `RBIOS16`, and `RBIOS32` use subtraction based span checks before
loading little endian values. A failed span returns zero and latches the parser
failure. COMBIOS contains no direct BIOS array subscript.

ASIC initialization uses a two pass transaction:

1. It resolves every selected table before a hardware operation.
2. It validates the complete MMIO, PLL, RAM reset, detected memory, memory
   configuration, and dynamic clock table grammar.
3. It executes the already validated tables in the original order.
4. It returns `-EINVAL` to the reset or resume owner when validation fails.

External TMDS programming applies the same full table preflight before MMIO,
PLL, delay, or I2C operations. Hardcoded EDID handling validates the base block
before reading the extension count and validates the resulting complete span
before allocation.

The contract prevents an out of bounds firmware read and prevents a truncated
hardware driving table from executing a valid prefix. It does not prove that a
well formed command is safe for a particular board. Register and runtime
verdicts remain owned by `steinmarder-r300`.

## ATOM interpreter boundary

`atom_parse` receives the admitted BIOS image size from `radeon_atombios_init`.
Its structural readers validate the ROM header, master command table, master
data table, indirect IO programs, and table headers against that full image.
Its execution readers use a narrower interval whose lower edge is the first
command byte and whose upper edge is the table's declared size. A nested table
call saves and restores its caller's interval.

An operand read that crosses the active command interval latches `io_error`.
Register, PLL, MC, scratch, parameter, and workspace access stops after that
latch, and the dispatcher returns `-EINVAL`. This prevents a truncated operand
from becoming register zero or another valid hardware access.

The boundary does not make every typed ATOM data table view size aware. Files
such as `radeon_atombios.c` and the DPM implementations still cast validated
table starts to versioned structures. The source verifier requires that
frontier to remain visible and nonempty. A later batch carries each table's
declared size through those consumers and proves the minimum structure extent
for every version before field access.

## Exact firmware replay

The source verifier accepts an optional ROM without touching hardware:

```sh
python3 scripts/check_radeon_bios_bounds.py \
  --rom /path/to/vostro1000-rs482-vbios.rom
```

The admitted Vostro ROM has SHA-256
`70868602cd6aafd7439532504e7dfabfa6966ae4b161b113e2aabad46a9ce807`
and a 53,248 byte declared first image. Its IGP tables contain 19 ASIC init 1
commands, 40 PLL init commands, 20 ASIC init 2 commands, and 8 dynamic clock 1
commands. These counts are static firmware structure, not runtime execution or
silicon evidence.

## Capacity authority separation

The signed source policy authority at commit
`6667d7561617debdc62cf99c62fb47bd67f95043` supplies the four row RS482 GTT
selector matrix and the original 14 row VRAM and GTT source contract. The
current capacity policy preserves that lineage and expands its source analysis.
That policy intake changes no driver C behavior.

The COMBIOS bound and the capacity policy answer independent questions. The
COMBIOS contract limits firmware parsing and table execution. The capacity
contract models aperture selection, metadata, allocator space, placement, and
observation. Neither contract selects an optimal GTT size or establishes a
hardware result.

## Verification

```sh
python3 scripts/check_radeon_bios_bounds.py --selftest
python3 scripts/check_radeon_bios_bounds.py
python3 scripts/check_radeon_atom_bounds.py --selftest
python3 scripts/check_radeon_atom_bounds.py
ruff check scripts/
ruff format --check scripts/
```

The self test admits the current source and rejects twelve mutations covering
direct BIOS access, missing extent ownership, arithmetic overflow, ATRM and
VFCT overrun, missing PCI image identity, incomplete EDID bounds, execution
before preflight, and missing TMDS preflight. Both required kernel module lanes
must also compile with warnings treated as errors.

The ATOM self test admits the current source and rejects seventeen mutations
covering missing image extent, overflow, unbounded reads, command underflow and
overflow, opcode fetch bypass, operand-triggered register access, nested-table
interval restoration, nested parameter windows, workspace failure cleanup,
malformed indirect IO, and raw master-table access.
