#!/usr/bin/env python3
"""Verify the source-static ATOM image bounds contract."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_BAD_COUNT = 17


class ContractError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def read_text(root: Path, relative_path: str) -> str:
    return (root / relative_path).read_text(encoding="ascii")


def check_tree(root: Path) -> None:
    atom_header = read_text(root, "drivers/gpu/drm/radeon/atom.h")
    atom_bits = read_text(root, "drivers/gpu/drm/radeon/atom-bits.h")
    atom_source = read_text(root, "drivers/gpu/drm/radeon/atom.c")
    device_source = read_text(root, "drivers/gpu/drm/radeon/radeon_device.c")

    require(
        "size_t bios_size;" in atom_header
        and "size_t bios_read_start;" in atom_header
        and "size_t bios_read_limit;" in atom_header
        and "bool io_error;" in atom_header,
        "ATOM context image bounds state differs",
    )
    require(
        "struct atom_context *atom_parse(struct card_info *, void *, size_t);"
        in atom_header,
        "ATOM parser extent interface differs",
    )
    require(
        "atom_parse(atom_card_info, rdev->bios," in device_source
        and "rdev->bios_size);" in device_source,
        "Radeon BIOS extent does not reach the ATOM parser",
    )
    require(
        "(size_t)ptr < ctx->bios_read_start" in atom_bits
        and "(size_t)ptr > ctx->bios_read_limit" in atom_bits
        and "length > ctx->bios_read_limit - (size_t)ptr" in atom_bits
        and "ctx->io_error = true;" in atom_bits,
        "ATOM active read span predicate differs",
    )
    require(
        "(size_t)ptr > ctx->bios_size" in atom_bits
        and "length > ctx->bios_size - (size_t)ptr" in atom_bits,
        "ATOM full image span predicate differs",
    )
    require(
        "if (!atom_span_valid(ctx, ptr, sizeof(uint8_t)))" in atom_bits
        and "return ((uint8_t *)ctx->bios)[ptr];" in atom_bits
        and "get_unaligned_le16((uint8_t *)ctx->bios + ptr)" in atom_bits
        and "get_unaligned_le32((uint8_t *)ctx->bios + ptr)" in atom_bits,
        "ATOM typed image readers differ",
    )
    require(
        "get_u8(void *bios" not in atom_bits
        and "get_u16(void *bios" not in atom_bits
        and "get_u32(void *bios" not in atom_bits
        and "#define CSTR" not in atom_bits,
        "an unbounded ATOM image reader remains",
    )
    require(
        "atom_span_valid(ctx, base + ATOM_ROM_MAGIC_PTR" in atom_source
        and "atom_span_valid(ctx, ctx->cmd_table, 4)" in atom_source
        and "atom_span_valid(ctx, ctx->data_table, 4)" in atom_source,
        "ATOM root table spans differ",
    )
    require(
        "op >= ARRAY_SIZE(atom_iio_len)" in atom_source
        and "atom_span_valid(ctx, base, atom_iio_len[op])" in atom_source,
        "ATOM indirect I/O table bounds differ",
    )
    require(
        "ctx->bios_read_start = base + ATOM_CT_CODE_PTR;" in atom_source
        and "ctx->bios_read_limit = base + len;" in atom_source
        and "size_t previous_read_start = ctx->bios_read_start;" in atom_source
        and "ctx->bios_read_start = previous_read_start;" in atom_source,
        "ATOM command bytecode interval differs",
    )
    require(
        "op = CU8(ptr++);" not in atom_source
        and "op = get_u8(ctx, ptr++);" in atom_source,
        "ATOM opcode fetch does not use the command interval",
    )
    require(
        atom_source.count("if (gctx->io_error)\n\t\t\treturn 0;") >= 6
        and atom_source.count("if (gctx->io_error)\n\t\t\treturn;") >= 6,
        "ATOM operand failure does not stop register or state access",
    )
    require(
        "if (gctx->io_error)\n\t\t\treturn 0;\n\t\tif (print)\n"
        '\t\t\tDEBUG("REG[0x%04X]", idx);'
        in atom_source
        and 'if (gctx->io_error)\n\t\t\treturn;\n\t\tDEBUG("REG[0x%04X]", idx);'
        in atom_source,
        "ATOM register operand failure guards differ",
    )
    require(
        "int parameter_bytes = ctx->ps_shift * sizeof(u32);" in atom_source
        and "if (parameter_bytes > ctx->ps_size)" in atom_source
        and "ctx->ps_size - parameter_bytes" in atom_source,
        "ATOM nested parameter window bounds differ",
    )
    require(
        "if (!ectx.ws) {\n\t\t\tret = -ENOMEM;" in atom_source
        and "free:\n\tdebug_depth--;\n\tkfree(ectx.ws);" in atom_source,
        "ATOM workspace failure cleanup differs",
    )
    require(
        "ctx->ps_size >= sizeof(u32)" in atom_source
        and atom_source.count("(ctx->ps_size - sizeof(u32)) / sizeof(u32)") == 2,
        "ATOM parameter byte extent differs",
    )
    require(
        atom_source.count("offset > table_size - sizeof(u16)") == 2
        and atom_source.count("atom_span_valid(ctx, idx, table_size)") == 2,
        "ATOM master table header bounds differ",
    )
    require(
        "(u16 *)(ctx->bios + ctx->data_table + 4)" not in atom_source
        and "(u16 *)(ctx->bios + ctx->cmd_table + 4)" not in atom_source,
        "ATOM master table lookup retains a raw cast",
    )

    raw_cast_rows = re.findall(
        r"atom_context->bios\s*\+|ctx->bios\s*\+\s*data_offset",
        "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted((root / "drivers/gpu/drm/radeon").glob("*.c"))
            if path.name != "atom.c"
        ),
    )
    require(raw_cast_rows, "downstream ATOM table-view denominator disappeared")


def self_test(root: Path) -> None:
    check_tree(root)
    source_paths = {
        "atom.h": "drivers/gpu/drm/radeon/atom.h",
        "atom-bits.h": "drivers/gpu/drm/radeon/atom-bits.h",
        "atom.c": "drivers/gpu/drm/radeon/atom.c",
        "radeon_device.c": "drivers/gpu/drm/radeon/radeon_device.c",
    }
    originals = {name: read_text(root, path) for name, path in source_paths.items()}
    mutations = (
        ("missing image extent", "atom.h", "\tsize_t bios_size;\n", ""),
        (
            "overflow-prone span arithmetic",
            "atom-bits.h",
            "length > ctx->bios_read_limit - (size_t)ptr",
            "(size_t)ptr + length > ctx->bios_read_limit",
        ),
        (
            "missing command lower bound",
            "atom-bits.h",
            " || (size_t)ptr < ctx->bios_read_start",
            "",
        ),
        (
            "opcode fetch bypasses command bounds",
            "atom.c",
            "\t\top = get_u8(ctx, ptr++);",
            "\t\top = CU8(ptr++);",
        ),
        (
            "command interval starts at image origin",
            "atom.c",
            "ctx->bios_read_start = base + ATOM_CT_CODE_PTR;",
            "ctx->bios_read_start = 0;",
        ),
        (
            "register write follows a failed operand read",
            "atom.c",
            '\t\tif (gctx->io_error)\n\t\t\treturn;\n\t\tDEBUG("REG[0x%04X]", idx);',
            '\t\tDEBUG("REG[0x%04X]", idx);',
        ),
        (
            "register read follows a failed operand read",
            "atom.c",
            '\t\tif (gctx->io_error)\n\t\t\treturn 0;\n\t\tif (print)\n\t\t\tDEBUG("REG[0x%04X]", idx);',
            '\t\tif (print)\n\t\t\tDEBUG("REG[0x%04X]", idx);',
        ),
        (
            "command interval is not restored",
            "atom.c",
            "\tctx->bios_read_start = previous_read_start;\n",
            "",
        ),
        (
            "nested table parameter window underflows",
            "atom.c",
            "\tif (parameter_bytes > ctx->ps_size) {\n",
            "\tif (false) {\n",
        ),
        (
            "workspace allocation failure is ignored",
            "atom.c",
            "\t\tif (!ectx.ws) {\n\t\t\tret = -ENOMEM;\n\t\t\tgoto restore;\n\t\t}\n",
            "",
        ),
        (
            "error exit leaks debug depth",
            "atom.c",
            "free:\n\tdebug_depth--;\n\tkfree(ectx.ws);",
            "free:\n\tkfree(ectx.ws);",
        ),
        (
            "parameter size is treated as a word count",
            "atom.c",
            "ctx->ps_size >= sizeof(u32) &&\n\t\t    ",
            "",
        ),
        (
            "unbounded byte reader",
            "atom-bits.h",
            "if (!atom_span_valid(ctx, ptr, sizeof(uint8_t)))",
            "if (false)",
        ),
        (
            "missing IIO opcode denominator",
            "atom.c",
            "op >= ARRAY_SIZE(atom_iio_len) ||\n\t\t\t    ",
            "",
        ),
        (
            "missing data-table extent",
            "atom.c",
            "\t    !atom_span_valid(ctx, ctx->data_table, 4) ||\n",
            "",
        ),
        (
            "raw data-table cast",
            "atom.c",
            "\tint idx;\n\tu16 table_size;\n",
            "\tint idx;\n\tu16 table_size;\n\tu16 *mdt = (u16 *)(ctx->bios + ctx->data_table + 4);\n",
        ),
        (
            "dropped Radeon extent",
            "radeon_device.c",
            "atom_parse(atom_card_info, rdev->bios,\n\t\t\t\t\t\t rdev->bios_size)",
            "atom_parse(atom_card_info, rdev->bios)",
        ),
    )

    import tempfile

    with tempfile.TemporaryDirectory(prefix="radeon-atom-bounds-") as temp_dir:
        temp_root = Path(temp_dir)
        for relative_path in source_paths.values():
            target = temp_root / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
        for path in (root / "drivers/gpu/drm/radeon").glob("*.c"):
            target = temp_root / "drivers/gpu/drm/radeon" / path.name
            target.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")

        for label, name, old, new in mutations:
            for source_name, relative_path in source_paths.items():
                (temp_root / relative_path).write_text(
                    originals[source_name], encoding="ascii"
                )
            require(old in originals[name], f"self-test anchor is absent: {label}")
            mutated = originals[name].replace(old, new, 1)
            (temp_root / source_paths[name]).write_text(mutated, encoding="ascii")
            try:
                check_tree(temp_root)
            except ContractError:
                continue
            raise ContractError(f"known-bad mutation accepted: {label}")

    require(
        len(mutations) == EXPECTED_BAD_COUNT,
        "self-test mutation denominator differs",
    )
    print(f"Radeon ATOM bounds: 1 good and {len(mutations)} bad source cases")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    try:
        if args.selftest:
            self_test(args.root.resolve())
        else:
            check_tree(args.root.resolve())
            print("Radeon ATOM bounds: source contract proven")
    except (ContractError, OSError) as error:
        print(f"Radeon ATOM bounds: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
