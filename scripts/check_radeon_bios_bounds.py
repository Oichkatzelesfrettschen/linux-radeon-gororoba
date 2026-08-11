#!/usr/bin/env python3
"""Prove the bounded Radeon BIOS acquisition and COMBIOS execution contract."""

from __future__ import annotations

import argparse
import copy
import hashlib
import re
import sys
from pathlib import Path

from check_all_dev_interfaces import InterfaceError, function_body

DRIVER = Path("drivers/gpu/drm/radeon")
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_ROM_BYTES = 1024 * 1024
EXPECTED_BAD_COUNT = 10


class BiosContractError(RuntimeError):
    """Report a bounded BIOS source or image contract violation."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BiosContractError(message)


def read_ascii(path: Path) -> str:
    require(path.is_file(), f"source file is absent: {path}")
    require(
        path.stat().st_size <= MAX_SOURCE_BYTES, f"source file is too large: {path}"
    )
    try:
        return path.read_text(encoding="ascii")
    except UnicodeDecodeError as error:
        raise BiosContractError(f"source file is not ASCII: {path}") from error


def load_sources(root: Path) -> dict[str, str]:
    names = (
        "cik.c",
        "evergreen.c",
        "ni.c",
        "r100.c",
        "r300.c",
        "r420.c",
        "r600.c",
        "radeon.h",
        "radeon_bios.c",
        "radeon_combios.c",
        "radeon_device.c",
        "radeon_mode.h",
        "rs400.c",
        "rs600.c",
        "rs690.c",
        "rv515.c",
        "rv770.c",
        "si.c",
    )
    return {name: read_ascii(root / DRIVER / name) for name in names}


def body(source: str, name: str) -> str:
    try:
        return function_body(source, name)
    except InterfaceError as error:
        raise BiosContractError(str(error)) from error


def require_order(text: str, names: tuple[str, ...], label: str) -> None:
    positions = [text.find(name) for name in names]
    require(all(position >= 0 for position in positions), f"{label} is incomplete")
    require(positions == sorted(positions), f"{label} order differs")


def validate_sources(sources: dict[str, str]) -> None:
    header = sources["radeon.h"]
    bios = sources["radeon_bios.c"]
    combios = sources["radeon_combios.c"]

    require(header.count("size_t\t\t\t\tbios_size;") == 1, "bios_size field differs")
    require(
        header.count("bool\t\t\t\tbios_parse_failed;") == 1,
        "bios_parse_failed field differs",
    )
    require(
        "#define RBIOS8(i) radeon_bios_read_u8(rdev, (size_t)(i))" in header
        and "#define RBIOS16(i) radeon_bios_read_u16(rdev, (size_t)(i))" in header
        and "#define RBIOS32(i) radeon_bios_read_u32(rdev, (size_t)(i))" in header,
        "bounded RBIOS accessors differ",
    )

    span = body(bios, "radeon_bios_span_valid")
    require(
        "offset > rdev->bios_size" in span
        and "length > rdev->bios_size - offset" in span
        and "WRITE_ONCE(rdev->bios_parse_failed, true)" in span,
        "overflow-safe BIOS span contract differs",
    )
    for name, width in (
        ("radeon_bios_read_u8", "sizeof(uint8_t)"),
        ("radeon_bios_read_u16", "sizeof(uint16_t)"),
        ("radeon_bios_read_u32", "sizeof(uint32_t)"),
    ):
        require(width in body(bios, name), f"{name} width differs")

    get_bios = body(bios, "radeon_get_bios")
    require_order(
        get_bios,
        (
            'memcmp(rdev->bios + pcir, "PCIR", 4)',
            "RBIOS16(pcir + 0x10) * 512",
            "rdev->bios_size = image_size",
            "RBIOS8(pcir + 0x14)",
            "radeon_bios_span_valid(rdev, bios_header, 8)",
        ),
        "PCI image admission",
    )
    require(
        "image_size > rdev->bios_size" in get_bios,
        "PCI image length ceiling is absent",
    )

    acquisition_tokens = (
        "rdev->bios_size = size;",
        "rdev->bios_size = romlen;",
        "rdev->bios_size += ret;",
        "rdev->bios_size = vhdr->ImageLength;",
    )
    require(
        all(token in bios for token in acquisition_tokens),
        "BIOS acquisition size propagation differs",
    )
    require(
        "obj->buffer.length > length" in body(bios, "radeon_atrm_call"),
        "ATRM returned-length ceiling is absent",
    )
    require(
        "vhdr->ImageLength > tbl_size - offset" in body(bios, "radeon_acpi_vfct_bios"),
        "VFCT subtraction bound is absent",
    )

    direct_indexes = re.findall(r"rdev->bios\s*\[", combios)
    require(not direct_indexes, "COMBIOS contains a direct BIOS array access")
    require(
        "radeon_bios_span_valid(rdev, edid_info, EDID_LENGTH)" in combios
        and "radeon_bios_span_valid(rdev, edid_info, size)" in combios,
        "hardcoded EDID span checks differ",
    )

    asic_init = body(combios, "radeon_combios_asic_init")
    require_order(
        asic_init,
        (
            "combios_validate_mmio_table(rdev, asic_init_1)",
            "combios_validate_pll_table(rdev, pll_init)",
            "combios_validate_ram_reset_table(rdev, ram_reset)",
            "combios_validate_ram_size_tables(rdev, detected_mem, mem_config)",
            "combios_parse_mmio_table(dev, asic_init_1)",
            "combios_write_ram_size(dev, detected_mem, mem_config)",
        ),
        "COMBIOS preflight and execution",
    )
    require(
        asic_init.count("combios_parse_mmio_table(dev, asic_init_1);") == 1,
        "ASIC init 1 execution denominator differs",
    )
    require(
        "return -EINVAL;" in asic_init,
        "COMBIOS preflight failure does not propagate",
    )
    require(
        "combios_validate_external_tmds_table(rdev, offset, true)" in combios
        and "combios_validate_external_tmds_table(rdev, offset, false)" in combios,
        "external TMDS table preflight differs",
    )

    for caller in ("r100.c", "r300.c", "r420.c", "rs400.c", "radeon_device.c"):
        require(
            "radeon_combios_asic_init" in sources[caller],
            f"{caller} COMBIOS call is absent",
        )
    require(
        all(
            "kfree(rdev->bios);" not in source
            for name, source in sources.items()
            if name != "radeon_bios.c"
        ),
        "a BIOS teardown bypasses radeon_bios_fini",
    )


def u16(image: bytes, offset: int) -> int:
    require(offset >= 0 and offset + 2 <= len(image), "ROM u16 read exceeds image")
    return image[offset] | image[offset + 1] << 8


def admit_pci_image(image: bytes) -> tuple[bytes, int]:
    require(0 < len(image) <= MAX_ROM_BYTES, "ROM size is outside the admitted range")
    require(len(image) >= 0x1A and image[:2] == b"\x55\xaa", "ROM signature differs")
    pcir = u16(image, 0x18)
    require(pcir + 0x18 <= len(image), "PCIR span exceeds the copied ROM")
    require(image[pcir : pcir + 4] == b"PCIR", "PCIR signature differs")
    declared_size = u16(image, pcir + 0x10) * 512
    require(declared_size > 0, "PCI image declares zero bytes")
    require(declared_size <= len(image), "PCI image exceeds the copied ROM")
    require(image[pcir + 0x14] == 0, "PCI image is not x86 code")
    image = image[:declared_size]
    header = u16(image, 0x48)
    require(header > 0 and header + 8 <= len(image), "BIOS header exceeds image")
    require(image[header + 4 : header + 8] not in {b"ATOM", b"MOTA"}, "ROM is ATOM")
    return image, header


def table_offset(image: bytes, header: int, header_slot: int) -> int:
    require(header + 7 <= len(image), "COMBIOS header size byte is absent")
    require(header_slot < image[header + 6], "COMBIOS table slot exceeds header")
    return u16(image, header + header_slot)


def validate_mmio(image: bytes, offset: int) -> int:
    commands = 0
    while True:
        entry = u16(image, offset)
        if entry == 0:
            return commands
        offset += 2
        payload = (4, 4, 8, 8, 2, 2, 0, 0)[entry >> 13]
        require(offset + payload <= len(image), "MMIO table payload exceeds image")
        offset += payload
        commands += 1


def validate_pll(image: bytes, offset: int) -> int:
    commands = 0
    while True:
        require(offset < len(image), "PLL table entry exceeds image")
        entry = image[offset]
        if entry == 0:
            return commands
        offset += 1
        payload = (4, 3, 0, 0)[entry >> 6]
        require(offset + payload <= len(image), "PLL table payload exceeds image")
        offset += payload
        commands += 1


def validate_rom(path: Path) -> str:
    require(path.is_file(), f"ROM file is absent: {path}")
    require(path.stat().st_size <= MAX_ROM_BYTES, "ROM file exceeds size ceiling")
    image, header = admit_pci_image(path.read_bytes())
    tables = (
        ("asic-init-1", 0x0C, validate_mmio),
        ("pll-init", 0x46, validate_pll),
        ("asic-init-2", 0x4E, validate_mmio),
        ("dynamic-clock-1", 0x52, validate_pll),
    )
    counts = []
    for name, slot, validator in tables:
        offset = table_offset(image, header, slot)
        counts.append(f"{name}={validator(image, offset) if offset else 0}")
    digest = hashlib.sha256(image).hexdigest()
    return f"COMBIOS {len(image)} bytes sha256={digest} " + " ".join(counts)


def self_test(sources: dict[str, str]) -> None:
    mutations: list[tuple[str, str, str, str, str]] = [
        (
            "direct-rbios",
            "radeon.h",
            "radeon_bios_read_u8(rdev, (size_t)(i))",
            "rdev->bios[i]",
            "bounded RBIOS accessors differ",
        ),
        (
            "missing-size-field",
            "radeon.h",
            "size_t\t\t\t\tbios_size;",
            "size_t\t\t\t\trom_extent;",
            "bios_size field differs",
        ),
        (
            "unsafe-span-addition",
            "radeon_bios.c",
            "length > rdev->bios_size - offset",
            "offset + length > rdev->bios_size",
            "overflow-safe BIOS span contract differs",
        ),
        (
            "atrm-overrun",
            "radeon_bios.c",
            "obj->buffer.length > length",
            "obj->buffer.length < length",
            "ATRM returned-length ceiling is absent",
        ),
        (
            "vfct-overflow",
            "radeon_bios.c",
            "vhdr->ImageLength > tbl_size - offset",
            "offset + vhdr->ImageLength > tbl_size",
            "VFCT subtraction bound is absent",
        ),
        (
            "missing-pcir-signature",
            "radeon_bios.c",
            'memcmp(rdev->bios + pcir, "PCIR", 4)',
            "false",
            "PCI image admission is incomplete",
        ),
        (
            "missing-edid-base-span",
            "radeon_combios.c",
            "radeon_bios_span_valid(rdev, edid_info, EDID_LENGTH)",
            "true",
            "hardcoded EDID span checks differ",
        ),
        (
            "direct-combios-index",
            "radeon_combios.c",
            "raw = rdev->bios + edid_info;",
            "raw = &rdev->bios[edid_info];",
            "COMBIOS contains a direct BIOS array access",
        ),
        (
            "execute-before-preflight",
            "radeon_combios.c",
            "combios_parse_mmio_table(dev, asic_init_1);",
            "combios_parse_mmio_table(dev, asic_init_1);\n\tcombios_parse_mmio_table(dev, asic_init_1);",
            "ASIC init 1 execution denominator differs",
        ),
        (
            "missing-tmds-preflight",
            "radeon_combios.c",
            "combios_validate_external_tmds_table(rdev, offset, true)",
            "offset",
            "external TMDS table preflight differs",
        ),
    ]
    require(len(mutations) == EXPECTED_BAD_COUNT, "self-test denominator differs")
    require(
        len({mutation[0] for mutation in mutations}) == len(mutations),
        "self-test labels repeat",
    )
    validate_sources(sources)
    for label, path, old, new, expected_error in mutations:
        mutated = copy.deepcopy(sources)
        require(mutated[path].count(old) == 1, f"{label}: mutation anchor differs")
        mutated[path] = mutated[path].replace(old, new, 1)
        try:
            validate_sources(mutated)
        except BiosContractError as error:
            require(
                expected_error in str(error),
                f"{label}: wrong error: {error}",
            )
            continue
        raise BiosContractError(f"known-bad source mutation accepted: {label}")

    image = bytearray(1024)
    image[0:2] = b"\x55\xaa"
    image[0x18:0x1A] = (0x80).to_bytes(2, "little")
    image[0x80:0x84] = b"PCIR"
    image[0x90:0x92] = (2).to_bytes(2, "little")
    image[0x94] = 0
    image[0x48:0x4A] = (0x100).to_bytes(2, "little")
    admitted, header = admit_pci_image(bytes(image))
    require(len(admitted) == 1024 and header == 0x100, "known-good ROM rejected")
    bad_image = bytearray(image)
    bad_image[0x90:0x92] = (3).to_bytes(2, "little")
    try:
        admit_pci_image(bytes(bad_image))
    except BiosContractError:
        pass
    else:
        raise BiosContractError("oversized PCI image accepted")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--rom", type=Path)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    try:
        sources = load_sources(args.root.resolve())
        if args.selftest:
            self_test(sources)
            print(
                f"Radeon BIOS bounds: 1 good and {EXPECTED_BAD_COUNT} bad source cases"
            )
        else:
            validate_sources(sources)
            print("Radeon BIOS bounds: source contract proven")
        if args.rom:
            print(validate_rom(args.rom.resolve()))
    except BiosContractError as error:
        print(f"Radeon BIOS bounds: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
