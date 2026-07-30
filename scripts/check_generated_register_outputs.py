#!/usr/bin/env python3
"""Regenerate Radeon safe-register tables and verify legacy output identity."""

from __future__ import annotations

import argparse
import csv
import hashlib
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path


class OutputError(Exception):
    """Generated register output differs from its frozen legacy identity."""


def read_expected(path: Path) -> dict[str, tuple[int, str]]:
    lines = [
        line
        for line in path.read_text(encoding="ascii").splitlines()
        if line and not line.startswith("#")
    ]
    rows = csv.DictReader(lines, delimiter="\t")
    expected: dict[str, tuple[int, str]] = {}
    for row in rows:
        name = row["path"]
        if not name.endswith("_reg_safe.h"):
            continue
        if name in expected:
            raise OutputError(f"payload manifest repeats generated output: {name}")
        expected[name] = (int(row["size"]), row["sha256"])
    return expected


def build_generator(tree: Path, output: Path) -> str:
    compiler = os.environ.get("CC", "cc")
    result = subprocess.run(
        [compiler, "-O2", "-o", str(output), str(tree / "mkregtable.c")],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise OutputError(f"mkregtable compilation failed: {detail}")
    version = subprocess.run(
        [compiler, "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    ).stdout.decode("utf-8", errors="replace").splitlines()[0]
    return version


def targets(tree: Path) -> list[str]:
    makefile = (tree / "Makefile").read_text(encoding="ascii")
    match = re.search(r"^targets := (.+)$", makefile, re.MULTILINE)
    if not match:
        raise OutputError("Radeon Makefile lacks the generated target list")
    names = match.group(1).split()
    if len(names) != len(set(names)):
        raise OutputError("Radeon Makefile repeats a generated target")
    if any(not name.endswith("_reg_safe.h") for name in names):
        raise OutputError("Radeon Makefile carries an unknown generated target")
    return names


def generate(generator: Path, source: Path) -> bytes:
    result = subprocess.run(
        [str(generator), str(source)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise OutputError(f"mkregtable failed for {source.name}: {detail}")
    return result.stdout


def verify_outputs(
    tree: Path,
    payload_manifest: Path,
    *,
    expected_legacy_count: int = 10,
) -> tuple[int, int, str]:
    forbidden = [
        path.name
        for path in tree.glob("*_reg_safe.h")
        if path.is_file() or path.is_symlink()
    ]
    if (tree / "mkregtable").exists():
        forbidden.append("mkregtable")
    if forbidden:
        raise OutputError(
            "source tree carries generated products: " + ", ".join(sorted(forbidden))
        )

    expected = read_expected(payload_manifest)
    if len(expected) != expected_legacy_count:
        raise OutputError(
            f"payload carries {len(expected)} legacy outputs, "
            f"expected {expected_legacy_count}"
        )

    with tempfile.TemporaryDirectory(prefix="radeon-register-output.") as temporary:
        generator = Path(temporary) / "mkregtable"
        compiler = build_generator(tree, generator)
        target_names = targets(tree)
        for target in target_names:
            source_name = target.removesuffix("_reg_safe.h")
            source = tree / "reg_srcs" / source_name
            if not source.is_file():
                raise OutputError(f"generated target lacks source: {target}")
            content = generate(generator, source)
            if target not in expected:
                continue
            expected_size, expected_sha = expected[target]
            actual_sha = hashlib.sha256(content).hexdigest()
            if len(content) != expected_size or actual_sha != expected_sha:
                raise OutputError(
                    f"{target}: size/hash {len(content)}/{actual_sha} != "
                    f"{expected_size}/{expected_sha}"
                )
        missing = sorted(set(expected) - set(target_names))
        if missing:
            raise OutputError(
                "legacy generated targets are absent: " + ", ".join(missing)
            )
    return len(expected), len(target_names), compiler


def self_test(root: Path) -> int:
    tree = root / "drivers/gpu/drm/radeon"
    try:
        with tempfile.TemporaryDirectory(prefix="register-output-test.") as temporary:
            work = Path(temporary)
            generator = work / "mkregtable"
            build_generator(tree, generator)
            content = generate(generator, tree / "reg_srcs/r100")
            digest = hashlib.sha256(content).hexdigest()
            good = work / "good.tsv"
            good.write_text(
                "# manifest-schema: gororoba-source-tree-v1\n"
                "path\tmode\tsize\tsha256\n"
                f"r100_reg_safe.h\t100644\t{len(content)}\t{digest}\n",
                encoding="ascii",
            )
            verify_outputs(tree, good, expected_legacy_count=1)
            bad = work / "bad.tsv"
            bad.write_text(
                good.read_text(encoding="ascii").replace(digest, "0" * 64),
                encoding="ascii",
            )
            try:
                verify_outputs(tree, bad, expected_legacy_count=1)
            except OutputError:
                pass
            else:
                raise OutputError("self-test accepted a changed generated hash")
    except (OSError, OutputError, UnicodeDecodeError, ValueError) as exc:
        print(f"generated-output calibration: FAIL: {exc}", file=sys.stderr)
        return 1
    print("generated-output calibration: exact output passes and drift fails closed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--tree", type=Path)
    parser.add_argument("--payload-manifest", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    root = args.repository.resolve()
    if args.self_test:
        return self_test(root)
    if not args.tree or not args.payload_manifest:
        parser.error("--tree and --payload-manifest are required")
    try:
        legacy_count, target_count, compiler = verify_outputs(
            args.tree.resolve(),
            args.payload_manifest.resolve(),
        )
    except (OSError, OutputError, UnicodeDecodeError, ValueError) as exc:
        print(f"generated register outputs: {exc}", file=sys.stderr)
        return 1
    print(
        f"generated register outputs: {legacy_count} legacy outputs match, "
        f"{target_count} targets generate with {compiler}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
