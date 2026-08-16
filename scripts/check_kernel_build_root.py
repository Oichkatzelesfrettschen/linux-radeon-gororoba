#!/usr/bin/env python3
"""Verify a retained kernel build root against its declaration and manifest."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path

SCHEMA = "gororoba-kernel-build-root-v1"
SCHEMA_LINE = f"# manifest-schema: {SCHEMA}"
COLUMNS = "path\ttype\tmode\tsize\tidentity_sha256"
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
VERSION_CODE = re.compile(r"^#define LINUX_VERSION_CODE ([0-9]+)$", re.MULTILINE)
COMPILER = re.compile(
    r'^#define LINUX_COMPILER\s+"clang version ([^,]+), LLD ([^"]+)"$',
    re.MULTILINE,
)


class VerificationError(Exception):
    """A retained root does not satisfy its declared content or host policy."""


@dataclass(frozen=True)
class ManifestEntry:
    path: str
    entry_type: str
    mode: str
    size: int
    identity_sha256: str

    def row(self) -> str:
        return (
            f"{self.path}\t{self.entry_type}\t{self.mode}\t"
            f"{self.size}\t{self.identity_sha256}"
        )


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def manifest_entry(root: Path, path: Path) -> ManifestEntry:
    info = path.lstat()
    rel = "." if path == root else path.relative_to(root).as_posix()
    mode = f"{stat.S_IMODE(info.st_mode):04o}"

    if stat.S_ISDIR(info.st_mode):
        return ManifestEntry(rel, "directory", mode, 0, "-")
    if stat.S_ISREG(info.st_mode):
        return ManifestEntry(rel, "regular", mode, info.st_size, sha256_file(path))
    if stat.S_ISLNK(info.st_mode):
        target = os.readlink(path).encode("utf-8")
        return ManifestEntry(rel, "symlink", mode, len(target), sha256_bytes(target))
    raise VerificationError(f"special file is forbidden: {rel}")


def build_manifest(root: Path) -> list[str]:
    if not root.is_dir():
        raise VerificationError(f"kernel build root is not a directory: {root}")
    entries = [manifest_entry(root, root)]
    entries.extend(manifest_entry(root, path) for path in root.rglob("*"))
    entries.sort(key=lambda item: item.path.encode("utf-8"))
    return [SCHEMA_LINE, COLUMNS, *(entry.row() for entry in entries)]


def parse_manifest(path: Path) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise VerificationError(f"manifest is not UTF-8 text: {path}") from exc
    if len(lines) < 2 or lines[0] != SCHEMA_LINE or lines[1] != COLUMNS:
        raise VerificationError(f"manifest schema or columns are invalid: {path}")
    seen: set[str] = set()
    for line_number, row in enumerate(lines[2:], 3):
        fields = row.split("\t")
        if len(fields) != 5:
            raise VerificationError(
                f"manifest row {line_number} has {len(fields)} fields"
            )
        rel, entry_type, mode, size_text, identity = fields
        if rel in seen:
            raise VerificationError(f"manifest repeats path: {rel}")
        seen.add(rel)
        if entry_type not in {"directory", "regular", "symlink"}:
            raise VerificationError(
                f"manifest carries unknown type for {rel}: {entry_type}"
            )
        if not re.fullmatch(r"[0-7]{4}", mode):
            raise VerificationError(f"manifest carries invalid mode for {rel}: {mode}")
        if not size_text.isdigit():
            raise VerificationError(
                f"manifest carries invalid size for {rel}: {size_text}"
            )
        if entry_type == "directory":
            if size_text != "0" or identity != "-":
                raise VerificationError(f"directory identity is not canonical: {rel}")
        elif not HEX_64.fullmatch(identity):
            raise VerificationError(f"manifest carries invalid SHA-256 for {rel}")
    return lines


def load_declaration(path: Path) -> dict[str, object]:
    try:
        with path.open("rb") as source:
            declaration = tomllib.load(source)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise VerificationError(f"cannot read declaration {path}: {exc}") from exc
    required = {
        "schema",
        "kernel_release",
        "linux_version_code",
        "headers_package",
        "package_sha256",
        "signature_file",
        "signature_sha256",
        "signature_result",
        "verified_signer_fingerprint",
        "verification_command",
        "verification_timestamp",
        "compiler_family",
        "compiler_version",
        "linker_family",
        "linker_version",
        "entry_count",
        "regular_file_count",
        "directory_count",
        "symlink_count",
        "manifest_sha256",
    }
    missing = sorted(required - declaration.keys())
    if missing:
        raise VerificationError(f"declaration is missing keys: {', '.join(missing)}")
    if declaration["schema"] != 1:
        raise VerificationError("declaration schema must equal 1")
    for key in (
        "package_sha256",
        "signature_sha256",
        "manifest_sha256",
    ):
        if not isinstance(declaration[key], str) or not HEX_64.fullmatch(
            declaration[key]
        ):
            raise VerificationError(f"{key} is not a lowercase SHA-256")
    if declaration["signature_result"] != "good":
        raise VerificationError("signature_result must equal good")
    fingerprint = declaration["verified_signer_fingerprint"]
    if not isinstance(fingerprint, str) or not re.fullmatch(
        r"[0-9A-F]{40}", fingerprint
    ):
        raise VerificationError(
            "verified_signer_fingerprint is not a 40-digit fingerprint"
        )
    host_policy = declaration.get("host_policy")
    if host_policy != {
        "uid": 0,
        "gid": 0,
        "group_writable": False,
        "other_writable": False,
        "runner_directory_write": False,
        "special_files": False,
    }:
        raise VerificationError(
            "host_policy does not carry the fail-closed declaration"
        )
    return declaration


def verify_manifest(root: Path, manifest_path: Path) -> None:
    expected = parse_manifest(manifest_path)
    actual = build_manifest(root)
    if actual == expected:
        return
    limit = max(len(actual), len(expected))
    for index in range(limit):
        actual_row = actual[index] if index < len(actual) else "<absent>"
        expected_row = expected[index] if index < len(expected) else "<absent>"
        if actual_row != expected_row:
            raise VerificationError(
                "kernel build root manifest differs at row "
                f"{index + 1}: expected {expected_row!r}, got {actual_row!r}"
            )
    raise VerificationError("kernel build root manifest differs")


def count_types(lines: list[str]) -> dict[str, int]:
    counts = {"regular": 0, "directory": 0, "symlink": 0}
    for row in lines[2:]:
        counts[row.split("\t")[1]] += 1
    return counts


def verify_kernel_identity(root: Path, declaration: dict[str, object]) -> None:
    release_path = root / "include/config/kernel.release"
    version_path = root / "include/generated/uapi/linux/version.h"
    compile_path = root / "include/generated/compile.h"
    for path in (release_path, version_path, compile_path):
        if not path.is_file():
            raise VerificationError(f"kernel identity file is missing: {path}")

    release = release_path.read_text(encoding="utf-8").strip()
    if release != declaration["kernel_release"]:
        raise VerificationError(
            f"kernel release differs: expected {declaration['kernel_release']}, got {release}"
        )

    version_match = VERSION_CODE.search(version_path.read_text(encoding="utf-8"))
    if not version_match:
        raise VerificationError("LINUX_VERSION_CODE is missing")
    version_code = int(version_match.group(1))
    if version_code != declaration["linux_version_code"]:
        raise VerificationError(
            "LINUX_VERSION_CODE differs: expected "
            f"{declaration['linux_version_code']}, got {version_code}"
        )

    compiler_match = COMPILER.search(compile_path.read_text(encoding="utf-8"))
    if not compiler_match:
        raise VerificationError("kernel compiler identity is missing or unsupported")
    compiler_version, linker_version = compiler_match.groups()
    if declaration["compiler_family"] != "clang":
        raise VerificationError("compiler_family must be clang for this root")
    if declaration["linker_family"] != "lld":
        raise VerificationError("linker_family must be lld for this root")
    if compiler_version != declaration["compiler_version"]:
        raise VerificationError(
            f"compiler version differs: expected {declaration['compiler_version']}, "
            f"got {compiler_version}"
        )
    if linker_version != declaration["linker_version"]:
        raise VerificationError(
            f"linker version differs: expected {declaration['linker_version']}, "
            f"got {linker_version}"
        )


def verify_host_policy(root: Path) -> None:
    if os.geteuid() == 0:
        raise VerificationError("host-policy verification must run as the runner")
    status = Path("/proc/self/status").read_text(encoding="utf-8")
    capability = re.search(r"^CapEff:\s+([0-9a-fA-F]+)$", status, re.MULTILINE)
    if capability is None or int(capability.group(1), 16) != 0:
        raise VerificationError("runner carries effective Linux capabilities")
    for path in (root, *root.rglob("*")):
        info = path.lstat()
        rel = "." if path == root else path.relative_to(root).as_posix()
        if info.st_uid != 0 or info.st_gid != 0:
            raise VerificationError(f"host ownership is not root:root: {rel}")
        if not stat.S_ISLNK(info.st_mode) and stat.S_IMODE(info.st_mode) & 0o022:
            raise VerificationError(
                f"host object is group-writable or other-writable: {rel}"
            )
        if stat.S_ISDIR(info.st_mode) and os.access(path, os.W_OK):
            raise VerificationError(f"runner can write retained-root directory: {rel}")
        attributes = os.listxattr(path, follow_symlinks=False)
        if any(name.startswith("system.posix_acl_") for name in attributes):
            raise VerificationError(f"host object carries an extended POSIX ACL: {rel}")


def verify(
    root: Path,
    declaration_path: Path,
    manifest_path: Path,
    check_host_policy: bool,
) -> None:
    root = root.resolve(strict=True)
    declaration = load_declaration(declaration_path)
    manifest_lines = parse_manifest(manifest_path)
    manifest_hash = sha256_file(manifest_path)
    if manifest_hash != declaration["manifest_sha256"]:
        raise VerificationError(
            "manifest file SHA-256 differs: expected "
            f"{declaration['manifest_sha256']}, got {manifest_hash}"
        )
    verify_manifest(root, manifest_path)
    counts = count_types(manifest_lines)
    expected_counts = {
        "regular": declaration["regular_file_count"],
        "directory": declaration["directory_count"],
        "symlink": declaration["symlink_count"],
    }
    if counts != expected_counts:
        raise VerificationError(
            f"manifest type counts differ: {counts} against {expected_counts}"
        )
    if sum(counts.values()) != declaration["entry_count"]:
        raise VerificationError("manifest entry count differs from declaration")
    verify_kernel_identity(root, declaration)
    if check_host_policy:
        verify_host_policy(root)
    print(
        "kernel build root verified: "
        f"{declaration['kernel_release']}, {declaration['entry_count']} entries, "
        f"manifest {manifest_hash}"
    )


def self_test() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        base = Path(temporary)
        root = base / "root"
        root.mkdir()
        (root / "empty").mkdir()
        (root / "file").write_bytes(b"kernel\n")
        (root / "link").symlink_to("file")
        baseline = build_manifest(root)

        def changed(label: str, mutation) -> None:
            import shutil

            candidate = base / "candidate"
            shutil.copytree(root, candidate, symlinks=True)
            try:
                mutation(candidate)
                if build_manifest(candidate) == baseline:
                    raise VerificationError(f"self-test missed mutation: {label}")
                print(f"  ok: {label}")
            finally:
                shutil.rmtree(candidate)

        changed("missing regular file", lambda path: (path / "file").unlink())
        changed("missing empty directory", lambda path: (path / "empty").rmdir())
        changed("changed regular mode", lambda path: (path / "file").chmod(0o755))
        changed(
            "changed symlink target",
            lambda path: (
                (path / "link").unlink(),
                (path / "link").symlink_to("empty"),
            ),
        )
        changed("unexpected file", lambda path: (path / "extra").write_bytes(b"x"))

        special = base / "special"
        special.mkdir()
        os.mkfifo(special / "fifo")
        try:
            build_manifest(special)
        except VerificationError:
            print("  ok: special file rejected")
        else:
            raise VerificationError("self-test accepted a special file")

        bad_manifest = base / "bad.tsv"
        bad_manifest.write_text("path\ttype\n", encoding="utf-8")
        try:
            parse_manifest(bad_manifest)
        except VerificationError:
            print("  ok: foreign manifest schema rejected")
        else:
            raise VerificationError("self-test accepted a foreign manifest")

        policy_root = base / "policy"
        policy_root.mkdir()
        (policy_root / "writable").mkdir()
        try:
            verify_host_policy(policy_root)
        except VerificationError as exc:
            if "ownership is not root:root" not in str(exc):
                raise
            print("  ok: non-root ownership rejected")
        else:
            raise VerificationError("self-test accepted non-root ownership")

    print("kernel build root calibration: every content class detected")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--declaration", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--emit-manifest", type=Path)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--skip-host-policy", action="store_true")
    args = parser.parse_args()

    try:
        if args.self_test:
            self_test()
            return 0
        if args.emit_manifest:
            if not args.root:
                parser.error("--emit-manifest requires --root")
            lines = build_manifest(args.root.resolve(strict=True))
            args.emit_manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
            print(f"wrote kernel build root manifest: {len(lines) - 2} entries")
            return 0
        if not args.root or not args.declaration or not args.manifest:
            parser.error("--root, --declaration, and --manifest are required")
        verify(
            args.root,
            args.declaration,
            args.manifest,
            not args.skip_host_policy,
        )
        return 0
    except VerificationError as exc:
        print(f"kernel build root verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
