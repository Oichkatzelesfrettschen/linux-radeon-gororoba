#!/usr/bin/env python3
"""Capture and verify a bounded Radeon driver source intelligence bundle.

The capture exports one committed driver tree, indexes every admitted source
file, records lexical call candidates, and verifies the callback and macro
bindings declared by policy. The resulting graph is a research candidate. It
does not prove runtime reachability, preprocessor activation, framework order,
or hardware behavior.

Exit: 0 capture or verification passed, 1 self-test failed, 2 input or policy
error, 3 analyzer or capture failure.
"""

from __future__ import annotations

import argparse
import csv
import fnmatch
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest import mock


CAPTURE_SCHEMA = "gororoba-radeon-driver-source-map-v2"
COMPARISON_SCHEMA = "gororoba-radeon-driver-source-map-comparison-v3"
CURRENT_COMPARISON_SCHEMAS = frozenset((COMPARISON_SCHEMA,))
RETAINED_CAPTURE_COMPARISON_SCHEMAS = frozenset(
    (
        "gororoba-radeon-driver-source-map-comparison-v2",
        COMPARISON_SCHEMA,
    )
)
LEXICAL_SCHEMA = "radeon-driver-lexical-map-v1"
DECLARED_BINDING_SCHEMA = "radeon-driver-declared-bindings-v2"
PATH_WITNESS_SCHEMA = "radeon-driver-contextual-path-witnesses-v2"
PATH_WITNESS_JOIN_SCHEMA = "radeon-driver-contextual-path-joins-v1"
PROFILE_SYMBOL_DELTA_SUMMARY_SCHEMA = (
    "radeon-driver-profile-symbol-delta-summary-v1"
)
PROFILE_SYMBOL_DELTA_MEMBERS_SCHEMA = (
    "radeon-driver-profile-symbol-delta-members-v1"
)
PROFILE_SYMBOL_DELTA_MEMBER_COMPARISON_SCHEMA = (
    "radeon-driver-profile-symbol-delta-member-delta-v2"
)
PROFILE_SYMBOL_DELTA_SUMMARY_COLUMNS = (
    "kernel_release",
    "baseline_profile",
    "target_profile",
    "baseline_count",
    "target_count",
    "added_count",
    "removed_count",
    "added_set_sha256",
    "removed_set_sha256",
)
PROFILE_SYMBOL_DELTA_MEMBER_COLUMNS = (
    "kernel_release",
    "baseline_profile",
    "target_profile",
    "change",
    "canonical_symbol",
    "baseline_raw_symbol",
    "target_raw_symbol",
)
HASH_LEDGER = "capture-hashes.sha256"
POLICY_PATH = Path("policy/radeon-driver-source-map.toml")
SCRIPT_PATH = Path("scripts/capture_radeon_driver_source_map.py")
KERNEL_ROOT_VALIDATOR_PATH = Path("scripts/check_kernel_build_root.py")
CANONICAL_SOURCE_ROOT = "drivers/gpu/drm/radeon"
MAX_SOURCE_FILES = 256
MAX_SOURCE_BYTES = 7_000_000
MAX_MANIFEST_BYTES = 1_048_576
MAX_ANALYSIS_ROWS = 1_000_000
MAX_TOOLCHAIN_PREFIX_ENTRIES = 8_192
MAX_TOOLCHAIN_PREFIX_DEPTH = 16
MAX_TOOLCHAIN_REGULAR_FILE_BYTES = 160_000_000
MAX_TOOLCHAIN_REGULAR_TOTAL_BYTES = 600_000_000
CANONICAL_PREPROCESSOR_WORK = "/gororoba/preprocessor-work"
CANONICAL_KERNEL_BUILD_ROOT = "/gororoba/kernel-build-root"
CANONICAL_KERNEL_TOOLCHAIN = "/gororoba/kernel-toolchain"
TOOLCHAIN_PREFIX_TREE_SCHEMA = "gororoba-kernel-toolchain-prefix-tree-v1"
GLOBAL_DATABASE_NAMES = ("GTAGS", "GRTAGS", "GPATH")
LLVM_KERNEL_TOOLS = (
    "clang",
    "clang++",
    "ld.lld",
    "llvm-ar",
    "llvm-nm",
    "llvm-objcopy",
    "llvm-objdump",
    "llvm-readelf",
    "llvm-strip",
)
LLVM_KERNEL_LIBRARIES = (
    "libLLVM.so.22.1",
    "libclang-cpp.so.22.1",
    "liblldCOFF.so.22.1",
    "liblldCommon.so.22.1",
    "liblldELF.so.22.1",
    "liblldMachO.so.22.1",
    "liblldMinGW.so.22.1",
    "liblldWasm.so.22.1",
)
CALL_CANDIDATE_EDGE_KINDS = {
    "declared-indirect",
    "extracted-indirect",
    "lexical",
}
PATH_WITNESS_JOIN_KINDS = {
    "callback-selection",
    "debugfs-read-event",
    "debugfs-write-event",
}
PATH_WITNESS_SEMANTIC_LIMIT = (
    "ordered-source-witness-not-runtime-reachability"
)
REQUIRED_PATH_WITNESS_ENDPOINTS = {
    "rs480-command-submission-packet-validation": (
        "drm_ioctl_dispatch",
        "r300_packet0_check",
    ),
    "rs480-debugfs-wedged-reset-request": (
        "drm_primary_minor_debugfs_init",
        "rs480_wedged_3d_reset",
    ),
    "rs480-wd3-forced-reset-asic-selection": (
        "rs480_wedged_3d_reset",
        "r300_asic_reset",
    ),
    "palm-debugfs-pci-config-reset": (
        "drm_primary_minor_debugfs_init",
        "radeon_pci_config_reset",
    ),
}
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
UTC_TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
C_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
MECHANISM_NAME = re.compile(r"^[a-z][a-z0-9-]*$")
MODULE_SYMBOL_LINE = re.compile(
    r"^(?P<name>\S+) (?P<type>[A-Za-z?]) "
    r"(?P<address>[0-9a-f]+) (?P<size>[0-9a-f]+)$"
)
LLVM_SYMBOL_SUFFIX = re.compile(r"[.]llvm[.][0-9]+$")
C_COMMENT_OR_LITERAL = re.compile(
    r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
    re.DOTALL,
)
C_LINE_SPLICE = re.compile(r"\\(?:\r\n|\n|\r)")
CFLOW_ROW = re.compile(r"^\s*\d+\s+\{\s*(\d+)\}\s+(\S[^:]*):\s*(.*)$")
FIELD_INITIALIZER = re.compile(
    r"(?m)^\s*\.([A-Za-z_][A-Za-z0-9_]*)\s*=\s*&?"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*,"
)
DEFINE_SHOW = re.compile(
    r"\bDEFINE_SHOW_ATTRIBUTE\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)"
)
DEFINE_DEBUGFS = re.compile(
    r"\bDEFINE_DEBUGFS_ATTRIBUTE\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,"
    r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*([A-Za-z_][A-Za-z0-9_]*)"
)
DRM_IOCTL = re.compile(
    r"\bDRM_IOCTL_DEF_DRV\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,"
    r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*,"
)
WORK_BINDING = re.compile(
    r"\b(INIT_WORK|INIT_DELAYED_WORK)\s*\([^,]+,\s*"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*\)"
)
MODULE_BINDING = re.compile(
    r"\b(module_init|module_exit)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)"
)
ABSOLUTE_PATH_TOKEN = re.compile(
    rb"(?<![A-Za-z0-9._+<>=:@%/-])/(?:[A-Za-z0-9._+@%=-]+(?:/[A-Za-z0-9._+@%=-]+)*)?"
)
PORTABLE_ABSOLUTE_ROOTS = (
    "/tmp/source",
    "/tmp/capture",
    CANONICAL_PREPROCESSOR_WORK,
    CANONICAL_KERNEL_BUILD_ROOT,
    CANONICAL_KERNEL_TOOLCHAIN,
)
PORTABLE_PLACEHOLDER_ROOTS = (
    "<capture-root>",
    "<repository>",
    "<source-root>",
    "<kernel-build-root>",
    "<kernel-toolchain-root>",
    "<preprocessor-work>",
)


class SourceMapError(Exception):
    """The source map input, policy, analyzer, or output is invalid."""


@dataclass(frozen=True)
class SourceEntry:
    path: str
    mode: str
    object_id: str
    size: int
    sha256: str
    source_class: str


@dataclass(frozen=True)
class Partition:
    name: str
    roots: tuple[str, ...]
    falsifier: str


@dataclass(frozen=True)
class GuardIdentifierCensus:
    owner: str
    identifiers: tuple[str, ...]


@dataclass(frozen=True)
class Hazard:
    symbol: str
    side_effect_class: str
    guard_identifier_census: tuple[GuardIdentifierCensus, ...]
    evidence_rank: str


@dataclass(frozen=True)
class Binding:
    name: str
    partition: str
    kind: str
    scope: str
    caller: str
    callee: str
    path: str
    pattern: str
    expected_matches: int
    match_literals: bool


@dataclass(frozen=True)
class PathWitnessEdge:
    axis: str
    edge_kind: str
    caller: str
    callee: str
    partition: str
    provenance: str
    classification: str


@dataclass(frozen=True)
class PathWitnessJoin:
    kind: str
    from_axis: str
    from_symbol: str
    to_axis: str
    to_symbol: str
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class PathWitness:
    name: str
    entry: str
    terminal: str
    context: tuple[str, ...]
    edges: tuple[PathWitnessEdge, ...]
    joins: tuple[PathWitnessJoin, ...]


@dataclass(frozen=True)
class BoundedQuery:
    name: str
    paths: tuple[str, ...]
    pattern: str
    expected_matches: int
    rationale: str


@dataclass(frozen=True)
class KernelLane:
    release: str
    declaration: str
    manifest: str
    toolchain_declaration: str
    toolchain_manifest: str
    toolchain_prefix_manifest: str
    profiles: tuple[str, ...]


@dataclass(frozen=True)
class ToolchainClosureEntry:
    kind: str
    logical_name: str
    relative_path: str
    entry_type: str
    mode: str
    size: int
    identity_sha256: str
    link_target: str
    resolved_sha256: str
    version_first_line: str
    version_output_sha256: str


@dataclass(frozen=True)
class ToolchainPrefixEntry:
    relative_path: str
    entry_type: str
    mode: str
    size: int | None
    identity_sha256: str
    link_target: str
    resolved_path: str
    resolved_sha256: str


@dataclass(frozen=True)
class Policy:
    capture_schema: str
    comparison_schema: str
    source_root: str
    max_source_files: int
    max_source_bytes: int
    required_tools: tuple[str, ...]
    optional_tools: tuple[str, ...]
    source_classes: dict[str, str]
    extractor_minimums: dict[str, int]
    global_version: str
    global_config_sha256: str
    ctags_version_first_line: str
    ctags_executable_sha256: str
    readtags_executable_sha256: str
    ctags_package_owner: str
    cflow_stderr: tuple[str, ...]
    ctags_stderr: tuple[str, ...]
    translation_units: tuple[str, ...]
    kernel_lanes: tuple[KernelLane, ...]
    partitions: tuple[Partition, ...]
    hazards: tuple[Hazard, ...]
    bindings: tuple[Binding, ...]
    path_witnesses: tuple[PathWitness, ...]
    bounded_queries: tuple[BoundedQuery, ...]


@dataclass(frozen=True)
class CommandRecord:
    command_id: str
    tool: str
    cwd: str
    status: int
    stdout_path: str
    stderr_path: str
    argv_json: str
    environment_json: str


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SourceMapError(message)


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def regular_tree_files(root: Path, label: str) -> set[str]:
    try:
        root_status = root.lstat()
    except OSError as exc:
        raise SourceMapError(f"{label} root is absent: {root}") from exc
    require(stat.S_ISDIR(root_status.st_mode), f"{label} root is not a real directory")
    files: set[str] = set()

    def walk(directory: Path, relative_parts: tuple[str, ...]) -> None:
        with os.scandir(directory) as iterator:
            entries = sorted(iterator, key=lambda entry: os.fsencode(entry.name))
        for entry in entries:
            require(
                entry.name.isascii()
                and not any(ord(character) < 32 for character in entry.name),
                f"{label} path is not plain ASCII",
            )
            status = entry.stat(follow_symlinks=False)
            path_parts = (*relative_parts, entry.name)
            relative = "/".join(path_parts)
            if stat.S_ISDIR(status.st_mode):
                walk(Path(entry.path), path_parts)
            elif stat.S_ISREG(status.st_mode):
                require(relative not in files, f"{label} repeats a file: {relative}")
                files.add(relative)
            else:
                raise SourceMapError(
                    f"{label} contains a symlink or special file: {relative}"
                )

    walk(root, ())
    return files


def regular_tree_directories(root: Path, label: str) -> set[str]:
    try:
        root_status = root.lstat()
    except OSError as exc:
        raise SourceMapError(f"{label} root is absent: {root}") from exc
    require(stat.S_ISDIR(root_status.st_mode), f"{label} root is not a real directory")
    directories: set[str] = set()

    def walk(directory: Path, relative_parts: tuple[str, ...]) -> None:
        with os.scandir(directory) as iterator:
            entries = sorted(iterator, key=lambda entry: os.fsencode(entry.name))
        for entry in entries:
            require(
                entry.name.isascii()
                and not any(ord(character) < 32 for character in entry.name),
                f"{label} path is not plain ASCII",
            )
            status = entry.stat(follow_symlinks=False)
            path_parts = (*relative_parts, entry.name)
            relative = "/".join(path_parts)
            if stat.S_ISDIR(status.st_mode):
                require(
                    relative not in directories,
                    f"{label} repeats a directory: {relative}",
                )
                directories.add(relative)
                walk(Path(entry.path), path_parts)
            elif not stat.S_ISREG(status.st_mode):
                raise SourceMapError(
                    f"{label} contains a symlink or special file: {relative}"
                )

    walk(root, ())
    return directories


def read_bounded_file(path: Path, maximum_size: int, label: str) -> bytes:
    require(maximum_size >= 0, f"{label} has an invalid size ceiling")
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | os.O_CLOEXEC
            | os.O_NOCTTY
            | os.O_NOFOLLOW
            | os.O_NONBLOCK,
        )
    except OSError as exc:
        raise SourceMapError(f"{label} is absent: {path}") from exc
    try:
        try:
            status_before = os.fstat(descriptor)
            require(
                stat.S_ISREG(status_before.st_mode),
                f"{label} is not a regular file",
            )
            require(
                status_before.st_size <= maximum_size,
                f"{label} exceeds its size ceiling",
            )
            chunks: list[bytes] = []
            remaining = maximum_size + 1
            while remaining:
                chunk = os.read(descriptor, min(1_048_576, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            content = b"".join(chunks)
            require(
                len(content) <= maximum_size,
                f"{label} exceeds its size ceiling",
            )
            status_after = os.fstat(descriptor)
        except OSError as exc:
            raise SourceMapError(f"cannot read {label}: {path}") from exc
        stable_before = (
            status_before.st_dev,
            status_before.st_ino,
            status_before.st_mode,
            status_before.st_nlink,
            status_before.st_size,
            status_before.st_mtime_ns,
            status_before.st_ctime_ns,
        )
        stable_after = (
            status_after.st_dev,
            status_after.st_ino,
            status_after.st_mode,
            status_after.st_nlink,
            status_after.st_size,
            status_after.st_mtime_ns,
            status_after.st_ctime_ns,
        )
        require(
            stable_before == stable_after
            and len(content) == status_before.st_size,
            f"{label} changes while it is read",
        )
        return content
    finally:
        os.close(descriptor)


def git_object_id(object_type: str, content: bytes) -> str:
    require(object_type in {"blob", "commit", "tree"}, f"unsupported Git object type: {object_type}")
    header = f"{object_type} {len(content)}\0".encode("ascii")
    return hashlib.sha1(header + content, usedforsecurity=False).hexdigest()


def commit_identity(content: bytes) -> tuple[str, str]:
    header, separator, _message = content.partition(b"\n\n")
    require(separator == b"\n\n", "Git commit object has no message separator")
    lines = header.splitlines()
    require(lines and lines[0].startswith(b"tree "), "Git commit object has no tree")
    tree_text = lines[0].removeprefix(b"tree ")
    try:
        tree_id = tree_text.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SourceMapError("Git commit tree identity is not ASCII") from exc
    require(HEX_40.fullmatch(tree_id) is not None, "Git commit tree identity is invalid")
    committer_lines = [line for line in lines if line.startswith(b"committer ")]
    require(len(committer_lines) == 1, "Git commit object has an invalid committer header")
    match = re.search(rb" ([0-9]+) [+-][0-9]{4}$", committer_lines[0])
    require(match is not None, "Git commit object has an invalid committer timestamp")
    timestamp = int(match.group(1))
    try:
        timestamp_utc = datetime.fromtimestamp(timestamp, UTC).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    except (OverflowError, OSError, ValueError) as exc:
        raise SourceMapError("Git commit timestamp is outside the supported range") from exc
    return tree_id, timestamp_utc


def parse_git_tree_object(content: bytes) -> list[tuple[str, bytes, str]]:
    entries: list[tuple[str, bytes, str]] = []
    offset = 0
    while offset < len(content):
        mode_end = content.find(b" ", offset)
        require(mode_end > offset, "Git tree object carries an invalid mode")
        name_end = content.find(b"\0", mode_end + 1)
        require(name_end > mode_end + 1, "Git tree object carries an invalid name")
        object_end = name_end + 21
        require(object_end <= len(content), "Git tree object carries a truncated object ID")
        try:
            mode = content[offset:mode_end].decode("ascii")
        except UnicodeDecodeError as exc:
            raise SourceMapError("Git tree object carries a non-ASCII mode") from exc
        name = content[mode_end + 1 : name_end]
        require(mode in {"40000", "100644", "100755", "120000", "160000"}, f"Git tree object carries an invalid mode: {mode}")
        require(b"/" not in name and b"\0" not in name, "Git tree object carries an invalid basename")
        entries.append((mode, name, content[name_end + 1 : object_end].hex()))
        offset = object_end
    require(offset == len(content), "Git tree object has trailing bytes")
    require(len({name for _mode, name, _object_id in entries}) == len(entries), "Git tree object repeats a basename")
    ordered = sorted(
        entries,
        key=lambda entry: entry[1] + (b"/" if entry[0] == "40000" else b"\0"),
    )
    require(entries == ordered, "Git tree object entries are not canonically ordered")
    return entries


def retained_driver_tree_id(entries: list[SourceEntry], source_root: str) -> str:
    root_parts = tuple(source_root.split("/"))
    leaves: list[tuple[tuple[bytes, ...], str, str]] = []
    for entry in entries:
        path_parts = tuple(entry.path.split("/"))
        require(path_parts[: len(root_parts)] == root_parts, f"retained source path leaves source root: {entry.path}")
        relative_parts = path_parts[len(root_parts) :]
        require(relative_parts and all(relative_parts), f"retained source path has an empty component: {entry.path}")
        leaves.append(
            (
                tuple(component.encode("utf-8") for component in relative_parts),
                entry.mode,
                entry.object_id,
            )
        )

    def tree_id(tree_leaves: list[tuple[tuple[bytes, ...], str, str]]) -> str:
        files: dict[bytes, tuple[str, str]] = {}
        directories: dict[bytes, list[tuple[tuple[bytes, ...], str, str]]] = defaultdict(list)
        for path_parts, mode, object_id in tree_leaves:
            name = path_parts[0]
            if len(path_parts) == 1:
                require(name not in files and name not in directories, "retained source tree repeats a path")
                files[name] = (mode, object_id)
            else:
                require(name not in files, "retained source tree uses one path as a file and directory")
                directories[name].append((path_parts[1:], mode, object_id))
        serialized: list[tuple[bytes, bool, bytes]] = []
        for name, (mode, object_id) in files.items():
            require(mode in {"100644", "100755"}, f"retained source file mode is invalid: {mode}")
            require(HEX_40.fullmatch(object_id) is not None, "retained source blob ID is invalid")
            serialized.append(
                (name, False, mode.encode("ascii") + b" " + name + b"\0" + bytes.fromhex(object_id))
            )
        for name, children in directories.items():
            child_id = tree_id(children)
            serialized.append(
                (name, True, b"40000 " + name + b"\0" + bytes.fromhex(child_id))
            )
        serialized.sort(key=lambda item: item[0] + (b"/" if item[1] else b"\0"))
        require(serialized, "retained source tree contains an empty directory")
        return git_object_id("tree", b"".join(item[2] for item in serialized))

    require(leaves, "retained source tree is empty")
    return tree_id(leaves)


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def write_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def canonical_tsv_bytes(
    schema: str,
    columns: tuple[str, ...] | list[str],
    rows: list[tuple[Any, ...]] | list[list[str]],
) -> bytes:
    """Serialize one TSV through the repository canonical byte grammar."""
    require_unique_tsv_columns(columns, schema)
    stream = io.StringIO(newline="")
    stream.write(f"# schema: {schema}\n")
    writer = csv.writer(stream, delimiter="\t", lineterminator="\n")
    writer.writerow(columns)
    for row in rows:
        writer.writerow(row)
    return stream.getvalue().encode("utf-8")


def require_unique_tsv_columns(
    columns: tuple[str, ...] | list[str],
    label: str,
) -> None:
    seen_columns: set[str] = set()
    duplicates: set[str] = set()
    for column in columns:
        if column in seen_columns:
            duplicates.add(column)
        else:
            seen_columns.add(column)
    duplicate_columns = sorted(duplicates)
    require(
        not duplicate_columns,
        f"{label} repeats columns: {', '.join(duplicate_columns)}",
    )


def write_tsv(path: Path, schema: str, columns: tuple[str, ...], rows: list[tuple[Any, ...]]) -> None:
    write_bytes(path, canonical_tsv_bytes(schema, columns, rows))


def read_tsv(path: Path, expected_schema: str) -> tuple[list[str], list[list[str]]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    require(lines and lines[0] == f"# schema: {expected_schema}", f"invalid schema: {path}")
    require(len(lines) >= 2, f"missing columns: {path}")
    parsed = list(csv.reader(lines[1:], delimiter="\t"))
    require(parsed and parsed[0], f"empty columns: {path}")
    require_unique_tsv_columns(parsed[0], str(path))
    return parsed[0], parsed[1:]


def read_canonical_ascii_tsv(
    path: Path,
    expected_schema: str,
    maximum_size: int,
    label: str,
    expected_sha256: str | None = None,
) -> tuple[list[str], list[list[str]]]:
    """Read, authenticate, and parse one bounded canonical ASCII TSV."""
    content = read_bounded_file(path, maximum_size, label)
    if expected_sha256 is not None:
        require(
            sha256_bytes(content) == expected_sha256,
            f"{label} identity differs",
        )
    try:
        text = content.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SourceMapError(f"{label} is not ASCII") from exc
    lines = text.splitlines()
    require(
        lines and lines[0] == f"# schema: {expected_schema}",
        f"invalid schema: {path}",
    )
    require(len(lines) >= 2, f"missing columns: {path}")
    parsed = list(csv.reader(lines[1:], delimiter="\t"))
    require(parsed and parsed[0], f"empty columns: {path}")
    columns, rows = parsed[0], parsed[1:]
    require_unique_tsv_columns(columns, label)
    require(
        content == canonical_tsv_bytes(expected_schema, columns, rows),
        f"{label} bytes are not canonical",
    )
    return columns, rows


def reject_unknown(mapping: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(mapping) - allowed)
    require(not unknown, f"{label} carries unknown keys: {', '.join(unknown)}")


def string_value(mapping: dict[str, Any], key: str, label: str) -> str:
    value = mapping.get(key)
    require(isinstance(value, str) and value, f"{label}.{key} must be a nonempty string")
    return value


def string_list(mapping: dict[str, Any], key: str, label: str, allow_empty: bool = False) -> tuple[str, ...]:
    value = mapping.get(key)
    require(isinstance(value, list), f"{label}.{key} must be a list")
    require(allow_empty or bool(value), f"{label}.{key} must not be empty")
    require(all(isinstance(item, str) and item for item in value), f"{label}.{key} contains an invalid string")
    return tuple(value)


def validate_path_witness_shape(
    witness: PathWitness,
    label: str,
    bindings: dict[str, Binding] | None = None,
) -> None:
    require(
        MECHANISM_NAME.fullmatch(witness.name) is not None,
        f"{label}.name is not mechanism-first ASCII",
    )
    require(
        all(
            value
            and value.isascii()
            and value.strip() == value
            and "\t" not in value
            and "\n" not in value
            for value in (witness.entry, witness.terminal)
        ),
        f"{label} entry or terminal is invalid",
    )
    require(witness.context, f"{label}.context must not be empty")
    require(
        all(
            item.isascii()
            and item.strip() == item
            and "\t" not in item
            and "\n" not in item
            for item in witness.context
        ),
        f"{label}.context contains invalid text",
    )
    require(
        tuple(sorted(set(witness.context))) == witness.context,
        f"{label}.context must be sorted and unique",
    )
    require(len(witness.edges) >= 2, f"{label}.edges must contain at least two edges")
    completed_axes: set[str] = set()
    axis_order: list[str] = []
    axis_entries: dict[str, str] = {}
    axis_terminals: dict[str, str] = {}
    active_axis = ""
    previous_callee = ""
    identities: set[tuple[str, ...]] = set()
    for edge_index, edge in enumerate(witness.edges):
        edge_label = f"{label}.edges[{edge_index}]"
        require(
            MECHANISM_NAME.fullmatch(edge.axis) is not None,
            f"{edge_label}.axis is invalid",
        )
        require(
            edge.edge_kind in CALL_CANDIDATE_EDGE_KINDS,
            f"{edge_label}.edge_kind is invalid",
        )
        require(
            all(
                value
                and value.isascii()
                and "\t" not in value
                and "\n" not in value
                for value in (
                    edge.caller,
                    edge.callee,
                    edge.partition,
                    edge.provenance,
                    edge.classification,
                )
            ),
            f"{edge_label} contains invalid candidate identity text",
        )
        if edge.axis != active_axis:
            if active_axis:
                completed_axes.add(active_axis)
            require(
                edge.axis not in completed_axes,
                f"{label} returns to a completed axis: {edge.axis}",
            )
            active_axis = edge.axis
            axis_order.append(active_axis)
            axis_entries[active_axis] = edge.caller
            previous_callee = ""
        if previous_callee:
            require(
                previous_callee == edge.caller,
                f"{label} axis {edge.axis} is not contiguous at edge {edge_index}",
            )
        previous_callee = edge.callee
        identity = (
            edge.edge_kind,
            edge.caller,
            edge.callee,
            edge.partition,
            edge.provenance,
            edge.classification,
        )
        require(identity not in identities, f"{label} repeats a candidate edge")
        identities.add(identity)
        axis_terminals[active_axis] = edge.callee
    require(
        witness.entry == witness.edges[0].caller
        and witness.terminal == witness.edges[-1].callee,
        f"{label} entry or terminal differs from its ordered edges",
    )

    require(
        len(witness.joins) == len(axis_order) - 1,
        f"{label} join denominator does not connect every axis",
    )
    axis_positions = {axis: index for index, axis in enumerate(axis_order)}
    parents = {axis: axis for axis in axis_order}

    def find(axis: str) -> str:
        while parents[axis] != axis:
            parents[axis] = parents[parents[axis]]
            axis = parents[axis]
        return axis

    join_identities: set[tuple[str, ...]] = set()
    for join_index, join in enumerate(witness.joins):
        join_label = f"{label}.joins[{join_index}]"
        require(
            join.kind in PATH_WITNESS_JOIN_KINDS,
            f"{join_label}.kind is invalid",
        )
        require(
            join.from_axis in axis_positions
            and join.to_axis in axis_positions
            and join.from_axis != join.to_axis,
            f"{join_label} names an absent or repeated axis",
        )
        require(
            axis_positions[join.from_axis] < axis_positions[join.to_axis],
            f"{join_label} reverses the ordered axis graph",
        )
        require(
            join.from_symbol == axis_terminals[join.from_axis]
            and join.to_symbol == axis_entries[join.to_axis],
            f"{join_label} does not bind exact axis boundaries",
        )
        require(
            join.evidence_ids
            and tuple(sorted(set(join.evidence_ids))) == join.evidence_ids
            and all(
                MECHANISM_NAME.fullmatch(evidence_id) is not None
                for evidence_id in join.evidence_ids
            ),
            f"{join_label}.evidence_ids must be sorted, unique binding IDs",
        )
        if bindings is not None:
            evidence_bindings = [
                bindings.get(evidence_id)
                for evidence_id in join.evidence_ids
            ]
            require(
                all(binding is not None for binding in evidence_bindings),
                f"{join_label} names unknown binding evidence",
            )
            require(
                any(
                    binding is not None and binding.scope == "brace"
                    for binding in evidence_bindings
                ),
                f"{join_label} has no brace-bounded binding evidence",
            )
        identity = (
            join.kind,
            join.from_axis,
            join.from_symbol,
            join.to_axis,
            join.to_symbol,
            *join.evidence_ids,
        )
        require(identity not in join_identities, f"{label} repeats a join")
        join_identities.add(identity)
        from_root = find(join.from_axis)
        to_root = find(join.to_axis)
        require(from_root != to_root, f"{label} joins contain a cycle")
        parents[to_root] = from_root
    require(
        len({find(axis) for axis in axis_order}) == 1,
        f"{label} axis graph is disconnected",
    )


def validate_required_path_witnesses(
    witnesses: tuple[PathWitness, ...] | list[PathWitness],
) -> None:
    endpoints = {
        witness.name: (witness.entry, witness.terminal)
        for witness in witnesses
    }
    require(
        endpoints == REQUIRED_PATH_WITNESS_ENDPOINTS,
        "contextual path witness endpoint denominator differs",
    )


def load_policy(
    path: Path,
    *,
    accepted_comparison_schemas: frozenset[str] = CURRENT_COMPARISON_SCHEMAS,
) -> Policy:
    try:
        content = path.read_bytes()
        content.decode("ascii")
        data = tomllib.loads(content.decode("ascii"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise SourceMapError(f"cannot read ASCII policy {path}: {exc}") from exc

    top_keys = {
        "schema",
        "capture_schema",
        "comparison_schema",
        "source_root",
        "max_source_files",
        "max_source_bytes",
        "required_tools",
        "optional_tools",
        "tool",
        "source_classes",
        "callback_extractor",
        "preprocessor",
        "partition",
        "hazard",
        "binding",
        "path_witness",
        "bounded_query",
    }
    reject_unknown(data, top_keys, "policy")
    require(data.get("schema") == 1, "policy.schema must equal 1")
    capture_schema = string_value(data, "capture_schema", "policy")
    comparison_schema = string_value(data, "comparison_schema", "policy")
    require(capture_schema == CAPTURE_SCHEMA, "policy capture schema differs from the producer")
    require(
        comparison_schema in accepted_comparison_schemas,
        "policy comparison schema differs from the producer",
    )
    source_root = string_value(data, "source_root", "policy")
    require(
        source_root == CANONICAL_SOURCE_ROOT,
        "source root differs from the canonical Radeon subtree",
    )
    max_source_files = data.get("max_source_files")
    max_source_bytes = data.get("max_source_bytes")
    require(
        max_source_files == MAX_SOURCE_FILES,
        "max_source_files differs from the verifier ceiling",
    )
    require(
        max_source_bytes == MAX_SOURCE_BYTES,
        "max_source_bytes differs from the verifier ceiling",
    )
    required_tools = string_list(data, "required_tools", "policy")
    optional_tools = string_list(data, "optional_tools", "policy", allow_empty=True)
    require(len(set(required_tools)) == len(required_tools), "required_tools repeats a tool")
    require(not set(required_tools) & set(optional_tools), "required and optional tools overlap")

    source_classes = data.get("source_classes")
    require(isinstance(source_classes, dict), "source_classes must be a table")
    reject_unknown(source_classes, {"c", "header", "register_policy", "makefile", "kconfig"}, "source_classes")
    require(all(isinstance(value, str) and value for value in source_classes.values()), "source_classes has an invalid pattern")

    extractor = data.get("callback_extractor")
    require(isinstance(extractor, dict), "callback_extractor must be a table")
    extractor_keys = {
        "minimum_field_initializers",
        "minimum_define_show_attributes",
        "minimum_drm_ioctl_bindings",
        "minimum_work_bindings",
    }
    reject_unknown(extractor, extractor_keys, "callback_extractor")
    require(set(extractor) == extractor_keys, "callback_extractor is incomplete")
    require(all(isinstance(value, int) and value >= 0 for value in extractor.values()), "callback extractor minima must be nonnegative")

    tool = data.get("tool")
    require(isinstance(tool, dict), "tool must be a table")
    reject_unknown(tool, {"gnu_global", "cflow", "ctags"}, "tool")
    global_policy = tool.get("gnu_global")
    cflow_policy = tool.get("cflow")
    ctags_policy = tool.get("ctags")
    require(isinstance(global_policy, dict), "tool.gnu_global must be a table")
    require(isinstance(cflow_policy, dict), "tool.cflow must be a table")
    require(isinstance(ctags_policy, dict), "tool.ctags must be a table")
    reject_unknown(global_policy, {"version", "config_sha256"}, "tool.gnu_global")
    reject_unknown(cflow_policy, {"allowed_stderr_patterns"}, "tool.cflow")
    reject_unknown(
        ctags_policy,
        {
            "version_first_line",
            "executable_sha256",
            "readtags_sha256",
            "package_owner",
            "allowed_stderr_patterns",
        },
        "tool.ctags",
    )
    global_version = string_value(global_policy, "version", "tool.gnu_global")
    global_config_sha256 = string_value(global_policy, "config_sha256", "tool.gnu_global")
    require(HEX_64.fullmatch(global_config_sha256) is not None, "GNU Global config digest is invalid")
    ctags_version_first_line = string_value(
        ctags_policy,
        "version_first_line",
        "tool.ctags",
    )
    ctags_executable_sha256 = string_value(
        ctags_policy,
        "executable_sha256",
        "tool.ctags",
    )
    readtags_executable_sha256 = string_value(
        ctags_policy,
        "readtags_sha256",
        "tool.ctags",
    )
    ctags_package_owner = string_value(
        ctags_policy,
        "package_owner",
        "tool.ctags",
    )
    require(
        HEX_64.fullmatch(ctags_executable_sha256) is not None
        and HEX_64.fullmatch(readtags_executable_sha256) is not None,
        "Ctags executable digest is invalid",
    )
    cflow_stderr = string_list(cflow_policy, "allowed_stderr_patterns", "tool.cflow")
    ctags_stderr = string_list(ctags_policy, "allowed_stderr_patterns", "tool.ctags")
    require(
        ctags_stderr
        == (r"^ctags: Notice: No options will be read from files or environment$",),
        "Universal Ctags diagnostic policy differs",
    )
    for pattern in (*cflow_stderr, *ctags_stderr):
        try:
            re.compile(pattern)
        except re.error as exc:
            raise SourceMapError(f"invalid tool diagnostic pattern {pattern!r}: {exc}") from exc

    preprocessor = data.get("preprocessor")
    require(isinstance(preprocessor, dict), "preprocessor must be a table")
    reject_unknown(preprocessor, {"translation_units", "kernel"}, "preprocessor")
    translation_units = string_list(preprocessor, "translation_units", "preprocessor")
    kernels = preprocessor.get("kernel")
    require(isinstance(kernels, list) and kernels, "preprocessor.kernel must be a nonempty table list")
    kernel_lanes: list[KernelLane] = []
    for index, kernel in enumerate(kernels):
        label = f"preprocessor.kernel[{index}]"
        require(isinstance(kernel, dict), f"{label} must be a table")
        reject_unknown(
            kernel,
            {
                "release",
                "declaration",
                "manifest",
                "toolchain_declaration",
                "toolchain_manifest",
                "toolchain_prefix_manifest",
                "profiles",
            },
            label,
        )
        kernel_lanes.append(
            KernelLane(
                string_value(kernel, "release", label),
                string_value(kernel, "declaration", label),
                string_value(kernel, "manifest", label),
                string_value(kernel, "toolchain_declaration", label),
                string_value(kernel, "toolchain_manifest", label),
                string_value(kernel, "toolchain_prefix_manifest", label),
                string_list(kernel, "profiles", label),
            )
        )
    require(len({lane.release for lane in kernel_lanes}) == len(kernel_lanes), "kernel release repeats")
    for lane in kernel_lanes:
        for declared_path in (
            lane.declaration,
            lane.manifest,
            lane.toolchain_declaration,
            lane.toolchain_manifest,
            lane.toolchain_prefix_manifest,
        ):
            path = Path(declared_path)
            require(
                not path.is_absolute()
                and ".." not in path.parts
                and "." not in path.parts,
                f"kernel lane {lane.release} carries an invalid evidence path",
            )
        require(
            len(set(lane.profiles)) == len(lane.profiles),
            f"kernel lane {lane.release} repeats a profile",
        )

    partitions: list[Partition] = []
    for index, item in enumerate(data.get("partition", [])):
        label = f"partition[{index}]"
        require(isinstance(item, dict), f"{label} must be a table")
        reject_unknown(item, {"name", "roots", "falsifier"}, label)
        partitions.append(
            Partition(
                string_value(item, "name", label),
                string_list(item, "roots", label),
                string_value(item, "falsifier", label),
            )
        )
    require(partitions, "policy carries no partitions")
    require(len({item.name for item in partitions}) == len(partitions), "partition name repeats")
    roots = [root for item in partitions for root in item.roots]
    require(len(set(roots)) == len(roots), "a root symbol appears in more than one partition")
    require(all(C_IDENTIFIER.fullmatch(root) for root in roots), "a root symbol is not a C identifier")

    hazards: list[Hazard] = []
    for index, item in enumerate(data.get("hazard", [])):
        label = f"hazard[{index}]"
        require(isinstance(item, dict), f"{label} must be a table")
        reject_unknown(
            item,
            {
                "symbol",
                "side_effect_class",
                "guard_identifier_census",
                "evidence_rank",
            },
            label,
        )
        symbol = string_value(item, "symbol", label)
        require(C_IDENTIFIER.fullmatch(symbol) is not None, f"{label}.symbol is invalid")
        raw_census = item.get("guard_identifier_census")
        require(
            isinstance(raw_census, list),
            f"{label}.guard_identifier_census must be a list",
        )
        guard_identifier_census: list[GuardIdentifierCensus] = []
        for census_index, census in enumerate(raw_census):
            census_label = f"{label}.guard_identifier_census[{census_index}]"
            require(isinstance(census, dict), f"{census_label} must be a table")
            reject_unknown(census, {"owner", "identifiers"}, census_label)
            owner = string_value(census, "owner", census_label)
            identifiers = string_list(census, "identifiers", census_label)
            require(C_IDENTIFIER.fullmatch(owner) is not None, f"{census_label}.owner is invalid")
            require(
                all(C_IDENTIFIER.fullmatch(identifier) for identifier in identifiers),
                f"{census_label}.identifiers contains an invalid C identifier",
            )
            require(
                len(set(identifiers)) == len(identifiers),
                f"{census_label}.identifiers repeats a value",
            )
            guard_identifier_census.append(GuardIdentifierCensus(owner, identifiers))
        require(
            len({census.owner for census in guard_identifier_census})
            == len(guard_identifier_census),
            f"{label}.guard_identifier_census repeats an owner",
        )
        hazards.append(
            Hazard(
                symbol,
                string_value(item, "side_effect_class", label),
                tuple(guard_identifier_census),
                string_value(item, "evidence_rank", label),
            )
        )
    require(hazards, "policy carries no hazards")
    require(len({item.symbol for item in hazards}) == len(hazards), "hazard symbol repeats")

    partition_names = {item.name for item in partitions}
    bindings: list[Binding] = []
    for index, item in enumerate(data.get("binding", [])):
        label = f"binding[{index}]"
        require(isinstance(item, dict), f"{label} must be a table")
        keys = {
            "name",
            "partition",
            "kind",
            "scope",
            "caller",
            "callee",
            "path",
            "pattern",
            "expected_matches",
            "match_literals",
        }
        reject_unknown(item, keys, label)
        expected = item.get("expected_matches")
        require(isinstance(expected, int) and expected > 0, f"{label}.expected_matches must be positive")
        partition_name = string_value(item, "partition", label)
        require(partition_name in partition_names, f"{label} names an unknown partition")
        path_value = string_value(item, "path", label)
        require(path_value.startswith(source_root + "/"), f"{label}.path is outside the source root")
        pattern = string_value(item, "pattern", label)
        try:
            re.compile(pattern, re.MULTILINE | re.DOTALL)
        except re.error as exc:
            raise SourceMapError(f"{label}.pattern is invalid: {exc}") from exc
        bindings.append(
            Binding(
                string_value(item, "name", label),
                partition_name,
                string_value(item, "kind", label),
                string_value(item, "scope", label),
                string_value(item, "caller", label),
                string_value(item, "callee", label),
                path_value,
                pattern,
                expected,
                item.get("match_literals", False),
            )
        )
        require(
            bindings[-1].scope in {"brace", "match"},
            f"{label}.scope must equal brace or match",
        )
        require(isinstance(bindings[-1].match_literals, bool), f"{label}.match_literals must be Boolean")
    require(bindings, "policy carries no declared bindings")
    require(len({item.name for item in bindings}) == len(bindings), "binding name repeats")
    binding_edges = {(item.kind, item.caller, item.callee) for item in bindings}
    require(len(binding_edges) == len(bindings), "declared binding edge repeats")

    path_witnesses: list[PathWitness] = []
    for index, item in enumerate(data.get("path_witness", [])):
        label = f"path_witness[{index}]"
        require(isinstance(item, dict), f"{label} must be a table")
        witness_keys = {
            "name",
            "entry",
            "terminal",
            "context",
            "edge",
            "join",
        }
        reject_unknown(item, witness_keys, label)
        require(set(item) == witness_keys, f"{label} is incomplete")
        raw_edges = item.get("edge")
        require(isinstance(raw_edges, list), f"{label}.edge must be a table list")
        edges: list[PathWitnessEdge] = []
        for edge_index, edge in enumerate(raw_edges):
            edge_label = f"{label}.edge[{edge_index}]"
            require(isinstance(edge, dict), f"{edge_label} must be a table")
            edge_keys = {
                "axis",
                "edge_kind",
                "caller",
                "callee",
                "partition",
                "provenance",
                "classification",
            }
            reject_unknown(edge, edge_keys, edge_label)
            require(set(edge) == edge_keys, f"{edge_label} is incomplete")
            edges.append(
                PathWitnessEdge(
                    string_value(edge, "axis", edge_label),
                    string_value(edge, "edge_kind", edge_label),
                    string_value(edge, "caller", edge_label),
                    string_value(edge, "callee", edge_label),
                    string_value(edge, "partition", edge_label),
                    string_value(edge, "provenance", edge_label),
                    string_value(edge, "classification", edge_label),
                )
            )
        raw_joins = item.get("join")
        require(isinstance(raw_joins, list), f"{label}.join must be a table list")
        joins: list[PathWitnessJoin] = []
        for join_index, join in enumerate(raw_joins):
            join_label = f"{label}.join[{join_index}]"
            require(isinstance(join, dict), f"{join_label} must be a table")
            join_keys = {
                "kind",
                "from_axis",
                "from_symbol",
                "to_axis",
                "to_symbol",
                "evidence_ids",
            }
            reject_unknown(join, join_keys, join_label)
            require(set(join) == join_keys, f"{join_label} is incomplete")
            joins.append(
                PathWitnessJoin(
                    string_value(join, "kind", join_label),
                    string_value(join, "from_axis", join_label),
                    string_value(join, "from_symbol", join_label),
                    string_value(join, "to_axis", join_label),
                    string_value(join, "to_symbol", join_label),
                    string_list(join, "evidence_ids", join_label),
                )
            )
        witness = PathWitness(
            string_value(item, "name", label),
            string_value(item, "entry", label),
            string_value(item, "terminal", label),
            string_list(item, "context", label),
            tuple(edges),
            tuple(joins),
        )
        validate_path_witness_shape(
            witness,
            label,
            {binding.name: binding for binding in bindings},
        )
        path_witnesses.append(witness)
    require(path_witnesses, "policy carries no contextual path witnesses")
    require(
        len({item.name for item in path_witnesses}) == len(path_witnesses),
        "path witness name repeats",
    )
    validate_required_path_witnesses(path_witnesses)

    bounded_queries: list[BoundedQuery] = []
    for index, item in enumerate(data.get("bounded_query", [])):
        label = f"bounded_query[{index}]"
        require(isinstance(item, dict), f"{label} must be a table")
        reject_unknown(
            item,
            {"name", "paths", "pattern", "expected_matches", "rationale"},
            label,
        )
        pattern = string_value(item, "pattern", label)
        try:
            re.compile(pattern, re.MULTILINE | re.DOTALL)
        except re.error as exc:
            raise SourceMapError(f"{label}.pattern is invalid: {exc}") from exc
        paths = string_list(item, "paths", label)
        require(all(path.startswith(source_root + "/") for path in paths), f"{label}.paths leave the source root")
        expected_matches = item.get("expected_matches")
        require(
            isinstance(expected_matches, int) and expected_matches >= 0,
            f"{label}.expected_matches must be nonnegative",
        )
        bounded_queries.append(
            BoundedQuery(
                string_value(item, "name", label),
                paths,
                pattern,
                expected_matches,
                string_value(item, "rationale", label),
            )
        )
    require(bounded_queries, "policy carries no bounded queries")
    require(len({item.name for item in bounded_queries}) == len(bounded_queries), "bounded query name repeats")

    return Policy(
        capture_schema,
        comparison_schema,
        source_root,
        max_source_files,
        max_source_bytes,
        required_tools,
        optional_tools,
        dict(source_classes),
        dict(extractor),
        global_version,
        global_config_sha256,
        ctags_version_first_line,
        ctags_executable_sha256,
        readtags_executable_sha256,
        ctags_package_owner,
        cflow_stderr,
        ctags_stderr,
        translation_units,
        tuple(kernel_lanes),
        tuple(partitions),
        tuple(hazards),
        tuple(bindings),
        tuple(path_witnesses),
        tuple(bounded_queries),
    )


def git_output(repository: Path, *args: str, text: bool = True) -> str | bytes:
    result = subprocess.run(
        ["git", "-C", str(repository), *args],
        check=False,
        capture_output=True,
        text=text,
        env=command_environment_contract("/tmp"),
    )
    stderr = result.stderr if text else result.stderr.decode("utf-8", errors="replace")
    require(result.returncode == 0, f"git {' '.join(args)} failed: {stderr.strip()}")
    return result.stdout


def resolve_repository(path: Path) -> Path:
    resolved = Path(str(git_output(path, "rev-parse", "--show-toplevel")).strip()).resolve()
    require((resolved / ".git").exists(), f"repository has no Git metadata: {resolved}")
    return resolved


def commit_timestamp_utc(repository: Path, commit: str) -> str:
    content = git_output(repository, "cat-file", "commit", commit, text=False)
    assert isinstance(content, bytes)
    require(
        git_object_id("commit", content) == commit,
        "source commit object identity differs while reading its timestamp",
    )
    _tree_id, timestamp_utc = commit_identity(content)
    return timestamp_utc


def parse_release_paths(specifications: list[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for specification in specifications:
        release, separator, raw_path = specification.partition("=")
        require(separator == "=" and release and raw_path, f"invalid release path: {specification}")
        require(
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", release) is not None,
            f"invalid kernel release in path: {release}",
        )
        require(release not in result, f"kernel release path repeats: {release}")
        result[release] = Path(raw_path).resolve()
    return result


def load_source_closure(repository: Path, commit: str, expected_root: str) -> bytes:
    content = git_output(repository, "show", f"{commit}:source-closure.toml", text=False)
    assert isinstance(content, bytes)
    try:
        declaration = tomllib.loads(content.decode("ascii"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise SourceMapError(f"source closure is not valid ASCII TOML: {exc}") from exc
    closure = declaration.get("closure")
    require(isinstance(closure, dict), "source closure has no closure table")
    require(closure.get("upstream_path") == expected_root, "source root differs from source-closure.toml")
    excluded = declaration.get("excluded")
    require(isinstance(excluded, list) and excluded, "source closure has no exclusions")
    patterns = {entry.get("pattern") for entry in excluded if isinstance(entry, dict)}
    require("*_reg_safe.h" in patterns, "source closure does not exclude generated register headers")
    repository_only = declaration.get("repository_only")
    require(isinstance(repository_only, list), "source closure repository_only is invalid")
    paths = {entry.get("path") for entry in repository_only if isinstance(entry, dict)}
    require(".gitignore" in paths, "source closure does not classify driver .gitignore")
    return content


def source_class(policy: Policy, path: str) -> str | None:
    relative = path.removeprefix(policy.source_root + "/")
    name = relative.rsplit("/", 1)[-1]
    if fnmatch.fnmatch(name, policy.source_classes["c"]):
        return "c"
    if fnmatch.fnmatch(name, policy.source_classes["header"]):
        return "header"
    if fnmatch.fnmatch(relative, policy.source_classes["register_policy"]):
        return "register-policy"
    if relative == policy.source_classes["makefile"]:
        return "makefile"
    if relative == policy.source_classes["kconfig"]:
        return "kconfig"
    if relative == ".gitignore":
        return "repository-metadata"
    raise SourceMapError(f"unclassified tracked path under source root: {path}")


def parse_ls_tree(raw: bytes, policy: Policy) -> list[tuple[str, str, str, int, str]]:
    entries: list[tuple[str, str, str, int, str]] = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            metadata, path_bytes = record.split(b"\t", 1)
            path = path_bytes.decode("utf-8")
            mode, object_type, object_id, size_text = metadata.decode("ascii").split()
        except (ValueError, UnicodeDecodeError) as exc:
            raise SourceMapError("git ls-tree emitted a malformed record") from exc
        require(object_type == "blob", f"non-blob source entry: {path}")
        require(mode in {"100644", "100755"}, f"special or symlinked source entry: {path}")
        require(HEX_40.fullmatch(object_id) is not None, f"invalid source object ID: {path}")
        require(size_text.isdigit(), f"invalid source size: {path}")
        require(path.startswith(policy.source_root + "/"), f"source path escaped root: {path}")
        require("\n" not in path and "\t" not in path and not any(ord(char) < 32 for char in path), f"source path carries a control character: {path!r}")
        path_parts = Path(path).parts
        require(".." not in path_parts and not Path(path).is_absolute(), f"source path traverses: {path}")
        entries.append((mode, object_type, object_id, int(size_text), path))
    require(entries, "tracked source denominator is empty")
    require(len({entry[4] for entry in entries}) == len(entries), "tracked source path repeats")
    return sorted(entries, key=lambda item: item[4].encode("utf-8"))


def export_source(repository: Path, commit: str, policy: Policy, destination: Path) -> list[SourceEntry]:
    raw_tree = git_output(repository, "ls-tree", "-r", "-z", "-l", commit, "--", policy.source_root, text=False)
    assert isinstance(raw_tree, bytes)
    tree_entries = parse_ls_tree(raw_tree, policy)
    admitted = [entry for entry in tree_entries if source_class(policy, entry[4]) is not None]
    require(len(admitted) <= policy.max_source_files, "source file count exceeds the policy ceiling")
    require(sum(entry[3] for entry in admitted) <= policy.max_source_bytes, "source byte count exceeds the policy ceiling")
    require(len(tree_entries) == len(admitted), "source closure contains an unclassified tracked path")

    source_entries: list[SourceEntry] = []
    for mode, _object_type, object_id, size, path in admitted:
        content = git_output(repository, "cat-file", "blob", object_id, text=False)
        assert isinstance(content, bytes)
        require(len(content) == size, f"Git blob size differs for {path}")
        require(
            git_object_id("blob", content) == object_id,
            f"Git blob identity differs for {path}",
        )
        target = destination / path
        write_bytes(target, content)
        target.chmod(0o755 if mode == "100755" else 0o644)
        source_entries.append(
            SourceEntry(
                path,
                mode,
                object_id,
                size,
                sha256_bytes(content),
                source_class(policy, path) or "",
            )
        )
    return sorted(source_entries, key=lambda item: item.path.encode("utf-8"))


def source_tree_proof_paths(source_root: str) -> list[tuple[str, str]]:
    components = source_root.split("/")
    require(components and all(components), "source root cannot form a Git proof path")
    result = [("tree-root.bin", components[0])]
    for index, component in enumerate(components[1:], 1):
        parent = "-".join(components[:index])
        result.append((f"tree-{parent}.bin", component))
    return result


def write_source_tree_proof(
    capture_root: Path,
    repository: Path,
    source_commit: str,
    source_tree: str,
    driver_tree: str,
    source_root: str,
) -> None:
    proof_root = capture_root / "metadata/git-source-proof"
    commit_content = git_output(repository, "cat-file", "commit", source_commit, text=False)
    assert isinstance(commit_content, bytes)
    require(git_object_id("commit", commit_content) == source_commit, "source commit object identity differs")
    commit_tree, _commit_timestamp = commit_identity(commit_content)
    require(commit_tree == source_tree, "source commit object names a different tree")
    write_bytes(proof_root / "commit.bin", commit_content)

    current_tree = source_tree
    for filename, component in source_tree_proof_paths(source_root):
        tree_content = git_output(repository, "cat-file", "tree", current_tree, text=False)
        assert isinstance(tree_content, bytes)
        require(git_object_id("tree", tree_content) == current_tree, "source tree object identity differs")
        write_bytes(proof_root / filename, tree_content)
        component_bytes = component.encode("utf-8")
        matches = [
            object_id
            for mode, name, object_id in parse_git_tree_object(tree_content)
            if mode == "40000" and name == component_bytes
        ]
        require(len(matches) == 1, f"source tree proof does not resolve directory: {component}")
        current_tree = matches[0]
    require(current_tree == driver_tree, "source tree proof resolves a different driver tree")


def verify_source_tree_proof(
    capture_root: Path,
    source_commit: str,
    source_tree: str,
    driver_tree: str,
    source_root: str,
) -> str:
    proof_root = capture_root / "metadata/git-source-proof"
    expected_files = {"commit.bin"} | {
        filename for filename, _component in source_tree_proof_paths(source_root)
    }
    require(
        regular_tree_files(proof_root, "retained source Git proof")
        == expected_files,
        "retained source Git proof file denominator differs",
    )
    commit_content = read_bounded_file(
        proof_root / "commit.bin",
        MAX_MANIFEST_BYTES,
        "retained source commit proof",
    )
    require(git_object_id("commit", commit_content) == source_commit, "retained source commit object identity differs")
    commit_tree, timestamp_utc = commit_identity(commit_content)
    require(commit_tree == source_tree, "retained source commit names a different source tree")

    current_tree = source_tree
    for filename, component in source_tree_proof_paths(source_root):
        tree_path = proof_root / filename
        require(tree_path.is_file() and not tree_path.is_symlink(), f"retained source tree proof is absent: {filename}")
        tree_content = tree_path.read_bytes()
        require(git_object_id("tree", tree_content) == current_tree, f"retained source tree object identity differs: {filename}")
        component_bytes = component.encode("utf-8")
        matches = [
            object_id
            for mode, name, object_id in parse_git_tree_object(tree_content)
            if mode == "40000" and name == component_bytes
        ]
        require(len(matches) == 1, f"retained source tree proof does not resolve directory: {component}")
        current_tree = matches[0]
    require(current_tree == driver_tree, "retained source tree proof resolves a different driver tree")
    return timestamp_utc


def git_file_proof_tree_filename(directory_parts: tuple[str, ...]) -> str:
    if not directory_parts:
        return "tree-root.bin"
    directory = "/".join(directory_parts)
    digest = hashlib.sha256(directory.encode("utf-8")).hexdigest()[:16]
    return f"tree-{len(directory_parts)}-{digest}.bin"


def git_file_proof_directories(repository_paths: set[str]) -> set[tuple[str, ...]]:
    directories: set[tuple[str, ...]] = {()}
    for repository_path in repository_paths:
        path = Path(repository_path)
        require(
            repository_path == path.as_posix()
            and not path.is_absolute()
            and "." not in path.parts
            and ".." not in path.parts
            and len(path.parts) >= 1,
            f"Git file proof path is invalid: {repository_path}",
        )
        for depth in range(1, len(path.parts)):
            directories.add(tuple(path.parts[:depth]))
    return directories


def write_git_file_proof(
    proof_root: Path,
    repository: Path,
    commit: str,
    tree: str,
    repository_paths: set[str],
) -> None:
    commit_content = git_output(repository, "cat-file", "commit", commit, text=False)
    assert isinstance(commit_content, bytes)
    require(git_object_id("commit", commit_content) == commit, "Git file proof commit identity differs")
    commit_tree, _timestamp_utc = commit_identity(commit_content)
    require(commit_tree == tree, "Git file proof commit names a different tree")
    write_bytes(proof_root / "commit.bin", commit_content)

    tree_ids: dict[tuple[str, ...], str] = {(): tree}
    for directory_parts in sorted(
        git_file_proof_directories(repository_paths),
        key=lambda parts: (len(parts), parts),
    ):
        tree_id = tree_ids.get(directory_parts)
        require(tree_id is not None, "Git file proof cannot resolve a parent tree")
        tree_content = git_output(repository, "cat-file", "tree", tree_id, text=False)
        assert isinstance(tree_content, bytes)
        require(git_object_id("tree", tree_content) == tree_id, "Git file proof tree identity differs")
        write_bytes(
            proof_root / git_file_proof_tree_filename(directory_parts),
            tree_content,
        )
        for mode, name, object_id in parse_git_tree_object(tree_content):
            if mode != "40000":
                continue
            try:
                component = name.decode("utf-8")
            except UnicodeDecodeError:
                continue
            tree_ids[(*directory_parts, component)] = object_id


def verify_git_file_proof(
    capture_root: Path,
    proof_root: Path,
    commit: str,
    tree: str,
    retained_paths: dict[str, str],
    label: str,
) -> str:
    repository_paths = set(retained_paths)
    directories = git_file_proof_directories(repository_paths)
    expected_files = {"commit.bin"} | {
        git_file_proof_tree_filename(directory_parts)
        for directory_parts in directories
    }
    require(
        regular_tree_files(proof_root, label) == expected_files,
        f"{label} file denominator differs",
    )
    commit_content = read_bounded_file(
        proof_root / "commit.bin",
        MAX_MANIFEST_BYTES,
        f"{label} commit",
    )
    require(git_object_id("commit", commit_content) == commit, f"{label} commit identity differs")
    commit_tree, timestamp_utc = commit_identity(commit_content)
    require(commit_tree == tree, f"{label} commit names a different tree")

    tree_ids: dict[tuple[str, ...], str] = {(): tree}
    tree_entries: dict[tuple[str, ...], list[tuple[str, bytes, str]]] = {}
    for directory_parts in sorted(directories, key=lambda parts: (len(parts), parts)):
        tree_id = tree_ids.get(directory_parts)
        require(tree_id is not None, f"{label} cannot resolve a parent tree")
        tree_content = read_bounded_file(
            proof_root / git_file_proof_tree_filename(directory_parts),
            16 * MAX_MANIFEST_BYTES,
            f"{label} tree",
        )
        require(
            git_object_id("tree", tree_content) == tree_id,
            f"{label} tree identity differs",
        )
        parsed = parse_git_tree_object(tree_content)
        tree_entries[directory_parts] = parsed
        for mode, name, object_id in parsed:
            if mode != "40000":
                continue
            try:
                component = name.decode("utf-8")
            except UnicodeDecodeError:
                continue
            tree_ids[(*directory_parts, component)] = object_id

    for repository_path, retained_path in sorted(retained_paths.items()):
        parts = Path(repository_path).parts
        parent = tuple(parts[:-1])
        basename = parts[-1].encode("utf-8")
        matches = [
            (mode, object_id)
            for mode, name, object_id in tree_entries[parent]
            if name == basename and mode in {"100644", "100755"}
        ]
        require(len(matches) == 1, f"{label} does not resolve {repository_path}")
        mode, object_id = matches[0]
        retained = capture_root / retained_path
        content = read_bounded_file(
            retained,
            MAX_SOURCE_BYTES,
            f"{label} retained file {retained_path}",
        )
        require(
            git_object_id("blob", content) == object_id,
            f"{label} retained blob differs: {repository_path}",
        )
        retained_mode = "100755" if retained.lstat().st_mode & 0o111 else "100644"
        require(retained_mode == mode, f"{label} retained mode differs: {repository_path}")
    return timestamp_utc


def producer_input_paths(policy: Policy) -> dict[str, str]:
    repository_paths = {
        "AGENTS.md",
        POLICY_PATH.as_posix(),
        SCRIPT_PATH.as_posix(),
        KERNEL_ROOT_VALIDATOR_PATH.as_posix(),
    }
    for lane in policy.kernel_lanes:
        repository_paths.update(
            {
                lane.declaration,
                lane.manifest,
                lane.toolchain_declaration,
                lane.toolchain_manifest,
                lane.toolchain_prefix_manifest,
            }
        )
    return {
        repository_path: (
            POLICY_PATH.as_posix()
            if repository_path == POLICY_PATH.as_posix()
            else f"producer/{repository_path}"
        )
        for repository_path in sorted(repository_paths)
    }


def source_input_paths() -> dict[str, str]:
    paths = (
        "UPSTREAM_BASE.toml",
        "source-closure.toml",
        "policy/build-features.toml",
    )
    return {path: path for path in paths}


def retain_producer_inputs(
    capture_root: Path,
    repository: Path,
    policy: Policy,
) -> dict[str, str]:
    retained_paths = producer_input_paths(policy)
    for repository_path, retained_path in retained_paths.items():
        if retained_path == POLICY_PATH.as_posix():
            continue
        source = repository / repository_path
        require(source.is_file() and not source.is_symlink(), f"producer input is absent: {repository_path}")
        target = capture_root / retained_path
        write_bytes(target, source.read_bytes())
        target.chmod(0o755 if source.stat().st_mode & 0o111 else 0o644)
    return retained_paths


def strip_comments(source: str) -> str:
    """Apply C line splicing, then blank comments while retaining literals."""

    def blank_comment(match: re.Match[str]) -> str:
        token = match.group(0)
        if not token.startswith(("/*", "//")):
            return token
        return re.sub(r"[^\n]", " ", token)

    return C_COMMENT_OR_LITERAL.sub(blank_comment, C_LINE_SPLICE.sub("", source))


def strip_comments_and_literals(source: str) -> str:
    """Apply C line splicing, then blank comments and C literals."""

    def blank(match: re.Match[str]) -> str:
        return re.sub(r"[^\n]", " ", match.group(0))

    return C_COMMENT_OR_LITERAL.sub(blank, C_LINE_SPLICE.sub("", source))


def physical_offset_after_splicing(source: str, logical_offset: int) -> int:
    """Map one phase-2 logical offset back to the physical source stream."""
    require(logical_offset >= 0, "logical source offset is negative")
    physical_offset = 0
    current_logical_offset = 0
    while physical_offset < len(source):
        splice = C_LINE_SPLICE.match(source, physical_offset)
        if splice is not None:
            physical_offset = splice.end()
            continue
        if current_logical_offset == logical_offset:
            return physical_offset
        physical_offset += 1
        current_logical_offset += 1
    require(
        current_logical_offset == logical_offset,
        "logical source offset exceeds the phase-2 translation stream",
    )
    return physical_offset


def physical_line_after_splicing(source: str, logical_offset: int) -> int:
    """Return the physical one-based line for one phase-2 logical offset."""
    physical_offset = physical_offset_after_splicing(source, logical_offset)
    return source.count("\n", 0, physical_offset) + 1


def missing_code_identifiers(source: str, identifiers: tuple[str, ...]) -> list[str]:
    code = strip_comments_and_literals(source)
    return [
        identifier
        for identifier in identifiers
        if re.search(rf"\b{re.escape(identifier)}\b", code) is None
    ]


def command_environment_contract(
    home: str,
    additions: dict[str, str] | None = None,
) -> dict[str, str]:
    """Build the complete allowlisted environment for retained commands."""
    extra = additions or {}
    require(
        set(extra).issubset(
            {"GTAGSDBPATH", "GTAGSROOT", "LD_LIBRARY_PATH", "PATH"}
        ),
        "command environment carries an unapproved variable",
    )
    return {
        "HOME": home,
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TZ": "UTC",
        **extra,
    }


def kernel_make_base_command(
    profile: str,
    kernel_root: str | Path,
    driver_work: str | Path,
    toolchain_bin: str | Path,
    toolchain_prefix: str | Path,
    preprocessor_work: str | Path,
) -> list[str]:
    """Build the single admitted Kbuild command prefix for one profile."""
    kernel_root_text = str(kernel_root)
    driver_work_text = str(driver_work)
    toolchain_bin_text = str(toolchain_bin).rstrip("/")
    toolchain_prefix_text = str(toolchain_prefix).rstrip("/")
    preprocessor_work_text = str(preprocessor_work).rstrip("/")
    include_trace = f"{preprocessor_work_text}/include/trace"
    profile_header_path = f"{preprocessor_work_text}/radeon_build_profile.h"
    prefix_maps = (
        "--no-default-config "
        f"-resource-dir={toolchain_prefix_text}/lib/clang/22 "
        f"-ffile-prefix-map={preprocessor_work_text}="
        f"{CANONICAL_PREPROCESSOR_WORK} "
        f"-fmacro-prefix-map={preprocessor_work_text}="
        f"{CANONICAL_PREPROCESSOR_WORK} "
        f"-ffile-prefix-map={kernel_root_text}={CANONICAL_KERNEL_BUILD_ROOT} "
        f"-fmacro-prefix-map={kernel_root_text}={CANONICAL_KERNEL_BUILD_ROOT} "
        f"-ffile-prefix-map={toolchain_prefix_text}={CANONICAL_KERNEL_TOOLCHAIN} "
        f"-fmacro-prefix-map={toolchain_prefix_text}={CANONICAL_KERNEL_TOOLCHAIN}"
    )
    kcflags = (
        f"-I{include_trace} -include {profile_header_path} {prefix_maps}"
    )
    return [
        "/usr/bin/make",
        f"LLVM={toolchain_bin_text}/",
        "SHELL=/usr/bin/sh",
        "CONFIG_SHELL=/usr/bin/sh",
        f"RADEON_BUILD_PROFILE={profile}",
        f"KCFLAGS={kcflags}",
        "-C",
        kernel_root_text,
        f"M={driver_work_text}",
    ]


class CommandRecorder:
    """Run argv-only analyzer commands and retain bounded diagnostics."""

    def __init__(self, capture_root: Path, repository: Path, source_root: Path):
        self.capture_root = capture_root
        self.repository = repository
        self.source_root = source_root
        self.records: list[CommandRecord] = []
        self.replacements: list[tuple[str, str]] = [
            (str(capture_root), "<capture-root>"),
            (str(repository), "<repository>"),
            (str(source_root), "<source-root>"),
        ]

    def add_replacement(self, path: Path, token: str) -> None:
        self.replacements.append((str(path), token))

    def sanitize(self, value: str) -> str:
        output = value
        for raw, token in sorted(self.replacements, key=lambda item: len(item[0]), reverse=True):
            output = output.replace(raw, token)
        return output

    def _validate_stderr(self, stderr: str, allowed_patterns: tuple[str, ...]) -> None:
        lines = [line for line in stderr.splitlines() if line]
        for line in lines:
            require(
                any(re.fullmatch(pattern, line) for pattern in allowed_patterns),
                f"analyzer emitted an unapproved diagnostic: {line}",
            )

    def run(
        self,
        command_id: str,
        argv: list[str],
        cwd: Path,
        stdout_path: str,
        stderr_path: str,
        *,
        environment: dict[str, str] | None = None,
        allowed_stderr: tuple[str, ...] = (),
        require_empty_stderr: bool = True,
        input_bytes: bytes | None = None,
    ) -> bytes:
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", command_id) is not None, f"invalid command ID: {command_id}")
        executable_replacements = [
            (item, Path(item).name)
            for item in argv
            if Path(item).is_absolute()
            and Path(item).is_file()
            and os.access(item, os.X_OK)
        ]

        def sanitize_runtime(value: str) -> str:
            output = self.sanitize(value)
            for raw, token in sorted(
                executable_replacements,
                key=lambda item: len(item[0]),
                reverse=True,
            ):
                output = output.replace(raw, token)
            return output

        env_additions = environment or {}
        command_environment = command_environment_contract(
            str(self.capture_root),
            env_additions,
        )
        result = subprocess.run(
            argv,
            cwd=cwd,
            env=command_environment,
            input=input_bytes,
            capture_output=True,
            check=False,
        )
        stdout_text = result.stdout.decode("utf-8", errors="replace")
        stderr_text = result.stderr.decode("utf-8", errors="replace")
        write_text(self.capture_root / stdout_path, sanitize_runtime(stdout_text))
        write_text(self.capture_root / stderr_path, sanitize_runtime(stderr_text))
        record_environment = {
            key: sanitize_runtime(value)
            for key, value in sorted(
                command_environment_contract("<capture-root>", env_additions).items()
            )
        }
        sanitized_executable = self.sanitize(str(argv[0]))
        retained_argv0 = (
            sanitized_executable
            if sanitized_executable == "/usr/bin/make"
            or sanitized_executable.startswith("<kernel-toolchain-root>/")
            else Path(argv[0]).name
        )
        self.records.append(
            CommandRecord(
                command_id,
                Path(argv[0]).name,
                self.sanitize(str(cwd)),
                result.returncode,
                stdout_path,
                stderr_path,
                json.dumps(
                    [retained_argv0, *[sanitize_runtime(item) for item in argv[1:]]],
                    separators=(",", ":"),
                ),
                json.dumps(record_environment, separators=(",", ":")),
            )
        )
        if result.returncode != 0:
            diagnostic_text = sanitize_runtime(stderr_text or stdout_text).strip()
            diagnostic_lines = diagnostic_text.splitlines()[-20:]
            diagnostic_tail = "\n".join(diagnostic_lines)
            if len(diagnostic_tail) > 4000:
                diagnostic_tail = diagnostic_tail[-4000:]
            detail = f":\n{diagnostic_tail}" if diagnostic_tail else ""
            raise SourceMapError(
                f"command {command_id} exited {result.returncode}{detail}"
            )
        if require_empty_stderr:
            diagnostic_text = sanitize_runtime(stderr_text).strip()
            diagnostic_lines = diagnostic_text.splitlines()[-20:]
            diagnostic_tail = "\n".join(diagnostic_lines)
            if len(diagnostic_tail) > 4000:
                diagnostic_tail = diagnostic_tail[-4000:]
            detail = f":\n{diagnostic_tail}" if diagnostic_tail else ""
            require(not stderr_text, f"command {command_id} emitted stderr{detail}")
        else:
            self._validate_stderr(stderr_text, allowed_stderr)
        return result.stdout

    def write_manifest(self) -> None:
        rows = [
            (
                item.command_id,
                item.tool,
                item.cwd,
                item.status,
                item.stdout_path,
                item.stderr_path,
                item.argv_json,
                item.environment_json,
            )
            for item in self.records
        ]
        require(len({item[0] for item in rows}) == len(rows), "command ID repeats")
        write_tsv(
            self.capture_root / "metadata/command-metadata.tsv",
            "radeon-driver-command-metadata-v1",
            (
                "command_id",
                "tool",
                "cwd",
                "status",
                "stdout_path",
                "stderr_path",
                "argv_json",
                "environment_json",
            ),
            rows,
        )


def command_record_row(
    command_id: str,
    tool: str,
    cwd: str,
    stdout_path: str,
    stderr_path: str,
    argv: list[str],
    environment: dict[str, str] | None = None,
) -> tuple[str, ...]:
    full_environment = command_environment_contract(
        "<capture-root>",
        environment,
    )
    return (
        command_id,
        tool,
        cwd,
        "0",
        stdout_path,
        stderr_path,
        json.dumps(argv, separators=(",", ":")),
        json.dumps(dict(sorted(full_environment.items())), separators=(",", ":")),
    )


def policy_root_symbols(policy: Policy) -> list[str]:
    return sorted(
        {
            root_symbol
            for partition in policy.partitions
            for root_symbol in partition.roots
        }
        | {hazard.symbol for hazard in policy.hazards}
    )


def canonical_analyzer_sandbox() -> list[str]:
    return [
        "bwrap",
        "--die-with-parent",
        "--ro-bind",
        "/",
        "/",
        "--tmpfs",
        "/tmp",
        "--dir",
        "/tmp/source",
        "--dir",
        "/tmp/capture",
        "--ro-bind",
        "<source-root>",
        "/tmp/source",
        "--bind",
        "<capture-root>",
        "/tmp/capture",
        "--chdir",
        "/tmp/source",
    ]


def expected_command_records(
    policy: Policy,
    source_entries: list[SourceEntry],
    active_releases: set[str],
) -> list[tuple[str, ...]]:
    c_and_header_paths = [
        entry.path
        for entry in source_entries
        if entry.source_class in {"c", "header"}
    ]
    c_paths = [entry.path for entry in source_entries if entry.source_class == "c"]
    require(c_and_header_paths and c_paths, "command contract source denominator is empty")
    symbols = policy_root_symbols(policy)
    display_components = max(len(Path(path).parts) for path in c_and_header_paths)
    sandbox = canonical_analyzer_sandbox()
    records: list[tuple[str, ...]] = []

    def add(
        command_id: str,
        tool: str,
        cwd: str,
        stdout_path: str,
        stderr_path: str,
        argv: list[str],
        environment: dict[str, str] | None = None,
    ) -> None:
        records.append(
            command_record_row(
                command_id,
                tool,
                cwd,
                stdout_path,
                stderr_path,
                argv,
                environment,
            )
        )

    add(
        "global-index",
        "bwrap",
        "<source-root>",
        "diagnostics/global-index.stdout",
        "diagnostics/global-index.stderr",
        [
            *sandbox,
            "gtags",
            "--file",
            "/tmp/capture/inputs/c-and-header-files.txt",
            "/tmp/capture/indexes/global",
        ],
    )
    global_environment = {
        "GTAGSROOT": "/tmp/source",
        "GTAGSDBPATH": "/tmp/capture/indexes/global",
    }
    add(
        "global-definitions",
        "bwrap",
        "<source-root>",
        "queries/global-definitions.txt",
        "diagnostics/global-definitions.stderr",
        [*sandbox, "global", "--result=ctags-x", "--definition", ".*"],
        global_environment,
    )
    add(
        "global-references",
        "bwrap",
        "<source-root>",
        "queries/global-references.txt",
        "diagnostics/global-references.stderr",
        [*sandbox, "global", "--result=ctags-x", "--reference", ".*"],
        global_environment,
    )
    for database_name in GLOBAL_DATABASE_NAMES:
        lower_name = database_name.lower()
        add(
            f"global-dump-{lower_name}",
            "bwrap",
            "<source-root>",
            f"indexes/global/{database_name}.dump.tsv",
            f"diagnostics/global-dump-{lower_name}.stderr",
            [
                *sandbox,
                "gtags",
                "--dump",
                f"/tmp/capture/indexes/global/{database_name}",
            ],
        )
    add(
        "ctags-index",
        "ctags",
        "<source-root>",
        "diagnostics/ctags-index.stdout",
        "diagnostics/ctags-index.stderr",
        [
            "ctags",
            "--options=NONE",
            "--language-force=C",
            "--fields=+neKSt",
            "--extras=+q",
            "--sort=yes",
            "--excmd=number",
            "--pseudo-tags=-TAG_PROC_CWD",
            "--tag-relative=no",
            "-L",
            "<capture-root>/inputs/c-and-header-files.txt",
            "-f",
            "<capture-root>/indexes/ctags/tags",
        ],
    )
    add(
        "readtags-roots",
        "readtags",
        "<source-root>",
        "indexes/ctags/readtags-all.txt",
        "diagnostics/readtags-root-symbols.stderr",
        [
            "readtags",
            "-t",
            "<capture-root>/indexes/ctags/tags",
            "-e",
            "-n",
            "-l",
        ],
    )
    add(
        "cscope-index",
        "bwrap",
        "<source-root>",
        "diagnostics/cscope-index.stdout",
        "diagnostics/cscope-index.stderr",
        [
            *sandbox,
            "cscope",
            "-b",
            "-k",
            "-c",
            "-i",
            "/tmp/capture/inputs/c-and-header-files.txt",
            "-f",
            "/tmp/capture/indexes/cscope/cscope.out",
        ],
    )
    for symbol in symbols:
        for query_kind, mode in (
            ("definition", "-1"),
            ("calls", "-2"),
            ("callers", "-3"),
        ):
            command_id = f"cscope-{query_kind}-{symbol}".replace("_", "-")
            add(
                command_id,
                "bwrap",
                "<source-root>",
                f"queries/cscope/{query_kind}-{symbol}.txt",
                f"diagnostics/cscope/{query_kind}-{symbol}.stderr",
                [
                    *sandbox,
                    "cscope",
                    "-d",
                    "-L",
                    f"-p{display_components}",
                    mode,
                    symbol,
                    "-f",
                    "/tmp/capture/indexes/cscope/cscope.out",
                ],
            )

    cflow_base = ["cflow", "-q", "--no-preprocess", "--symbol=__packed:qualifier"]
    cflow_posix = [*cflow_base, "--brief", "--number", "--print-level"]
    add(
        "cflow-full-posix",
        "cflow",
        "<source-root>",
        "cflow/full-call-candidates.txt",
        "diagnostics/cflow-full.stderr",
        [*cflow_posix, "--all", "--format=posix", *c_paths],
    )
    add(
        "cflow-full-dot",
        "cflow",
        "<source-root>",
        "cflow/full-call-candidates.dot",
        "diagnostics/cflow-full-dot.stderr",
        [*cflow_base, "--all", "--format=dot", *c_paths],
    )
    for partition in policy.partitions:
        roots = [f"--main={root}" for root in partition.roots]
        add(
            f"cflow-{partition.name}-posix",
            "cflow",
            "<source-root>",
            f"cflow/partitions/{partition.name}.txt",
            f"diagnostics/cflow-{partition.name}.stderr",
            [*cflow_posix, "--format=posix", *roots, *c_paths],
        )
        add(
            f"cflow-{partition.name}-dot",
            "cflow",
            "<source-root>",
            f"cflow/partitions/{partition.name}.dot",
            f"diagnostics/cflow-{partition.name}-dot.stderr",
            [*cflow_base, "--format=dot", *roots, *c_paths],
        )
    add(
        "lizard-complexity",
        "lizard",
        "<source-root>",
        "diagnostics/lizard.stdout",
        "diagnostics/lizard.stderr",
        [
            "lizard",
            "-l",
            "cpp",
            "--csv",
            "-f",
            "<capture-root>/inputs/c-and-header-files.txt",
            "-o",
            "<capture-root>/analysis/lizard.csv",
        ],
    )
    add(
        "scc-census",
        "scc",
        "<source-root>",
        "diagnostics/scc.stdout",
        "diagnostics/scc.stderr",
        [
            "scc",
            "--ci",
            "--by-file",
            "--format",
            "json",
            "--no-cocomo",
            "--no-gitignore",
            "--no-ignore",
            "--no-scc-ignore",
            "--output",
            "<capture-root>/analysis/scc.json",
            policy.source_root,
        ],
    )

    policy_releases = {lane.release for lane in policy.kernel_lanes}
    require(
        not active_releases or active_releases == policy_releases,
        "command contract kernel release set differs from policy",
    )
    translation_targets = [
        f"{Path(path).stem}.i" for path in policy.translation_units
    ]
    toolchain_environment = {
        "PATH": "/usr/bin:/bin",
        "LD_LIBRARY_PATH": "<kernel-toolchain-root>/lib",
    }
    for lane in policy.kernel_lanes:
        if lane.release not in active_releases:
            continue
        release = lane.release
        add(
            f"kernel-root-{release}",
            "python3",
            "<repository>",
            f"diagnostics/kernel-root-{release}.stdout",
            f"diagnostics/kernel-root-{release}.stderr",
            [
                "python3",
                "<repository>/scripts/check_kernel_build_root.py",
                "--root",
                "<kernel-build-root>",
                "--declaration",
                f"<repository>/{lane.declaration}",
                "--manifest",
                f"<repository>/{lane.manifest}",
            ],
        )
        for profile in lane.profiles:
            lane_prefix = f"preprocessed/{release}/{profile}"
            work_source = f"<preprocessor-work>/{policy.source_root}"
            make_base = kernel_make_base_command(
                profile,
                "<kernel-build-root>",
                work_source,
                "<kernel-toolchain-root>/bin",
                "<kernel-toolchain-root>",
                "<preprocessor-work>",
            )
            add(
                f"preprocess-build-{release}-{profile}",
                "make",
                work_source,
                f"{lane_prefix}/module-build.log",
                f"diagnostics/preprocess-build-{release}-{profile}.stderr",
                [*make_base, "modules"],
                toolchain_environment,
            )
            add(
                f"module-symbols-{release}-{profile}",
                "llvm-nm",
                work_source,
                f"{lane_prefix}/module-defined-symbols.txt",
                f"diagnostics/module-symbols-{release}-{profile}.stderr",
                [
                    "<kernel-toolchain-root>/bin/llvm-nm",
                    "--defined-only",
                    "--extern-only",
                    "--format=posix",
                    f"{work_source}/radeon.ko",
                ],
                toolchain_environment,
            )
            add(
                f"preprocess-units-{release}-{profile}",
                "make",
                work_source,
                f"{lane_prefix}/preprocess.log",
                f"diagnostics/preprocess-units-{release}-{profile}.stderr",
                [*make_base, *translation_targets],
                toolchain_environment,
            )
    require(
        len({row[0] for row in records}) == len(records),
        "expected command contract repeats an ID",
    )
    require(
        len({row[4] for row in records}) == len(records)
        and len({row[5] for row in records}) == len(records),
        "expected command contract repeats an output path",
    )
    return records


def verify_command_records(
    columns: list[str],
    rows: list[list[str]],
    expected_rows: list[tuple[str, ...]],
) -> None:
    require(
        columns
        == [
            "command_id",
            "tool",
            "cwd",
            "status",
            "stdout_path",
            "stderr_path",
            "argv_json",
            "environment_json",
        ],
        "command metadata columns differ",
    )
    require(
        rows == [list(row) for row in expected_rows],
        "command metadata differs from the producer-derived command contract",
    )
    require(
        len({row[0] for row in rows}) == len(rows)
        and len({row[4] for row in rows}) == len(rows)
        and len({row[5] for row in rows}) == len(rows),
        "command metadata repeats an ID or output path",
    )


def analyzer_sandbox(source_root: Path, capture_root: Path) -> list[str]:
    return [
        shutil.which("bwrap") or "bwrap",
        "--die-with-parent",
        "--ro-bind",
        "/",
        "/",
        "--tmpfs",
        "/tmp",
        "--dir",
        "/tmp/source",
        "--dir",
        "/tmp/capture",
        "--ro-bind",
        str(source_root),
        "/tmp/source",
        "--bind",
        str(capture_root),
        "/tmp/capture",
        "--chdir",
        "/tmp/source",
    ]


def command_version(tool: str, executable: str) -> tuple[int, str, str]:
    version_args = {
        "bwrap": ["--version"],
        "git": ["--version"],
        "cflow": ["--version"],
        "cscope": ["-V"],
        "ctags": ["--version"],
        "readtags": ["--version"],
        "gtags": ["--version"],
        "global": ["--version"],
        "lizard": ["--version"],
        "scc": ["--version"],
        "dot": ["-V"],
        "ldd": ["--version"],
        "pacman": ["--version"],
        "clang": ["--version"],
        "gcc": ["--version"],
        "sparse": ["--version"],
        "semgrep": ["--version"],
        "weggli": ["--version"],
        "spatch": ["--version"],
        "doxygen": ["--version"],
        "tree-sitter": ["--version"],
        "python3": ["--version"],
        "make": ["--version"],
        "sh": ["--version"],
    }
    result = subprocess.run(
        [executable, *version_args[tool]],
        check=False,
        capture_output=True,
        text=True,
        env=command_environment_contract("/tmp"),
    )
    combined = "\n".join(part.strip() for part in (result.stdout, result.stderr) if part.strip())
    combined = combined.replace(executable, Path(executable).name)
    first_line = combined.splitlines()[0] if combined else ""
    return result.returncode, first_line, combined


def capture_tool_versions(capture_root: Path, policy: Policy) -> dict[str, str]:
    rows: list[tuple[Any, ...]] = []
    versions: dict[str, str] = {}
    required = set(policy.required_tools)
    for tool in sorted(required | set(policy.optional_tools)):
        executable = shutil.which(tool)
        if executable is None:
            require(tool not in required, f"required analyzer is absent: {tool}")
            rows.append((tool, "no", "absent", "absent", "", "absent"))
            continue
        if tool in {"make", "sh"}:
            require(
                Path(executable) == Path(f"/usr/bin/{tool}")
                and (
                    tool != "sh"
                    or Path(executable).resolve(strict=True)
                    == Path("/usr/bin/bash")
                ),
                f"host build command path differs: {tool}",
            )
        status, first_line, combined = command_version(tool, executable)
        require(status == 0, f"cannot read analyzer version: {tool}")
        require(first_line, f"analyzer version is empty: {tool}")
        versions[tool] = first_line
        rows.append(
            (
                tool,
                "yes" if tool in required else "no",
                Path(executable).name,
                sha256_file(Path(executable)),
                first_line,
                sha256_bytes(combined.encode("utf-8")),
            )
        )
    expected_global = f"global (GNU Global) {policy.global_version}"
    expected_gtags = f"gtags (GNU Global) {policy.global_version}"
    require(versions.get("global") == expected_global, "GNU Global version differs from policy")
    require(versions.get("gtags") == expected_gtags, "GNU gtags version differs from policy")
    ctags_path = Path(shutil.which("ctags") or "ctags")
    readtags_path = Path(shutil.which("readtags") or "readtags")
    require(
        versions.get("ctags") == policy.ctags_version_first_line,
        "Universal Ctags version differs from policy",
    )
    require(
        sha256_file(ctags_path) == policy.ctags_executable_sha256
        and sha256_file(readtags_path) == policy.readtags_executable_sha256,
        "Universal Ctags executable identity differs from policy",
    )
    ctags_package = subprocess.run(
        [shutil.which("pacman") or "pacman", "-Q", "ctags"],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "LC_ALL": "C", "LANG": "C"},
    )
    require(
        ctags_package.returncode == 0
        and not ctags_package.stderr
        and ctags_package.stdout.strip() == policy.ctags_package_owner,
        "Universal Ctags package identity differs from policy",
    )
    config = subprocess.run(
        [shutil.which("gtags") or "gtags", "--config"],
        check=False,
        capture_output=True,
        env={**os.environ, "LC_ALL": "C", "LANG": "C"},
    )
    require(config.returncode == 0 and not config.stderr, "gtags --config failed")
    require(sha256_bytes(config.stdout) == policy.global_config_sha256, "GNU Global configuration differs from policy")
    write_tsv(
        capture_root / "metadata/tool-versions.tsv",
        "radeon-driver-tool-versions-v1",
        (
            "tool",
            "required",
            "executable_name",
            "executable_sha256",
            "version",
            "version_output_sha256",
        ),
        rows,
    )
    return versions


def source_manifest_rows(entries: list[SourceEntry]) -> list[tuple[Any, ...]]:
    return [
        (entry.path, entry.source_class, entry.mode, entry.size, entry.object_id, entry.sha256)
        for entry in entries
    ]


def write_source_inputs(capture_root: Path, entries: list[SourceEntry]) -> tuple[Path, Path]:
    c_and_headers = [entry.path for entry in entries if entry.source_class in {"c", "header"}]
    c_files = [entry.path for entry in entries if entry.source_class == "c"]
    require(c_and_headers and c_files, "analyzer input denominator is empty")
    source_list = capture_root / "inputs/c-and-header-files.txt"
    c_list = capture_root / "inputs/c-files.txt"
    write_text(source_list, "\n".join(c_and_headers) + "\n")
    write_text(c_list, "\n".join(c_files) + "\n")
    write_tsv(
        capture_root / "metadata/tool-inputs.tsv",
        "radeon-driver-tool-inputs-v1",
        ("input_name", "file_count", "content_sha256", "consumers"),
        [
            ("c-and-header-files", len(c_and_headers), sha256_file(source_list), "cscope;ctags;gnu-global;lizard"),
            ("c-files", len(c_files), sha256_file(c_list), "cflow"),
        ],
    )
    return source_list, c_list


def parse_global_rows(
    raw: bytes,
    record_kind: str,
    entries: dict[str, SourceEntry],
    source_root: Path | None = None,
) -> list[tuple[Any, ...]]:
    rows: list[tuple[Any, ...]] = []
    for line_number, raw_line in enumerate(raw.decode("utf-8", errors="strict").splitlines(), 1):
        fields = raw_line.split(maxsplit=3)
        require(len(fields) == 4, f"GNU Global {record_kind} row {line_number} is malformed")
        symbol, source_line, source_path, _snippet = fields
        require(C_IDENTIFIER.fullmatch(symbol) is not None, f"GNU Global emitted an invalid identifier: {symbol}")
        require(source_line.isdigit() and int(source_line) > 0, f"GNU Global emitted an invalid line: {source_line}")
        entry = entries.get(source_path)
        require(entry is not None and entry.source_class in {"c", "header"}, f"GNU Global emitted a foreign path: {source_path}")
        if source_root is not None:
            line_count = len((source_root / source_path).read_text(encoding="utf-8").splitlines())
            require(int(source_line) <= line_count, f"GNU Global line is outside {source_path}: {source_line}")
        rows.append((record_kind, symbol, source_path, int(source_line), entry.sha256, "gnu-global"))
    require(len(set(rows)) == len(rows), f"GNU Global emitted duplicate {record_kind} rows")
    return rows


def derive_lexical_rows(
    capture_root: Path,
    source_root: Path,
    entries: list[SourceEntry],
) -> list[tuple[Any, ...]]:
    entry_map = {entry.path: entry for entry in entries}
    rows: list[tuple[Any, ...]] = [
        ("file", "", entry.path, 0, entry.sha256, "git-tracked")
        for entry in entries
        if entry.source_class in {"c", "header"}
    ]
    for filename, record_kind in (
        ("global-definitions.txt", "definition"),
        ("global-references.txt", "reference"),
    ):
        raw_path = capture_root / "queries" / filename
        require(raw_path.is_file(), f"GNU Global raw query is absent: {filename}")
        rows.extend(
            parse_global_rows(
                raw_path.read_bytes(),
                record_kind,
                entry_map,
                source_root,
            )
        )
    rows.sort(
        key=lambda row: (
            str(row[0]),
            str(row[2]).encode("utf-8"),
            int(row[3]),
            str(row[1]),
        )
    )
    require(
        len(set(rows)) == len(rows),
        "derived lexical map contains duplicate normalized rows",
    )
    return rows


def build_lexical_index(
    capture_root: Path,
    source_root: Path,
    source_list: Path,
    entries: list[SourceEntry],
    recorder: CommandRecorder,
) -> list[tuple[Any, ...]]:
    database = capture_root / "indexes/global"
    database.mkdir(parents=True)
    require(
        source_list == capture_root / "inputs/c-and-header-files.txt",
        "GNU Global source list is outside the canonical capture path",
    )
    sandbox = analyzer_sandbox(source_root, capture_root)
    gtags = shutil.which("gtags") or "gtags"
    global_tool = shutil.which("global") or "global"
    recorder.run(
        "global-index",
        [
            *sandbox,
            gtags,
            "--file",
            "/tmp/capture/inputs/c-and-header-files.txt",
            "/tmp/capture/indexes/global",
        ],
        source_root,
        "diagnostics/global-index.stdout",
        "diagnostics/global-index.stderr",
    )
    environment = {
        "GTAGSROOT": "/tmp/source",
        "GTAGSDBPATH": "/tmp/capture/indexes/global",
    }
    definitions = recorder.run(
        "global-definitions",
        [*sandbox, global_tool, "--result=ctags-x", "--definition", ".*"],
        source_root,
        "queries/global-definitions.txt",
        "diagnostics/global-definitions.stderr",
        environment=environment,
    )
    references = recorder.run(
        "global-references",
        [*sandbox, global_tool, "--result=ctags-x", "--reference", ".*"],
        source_root,
        "queries/global-references.txt",
        "diagnostics/global-references.stderr",
        environment=environment,
    )
    for database_name in GLOBAL_DATABASE_NAMES:
        database_path = database / database_name
        require(database_path.is_file(), f"GNU Global omitted {database_name}")
        recorder.run(
            f"global-dump-{database_name.lower()}",
            [
                *sandbox,
                gtags,
                "--dump",
                f"/tmp/capture/indexes/global/{database_name}",
            ],
            source_root,
            f"indexes/global/{database_name}.dump.tsv",
            f"diagnostics/global-dump-{database_name.lower()}.stderr",
        )
        database_path.unlink()
    entry_map = {entry.path: entry for entry in entries}
    rows: list[tuple[Any, ...]] = [
        ("file", "", entry.path, 0, entry.sha256, "git-tracked")
        for entry in entries
        if entry.source_class in {"c", "header"}
    ]
    rows.extend(parse_global_rows(definitions, "definition", entry_map, source_root))
    rows.extend(parse_global_rows(references, "reference", entry_map, source_root))
    rows.sort(key=lambda row: (str(row[0]), str(row[2]).encode("utf-8"), int(row[3]), str(row[1])))
    require(len(set(rows)) == len(rows), "lexical map contains duplicate normalized rows")
    write_tsv(
        capture_root / "radeon-driver-lexical-map.tsv",
        LEXICAL_SCHEMA,
        ("record_kind", "symbol", "source_path", "line", "source_sha256", "provenance"),
        rows,
    )
    return rows


def canonical_ctags_record(
    line: str,
    label: str,
    row_number: int,
) -> tuple[str, ...]:
    fields = line.split("\t")
    require(
        len(fields) >= 4 and all(fields[:3]),
        f"{label} row {row_number} is malformed",
    )
    require(
        re.fullmatch(r'[1-9][0-9]*;"', fields[2]) is not None,
        f"{label} row {row_number} has a nonnumeric address",
    )
    normalized_extensions: list[str] = []
    extension_keys: set[str] = set()
    for extension in fields[3:]:
        require(extension, f"{label} row {row_number} has an empty extension")
        if ":" in extension:
            key, _separator, value = extension.partition(":")
            require(
                C_IDENTIFIER.fullmatch(key) is not None,
                f"{label} row {row_number} has an invalid extension key",
            )
            normalized = extension
        else:
            key = "kind"
            value = extension
            normalized = f"kind:{extension}"
        require(
            key not in extension_keys and (key != "kind" or value),
            f"{label} row {row_number} repeats or empties an extension",
        )
        extension_keys.add(key)
        normalized_extensions.append(normalized)
    require(
        "kind" in extension_keys and "line" in extension_keys,
        f"{label} row {row_number} omits kind or line identity",
    )
    require(
        f"line:{fields[2][:-2]}" in normalized_extensions,
        f"{label} row {row_number} line identity differs from its address",
    )
    return (*fields[:3], *sorted(normalized_extensions))


def build_ctags_index(
    capture_root: Path,
    source_root: Path,
    source_list: Path,
    symbols: list[str],
    recorder: CommandRecorder,
    policy: Policy,
) -> list[str]:
    tags = capture_root / "indexes/ctags/tags"
    tags.parent.mkdir(parents=True)
    ctags = shutil.which("ctags") or "ctags"
    recorder.run(
        "ctags-index",
        [
            ctags,
            "--options=NONE",
            "--language-force=C",
            "--fields=+neKSt",
            "--extras=+q",
            "--sort=yes",
            "--excmd=number",
            "--pseudo-tags=-TAG_PROC_CWD",
            "--tag-relative=no",
            "-L",
            str(source_list),
            "-f",
            str(tags),
        ],
        source_root,
        "diagnostics/ctags-index.stdout",
        "diagnostics/ctags-index.stderr",
        allowed_stderr=policy.ctags_stderr,
        require_empty_stderr=False,
    )
    readtags = shutil.which("readtags") or "readtags"
    raw = recorder.run(
        "readtags-roots",
        [readtags, "-t", str(tags), "-e", "-n", "-l"],
        source_root,
        "indexes/ctags/readtags-all.txt",
        "diagnostics/readtags-root-symbols.stderr",
    )
    lines = raw.decode("utf-8", errors="strict").splitlines()
    selected = [
        line
        for line in lines
        if line and line.split("\t", 1)[0] in set(symbols)
    ]
    write_text(
        capture_root / "queries/readtags-root-symbols.txt",
        "\n".join(selected) + "\n",
    )
    found = {line.split("\t", 1)[0] for line in selected}
    missing = sorted(set(symbols) - found)
    require(
        not missing,
        "Ctags index omits declared roots: " + ", ".join(missing),
    )
    write_tsv(
        capture_root / "queries/ctags-root-coverage.tsv",
        "radeon-driver-ctags-root-coverage-v1",
        ("symbol", "ctags_record_count", "classification"),
        [
            (
                symbol,
                sum(1 for line in selected if line.split("\t", 1)[0] == symbol),
                "indexed",
            )
            for symbol in symbols
        ],
    )
    return selected


def parse_cscope_rows(
    raw: bytes,
    query_kind: str,
    query_symbol: str,
    entries: dict[str, SourceEntry],
    source_root: Path,
) -> list[tuple[Any, ...]]:
    require(query_kind in {"definition", "calls", "callers"}, f"cscope query kind is invalid: {query_kind}")
    require(C_IDENTIFIER.fullmatch(query_symbol) is not None, f"cscope query symbol is invalid: {query_symbol}")
    rows: list[tuple[Any, ...]] = []
    for row_number, line in enumerate(raw.decode("utf-8", errors="strict").splitlines(), 1):
        fields = line.split(maxsplit=3)
        require(len(fields) == 4, f"cscope {query_symbol} row {row_number} is malformed")
        source_path, function, line_text, source_text = fields
        entry = entries.get(source_path)
        require(
            entry is not None and entry.source_class in {"c", "header"},
            f"cscope emitted a foreign path for {query_symbol}: {source_path}",
        )
        require(
            function == "<global>" or C_IDENTIFIER.fullmatch(function) is not None,
            f"cscope function is invalid for {query_symbol}: {function}",
        )
        require(line_text.isdigit() and int(line_text) > 0, f"cscope line is invalid for {query_symbol}")
        source_lines = (source_root / source_path).read_text(encoding="utf-8").splitlines()
        source_line = int(line_text)
        require(
            source_line <= len(source_lines),
            f"cscope line is outside {source_path}: {source_line}",
        )
        normalized_source = source_text.strip()
        require(
            normalized_source == source_lines[source_line - 1].strip(),
            f"cscope source text differs from retained source: {source_path}:{source_line}",
        )
        rows.append(
            (
                query_kind,
                query_symbol,
                source_path,
                function,
                source_line,
                normalized_source,
            )
        )
    require(len(set(rows)) == len(rows), f"cscope emitted duplicate rows for {query_kind} {query_symbol}")
    return rows


def build_cscope_index(
    capture_root: Path,
    source_root: Path,
    source_list: Path,
    entries: list[SourceEntry],
    symbols: list[str],
    recorder: CommandRecorder,
) -> list[tuple[Any, ...]]:
    database = capture_root / "indexes/cscope/cscope.out"
    database.parent.mkdir(parents=True)
    require(
        source_list == capture_root / "inputs/c-and-header-files.txt",
        "cscope source list is outside the canonical capture path",
    )
    cscope = shutil.which("cscope") or "cscope"
    entry_map = {entry.path: entry for entry in entries}
    analyzer_paths = [
        entry.path for entry in entries if entry.source_class in {"c", "header"}
    ]
    display_components = max(len(Path(path).parts) for path in analyzer_paths)
    sandbox = analyzer_sandbox(source_root, capture_root)
    sandbox_source_list = "/tmp/capture/inputs/c-and-header-files.txt"
    sandbox_database = "/tmp/capture/indexes/cscope/cscope.out"
    recorder.run(
        "cscope-index",
        [
            *sandbox,
            cscope,
            "-b",
            "-k",
            "-c",
            "-i",
            sandbox_source_list,
            "-f",
            sandbox_database,
        ],
        source_root,
        "diagnostics/cscope-index.stdout",
        "diagnostics/cscope-index.stderr",
    )
    rows: list[tuple[Any, ...]] = []
    query_modes = (("definition", "-1"), ("calls", "-2"), ("callers", "-3"))
    for symbol in symbols:
        for query_kind, mode in query_modes:
            command_id = f"cscope-{query_kind}-{symbol}".replace("_", "-")
            raw = recorder.run(
                command_id,
                [
                    *sandbox,
                    cscope,
                    "-d",
                    "-L",
                    f"-p{display_components}",
                    mode,
                    symbol,
                    "-f",
                    sandbox_database,
                ],
                source_root,
                f"queries/cscope/{query_kind}-{symbol}.txt",
                f"diagnostics/cscope/{query_kind}-{symbol}.stderr",
            )
            rows.extend(
                parse_cscope_rows(
                    raw,
                    query_kind,
                    symbol,
                    entry_map,
                    source_root,
                )
            )
    rows.sort(key=lambda row: (row[0], row[1], row[2], row[4], row[3], row[5]))
    write_tsv(
        capture_root / "queries/cscope-root-symbols.tsv",
        "radeon-driver-cscope-root-queries-v1",
        ("query_kind", "query_symbol", "source_path", "function", "line", "source_text"),
        rows,
    )
    return rows


def replay_cscope_queries(
    capture_root: Path,
    entries: dict[str, SourceEntry],
    symbols: list[str],
    retained_rows: list[list[str]],
    cscope_executable_sha256: str,
    *,
    executable: Path | None = None,
) -> None:
    cscope_path = executable or Path(shutil.which("cscope") or "cscope")
    require(
        cscope_path.is_file()
        and os.access(cscope_path, os.X_OK)
        and sha256_file(cscope_path) == cscope_executable_sha256,
        "cscope replay executable identity differs from retained metadata",
    )
    source_root = capture_root / "source"
    database = capture_root / "indexes/cscope/cscope.out"
    require(database.is_file(), "cscope replay database is absent")
    analyzer_paths = [
        entry.path
        for entry in entries.values()
        if entry.source_class in {"c", "header"}
    ]
    require(analyzer_paths, "cscope replay source denominator is empty")
    display_components = max(len(Path(path).parts) for path in analyzer_paths)
    replayed_rows: list[tuple[Any, ...]] = []
    for symbol in symbols:
        for query_kind, mode in (
            ("definition", "-1"),
            ("calls", "-2"),
            ("callers", "-3"),
        ):
            result = subprocess.run(
                [
                    str(cscope_path),
                    "-d",
                    "-L",
                    f"-p{display_components}",
                    mode,
                    symbol,
                    "-f",
                    str(database),
                ],
                cwd=source_root,
                env={**os.environ, "LC_ALL": "C", "LANG": "C", "TZ": "UTC"},
                capture_output=True,
                check=False,
            )
            require(
                result.returncode == 0 and not result.stderr,
                f"cscope replay failed for {query_kind} {symbol}",
            )
            raw_path = (
                capture_root
                / f"queries/cscope/{query_kind}-{symbol}.txt"
            )
            require(
                result.stdout == raw_path.read_bytes(),
                f"cscope replay differs for {query_kind} {symbol}",
            )
            replayed_rows.extend(
                parse_cscope_rows(
                    result.stdout,
                    query_kind,
                    symbol,
                    entries,
                    source_root,
                )
            )
    replayed_rows.sort(
        key=lambda row: (row[0], row[1], row[2], row[4], row[3], row[5])
    )
    require(
        [tuple(str(value) for value in row) for row in replayed_rows]
        == [tuple(row) for row in retained_rows],
        "retained cscope query table differs from command replay",
    )


def pinned_tool_path(
    tool_rows: list[list[str]],
    tool_name: str,
) -> Path:
    matches = [row for row in tool_rows if row[0] == tool_name]
    require(
        len(matches) == 1 and matches[0][2] not in {"", "absent"},
        f"required replay tool is absent from metadata: {tool_name}",
    )
    executable = Path(shutil.which(matches[0][2]) or "")
    require(
        executable.is_file()
        and os.access(executable, os.X_OK)
        and sha256_file(executable) == matches[0][3],
        f"replay tool identity differs: {tool_name}",
    )
    return executable


def replay_exact_command(
    argv: list[str],
    cwd: Path,
    expected_stdout: Path,
    expected_stderr: Path,
    environment: dict[str, str] | None = None,
    output_replacements: tuple[tuple[bytes, bytes], ...] = (),
) -> None:
    result = subprocess.run(
        argv,
        cwd=cwd,
        env={
            **os.environ,
            "LC_ALL": "C",
            "LANG": "C",
            "TZ": "UTC",
            **(environment or {}),
        },
        capture_output=True,
        check=False,
    )
    require(
        result.returncode == 0,
        f"offline replay command failed: {Path(argv[0]).name}",
    )
    normalized_stdout = result.stdout
    normalized_stderr = result.stderr
    for original, replacement in output_replacements:
        normalized_stdout = normalized_stdout.replace(original, replacement)
        normalized_stderr = normalized_stderr.replace(original, replacement)
    require(
        normalized_stdout == expected_stdout.read_bytes(),
        f"offline replay stdout differs: {expected_stdout.relative_to(expected_stdout.parents[1])}",
    )
    require(
        normalized_stderr == expected_stderr.read_bytes(),
        f"offline replay stderr differs: {expected_stderr.relative_to(expected_stderr.parents[1])}",
    )


def replay_global_queries(
    capture_root: Path,
    tool_rows: list[list[str]],
    policy: Policy,
) -> None:
    source_root = capture_root / "source"
    gtags = pinned_tool_path(tool_rows, "gtags")
    global_tool = pinned_tool_path(tool_rows, "global")
    config = subprocess.run(
        [str(gtags), "--config"],
        cwd=source_root,
        env={**os.environ, "LC_ALL": "C", "LANG": "C", "TZ": "UTC"},
        capture_output=True,
        check=False,
    )
    require(
        config.returncode == 0
        and not config.stderr
        and sha256_bytes(config.stdout) == policy.global_config_sha256,
        "GNU Global replay configuration differs from policy",
    )
    with tempfile.TemporaryDirectory(prefix="radeon-global-replay-") as name:
        database = Path(name) / "global"
        database.mkdir()
        replay_exact_command(
            [
                str(gtags),
                "--file",
                str(capture_root / "inputs/c-and-header-files.txt"),
                str(database),
            ],
            source_root,
            capture_root / "diagnostics/global-index.stdout",
            capture_root / "diagnostics/global-index.stderr",
        )
        query_environment = {
            "GTAGSROOT": str(source_root),
            "GTAGSDBPATH": str(database),
        }
        for record_kind, switch in (
            ("definitions", "--definition"),
            ("references", "--reference"),
        ):
            replay_exact_command(
                [
                    str(global_tool),
                    "--result=ctags-x",
                    switch,
                    ".*",
                ],
                source_root,
                capture_root / f"queries/global-{record_kind}.txt",
                capture_root / f"diagnostics/global-{record_kind}.stderr",
                query_environment,
            )
        for database_name in GLOBAL_DATABASE_NAMES:
            replay_exact_command(
                [str(gtags), "--dump", str(database / database_name)],
                source_root,
                capture_root
                / f"indexes/global/{database_name}.dump.tsv",
                capture_root
                / f"diagnostics/global-dump-{database_name.lower()}.stderr",
            )


def replay_ctags_queries(
    capture_root: Path,
    tool_rows: list[list[str]],
) -> None:
    source_root = capture_root / "source"
    ctags = pinned_tool_path(tool_rows, "ctags")
    readtags = pinned_tool_path(tool_rows, "readtags")
    with tempfile.TemporaryDirectory(prefix="radeon-ctags-replay-") as name:
        tags = Path(name) / "tags"
        replay_exact_command(
            [
                str(ctags),
                "--options=NONE",
                "--language-force=C",
                "--fields=+neKSt",
                "--extras=+q",
                "--sort=yes",
                "--excmd=number",
                "--pseudo-tags=-TAG_PROC_CWD",
                "--tag-relative=no",
                "-L",
                str(capture_root / "inputs/c-and-header-files.txt"),
                "-f",
                str(tags),
            ],
            source_root,
            capture_root / "diagnostics/ctags-index.stdout",
            capture_root / "diagnostics/ctags-index.stderr",
        )
        require(
            tags.read_bytes() == (capture_root / "indexes/ctags/tags").read_bytes(),
            "Ctags replay index differs from retained index",
        )
        replay_exact_command(
            [str(readtags), "-t", str(tags), "-e", "-n", "-l"],
            source_root,
            capture_root / "indexes/ctags/readtags-all.txt",
            capture_root / "diagnostics/readtags-root-symbols.stderr",
        )


def replay_cflow_outputs(
    capture_root: Path,
    tool_rows: list[list[str]],
    policy: Policy,
) -> None:
    source_root = capture_root / "source"
    cflow = pinned_tool_path(tool_rows, "cflow")
    c_files = (
        capture_root / "inputs/c-files.txt"
    ).read_text(encoding="utf-8").splitlines()
    parser_args = [
        str(cflow),
        "-q",
        "--no-preprocess",
        "--symbol=__packed:qualifier",
    ]
    posix_args = [*parser_args, "--brief", "--number", "--print-level"]
    diagnostic_replacements = ((str(cflow).encode("utf-8"), b"cflow"),)
    replay_exact_command(
        [*posix_args, "--all", "--format=posix", *c_files],
        source_root,
        capture_root / "cflow/full-call-candidates.txt",
        capture_root / "diagnostics/cflow-full.stderr",
        output_replacements=diagnostic_replacements,
    )
    replay_exact_command(
        [*parser_args, "--all", "--format=dot", *c_files],
        source_root,
        capture_root / "cflow/full-call-candidates.dot",
        capture_root / "diagnostics/cflow-full-dot.stderr",
        output_replacements=diagnostic_replacements,
    )
    for partition in policy.partitions:
        roots = [f"--main={root}" for root in partition.roots]
        replay_exact_command(
            [*posix_args, "--format=posix", *roots, *c_files],
            source_root,
            capture_root / f"cflow/partitions/{partition.name}.txt",
            capture_root / f"diagnostics/cflow-{partition.name}.stderr",
            output_replacements=diagnostic_replacements,
        )
        replay_exact_command(
            [*parser_args, "--format=dot", *roots, *c_files],
            source_root,
            capture_root / f"cflow/partitions/{partition.name}.dot",
            capture_root
            / f"diagnostics/cflow-{partition.name}-dot.stderr",
            output_replacements=diagnostic_replacements,
        )


def replay_metric_outputs(
    capture_root: Path,
    tool_rows: list[list[str]],
    policy: Policy,
) -> None:
    source_root = capture_root / "source"
    lizard = pinned_tool_path(tool_rows, "lizard")
    scc = pinned_tool_path(tool_rows, "scc")
    with tempfile.TemporaryDirectory(prefix="radeon-metric-replay-") as name:
        temporary = Path(name)
        lizard_output = temporary / "lizard.csv"
        replay_exact_command(
            [
                str(lizard),
                "-l",
                "cpp",
                "--csv",
                "-f",
                str(capture_root / "inputs/c-and-header-files.txt"),
                "-o",
                str(lizard_output),
            ],
            source_root,
            capture_root / "diagnostics/lizard.stdout",
            capture_root / "diagnostics/lizard.stderr",
        )
        require(
            lizard_output.read_bytes()
            == (capture_root / "analysis/lizard.csv").read_bytes(),
            "lizard replay differs from retained function metrics",
        )

        scc_output = temporary / "scc.json"
        result = subprocess.run(
            [
                str(scc),
                "--ci",
                "--by-file",
                "--format",
                "json",
                "--no-cocomo",
                "--no-gitignore",
                "--no-ignore",
                "--no-scc-ignore",
                "--output",
                str(scc_output),
                policy.source_root,
            ],
            cwd=source_root,
            env={**os.environ, "LC_ALL": "C", "LANG": "C", "TZ": "UTC"},
            capture_output=True,
            check=False,
        )
        require(result.returncode == 0, "SCC offline replay failed")
        normalized_stdout = result.stdout.replace(
            str(scc_output).encode("utf-8"),
            b"<capture-root>/analysis/scc.json",
        )
        require(
            normalized_stdout
            == (capture_root / "diagnostics/scc.stdout").read_bytes()
            and result.stderr
            == (capture_root / "diagnostics/scc.stderr").read_bytes(),
            "SCC replay diagnostics differ",
        )
        require(
            normalized_scc_json(scc_output)
            == (capture_root / "analysis/scc.json").read_text(encoding="utf-8"),
            "SCC replay differs from retained census",
        )


def parse_cflow_edges(raw: bytes) -> list[tuple[str, str, str]]:
    stack: dict[int, str] = {}
    edges: set[tuple[str, str, str]] = set()
    for line_number, line in enumerate(raw.decode("utf-8", errors="strict").splitlines(), 1):
        match = CFLOW_ROW.match(line)
        require(match is not None, f"cflow row {line_number} is malformed")
        depth = int(match.group(1))
        symbol = match.group(2).strip()
        detail = match.group(3).strip()
        require(C_IDENTIFIER.fullmatch(symbol) is not None, f"cflow emitted an invalid symbol: {symbol}")
        require(depth >= 0, "cflow emitted a negative depth")
        if depth > 0:
            caller = stack.get(depth - 1)
            require(caller is not None, f"cflow depth skips a parent at row {line_number}")
            callee_kind = "external" if detail == "<>" else "driver"
            edges.add((caller, symbol, callee_kind))
        stack[depth] = symbol
        for stale_depth in [item for item in stack if item > depth]:
            del stack[stale_depth]
    return sorted(edges)


def derive_cflow_products(
    capture_root: Path,
    policy: Policy,
) -> tuple[
    list[tuple[str, str, str]],
    dict[str, list[tuple[str, str, str]]],
    list[tuple[Any, ...]],
    list[tuple[Any, ...]],
]:
    full_path = capture_root / "cflow/full-call-candidates.txt"
    require(full_path.is_file(), "full cflow raw output is absent")
    full_edges = parse_cflow_edges(full_path.read_bytes())
    full_rows = [
        (
            caller,
            callee,
            callee_kind,
            "gnu-cflow-raw-source",
            "lexical-candidate-not-runtime-reachability",
        )
        for caller, callee, callee_kind in full_edges
    ]
    partition_edges: dict[str, list[tuple[str, str, str]]] = {}
    partition_rows: list[tuple[Any, ...]] = []
    for partition in policy.partitions:
        raw_path = capture_root / f"cflow/partitions/{partition.name}.txt"
        require(
            raw_path.is_file(),
            f"partition cflow raw output is absent: {partition.name}",
        )
        edges = parse_cflow_edges(raw_path.read_bytes())
        partition_edges[partition.name] = edges
        partition_rows.extend(
            (partition.name, caller, callee, callee_kind)
            for caller, callee, callee_kind in edges
        )
    return full_edges, partition_edges, full_rows, sorted(partition_rows)


def build_cflow_maps(
    capture_root: Path,
    source_root: Path,
    c_list: Path,
    policy: Policy,
    recorder: CommandRecorder,
) -> tuple[list[tuple[str, str, str]], dict[str, list[tuple[str, str, str]]]]:
    cflow = shutil.which("cflow") or "cflow"
    c_files = c_list.read_text(encoding="utf-8").splitlines()
    parser_args = [cflow, "-q", "--no-preprocess", "--symbol=__packed:qualifier"]
    posix_args = [*parser_args, "--brief", "--number", "--print-level"]
    full = recorder.run(
        "cflow-full-posix",
        [*posix_args, "--all", "--format=posix", *c_files],
        source_root,
        "cflow/full-call-candidates.txt",
        "diagnostics/cflow-full.stderr",
        allowed_stderr=policy.cflow_stderr,
        require_empty_stderr=False,
    )
    recorder.run(
        "cflow-full-dot",
        [*parser_args, "--all", "--format=dot", *c_files],
        source_root,
        "cflow/full-call-candidates.dot",
        "diagnostics/cflow-full-dot.stderr",
        allowed_stderr=policy.cflow_stderr,
        require_empty_stderr=False,
    )
    full_edges = parse_cflow_edges(full)
    write_tsv(
        capture_root / "analysis/cflow-lexical-edges.tsv",
        "radeon-driver-cflow-lexical-edges-v1",
        ("caller", "callee", "callee_kind", "provenance", "semantic_limit"),
        [
            (
                caller,
                callee,
                callee_kind,
                "gnu-cflow-raw-source",
                "lexical-candidate-not-runtime-reachability",
            )
            for caller, callee, callee_kind in full_edges
        ],
    )

    partition_edges: dict[str, list[tuple[str, str, str]]] = {}
    for partition in policy.partitions:
        main_args = [f"--main={root}" for root in partition.roots]
        raw = recorder.run(
            f"cflow-{partition.name}-posix",
            [*posix_args, "--format=posix", *main_args, *c_files],
            source_root,
            f"cflow/partitions/{partition.name}.txt",
            f"diagnostics/cflow-{partition.name}.stderr",
            allowed_stderr=policy.cflow_stderr,
            require_empty_stderr=False,
        )
        recorder.run(
            f"cflow-{partition.name}-dot",
            [*parser_args, "--format=dot", *main_args, *c_files],
            source_root,
            f"cflow/partitions/{partition.name}.dot",
            f"diagnostics/cflow-{partition.name}-dot.stderr",
            allowed_stderr=policy.cflow_stderr,
            require_empty_stderr=False,
        )
        partition_edges[partition.name] = parse_cflow_edges(raw)
    partition_rows = [
        (partition, caller, callee, callee_kind)
        for partition, edges in partition_edges.items()
        for caller, callee, callee_kind in edges
    ]
    partition_rows.sort()
    write_tsv(
        capture_root / "analysis/partition-lexical-edges.tsv",
        "radeon-driver-partition-lexical-edges-v1",
        ("partition", "caller", "callee", "callee_kind"),
        partition_rows,
    )
    return full_edges, partition_edges


def binding_matches(source: str, binding: Binding) -> list[re.Match[str]]:
    code_mask = strip_comments_and_literals(source)
    search_text = strip_comments(source) if binding.match_literals else code_mask
    matches = list(re.finditer(binding.pattern, search_text, re.MULTILINE | re.DOTALL))

    def remains_in_opening_scope(match: re.Match[str]) -> bool:
        if binding.scope != "brace":
            return True
        opening = code_mask.find("{", match.start(), match.end())
        require(opening >= 0, f"brace-scoped binding {binding.name} does not match an opening brace")
        depth = 0
        for offset in range(opening, match.end()):
            token = code_mask[offset]
            if token == "{":
                depth += 1
            elif token == "}":
                depth -= 1
                require(depth >= 0, f"brace-scoped binding {binding.name} has an invalid brace order")
                if depth == 0:
                    return not code_mask[offset + 1 : match.end()].strip()
        return depth > 0

    return [
        match
        for match in matches
        if match.start() < len(code_mask)
        and not code_mask[match.start()].isspace()
        and remains_in_opening_scope(match)
    ]


def verify_declared_bindings(
    capture_root: Path,
    source_root: Path,
    entries: dict[str, SourceEntry],
    policy: Policy,
    *,
    write_output: bool = True,
) -> list[tuple[Any, ...]]:
    rows: list[tuple[Any, ...]] = []
    for binding in policy.bindings:
        entry = entries.get(binding.path)
        require(entry is not None, f"declared binding source is absent: {binding.path}")
        source = (source_root / binding.path).read_text(encoding="utf-8")
        matches = binding_matches(source, binding)
        require(
            len(matches) == binding.expected_matches,
            f"binding {binding.name} expected {binding.expected_matches} matches, found {len(matches)}",
        )
        for match in matches:
            line = physical_line_after_splicing(source, match.start())
            normalized = " ".join(match.group(0).split())
            rows.append(
                (
                    binding.name,
                    binding.kind,
                    binding.partition,
                    binding.path,
                    line,
                    binding.caller,
                    binding.callee,
                    entry.sha256,
                    sha256_bytes(normalized.encode("utf-8")),
                    "policy-declared",
                    binding.scope,
                )
            )
    rows.sort(key=lambda row: (row[0], row[4]))
    require(len(rows) == sum(item.expected_matches for item in policy.bindings), "binding output does not close the policy denominator")
    if write_output:
        write_tsv(
            capture_root / "radeon-driver-declared-bindings.tsv",
            DECLARED_BINDING_SCHEMA,
            (
                "binding_id",
                "binding_kind",
                "partition",
                "source_path",
                "line",
                "caller_symbol",
                "target_symbol",
                "source_sha256",
                "matched_text_sha256",
                "provenance",
                "match_scope",
            ),
            rows,
        )
    return rows


def extract_callback_candidates(
    capture_root: Path,
    source_root: Path,
    entries: list[SourceEntry],
    policy: Policy,
    *,
    write_output: bool = True,
) -> tuple[list[tuple[Any, ...]], list[tuple[str, str, str]]]:
    rows: list[tuple[Any, ...]] = []
    generated_edges: set[tuple[str, str, str]] = set()
    counts: defaultdict[str, int] = defaultdict(int)
    for entry in entries:
        if entry.source_class != "c":
            continue
        source = (source_root / entry.path).read_text(encoding="utf-8")
        code = strip_comments_and_literals(source)

        for match in FIELD_INITIALIZER.finditer(code):
            selector, target = match.groups()
            line = physical_line_after_splicing(source, match.start())
            rows.append(("field-initializer", entry.path, line, selector, target, entry.sha256))
            counts["minimum_field_initializers"] += 1

        for match in DEFINE_SHOW.finditer(code):
            symbol = match.group(1)
            line = physical_line_after_splicing(source, match.start())
            rows.append(("define-show-attribute", entry.path, line, f"{symbol}_fops", f"{symbol}_show", entry.sha256))
            generated_edges.add((f"{symbol}_fops", f"{symbol}_show", "macro-generated-vfs"))
            counts["minimum_define_show_attributes"] += 1

        for match in DEFINE_DEBUGFS.finditer(code):
            fops, getter, setter = match.groups()
            line = physical_line_after_splicing(source, match.start())
            for selector, target in (("get", getter), ("set", setter)):
                rows.append(("define-debugfs-attribute", entry.path, line, f"{fops}:{selector}", target, entry.sha256))
                generated_edges.add((fops, target, "macro-generated-vfs"))

        for match in DRM_IOCTL.finditer(code):
            ioctl_name, target = match.groups()
            line = physical_line_after_splicing(source, match.start())
            rows.append(("drm-ioctl", entry.path, line, ioctl_name, target, entry.sha256))
            generated_edges.add((f"DRM_IOCTL_{ioctl_name}", target, "macro-generated-ioctl"))
            counts["minimum_drm_ioctl_bindings"] += 1

        for match in WORK_BINDING.finditer(code):
            macro, target = match.groups()
            line = physical_line_after_splicing(source, match.start())
            rows.append(("workqueue", entry.path, line, macro, target, entry.sha256))
            generated_edges.add((macro, target, "macro-generated-workqueue"))
            counts["minimum_work_bindings"] += 1

        for match in MODULE_BINDING.finditer(code):
            macro, target = match.groups()
            line = physical_line_after_splicing(source, match.start())
            rows.append(("module-entry", entry.path, line, macro, target, entry.sha256))
            generated_edges.add((macro, target, "macro-generated-module-entry"))

    for minimum, expected in policy.extractor_minimums.items():
        require(counts[minimum] >= expected, f"callback extractor {minimum} fell below {expected}: {counts[minimum]}")
    rows.sort(key=lambda row: (row[0], row[1], row[2], row[3], row[4]))
    require(len(set(rows)) == len(rows), "callback extractor emitted duplicate rows")
    if write_output:
        write_tsv(
            capture_root / "analysis/extracted-binding-candidates.tsv",
            "radeon-driver-extracted-binding-candidates-v1",
            (
                "extractor",
                "source_path",
                "line",
                "selector",
                "target_symbol",
                "source_sha256",
            ),
            rows,
        )
    return rows, sorted(generated_edges)


def write_call_candidates(
    capture_root: Path,
    cflow_edges: list[tuple[str, str, str]],
    declared_rows: list[tuple[Any, ...]],
    generated_edges: list[tuple[str, str, str]],
    *,
    write_output: bool = True,
) -> list[tuple[Any, ...]]:
    rows: set[tuple[Any, ...]] = set()
    for caller, callee, callee_kind in cflow_edges:
        rows.add(("lexical", caller, callee, "full-tree", "gnu-cflow", callee_kind))
    for row in declared_rows:
        rows.add(("declared-indirect", row[5], row[6], row[2], row[0], row[1]))
    for caller, callee, kind in generated_edges:
        rows.add(("extracted-indirect", caller, callee, "full-tree", kind, "candidate"))
    ordered = sorted(rows)
    if write_output:
        write_tsv(
            capture_root / "analysis/call-candidates.tsv",
            "radeon-driver-call-candidates-v1",
            (
                "edge_kind",
                "caller",
                "callee",
                "partition",
                "provenance",
                "classification",
            ),
            ordered,
        )
    return ordered


def verify_call_candidate_rows(
    retained_rows: list[list[str]] | list[tuple[Any, ...]],
    cflow_edges: list[tuple[str, str, str]],
    declared_rows: list[tuple[Any, ...]],
    generated_edges: list[tuple[str, str, str]],
) -> list[tuple[Any, ...]]:
    expected_rows = write_call_candidates(
        Path("."),
        cflow_edges,
        declared_rows,
        generated_edges,
        write_output=False,
    )
    require(
        [tuple(str(value) for value in row) for row in retained_rows]
        == [tuple(str(value) for value in row) for row in expected_rows],
        "call candidates differ from raw cflow and retained source replay",
    )
    return expected_rows


def build_contextual_path_witnesses(
    capture_root: Path,
    policy: Policy,
    call_rows: list[tuple[Any, ...]] | list[list[str]],
    *,
    write_output: bool = True,
) -> tuple[list[tuple[Any, ...]], list[tuple[Any, ...]]]:
    normalized_candidates = [tuple(str(value) for value in row) for row in call_rows]
    require(
        all(len(row) == 6 for row in normalized_candidates),
        "call candidate row width differs while building path witnesses",
    )
    require(
        len(set(normalized_candidates)) == len(normalized_candidates),
        "call candidates repeat an edge while building path witnesses",
    )
    candidate_set = set(normalized_candidates)
    edge_rows: list[tuple[Any, ...]] = []
    join_rows: list[tuple[Any, ...]] = []
    binding_map = {binding.name: binding for binding in policy.bindings}
    for witness in policy.path_witnesses:
        validate_path_witness_shape(
            witness,
            f"path witness {witness.name}",
            binding_map,
        )
        axis_steps: defaultdict[str, int] = defaultdict(int)
        context_json = json.dumps(
            list(witness.context),
            ensure_ascii=True,
            separators=(",", ":"),
        )
        for edge in witness.edges:
            candidate = (
                edge.edge_kind,
                edge.caller,
                edge.callee,
                edge.partition,
                edge.provenance,
                edge.classification,
            )
            require(
                candidate in candidate_set,
                "path witness "
                f"{witness.name} lacks candidate edge "
                f"{edge.caller} -> {edge.callee}",
            )
            axis_steps[edge.axis] += 1
            edge_rows.append(
                (
                    witness.name,
                    witness.entry,
                    witness.terminal,
                    edge.axis,
                    axis_steps[edge.axis],
                    edge.edge_kind,
                    edge.caller,
                    edge.callee,
                    edge.partition,
                    edge.provenance,
                    edge.classification,
                    context_json,
                    PATH_WITNESS_SEMANTIC_LIMIT,
                )
            )
        for join_step, join in enumerate(witness.joins, 1):
            join_rows.append(
                (
                    witness.name,
                    join_step,
                    join.kind,
                    join.from_axis,
                    join.from_symbol,
                    join.to_axis,
                    join.to_symbol,
                    json.dumps(
                        list(join.evidence_ids),
                        ensure_ascii=True,
                        separators=(",", ":"),
                    ),
                    PATH_WITNESS_SEMANTIC_LIMIT,
                )
            )
    require(
        len(edge_rows) == sum(len(item.edges) for item in policy.path_witnesses),
        "path witness output does not close the policy denominator",
    )
    require(
        len(join_rows) == sum(len(item.joins) for item in policy.path_witnesses),
        "path witness join output does not close the policy denominator",
    )
    require(len(set(edge_rows)) == len(edge_rows), "path witness output repeats a row")
    require(len(set(join_rows)) == len(join_rows), "path witness join output repeats a row")
    if write_output:
        write_tsv(
            capture_root / "analysis/contextual-path-witnesses.tsv",
            PATH_WITNESS_SCHEMA,
            (
                "witness_id",
                "entry",
                "terminal",
                "axis",
                "step",
                "edge_kind",
                "caller",
                "callee",
                "edge_partition",
                "edge_provenance",
                "edge_classification",
                "required_context_json",
                "semantic_limit",
            ),
            edge_rows,
        )
        write_tsv(
            capture_root / "analysis/contextual-path-joins.tsv",
            PATH_WITNESS_JOIN_SCHEMA,
            (
                "witness_id",
                "join_step",
                "join_kind",
                "from_axis",
                "from_symbol",
                "to_axis",
                "to_symbol",
                "evidence_ids_json",
                "semantic_limit",
            ),
            join_rows,
        )
    return edge_rows, join_rows


def evaluate_bounded_queries(
    source_root: Path,
    entries: list[SourceEntry],
    queries: tuple[BoundedQuery, ...],
) -> tuple[list[tuple[Any, ...]], list[tuple[Any, ...]]]:
    paths = [entry.path for entry in entries]
    entry_map = {entry.path: entry for entry in entries}
    summary_rows: list[tuple[Any, ...]] = []
    match_rows: list[tuple[Any, ...]] = []
    for query in queries:
        selected = sorted(
            {
                path
                for pattern in query.paths
                for path in paths
                if fnmatch.fnmatch(path, pattern)
            }
        )
        require(selected, f"bounded query selects no files: {query.name}")
        expression = re.compile(query.pattern, re.MULTILINE | re.DOTALL)
        match_count = 0
        for path in selected:
            source = (source_root / path).read_text(encoding="utf-8")
            code_mask = strip_comments_and_literals(source)
            for match in expression.finditer(code_mask):
                line = physical_line_after_splicing(source, match.start())
                normalized = " ".join(match.group(0).split())
                match_rows.append(
                    (
                        query.name,
                        path,
                        line,
                        entry_map[path].sha256,
                        sha256_bytes(normalized.encode("utf-8")),
                        "lexical-code-mask",
                    )
                )
                match_count += 1
        require(
            match_count == query.expected_matches,
            f"bounded query {query.name} expected {query.expected_matches} matches, found {match_count}",
        )
        summary_rows.append(
            (
                query.name,
                len(selected),
                query.expected_matches,
                match_count,
                sha256_bytes(query.pattern.encode("ascii")),
                sha256_bytes(
                    b"".join(path.encode("utf-8") + b"\0" for path in selected)
                ),
                query.rationale,
                "lexical-code-mask-not-runtime-reachability",
            )
        )
    require(
        len(set(match_rows)) == len(match_rows),
        "bounded query evaluation repeats a match row",
    )
    return summary_rows, sorted(match_rows)


def run_bounded_queries(
    capture_root: Path,
    source_root: Path,
    entries: list[SourceEntry],
    policy: Policy,
) -> None:
    summary_rows, match_rows = evaluate_bounded_queries(
        source_root,
        entries,
        policy.bounded_queries,
    )
    write_tsv(
        capture_root / "analysis/bounded-query-summary.tsv",
        "radeon-driver-bounded-query-summary-v2",
        (
            "query_name",
            "file_count",
            "expected_match_count",
            "match_count",
            "pattern_sha256",
            "selected_path_set_sha256",
            "rationale",
            "semantic_limit",
        ),
        summary_rows,
    )
    write_tsv(
        capture_root / "analysis/bounded-query-matches.tsv",
        "radeon-driver-bounded-query-matches-v2",
        (
            "query_name",
            "source_path",
            "line",
            "source_sha256",
            "matched_text_sha256",
            "provenance",
        ),
        match_rows,
    )


def parse_lizard_rows(
    raw_path: Path,
    allowed_source_paths: set[str] | None = None,
    source_root: Path | None = None,
) -> list[dict[str, Any]]:
    functions: list[dict[str, Any]] = []
    identities: set[tuple[str, str, int, int]] = set()
    source_line_counts: dict[str, int] = {}
    with raw_path.open("r", encoding="utf-8", newline="") as source:
        for row_number, row in enumerate(csv.reader(source), 1):
            require(len(row) == 11, f"lizard row {row_number} has {len(row)} fields")
            numeric = [int(row[index]) for index in (0, 1, 2, 3, 4, 9, 10)]
            nloc, ccn, token_count, parameter_count, length, start, end = numeric
            path = row[6]
            symbol = row[7]
            require(
                nloc > 0
                and ccn > 0
                and token_count >= 0
                and parameter_count >= 0
                and length > 0
                and start > 0
                and end >= start,
                f"lizard row {row_number} has invalid numeric fields",
            )
            require(
                C_IDENTIFIER.fullmatch(symbol) is not None,
                f"lizard row {row_number} has an invalid symbol",
            )
            if allowed_source_paths is not None:
                require(
                    path in allowed_source_paths,
                    f"lizard row {row_number} names a foreign source path: {path}",
                )
            if source_root is not None:
                source_path = source_root / path
                if path not in source_line_counts:
                    require(
                        source_path.is_file(),
                        f"lizard row {row_number} source is absent: {path}",
                    )
                    source_line_counts[path] = len(
                        source_path.read_text(encoding="utf-8").splitlines()
                    )
                require(
                    end <= source_line_counts[path],
                    f"lizard row {row_number} exceeds its retained source: {path}",
                )
            identity = (path, symbol, start, end)
            require(
                identity not in identities,
                f"lizard row {row_number} repeats a function identity",
            )
            identities.add(identity)
            functions.append(
                {
                    "nloc": nloc,
                    "ccn": ccn,
                    "token_count": token_count,
                    "parameter_count": parameter_count,
                    "length": length,
                    "path": path,
                    "symbol": symbol,
                    "start": start,
                    "end": end,
                }
            )
    require(functions, "lizard emitted no functions")
    return functions


def normalized_scc_json(path: Path) -> str:
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceMapError(f"SCC report is invalid: {exc}") from exc
    require(isinstance(report, list) and report, "SCC report has no language rows")
    for language in report:
        require(isinstance(language, dict), "SCC language row is not an object")
        require(isinstance(language.get("Name"), str), "SCC language name is invalid")
        files = language.get("Files")
        require(isinstance(files, list), "SCC language file list is invalid")
        require(
            all(
                isinstance(item, dict)
                and isinstance(item.get("Location"), str)
                and isinstance(item.get("Filename"), str)
                for item in files
            ),
            "SCC file row is invalid",
        )
        language["Files"] = sorted(
            files,
            key=lambda item: (
                item["Location"].encode("utf-8"),
                item["Filename"].encode("utf-8"),
            ),
        )
    report.sort(key=lambda item: item["Name"].encode("utf-8"))
    return json.dumps(report, indent=2, sort_keys=True) + "\n"


def normalize_scc_json(path: Path) -> None:
    write_text(path, normalized_scc_json(path))


def derive_complexity_and_coefficients(
    capture_root: Path,
    source_root: Path,
    policy: Policy,
    cflow_edges: list[tuple[str, str, str]],
    declared_rows: list[tuple[Any, ...]],
    allowed_source_paths: set[str],
) -> tuple[list[tuple[Any, ...]], list[tuple[Any, ...]]]:
    functions = parse_lizard_rows(
        capture_root / "analysis/lizard.csv",
        allowed_source_paths,
        source_root,
    )
    by_symbol: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for function in functions:
        by_symbol[function["symbol"]].append(function)
    fan_in: defaultdict[str, set[str]] = defaultdict(set)
    fan_out: defaultdict[str, set[str]] = defaultdict(set)
    for caller, callee, _callee_kind in cflow_edges:
        fan_out[caller].add(callee)
        fan_in[callee].add(caller)
    indirect_in: defaultdict[str, set[str]] = defaultdict(set)
    indirect_out: defaultdict[str, set[str]] = defaultdict(set)
    for row in declared_rows:
        caller, callee = row[5], row[6]
        indirect_out[caller].add(callee)
        indirect_in[callee].add(caller)

    coefficient_rows: list[tuple[Any, ...]] = []
    guard_identifier_rows: list[tuple[Any, ...]] = []
    for hazard in policy.hazards:
        candidates = by_symbol.get(hazard.symbol, [])
        require(
            len(candidates) == 1,
            f"hazard {hazard.symbol} resolves to {len(candidates)} lizard functions",
        )
        function = candidates[0]
        required_guard_identifier_count = 0
        for census in hazard.guard_identifier_census:
            guard_candidates = by_symbol.get(census.owner, [])
            require(
                len(guard_candidates) == 1,
                "guard census owner "
                f"{census.owner} resolves to {len(guard_candidates)} "
                "lizard functions",
            )
            guard_function = guard_candidates[0]
            guard_path = source_root / guard_function["path"]
            guard_source = guard_path.read_text(encoding="utf-8")
            guard_body = "\n".join(
                guard_source.splitlines()[
                    guard_function["start"] - 1 : guard_function["end"]
                ]
            )
            missing_identifiers = missing_code_identifiers(
                guard_body,
                census.identifiers,
            )
            require(
                not missing_identifiers,
                f"hazard {hazard.symbol} guard census owner "
                f"{census.owner} lost identifiers: "
                + ", ".join(missing_identifiers),
            )
            required_guard_identifier_count += len(census.identifiers)
            for identifier in census.identifiers:
                guard_identifier_rows.append(
                    (
                        hazard.symbol,
                        census.owner,
                        guard_function["path"],
                        guard_function["start"],
                        identifier,
                        sha256_file(guard_path),
                        "policy-declared",
                        "lexical-identifier-census-not-control-flow-proof",
                    )
                )
        coefficient_rows.append(
            (
                hazard.symbol,
                function["path"],
                function["start"],
                function["nloc"],
                function["ccn"],
                len(fan_in[hazard.symbol]),
                len(fan_out[hazard.symbol]),
                len(indirect_in[hazard.symbol])
                + len(indirect_out[hazard.symbol]),
                hazard.side_effect_class,
                len(hazard.guard_identifier_census),
                required_guard_identifier_count,
                hazard.evidence_rank,
            )
        )
    return coefficient_rows, guard_identifier_rows


def build_complexity_and_coefficients(
    capture_root: Path,
    source_root: Path,
    source_list: Path,
    policy: Policy,
    recorder: CommandRecorder,
    cflow_edges: list[tuple[str, str, str]],
    declared_rows: list[tuple[Any, ...]],
) -> None:
    lizard_output = capture_root / "analysis/lizard.csv"
    lizard_output.parent.mkdir(parents=True, exist_ok=True)
    recorder.run(
        "lizard-complexity",
        [
            shutil.which("lizard") or "lizard",
            "-l",
            "cpp",
            "--csv",
            "-f",
            str(source_list),
            "-o",
            str(lizard_output),
        ],
        source_root,
        "diagnostics/lizard.stdout",
        "diagnostics/lizard.stderr",
    )
    recorder.run(
        "scc-census",
        [
            shutil.which("scc") or "scc",
            "--ci",
            "--by-file",
            "--format",
            "json",
            "--no-cocomo",
            "--no-gitignore",
            "--no-ignore",
            "--no-scc-ignore",
            "--output",
            str(capture_root / "analysis/scc.json"),
            policy.source_root,
        ],
        source_root,
        "diagnostics/scc.stdout",
        "diagnostics/scc.stderr",
    )
    normalize_scc_json(capture_root / "analysis/scc.json")
    coefficient_rows, guard_identifier_rows = (
        derive_complexity_and_coefficients(
            capture_root,
            source_root,
            policy,
            cflow_edges,
            declared_rows,
            set(source_list.read_text(encoding="utf-8").splitlines()),
        )
    )
    write_tsv(
        capture_root / "analysis/hazard-guard-identifier-census.tsv",
        "radeon-driver-hazard-guard-identifier-census-v1",
        (
            "hazard_symbol",
            "guard_census_owner_symbol",
            "source_path",
            "line",
            "required_identifier",
            "source_sha256",
            "provenance",
            "semantic_limit",
        ),
        guard_identifier_rows,
    )
    write_tsv(
        capture_root / "analysis/coefficient-vectors.tsv",
        "radeon-driver-coefficient-vectors-v2",
        (
            "symbol",
            "source_path",
            "line",
            "nloc",
            "ccn",
            "lexical_fan_in",
            "lexical_fan_out",
            "declared_indirect_edges",
            "maximum_side_effect_class",
            "guard_census_owner_count",
            "required_guard_identifier_count",
            "evidence_rank",
        ),
        coefficient_rows,
    )


def parse_top_level_toml(repository: Path, commit: str, path: str) -> tuple[bytes, dict[str, Any]]:
    content = git_output(repository, "show", f"{commit}:{path}", text=False)
    assert isinstance(content, bytes)
    try:
        data = tomllib.loads(content.decode("ascii"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise SourceMapError(f"{path} is not valid ASCII TOML at {commit}: {exc}") from exc
    return content, data


def profile_header(
    profile: str,
    source_commit: str,
    driver_tree: str,
    feature_policy_sha256: str,
    upstream_base: str,
) -> str:
    return (
        "#ifndef RADEON_BUILD_PROFILE_H\n"
        "#define RADEON_BUILD_PROFILE_H\n"
        f'#define RADEON_BUILD_PROFILE "{profile}"\n'
        f'#define RADEON_BUILD_SOURCE_COMMIT "{source_commit}"\n'
        f'#define RADEON_BUILD_DRIVER_TREE "{driver_tree}"\n'
        f'#define RADEON_BUILD_FEATURE_POLICY_SHA256 "{feature_policy_sha256}"\n'
        f'#define RADEON_BUILD_UPSTREAM_BASE "{upstream_base}"\n'
        "#endif\n"
    )


def sanitize_preprocessor_bytes(content: bytes, replacements: list[tuple[Path, str]]) -> bytes:
    output = content
    for path, token in sorted(replacements, key=lambda item: len(str(item[0])), reverse=True):
        output = output.replace(str(path).encode("utf-8"), token.encode("ascii"))
    return output


def validate_toolchain_prefix_relative_path(relative_path: str, label: str) -> Path:
    """Validate one canonical portable path below a toolchain prefix."""
    require(
        relative_path.isascii()
        and relative_path
        and relative_path not in {".", ".."}
        and not any(
            character == "\\" or ord(character) < 32 or ord(character) == 127
            for character in relative_path
        ),
        f"{label} is not plain ASCII: {relative_path!r}",
    )
    path = Path(relative_path)
    require(
        not path.is_absolute()
        and bool(path.parts)
        and path.as_posix() == relative_path
        and "." not in path.parts
        and ".." not in path.parts,
        f"{label} is invalid: {relative_path}",
    )
    return path


def resolve_toolchain_manifest_symlink(
    entry: ToolchainPrefixEntry,
    entries_by_path: dict[str, ToolchainPrefixEntry],
) -> ToolchainPrefixEntry:
    """Resolve one retained relative symlink through the admitted path set."""
    require(entry.entry_type == "symlink", "toolchain manifest resolver needs a symlink")
    current_parts = list(Path(entry.relative_path).parent.parts)
    if current_parts == ["."]:
        current_parts = []
    pending_parts = list(Path(entry.link_target).parts)
    traversed_symlinks: set[str] = set()
    final_entry: ToolchainPrefixEntry | None = None
    while pending_parts:
        component = pending_parts.pop(0)
        if component in {"", "."}:
            continue
        if component == "..":
            require(
                current_parts,
                f"kernel toolchain symlink escapes its prefix: {entry.relative_path}",
            )
            current_parts.pop()
            continue
        current_parts.append(component)
        current_path = "/".join(current_parts)
        current_entry = entries_by_path.get(current_path)
        require(
            current_entry is not None,
            f"kernel toolchain symlink dangles: {entry.relative_path}",
        )
        if current_entry.entry_type == "symlink":
            require(
                current_path not in traversed_symlinks,
                f"kernel toolchain symlink cycle: {entry.relative_path}",
            )
            traversed_symlinks.add(current_path)
            current_parts.pop()
            pending_parts = [
                *Path(current_entry.link_target).parts,
                *pending_parts,
            ]
            continue
        if pending_parts:
            require(
                current_entry.entry_type == "directory",
                f"kernel toolchain symlink traverses a file: {entry.relative_path}",
            )
        final_entry = current_entry
    require(
        final_entry is not None and final_entry.entry_type == "regular",
        f"kernel toolchain symlink does not resolve to a regular file: {entry.relative_path}",
    )
    return final_entry


def load_toolchain_prefix_manifest(
    manifest: Path,
    expected_entry_count: int | None = None,
    expected_sha256: str | None = None,
) -> list[ToolchainPrefixEntry]:
    """Load the exact finite tree admitted below one LLVM prefix."""
    if expected_entry_count is not None:
        require(
            0 < expected_entry_count <= MAX_TOOLCHAIN_PREFIX_ENTRIES,
            "kernel toolchain prefix declaration exceeds its row boundary",
        )
    columns, rows = read_canonical_ascii_tsv(
        manifest,
        TOOLCHAIN_PREFIX_TREE_SCHEMA,
        MAX_MANIFEST_BYTES,
        "kernel toolchain prefix manifest",
        expected_sha256,
    )
    require(
        len(rows) <= MAX_TOOLCHAIN_PREFIX_ENTRIES
        and (
            expected_entry_count is None
            or len(rows) == expected_entry_count
        ),
        "kernel toolchain prefix row denominator differs",
    )
    expected_columns = [
        "relative_path",
        "entry_type",
        "mode",
        "size",
        "identity_sha256",
        "link_target",
        "resolved_path",
        "resolved_sha256",
    ]
    require(columns == expected_columns, "kernel toolchain prefix columns differ")
    entries: list[ToolchainPrefixEntry] = []
    for row_number, row in enumerate(rows, 3):
        require(
            len(entries) < MAX_TOOLCHAIN_PREFIX_ENTRIES,
            "kernel toolchain prefix row boundary is exceeded",
        )
        require(
            len(row) == len(columns),
            f"kernel toolchain prefix row {row_number} width differs",
        )
        (
            relative_path,
            entry_type,
            mode,
            size_text,
            identity_sha256,
            link_target,
            resolved_path,
            resolved_sha256,
        ) = row
        path = validate_toolchain_prefix_relative_path(
            relative_path,
            "kernel toolchain prefix path",
        )
        require(
            entry_type in {"directory", "regular", "symlink"},
            f"kernel toolchain prefix type is invalid: {relative_path}",
        )
        require(
            re.fullmatch(r"0[0-7]{3}", mode) is not None,
            f"kernel toolchain prefix mode is invalid: {relative_path}",
        )
        if entry_type == "directory":
            require(
                size_text == "-"
                and identity_sha256 == "-"
                and link_target == "-"
                and resolved_path == "-"
                and resolved_sha256 == "-",
                f"kernel toolchain directory identity differs: {relative_path}",
            )
            size = None
        elif entry_type == "regular":
            require(
                size_text.isdigit(),
                f"kernel toolchain regular size is invalid: {relative_path}",
            )
            size = int(size_text)
            require(
                HEX_64.fullmatch(identity_sha256) is not None
                and link_target == "-"
                and resolved_path == "-"
                and resolved_sha256 == "-",
                f"kernel toolchain regular identity differs: {relative_path}",
            )
        else:
            require(
                size_text.isdigit(),
                f"kernel toolchain symlink size is invalid: {relative_path}",
            )
            size = int(size_text)
            require(
                link_target.isascii()
                and link_target not in {"", "-"}
                and not any(
                    character == "\\"
                    or ord(character) < 32
                    or ord(character) == 127
                    for character in link_target
                )
                and not Path(link_target).is_absolute()
                and size == len(os.fsencode(link_target))
                and identity_sha256
                == sha256_bytes(link_target.encode("ascii"))
                and HEX_64.fullmatch(resolved_sha256) is not None,
                f"kernel toolchain symlink identity differs: {relative_path}",
            )
            validate_toolchain_prefix_relative_path(
                resolved_path,
                "kernel toolchain resolved path",
            )
        entries.append(
            ToolchainPrefixEntry(
                relative_path,
                entry_type,
                mode,
                size,
                identity_sha256,
                link_target,
                resolved_path,
                resolved_sha256,
            )
        )
        if len(path.parts) > 1:
            require(
                path.parent.as_posix() != ".",
                f"kernel toolchain prefix parent is invalid: {relative_path}",
            )
    require(entries, "kernel toolchain prefix manifest is empty")
    require(
        entries == sorted(entries, key=lambda entry: os.fsencode(entry.relative_path))
        and len({entry.relative_path for entry in entries}) == len(entries),
        "kernel toolchain prefix manifest is not a unique byte-sorted set",
    )
    by_path = {entry.relative_path: entry for entry in entries}
    for entry in entries:
        path = Path(entry.relative_path)
        if len(path.parts) > 1:
            parent = by_path.get(path.parent.as_posix())
            require(
                parent is not None and parent.entry_type == "directory",
                f"kernel toolchain prefix parent is absent: {entry.relative_path}",
            )
        if entry.entry_type != "symlink":
            continue
        resolved = resolve_toolchain_manifest_symlink(entry, by_path)
        require(
            resolved.relative_path == entry.resolved_path
            and resolved.identity_sha256 == entry.resolved_sha256,
            f"kernel toolchain symlink resolution differs: {entry.relative_path}",
        )
    return entries


def derive_toolchain_prefix_entries(
    toolchain_prefix: Path,
    expected_entries: list[ToolchainPrefixEntry] | None = None,
) -> list[ToolchainPrefixEntry]:
    """Derive the exact root-owned, nonwritable LLVM prefix tree."""
    def require_no_extended_attributes(path: Path, label: str) -> None:
        try:
            extended_attributes = os.listxattr(path, follow_symlinks=False)
        except OSError as exc:
            raise SourceMapError(
                f"cannot inspect kernel toolchain extended attributes: {label}"
            ) from exc
        require(
            not extended_attributes,
            f"kernel toolchain entry carries extended attributes: {label}",
        )

    require(toolchain_prefix.is_absolute(), "kernel toolchain root is not absolute")
    unresolved_components = [Path(toolchain_prefix.anchor)]
    for part in toolchain_prefix.parts[1:]:
        unresolved_components.append(unresolved_components[-1] / part)
    for component in unresolved_components:
        try:
            status = component.lstat()
        except OSError as exc:
            raise SourceMapError(
                f"kernel toolchain ancestor is absent: {component}"
            ) from exc
        require(
            stat.S_ISDIR(status.st_mode),
            f"kernel toolchain ancestor is not a real directory: {component}",
        )
        require(
            status.st_uid == 0
            and status.st_gid == 0
            and stat.S_IMODE(status.st_mode) & 0o7022 == 0,
            f"kernel toolchain ancestor ownership or mode differs: {component}",
        )
        require(
            not os.access(component, os.W_OK),
            f"kernel toolchain ancestor is runner writable: {component}",
        )
        require_no_extended_attributes(component, str(component))
    resolved_prefix = toolchain_prefix.resolve(strict=True)
    require(
        resolved_prefix == toolchain_prefix,
        "kernel toolchain root resolves through an alias",
    )
    root_status = resolved_prefix.lstat()
    root_device = root_status.st_dev
    entries: list[ToolchainPrefixEntry] = []
    expected_by_path = {
        entry.relative_path: entry for entry in (expected_entries or [])
    }
    require(
        len(expected_by_path) <= MAX_TOOLCHAIN_PREFIX_ENTRIES,
        "kernel toolchain admitted prefix exceeds its row boundary",
    )
    regular_total_bytes = 0
    digest_cache: dict[Path, str] = {}

    def bounded_digest(path: Path) -> str:
        resolved_path = path.resolve(strict=True)
        digest = digest_cache.get(resolved_path)
        if digest is None:
            digest = sha256_file(resolved_path)
            digest_cache[resolved_path] = digest
        return digest

    def walk(directory: Path, relative_parts: tuple[str, ...]) -> None:
        nonlocal regular_total_bytes
        require(
            len(relative_parts) < MAX_TOOLCHAIN_PREFIX_DEPTH,
            "kernel toolchain prefix exceeds its depth boundary",
        )
        with os.scandir(directory) as iterator:
            children = sorted(iterator, key=lambda entry: os.fsencode(entry.name))
        for child in children:
            require(
                len(entries) < MAX_TOOLCHAIN_PREFIX_ENTRIES,
                "kernel toolchain live prefix exceeds its row boundary",
            )
            require(
                child.name.isascii()
                and not any(
                    character in "\\\t\r\n" or ord(character) < 32
                    for character in child.name
                ),
                "kernel toolchain prefix path is not plain ASCII",
            )
            try:
                status = child.stat(follow_symlinks=False)
            except OSError as exc:
                raise SourceMapError(
                    f"cannot stat kernel toolchain entry: {child.path}"
                ) from exc
            path_parts = (*relative_parts, child.name)
            require(
                len(path_parts) <= MAX_TOOLCHAIN_PREFIX_DEPTH,
                "kernel toolchain prefix path exceeds its depth boundary",
            )
            relative_path = "/".join(path_parts)
            require(
                status.st_dev == root_device,
                f"kernel toolchain entry crosses a filesystem boundary: {relative_path}",
            )
            require(
                status.st_uid == 0 and status.st_gid == 0,
                f"kernel toolchain entry ownership differs: {relative_path}",
            )
            require(
                stat.S_IMODE(status.st_mode) & 0o7000 == 0,
                f"kernel toolchain entry carries special mode bits: {relative_path}",
            )
            mode = f"{stat.S_IMODE(status.st_mode):04o}"
            path = Path(child.path)
            if stat.S_ISDIR(status.st_mode):
                entry_type = "directory"
                entry_size = None
            elif stat.S_ISREG(status.st_mode):
                entry_type = "regular"
                entry_size = status.st_size
            elif stat.S_ISLNK(status.st_mode):
                entry_type = "symlink"
                entry_size = status.st_size
            else:
                raise SourceMapError(
                    "kernel toolchain prefix contains a special file: "
                    f"{relative_path}"
                )
            if expected_entries is not None:
                expected_entry = expected_by_path.get(relative_path)
                require(
                    expected_entry is not None,
                    "kernel toolchain live prefix has an unexpected path: "
                    f"{relative_path}",
                )
                require(
                    expected_entry.entry_type == entry_type
                    and expected_entry.mode == mode
                    and expected_entry.size == entry_size,
                    "kernel toolchain live prefix metadata differs before hash: "
                    f"{relative_path}",
                )
            require_no_extended_attributes(path, relative_path)
            if entry_type == "directory":
                require(
                    stat.S_IMODE(status.st_mode) & 0o022 == 0
                    and not os.access(path, os.W_OK),
                    f"kernel toolchain directory is writable: {relative_path}",
                )
                entries.append(
                    ToolchainPrefixEntry(
                        relative_path,
                        "directory",
                        mode,
                        None,
                        "-",
                        "-",
                        "-",
                        "-",
                    )
                )
                walk(path, path_parts)
            elif entry_type == "regular":
                require(
                    status.st_size <= MAX_TOOLCHAIN_REGULAR_FILE_BYTES,
                    "kernel toolchain file exceeds its byte boundary: "
                    f"{relative_path}",
                )
                regular_total_bytes += status.st_size
                require(
                    regular_total_bytes <= MAX_TOOLCHAIN_REGULAR_TOTAL_BYTES,
                    "kernel toolchain regular files exceed their total byte boundary",
                )
                require(
                    stat.S_IMODE(status.st_mode) & 0o022 == 0
                    and status.st_nlink == 1
                    and not os.access(path, os.W_OK),
                    f"kernel toolchain file is writable: {relative_path}",
                )
                digest = bounded_digest(path)
                entries.append(
                    ToolchainPrefixEntry(
                        relative_path,
                        "regular",
                        mode,
                        status.st_size,
                        digest,
                        "-",
                        "-",
                        "-",
                    )
                )
            else:
                target = os.readlink(path)
                require(
                    target.isascii()
                    and target
                    and not any(
                        character == "\\"
                        or ord(character) < 32
                        or ord(character) == 127
                        for character in target
                    )
                    and not Path(target).is_absolute(),
                    f"kernel toolchain symlink target is invalid: {relative_path}",
                )
                try:
                    resolved = path.resolve(strict=True)
                    resolved_relative = resolved.relative_to(resolved_prefix)
                    resolved_status = resolved.lstat()
                except (OSError, ValueError) as exc:
                    raise SourceMapError(
                        f"kernel toolchain symlink escapes or dangles: {relative_path}"
                    ) from exc
                require(
                    stat.S_ISREG(resolved_status.st_mode)
                    and resolved_status.st_dev == root_device
                    and resolved_status.st_uid == 0
                    and resolved_status.st_gid == 0
                    and stat.S_IMODE(resolved_status.st_mode) & 0o022 == 0,
                    f"kernel toolchain symlink resolution differs: {relative_path}",
                )
                require(
                    not os.access(resolved, os.W_OK),
                    f"kernel toolchain symlink target is writable: {relative_path}",
                )
                require(
                    resolved_status.st_size <= MAX_TOOLCHAIN_REGULAR_FILE_BYTES,
                    "kernel toolchain symlink target exceeds its byte boundary: "
                    f"{relative_path}",
                )
                resolved_sha256 = bounded_digest(resolved)
                entries.append(
                    ToolchainPrefixEntry(
                        relative_path,
                        "symlink",
                        mode,
                        status.st_size,
                        sha256_bytes(target.encode("ascii")),
                        target,
                        resolved_relative.as_posix(),
                        resolved_sha256,
                    )
                )

    walk(resolved_prefix, ())
    entries.sort(key=lambda entry: os.fsencode(entry.relative_path))
    require(entries, "kernel toolchain prefix is empty")
    if expected_entries is not None:
        require(
            {entry.relative_path for entry in entries} == set(expected_by_path),
            "kernel toolchain live prefix omits admitted paths",
        )
    return entries


def toolchain_prefix_rows(
    entries: list[ToolchainPrefixEntry],
) -> list[tuple[Any, ...]]:
    """Serialize one canonical prefix tree for retention and comparison."""
    return [
        (
            entry.relative_path,
            entry.entry_type,
            entry.mode,
            "-" if entry.size is None else entry.size,
            entry.identity_sha256,
            entry.link_target,
            entry.resolved_path,
            entry.resolved_sha256,
        )
        for entry in entries
    ]


def write_toolchain_prefix_manifest(toolchain_prefix: Path, output: Path) -> None:
    """Write one deterministic manifest for a validated LLVM prefix."""
    entries = derive_toolchain_prefix_entries(toolchain_prefix)
    write_tsv(
        output,
        TOOLCHAIN_PREFIX_TREE_SCHEMA,
        (
            "relative_path",
            "entry_type",
            "mode",
            "size",
            "identity_sha256",
            "link_target",
            "resolved_path",
            "resolved_sha256",
        ),
        toolchain_prefix_rows(entries),
    )


def load_toolchain_closure(
    declaration: Path,
    manifest: Path,
    prefix_manifest: Path,
) -> tuple[
    dict[str, Any],
    list[ToolchainClosureEntry],
    list[ToolchainPrefixEntry],
]:
    try:
        declaration_data = tomllib.loads(declaration.read_text(encoding="ascii"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise SourceMapError(
            f"kernel toolchain declaration is invalid: {declaration}: {exc}"
        ) from exc
    declaration_keys = {
        "schema",
        "family",
        "version",
        "architecture",
        "command_count",
        "library_count",
        "support_count",
        "manifest",
        "manifest_sha256",
        "prefix_tree_schema",
        "prefix_tree_manifest",
        "prefix_tree_manifest_sha256",
        "prefix_entry_count",
        "prefix_directory_count",
        "prefix_regular_count",
        "prefix_symlink_count",
        "resource_directory",
        "resource_entry_count",
        "resource_directory_count",
        "resource_regular_count",
        "runtime_boundary",
        "package",
        "host_policy",
    }
    reject_unknown(
        declaration_data,
        declaration_keys,
        "kernel toolchain declaration",
    )
    require(
        set(declaration_data) == declaration_keys
        and declaration_data["schema"] == 2
        and declaration_data["family"] == "llvm"
        and isinstance(declaration_data["version"], str)
        and declaration_data["version"]
        and declaration_data["architecture"] == "x86_64_v3",
        "kernel toolchain declaration identity differs",
    )
    require(
        declaration_data["prefix_tree_schema"] == TOOLCHAIN_PREFIX_TREE_SCHEMA
        and isinstance(declaration_data["prefix_tree_manifest"], str)
        and declaration_data["prefix_tree_manifest"]
        and isinstance(declaration_data["prefix_entry_count"], int)
        and 0
        < declaration_data["prefix_entry_count"]
        <= MAX_TOOLCHAIN_PREFIX_ENTRIES
        and HEX_64.fullmatch(
            declaration_data["prefix_tree_manifest_sha256"]
        )
        is not None
        and all(
            isinstance(declaration_data[key], int)
            and declaration_data[key] > 0
            for key in (
                "prefix_directory_count",
                "prefix_regular_count",
                "prefix_symlink_count",
                "resource_entry_count",
                "resource_directory_count",
                "resource_regular_count",
            )
        )
        and declaration_data["resource_directory"] == "lib/clang/22"
        and declaration_data["runtime_boundary"]
        == "exact-llvm-prefix-tree-with-recorded-host-runtime-closure",
        "kernel toolchain runtime boundary differs",
    )
    require(
        HEX_64.fullmatch(declaration_data["manifest_sha256"]) is not None,
        "kernel toolchain manifest digest is invalid",
    )
    prefix_entries = load_toolchain_prefix_manifest(
        prefix_manifest,
        declaration_data["prefix_entry_count"],
        declaration_data["prefix_tree_manifest_sha256"],
    )
    prefix_counts = {
        entry_type: sum(
            entry.entry_type == entry_type for entry in prefix_entries
        )
        for entry_type in ("directory", "regular", "symlink")
    }
    resource_prefix = declaration_data["resource_directory"]
    resource_entries = [
        entry
        for entry in prefix_entries
        if entry.relative_path == resource_prefix
        or entry.relative_path.startswith(resource_prefix + "/")
    ]
    require(
        len(prefix_entries) == declaration_data["prefix_entry_count"]
        and prefix_counts["directory"]
        == declaration_data["prefix_directory_count"]
        and prefix_counts["regular"]
        == declaration_data["prefix_regular_count"]
        and prefix_counts["symlink"]
        == declaration_data["prefix_symlink_count"]
        and len(resource_entries) == declaration_data["resource_entry_count"]
        and sum(
            entry.entry_type == "directory" for entry in resource_entries
        )
        == declaration_data["resource_directory_count"]
        and sum(entry.entry_type == "regular" for entry in resource_entries)
        == declaration_data["resource_regular_count"]
        and all(entry.entry_type != "symlink" for entry in resource_entries),
        "kernel toolchain prefix identity differs",
    )
    prefix_by_path = {
        entry.relative_path: entry for entry in prefix_entries
    }
    require(
        prefix_by_path.get(resource_prefix) is not None
        and prefix_by_path[resource_prefix].entry_type == "directory"
        and prefix_by_path.get(resource_prefix + "/include") is not None
        and prefix_by_path[resource_prefix + "/include"].entry_type
        == "directory",
        "kernel toolchain resource directory rows differ",
    )
    packages = declaration_data["package"]
    package_keys = {
        "component",
        "archive",
        "archive_sha256",
        "signature",
        "signature_sha256",
        "signature_result",
        "signer_fingerprint",
    }
    require(isinstance(packages, list) and len(packages) == 4, "kernel toolchain package denominator differs")
    for index, package in enumerate(packages):
        require(isinstance(package, dict), f"kernel toolchain package {index} is invalid")
        require(set(package) == package_keys, f"kernel toolchain package {index} fields differ")
        require(
            package["component"] in {"clang", "llvm", "llvm-libs", "lld"}
            and isinstance(package["archive"], str)
            and package["archive"]
            and isinstance(package["signature"], str)
            and package["signature"]
            and HEX_64.fullmatch(package["archive_sha256"]) is not None
            and HEX_64.fullmatch(package["signature_sha256"]) is not None
            and package["signature_result"] == "good"
            and package["signer_fingerprint"]
            == "882DCFE48E2051D48E2562ABF3B607488DB35A47",
            f"kernel toolchain package {index} identity differs",
        )
    require(
        {package["component"] for package in packages}
        == {"clang", "llvm", "llvm-libs", "lld"},
        "kernel toolchain package components differ",
    )
    require(
        declaration_data["host_policy"]
        == {
            "uid": 0,
            "gid": 0,
            "group_writable": False,
            "other_writable": False,
            "runner_directory_write": False,
            "runner_file_write": False,
            "extended_attributes": False,
            "special_files": False,
        },
        "kernel toolchain host policy differs",
    )

    columns, rows = read_canonical_ascii_tsv(
        manifest,
        "gororoba-kernel-toolchain-closure-v1",
        MAX_MANIFEST_BYTES,
        "kernel toolchain semantic closure manifest",
        declaration_data["manifest_sha256"],
    )
    expected_columns = [
        "kind",
        "logical_name",
        "relative_path",
        "entry_type",
        "mode",
        "size",
        "identity_sha256",
        "link_target",
        "resolved_sha256",
        "version_first_line",
        "version_output_sha256",
    ]
    require(columns == expected_columns, "kernel toolchain manifest columns differ")
    entries: list[ToolchainClosureEntry] = []
    for row_number, row in enumerate(rows, 3):
        require(len(row) == len(columns), f"kernel toolchain manifest row {row_number} width differs")
        kind, logical_name, relative_path, entry_type, mode, size_text, identity_sha256, link_target, resolved_sha256, version_first_line, version_output_sha256 = row
        path = Path(relative_path)
        require(
            not path.is_absolute()
            and ".." not in path.parts
            and "." not in path.parts
            and len(path.parts) == 2,
            f"kernel toolchain manifest path is invalid: {relative_path}",
        )
        require(kind in {"command", "library", "support"}, f"kernel toolchain manifest kind is invalid: {kind}")
        require(entry_type in {"regular", "symlink"}, f"kernel toolchain manifest type is invalid: {relative_path}")
        require(re.fullmatch(r"0[0-7]{3}", mode) is not None, f"kernel toolchain manifest mode is invalid: {relative_path}")
        require(size_text.isdigit() and int(size_text) > 0, f"kernel toolchain manifest size is invalid: {relative_path}")
        require(
            HEX_64.fullmatch(identity_sha256) is not None
            and HEX_64.fullmatch(resolved_sha256) is not None,
            f"kernel toolchain manifest digest is invalid: {relative_path}",
        )
        if entry_type == "regular":
            require(link_target == "-" and identity_sha256 == resolved_sha256, f"regular toolchain entry identity differs: {relative_path}")
        else:
            target = Path(link_target)
            require(
                link_target != "-"
                and not target.is_absolute()
                and ".." not in target.parts,
                f"toolchain symlink target is invalid: {relative_path}",
            )
        if kind == "command":
            require(
                logical_name in LLVM_KERNEL_TOOLS
                and relative_path == f"bin/{logical_name}"
                and version_first_line != "-"
                and HEX_64.fullmatch(version_output_sha256) is not None,
                f"kernel toolchain command row differs: {logical_name}",
            )
        else:
            require(version_first_line == "-" and version_output_sha256 == "-", f"non-command toolchain row carries a version: {relative_path}")
        if kind == "library":
            require(
                logical_name in LLVM_KERNEL_LIBRARIES
                and relative_path == f"lib/{logical_name}",
                f"kernel toolchain library row differs: {logical_name}",
            )
        entries.append(
            ToolchainClosureEntry(
                kind,
                logical_name,
                relative_path,
                entry_type,
                mode,
                int(size_text),
                identity_sha256,
                link_target,
                resolved_sha256,
                version_first_line,
                version_output_sha256,
            )
        )
    require(
        len({entry.relative_path for entry in entries}) == len(entries)
        and len({(entry.kind, entry.logical_name) for entry in entries})
        == len(entries),
        "kernel toolchain manifest repeats an entry",
    )
    commands = [entry for entry in entries if entry.kind == "command"]
    libraries = [entry for entry in entries if entry.kind == "library"]
    supports = [entry for entry in entries if entry.kind == "support"]
    require(
        {entry.logical_name for entry in commands} == set(LLVM_KERNEL_TOOLS)
        and {entry.logical_name for entry in libraries}
        == set(LLVM_KERNEL_LIBRARIES),
        "kernel toolchain command or library denominator differs",
    )
    require(
        declaration_data["command_count"] == len(commands)
        and declaration_data["library_count"] == len(libraries)
        and declaration_data["support_count"] == len(supports),
        "kernel toolchain closure counts differ",
    )
    by_path = {entry.relative_path: entry for entry in entries}
    for entry in entries:
        if entry.entry_type != "symlink":
            continue
        target_path = (Path(entry.relative_path).parent / entry.link_target).as_posix()
        target_entry = by_path.get(target_path)
        require(
            target_entry is not None
            and target_entry.entry_type == "regular"
            and target_entry.resolved_sha256 == entry.resolved_sha256,
            f"kernel toolchain symlink target is outside the closure: {entry.relative_path}",
        )
    validate_toolchain_semantic_closure(entries, prefix_entries)
    return declaration_data, entries, prefix_entries


def validate_toolchain_semantic_closure(
    entries: list[ToolchainClosureEntry],
    prefix_entries: list[ToolchainPrefixEntry],
) -> None:
    """Join every semantic command and library to the finite prefix tree."""
    prefix_by_path = {
        entry.relative_path: entry for entry in prefix_entries
    }
    for entry in entries:
        prefix_entry = prefix_by_path.get(entry.relative_path)
        shared_identity_matches = (
            prefix_entry is not None
            and prefix_entry.entry_type == entry.entry_type
            and prefix_entry.mode == entry.mode
            and prefix_entry.size == entry.size
            and prefix_entry.identity_sha256 == entry.identity_sha256
            and prefix_entry.link_target == entry.link_target
        )
        resolved_identity_matches = (
            prefix_entry is not None
            and (
                (
                    entry.entry_type == "regular"
                    and entry.resolved_sha256 == prefix_entry.identity_sha256
                )
                or (
                    entry.entry_type == "symlink"
                    and entry.resolved_sha256 == prefix_entry.resolved_sha256
                )
            )
        )
        require(
            shared_identity_matches and resolved_identity_matches,
            "kernel toolchain semantic closure differs from prefix tree: "
            f"{entry.relative_path}",
        )


def require_exact_toolchain_prefix(
    expected_entries: list[ToolchainPrefixEntry],
    actual_entries: list[ToolchainPrefixEntry],
) -> None:
    """Require exact prefix membership and identities with bounded residuals."""
    expected_by_path = {
        entry.relative_path: entry for entry in expected_entries
    }
    actual_by_path = {
        entry.relative_path: entry for entry in actual_entries
    }
    missing_paths = sorted(set(expected_by_path) - set(actual_by_path))
    unexpected_paths = sorted(set(actual_by_path) - set(expected_by_path))
    require(
        not missing_paths and not unexpected_paths,
        "kernel toolchain live prefix path set differs: "
        f"missing={missing_paths[:20]} unexpected={unexpected_paths[:20]}",
    )
    changed_paths = [
        path
        for path in sorted(expected_by_path)
        if expected_by_path[path] != actual_by_path[path]
    ]
    require(
        not changed_paths,
        "kernel toolchain live prefix entries differ: "
        f"changed={changed_paths[:20]}",
    )


def validate_toolchain_payload(
    toolchain_prefix: Path,
    entries: list[ToolchainClosureEntry],
    prefix_entries: list[ToolchainPrefixEntry],
) -> None:
    actual_prefix_entries = derive_toolchain_prefix_entries(
        toolchain_prefix,
        prefix_entries,
    )
    require_exact_toolchain_prefix(prefix_entries, actual_prefix_entries)
    resolved_prefix = toolchain_prefix.resolve(strict=True)
    for entry in entries:
        if entry.kind == "command":
            executable = (resolved_prefix / entry.relative_path).resolve(strict=True)
            require(
                executable.is_file() and os.access(executable, os.X_OK),
                f"kernel toolchain command is not executable: {entry.logical_name}",
            )


def validate_kernel_toolchain(
    release: str,
    bin_directory: Path,
    kernel_declaration: Path,
    toolchain_declaration: Path,
    toolchain_manifest: Path,
    toolchain_prefix_manifest: Path,
    expected_toolchain_manifest: str,
    expected_toolchain_prefix_manifest: str,
) -> tuple[
    list[tuple[Any, ...]],
    dict[str, str],
    Path,
    list[ToolchainClosureEntry],
    list[ToolchainPrefixEntry],
]:
    require(bin_directory.is_dir(), f"kernel toolchain bin directory is absent: {bin_directory}")
    toolchain_prefix = bin_directory.parent
    library_directory = toolchain_prefix / "lib"
    require(library_directory.is_dir(), f"kernel toolchain library directory is absent: {library_directory}")
    try:
        kernel_declaration_data = tomllib.loads(
            kernel_declaration.read_text(encoding="ascii")
        )
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise SourceMapError(
            f"kernel root declaration is invalid: {kernel_declaration}: {exc}"
        ) from exc
    compiler_version = kernel_declaration_data.get("compiler_version")
    linker_version = kernel_declaration_data.get("linker_version")
    require(
        kernel_declaration_data.get("compiler_family") == "clang"
        and isinstance(compiler_version, str)
        and compiler_version,
        f"kernel root declaration has no Clang identity: {release}",
    )
    require(
        kernel_declaration_data.get("linker_family") == "lld"
        and isinstance(linker_version, str)
        and linker_version,
        f"kernel root declaration has no LLD identity: {release}",
    )
    (
        closure_declaration,
        closure_entries,
        prefix_entries,
    ) = load_toolchain_closure(
        toolchain_declaration,
        toolchain_manifest,
        toolchain_prefix_manifest,
    )
    require(
        closure_declaration["manifest"] == expected_toolchain_manifest
        and closure_declaration["prefix_tree_manifest"]
        == expected_toolchain_prefix_manifest
        and closure_declaration["version"] == compiler_version == linker_version,
        f"kernel toolchain closure identity differs from policy or kernel declaration: {release}",
    )
    validate_toolchain_payload(toolchain_prefix, closure_entries, prefix_entries)
    command_entries = {
        entry.logical_name: entry
        for entry in closure_entries
        if entry.kind == "command"
    }
    environment = {
        "PATH": "/usr/bin:/bin",
        "LD_LIBRARY_PATH": str(library_directory),
    }
    resource_queries = {
        "resource_directory": ["--no-default-config", "-print-resource-dir"],
        "resource_include_directory": [
            "--no-default-config",
            "-print-file-name=include",
        ],
    }
    resource_outputs: dict[str, str] = {}
    clang_executable = bin_directory / "clang"
    for query_name, query_arguments in resource_queries.items():
        query_result = subprocess.run(
            [str(clang_executable), *query_arguments],
            check=False,
            capture_output=True,
            text=True,
            env=command_environment_contract("/tmp", environment),
        )
        require(
            query_result.returncode == 0
            and not query_result.stderr
            and query_result.stdout.strip(),
            f"cannot read kernel toolchain {query_name}: {release}",
        )
        resource_outputs[query_name] = query_result.stdout.strip()
    expected_resource_directory = toolchain_prefix / "lib/clang/22"
    require(
        resource_outputs["resource_directory"]
        == expected_resource_directory.as_posix()
        and resource_outputs["resource_include_directory"]
        == (expected_resource_directory / "include").as_posix(),
        f"kernel toolchain Clang resource path differs: {release}",
    )
    rows: list[tuple[Any, ...]] = []
    version_outputs: dict[str, str] = {}
    for tool in LLVM_KERNEL_TOOLS:
        executable = bin_directory / tool
        require(
            executable.is_file() and os.access(executable, os.X_OK),
            f"kernel toolchain executable is absent: {release} {tool}",
        )
        result = subprocess.run(
            [str(executable), "--version"],
            check=False,
            capture_output=True,
            text=True,
            env=command_environment_contract("/tmp", environment),
        )
        combined = "\n".join(
            part.strip() for part in (result.stdout, result.stderr) if part.strip()
        )
        combined = combined.replace(str(toolchain_prefix), CANONICAL_KERNEL_TOOLCHAIN)
        require(result.returncode == 0 and combined, f"cannot read kernel toolchain version: {release} {tool}")
        expected = command_entries[tool]
        require(
            combined.splitlines()[0] == expected.version_first_line
            and sha256_bytes(combined.encode("utf-8"))
            == expected.version_output_sha256,
            f"kernel toolchain version output differs from closure: {release} {tool}",
        )
        version_outputs[tool] = combined
        rows.append(
            (
                release,
                tool,
                executable.name,
                expected.resolved_sha256,
                combined.splitlines()[0],
                sha256_bytes(combined.encode("utf-8")),
                (
                    "<kernel-toolchain-root>/lib/clang/22"
                    if tool == "clang"
                    else "-"
                ),
                (
                    "<kernel-toolchain-root>/lib/clang/22/include"
                    if tool == "clang"
                    else "-"
                ),
            )
        )
    require(
        version_outputs["clang"].splitlines()[0] == f"clang version {compiler_version}",
        f"kernel toolchain compiler differs from declaration: {release}",
    )
    require(
        version_outputs["ld.lld"].splitlines()[0].startswith(f"LLD {linker_version} "),
        f"kernel toolchain linker differs from declaration: {release}",
    )
    return (
        rows,
        environment,
        toolchain_prefix,
        closure_entries,
        prefix_entries,
    )


def normalize_runtime_library_soname(
    requested_name: str,
    dynamic_table: str,
) -> str:
    soname_matches = re.findall(
        r"\(SONAME\)[^\r\n]*\[([^\]\r\n]+)\]",
        dynamic_table,
    )
    require(
        len(soname_matches) == 1
        and re.fullmatch(r"[^/\s]+", soname_matches[0]) is not None,
        "runtime library dynamic table does not carry one valid SONAME",
    )
    soname = soname_matches[0]
    requested_path = Path(requested_name)
    if requested_path.is_absolute():
        require(
            "." not in requested_path.parts
            and ".." not in requested_path.parts
            and requested_name.startswith(
                ("/usr/lib/", "/usr/lib64/", "/lib/", "/lib64/")
            )
            and requested_path.name == soname,
            "absolute runtime loader name differs from the ELF SONAME",
        )
    else:
        require(
            re.fullmatch(r"[^/\s]+", requested_name) is not None
            and requested_name == soname,
            "runtime loader name differs from the ELF SONAME",
        )
    return soname


def parse_ldd_runtime_row(row: str) -> tuple[str, str] | None:
    """Parse one C locale ldd dependency row.

    The virtual DSO has no file identity. Ordinary dependencies use the
    requested-name arrow resolved-path form. Dynamic loaders may instead use
    one direct absolute path, which serves as both the request and resolution
    and remains subject to ELF SONAME validation.
    """
    if re.fullmatch(r"linux-vdso\.so\.1\s+\(0x[0-9a-fA-F]+\)", row):
        return None
    missing = re.fullmatch(r"(\S+)\s+=>\s+not found", row)
    if missing is not None:
        raise SourceMapError(
            f"kernel tool runtime library is absent: {missing.group(1)}"
        )
    indirect = re.fullmatch(
        r"(\S+)\s+=>\s+(\S+)\s+\(0x[0-9a-fA-F]+\)",
        row,
    )
    if indirect is not None:
        return indirect.groups()
    direct = re.fullmatch(r"(/\S+)\s+\(0x[0-9a-fA-F]+\)", row)
    require(direct is not None, f"ldd emitted an unparsed row: {row}")
    path = direct.group(1)
    return path, path


def capture_toolchain_runtime_libraries(
    release: str,
    bin_directory: Path,
    environment: dict[str, str],
    toolchain_prefix: Path,
    closure_entries: list[ToolchainClosureEntry],
) -> list[tuple[Any, ...]]:
    ldd = Path("/usr/bin/ldd")
    pacman = Path("/usr/bin/pacman")
    readelf = bin_directory / "llvm-readelf"
    require(ldd.is_file() and pacman.is_file(), "host runtime closure tools are absent")
    pinned_libraries = {
        entry.logical_name: entry
        for entry in closure_entries
        if entry.kind == "library"
    }
    rows: set[tuple[Any, ...]] = set()
    observed_pinned: set[str] = set()
    command_environment = command_environment_contract("/tmp", environment)
    for tool in LLVM_KERNEL_TOOLS:
        executable = bin_directory / tool
        result = subprocess.run(
            [str(ldd), str(executable)],
            check=False,
            capture_output=True,
            text=True,
            env=command_environment,
        )
        require(
            result.returncode == 0 and not result.stderr,
            f"cannot resolve kernel tool runtime libraries: {release} {tool}",
        )
        for line in result.stdout.splitlines():
            stripped = line.strip()
            parsed = parse_ldd_runtime_row(stripped)
            if parsed is None:
                rows.add(
                    (
                        release,
                        tool,
                        "linux-vdso.so.1",
                        "kernel-virtual",
                        "<kernel-virtual>",
                        "-",
                        "-",
                        "kernel",
                    )
                )
                continue
            requested_name, raw_path = parsed
            resolved = Path(raw_path).resolve(strict=True)
            status = resolved.stat()
            require(
                stat.S_ISREG(status.st_mode)
                and status.st_uid == 0
                and status.st_gid == 0
                and stat.S_IMODE(status.st_mode) & 0o022 == 0,
                f"kernel tool runtime library host policy differs: {resolved}",
            )
            digest = sha256_file(resolved)
            notes = subprocess.run(
                [str(readelf), "--notes", str(resolved)],
                check=False,
                capture_output=True,
                text=True,
                env=command_environment,
            )
            build_id_match = re.search(r"Build ID: ([0-9a-fA-F]+)", notes.stdout)
            require(
                notes.returncode == 0
                and not notes.stderr
                and build_id_match is not None,
                f"kernel tool runtime library has no readable build ID: {resolved}",
            )
            dynamic = subprocess.run(
                [str(readelf), "--dynamic-table", str(resolved)],
                check=False,
                capture_output=True,
                text=True,
                env=command_environment,
            )
            require(
                dynamic.returncode == 0 and not dynamic.stderr,
                f"kernel tool runtime library has no readable dynamic table: {resolved}",
            )
            soname = normalize_runtime_library_soname(
                requested_name,
                dynamic.stdout,
            )
            try:
                relative = resolved.relative_to(toolchain_prefix.resolve())
            except ValueError:
                owner_result = subprocess.run(
                    [str(pacman), "-Qoq", str(resolved)],
                    check=False,
                    capture_output=True,
                    text=True,
                    env=command_environment,
                )
                require(
                    owner_result.returncode == 0
                    and owner_result.stdout.strip()
                    and not owner_result.stderr,
                    f"kernel tool host runtime library has no package owner: {resolved}",
                )
                provider = "host-runtime-recorded"
                canonical_path = resolved.as_posix()
                package_owner = owner_result.stdout.strip()
            else:
                expected = pinned_libraries.get(soname)
                require(
                    expected is not None
                    and relative.as_posix() == expected.relative_path
                    and digest == expected.resolved_sha256,
                    f"loaded toolchain library differs from pinned closure: {soname}",
                )
                observed_pinned.add(soname)
                provider = "toolchain-pinned"
                canonical_path = f"<kernel-toolchain-root>/{relative.as_posix()}"
                package_owner = "toolchain-closure-declaration"
            rows.add(
                (
                    release,
                    tool,
                    soname,
                    provider,
                    canonical_path,
                    digest,
                    build_id_match.group(1).lower(),
                    package_owner,
                )
            )
    require(
        observed_pinned == set(LLVM_KERNEL_LIBRARIES),
        f"loaded LLVM library set differs from pinned closure: {release}",
    )
    return sorted(rows)


def validate_toolchain_runtime_rows(
    runtime_rows: list[tuple[Any, ...]] | list[list[str]],
    lane_releases: set[str],
    closure_entries_by_release: dict[str, list[ToolchainClosureEntry]],
) -> None:
    require(
        runtime_rows == sorted(runtime_rows),
        "toolchain runtime library rows are not sorted",
    )
    require(
        len({tuple(row) for row in runtime_rows}) == len(runtime_rows),
        "toolchain runtime library rows repeat",
    )
    expected_runtime_pairs = {
        (release, tool)
        for release in lane_releases
        for tool in LLVM_KERNEL_TOOLS
    }
    require(
        {(row[0], row[1]) for row in runtime_rows} == expected_runtime_pairs,
        "toolchain runtime command denominator differs",
    )
    for row in runtime_rows:
        require(
            len(row) == 8 and all(isinstance(value, str) for value in row),
            "toolchain runtime library row width or type differs",
        )
        release, command, soname, provider, resolved_path, digest, build_id, package_owner = row
        require(
            release in lane_releases
            and command in LLVM_KERNEL_TOOLS
            and re.fullmatch(r"[^/\s]+", soname) is not None,
            "toolchain runtime library row identity differs",
        )
        if provider == "kernel-virtual":
            require(
                soname == "linux-vdso.so.1"
                and resolved_path == "<kernel-virtual>"
                and digest == "-"
                and build_id == "-"
                and package_owner == "kernel",
                "kernel virtual runtime row differs",
            )
            continue
        require(
            HEX_64.fullmatch(digest) is not None
            and re.fullmatch(r"[0-9a-f]{16,128}", build_id) is not None,
            "toolchain runtime library identity is invalid",
        )
        if provider == "toolchain-pinned":
            entries = {
                entry.logical_name: entry
                for entry in closure_entries_by_release[release]
                if entry.kind == "library"
            }
            expected_entry = entries.get(soname)
            require(
                expected_entry is not None
                and resolved_path
                == f"<kernel-toolchain-root>/{expected_entry.relative_path}"
                and digest == expected_entry.resolved_sha256
                and package_owner == "toolchain-closure-declaration",
                f"pinned runtime library differs from closure: {release} {soname}",
            )
        elif provider == "host-runtime-recorded":
            host_path = Path(resolved_path)
            require(
                host_path.is_absolute()
                and "." not in host_path.parts
                and ".." not in host_path.parts
                and (
                    resolved_path.startswith("/usr/")
                    or resolved_path.startswith("/lib/")
                    or resolved_path.startswith("/lib64/")
                )
                and re.fullmatch(r"[A-Za-z0-9@._+:-]+", package_owner)
                is not None,
                "host runtime library provenance is invalid",
            )
        else:
            raise SourceMapError(
                f"toolchain runtime library provider is invalid: {provider}"
            )
    for release in lane_releases:
        require(
            {
                row[2]
                for row in runtime_rows
                if row[0] == release and row[3] == "toolchain-pinned"
            }
            == set(LLVM_KERNEL_LIBRARIES),
            f"pinned runtime library denominator differs: {release}",
        )
        for command in LLVM_KERNEL_TOOLS:
            require(
                sum(
                    row[0] == release
                    and row[1] == command
                    and row[3] == "kernel-virtual"
                    for row in runtime_rows
                )
                == 1,
                f"kernel virtual runtime row differs: {release} {command}",
            )


def parse_module_symbol_map(content: bytes, label: str) -> dict[str, str]:
    """Parse one exact llvm-nm POSIX map into canonical to raw names."""
    try:
        text = content.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise SourceMapError(f"module symbol map is not ASCII: {label}") from exc
    require(text.endswith("\n"), f"module symbol map lacks final newline: {label}")
    lines = text.splitlines()
    require(bool(lines), f"module symbol map is empty: {label}")
    raw_names: set[str] = set()
    canonical_names: dict[str, str] = {}
    for line_number, line in enumerate(lines, 1):
        match = MODULE_SYMBOL_LINE.fullmatch(line)
        require(
            match is not None,
            f"module symbol row is invalid at {label}:{line_number}",
        )
        raw_name = match.group("name")
        require(
            raw_name not in raw_names,
            f"module symbol map repeats a raw name: {label} {raw_name}",
        )
        raw_names.add(raw_name)
        canonical_name = LLVM_SYMBOL_SUFFIX.sub("", raw_name)
        require(
            bool(canonical_name),
            f"module symbol canonical name is empty: {label} {raw_name}",
        )
        require(
            canonical_name not in canonical_names,
            "module symbol canonicalization collides: "
            f"{label} {canonical_names.get(canonical_name, '')} {raw_name}",
        )
        canonical_names[canonical_name] = raw_name
    return canonical_names


def symbol_name_set_sha256(names: set[str]) -> str:
    serialized = "".join(f"{name}\n" for name in sorted(names)).encode("ascii")
    return sha256_bytes(serialized)


def derive_profile_symbol_delta_rows(
    kernel_lanes: tuple[KernelLane, ...],
    symbol_maps: dict[tuple[str, str], dict[str, str]],
) -> tuple[list[tuple[Any, ...]], list[tuple[Any, ...]]]:
    """Derive every policy ordered profile comparison from canonical names."""
    if not symbol_maps:
        return [], []
    declared_keys = {
        (lane.release, profile)
        for lane in kernel_lanes
        for profile in lane.profiles
    }
    require(
        set(symbol_maps) == declared_keys,
        "profile symbol map lane denominator differs from policy",
    )
    summary_rows: list[tuple[Any, ...]] = []
    member_rows: list[tuple[Any, ...]] = []
    prod_to_mutate_additions: list[set[str]] = []
    for lane in kernel_lanes:
        require(
            "prod" in lane.profiles and "mutate-dev" in lane.profiles,
            f"kernel profile order lacks prod or mutate-dev: {lane.release}",
        )
        for baseline_index, baseline_profile in enumerate(lane.profiles):
            baseline_map = symbol_maps[(lane.release, baseline_profile)]
            baseline_names = set(baseline_map)
            for target_profile in lane.profiles[baseline_index + 1 :]:
                target_map = symbol_maps[(lane.release, target_profile)]
                target_names = set(target_map)
                added = target_names - baseline_names
                removed = baseline_names - target_names
                require(
                    not removed,
                    "profile symbol ordering removes canonical names: "
                    f"{lane.release} {baseline_profile} {target_profile}",
                )
                require(
                    bool(added),
                    "profile symbol ordering is not strict: "
                    f"{lane.release} {baseline_profile} {target_profile}",
                )
                summary_rows.append(
                    (
                        lane.release,
                        baseline_profile,
                        target_profile,
                        len(baseline_names),
                        len(target_names),
                        len(added),
                        len(removed),
                        symbol_name_set_sha256(added),
                        symbol_name_set_sha256(removed),
                    )
                )
                member_rows.extend(
                    (
                        lane.release,
                        baseline_profile,
                        target_profile,
                        "added",
                        canonical_name,
                        "",
                        target_map[canonical_name],
                    )
                    for canonical_name in sorted(added)
                )
                member_rows.extend(
                    (
                        lane.release,
                        baseline_profile,
                        target_profile,
                        "removed",
                        canonical_name,
                        baseline_map[canonical_name],
                        "",
                    )
                    for canonical_name in sorted(removed)
                )
                if baseline_profile == "prod" and target_profile == "mutate-dev":
                    prod_to_mutate_additions.append(added)
    require(
        len(prod_to_mutate_additions) == len(kernel_lanes),
        "prod to mutate-dev symbol comparisons do not close every kernel",
    )
    require(
        all(
            additions == prod_to_mutate_additions[0]
            for additions in prod_to_mutate_additions[1:]
        ),
        "prod to mutate-dev canonical symbol additions differ across kernels",
    )
    return sorted(summary_rows), sorted(member_rows)


def build_profile_symbol_delta_artifacts(
    capture_root: Path,
    policy: Policy,
    preprocessor_lanes: list[dict[str, Any]],
    *,
    write_output: bool = True,
) -> tuple[list[tuple[Any, ...]], list[tuple[Any, ...]]]:
    symbol_maps: dict[tuple[str, str], dict[str, str]] = {}
    for lane in preprocessor_lanes:
        release = str(lane["kernel_release"])
        profile = str(lane["profile"])
        symbol_path = (
            capture_root
            / "preprocessed"
            / release
            / profile
            / "module-defined-symbols.txt"
        )
        content = symbol_path.read_bytes()
        require(
            sha256_bytes(content) == lane["defined_symbols_sha256"],
            f"module symbol map digest differs: {release} {profile}",
        )
        symbol_map = parse_module_symbol_map(
            content,
            f"{release}/{profile}",
        )
        require(
            len(symbol_map) == lane["defined_symbol_count"],
            f"module symbol map count differs: {release} {profile}",
        )
        key = (release, profile)
        require(key not in symbol_maps, f"module symbol lane repeats: {key}")
        symbol_maps[key] = symbol_map
    summary_rows, member_rows = derive_profile_symbol_delta_rows(
        policy.kernel_lanes,
        symbol_maps,
    )
    if write_output:
        write_tsv(
            capture_root / "analysis/profile-symbol-delta-summary.tsv",
            PROFILE_SYMBOL_DELTA_SUMMARY_SCHEMA,
            PROFILE_SYMBOL_DELTA_SUMMARY_COLUMNS,
            summary_rows,
        )
        write_tsv(
            capture_root / "analysis/profile-symbol-delta-members.tsv",
            PROFILE_SYMBOL_DELTA_MEMBERS_SCHEMA,
            PROFILE_SYMBOL_DELTA_MEMBER_COLUMNS,
            member_rows,
        )
    return summary_rows, member_rows


def verify_profile_symbol_delta_artifacts(
    capture_root: Path,
    policy: Policy,
    preprocessor_lanes: list[dict[str, Any]],
) -> tuple[list[list[str]], list[list[str]]]:
    expected_summary, expected_members = build_profile_symbol_delta_artifacts(
        capture_root,
        policy,
        preprocessor_lanes,
        write_output=False,
    )
    summary_columns, summary_rows = read_tsv(
        capture_root / "analysis/profile-symbol-delta-summary.tsv",
        PROFILE_SYMBOL_DELTA_SUMMARY_SCHEMA,
    )
    require(
        summary_columns == list(PROFILE_SYMBOL_DELTA_SUMMARY_COLUMNS),
        "profile symbol delta summary columns differ",
    )
    member_columns, member_rows = read_tsv(
        capture_root / "analysis/profile-symbol-delta-members.tsv",
        PROFILE_SYMBOL_DELTA_MEMBERS_SCHEMA,
    )
    require(
        member_columns == list(PROFILE_SYMBOL_DELTA_MEMBER_COLUMNS),
        "profile symbol delta member columns differ",
    )
    require(
        summary_rows == [[str(value) for value in row] for row in expected_summary],
        "profile symbol delta summary differs from raw module maps",
    )
    require(
        member_rows == [[str(value) for value in row] for row in expected_members],
        "profile symbol delta members differ from raw module maps",
    )
    return summary_rows, member_rows


def capture_preprocessor_views(
    capture_root: Path,
    repository: Path,
    source_root: Path,
    policy: Policy,
    recorder: CommandRecorder,
    kernel_roots: list[Path],
    source_commit: str,
    driver_tree: str,
    feature_policy: bytes,
    upstream_base: str,
    kernel_toolchain_bins: dict[str, Path],
) -> list[dict[str, Any]]:
    if not kernel_roots:
        require(not kernel_toolchain_bins, "kernel toolchain paths require kernel build roots")
        write_tsv(
            capture_root / "preprocessed/preprocessor-inputs.tsv",
            "radeon-driver-preprocessor-inputs-v1",
            (
                "kernel_release",
                "profile",
                "translation_unit",
                "preprocessed_path",
                "preprocessed_sha256",
                "command_path",
                "dependency_path",
            ),
            [],
        )
        write_tsv(
            capture_root / "preprocessed/preprocessor-lanes.tsv",
            "radeon-driver-preprocessor-lanes-v1",
            (
                "kernel_release",
                "profile",
                "translation_unit_count",
                "module_path",
                "module_sha256",
                "defined_symbol_count",
                "defined_symbols_sha256",
                "status",
            ),
            [],
        )
        write_tsv(
            capture_root / "metadata/kernel-toolchains.tsv",
            "radeon-driver-kernel-toolchains-v2",
            (
                "kernel_release",
                "tool",
                "executable_name",
                "executable_sha256",
                "version_first_line",
                "version_output_sha256",
                "resource_directory",
                "resource_include_directory",
            ),
            [],
        )
        write_tsv(
            capture_root / "metadata/toolchain-runtime-libraries.tsv",
            "radeon-driver-toolchain-runtime-libraries-v1",
            (
                "kernel_release",
                "command",
                "soname",
                "provider",
                "resolved_path",
                "sha256",
                "build_id",
                "package_owner",
            ),
            [],
        )
        return []

    lane_by_release = {lane.release: lane for lane in policy.kernel_lanes}
    resolved_kernel_roots: list[tuple[Path, str]] = []
    requested_releases: set[str] = set()
    for root_input in kernel_roots:
        kernel_root = root_input.resolve()
        release_path = kernel_root / "include/config/kernel.release"
        require(
            release_path.is_file(),
            f"kernel build root has no release: {kernel_root}",
        )
        release = release_path.read_text(encoding="ascii").strip()
        require(
            release in lane_by_release,
            f"kernel release is not declared by source-map policy: {release}",
        )
        require(release not in requested_releases, f"kernel release repeats: {release}")
        requested_releases.add(release)
        resolved_kernel_roots.append((kernel_root, release))
    require(
        requested_releases == set(lane_by_release),
        "kernel capture must include every policy kernel release",
    )
    require(
        set(kernel_toolchain_bins) == requested_releases,
        "kernel toolchain declarations do not match the policy kernel releases",
    )
    results: list[dict[str, Any]] = []
    input_rows: list[tuple[Any, ...]] = []
    toolchain_rows: list[tuple[Any, ...]] = []
    runtime_library_rows: list[tuple[Any, ...]] = []
    for kernel_root, release in resolved_kernel_roots:
        lane = lane_by_release[release]
        declaration = repository / lane.declaration
        manifest = repository / lane.manifest
        require(declaration.is_file() and manifest.is_file(), f"kernel root evidence is absent for {release}")
        toolchain_declaration = repository / lane.toolchain_declaration
        toolchain_manifest = repository / lane.toolchain_manifest
        toolchain_prefix_manifest = repository / lane.toolchain_prefix_manifest
        require(
            toolchain_declaration.is_file()
            and toolchain_manifest.is_file()
            and toolchain_prefix_manifest.is_file(),
            f"kernel toolchain evidence is absent for {release}",
        )
        toolchain_bin = kernel_toolchain_bins.get(release)
        require(toolchain_bin is not None, f"kernel toolchain bin directory is not declared: {release}")
        (
            release_toolchain_rows,
            toolchain_environment,
            toolchain_prefix,
            closure_entries,
            admitted_prefix_entries,
        ) = validate_kernel_toolchain(
            release,
            toolchain_bin,
            declaration,
            toolchain_declaration,
            toolchain_manifest,
            toolchain_prefix_manifest,
            lane.toolchain_manifest,
            lane.toolchain_prefix_manifest,
        )
        toolchain_rows.extend(release_toolchain_rows)
        release_runtime_rows = capture_toolchain_runtime_libraries(
            release,
            toolchain_bin,
            toolchain_environment,
            toolchain_prefix,
            closure_entries,
        )
        validate_toolchain_runtime_rows(
            release_runtime_rows,
            {release},
            {release: closure_entries},
        )
        runtime_library_rows.extend(release_runtime_rows)
        recorder.add_replacement(kernel_root, "<kernel-build-root>")
        recorder.add_replacement(toolchain_prefix, "<kernel-toolchain-root>")
        recorder.run(
            f"kernel-root-{release}",
            [
                shutil.which("python3") or "python3",
                str(repository / "scripts/check_kernel_build_root.py"),
                "--root",
                str(kernel_root),
                "--declaration",
                str(declaration),
                "--manifest",
                str(manifest),
            ],
            repository,
            f"diagnostics/kernel-root-{release}.stdout",
            f"diagnostics/kernel-root-{release}.stderr",
        )
        retained_root = capture_root / "metadata/kernel-build-roots"
        retained_root.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(declaration, retained_root / f"{release}.toml")
        shutil.copyfile(manifest, retained_root / f"{release}.manifest.tsv")
        retained_toolchain_root = capture_root / "metadata/kernel-toolchain-closures"
        retained_toolchain_root.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(
            toolchain_declaration,
            retained_toolchain_root / f"{release}.toml",
        )
        shutil.copyfile(
            toolchain_manifest,
            retained_toolchain_root / f"{release}.manifest.tsv",
        )
        shutil.copyfile(
            toolchain_prefix_manifest,
            retained_toolchain_root / f"{release}.prefix-tree.tsv",
        )

        for profile in lane.profiles:
            with tempfile.TemporaryDirectory(prefix="radeon-preprocess-", dir=capture_root.parent) as temporary:
                work = Path(temporary)
                driver_work = work / policy.source_root
                driver_work.parent.mkdir(parents=True, exist_ok=True)
                shutil.copytree(source_root / policy.source_root, driver_work)
                include_trace = work / "include/trace"
                include_trace.mkdir(parents=True)
                header = work / "radeon_build_profile.h"
                write_text(
                    header,
                    profile_header(
                        profile,
                        source_commit,
                        driver_tree,
                        sha256_bytes(feature_policy),
                        upstream_base,
                    ),
                )
                recorder.add_replacement(work, "<preprocessor-work>")
                make_base = kernel_make_base_command(
                    profile,
                    kernel_root,
                    driver_work,
                    toolchain_bin,
                    toolchain_prefix,
                    work,
                )
                recorder.run(
                    f"preprocess-build-{release}-{profile}",
                    [*make_base, "modules"],
                    driver_work,
                    f"preprocessed/{release}/{profile}/module-build.log",
                    f"diagnostics/preprocess-build-{release}-{profile}.stderr",
                    environment=toolchain_environment,
                )
                module = driver_work / "radeon.ko"
                require(module.is_file(), f"preprocessor module build omitted radeon.ko for {release} {profile}")
                lane_output = capture_root / f"preprocessed/{release}/{profile}"
                retained_module = lane_output / "radeon.ko"
                retained_module.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(module, retained_module)
                retained_module.chmod(0o644)
                module_symbols_path = lane_output / "module-defined-symbols.txt"
                recorder.run(
                    f"module-symbols-{release}-{profile}",
                    [
                        str(toolchain_bin / "llvm-nm"),
                        "--defined-only",
                        "--extern-only",
                        "--format=posix",
                        str(module),
                    ],
                    driver_work,
                    f"preprocessed/{release}/{profile}/module-defined-symbols.txt",
                    f"diagnostics/module-symbols-{release}-{profile}.stderr",
                    environment=toolchain_environment,
                )
                defined_symbols = module_symbols_path.read_bytes()
                defined_symbol_lines = defined_symbols.decode("utf-8", errors="strict").splitlines()
                require(defined_symbol_lines, f"linked module has no defined symbols: {release} {profile}")
                targets = [Path(path).with_suffix(".i").name for path in policy.translation_units]
                recorder.run(
                    f"preprocess-units-{release}-{profile}",
                    [*make_base, *targets],
                    driver_work,
                    f"preprocessed/{release}/{profile}/preprocess.log",
                    f"diagnostics/preprocess-units-{release}-{profile}.stderr",
                    environment=toolchain_environment,
                )
                replacements = [
                    (work, CANONICAL_PREPROCESSOR_WORK),
                    (kernel_root, CANONICAL_KERNEL_BUILD_ROOT),
                    (toolchain_prefix, CANONICAL_KERNEL_TOOLCHAIN),
                ]
                for translation_unit in policy.translation_units:
                    stem = Path(translation_unit).stem
                    preprocessed = driver_work / f"{stem}.i"
                    require(preprocessed.is_file(), f"preprocessed translation unit is absent: {release} {profile} {stem}")
                    normalized = sanitize_preprocessor_bytes(preprocessed.read_bytes(), replacements)
                    require(str(work).encode("utf-8") not in normalized, f"preprocessed output retains work path: {stem}")
                    require(str(kernel_root).encode("utf-8") not in normalized, f"preprocessed output retains kernel root: {stem}")
                    require(
                        str(toolchain_prefix).encode("utf-8") not in normalized,
                        f"preprocessed output retains kernel toolchain path: {stem}",
                    )
                    output = lane_output / f"{stem}.i"
                    write_bytes(output, normalized)
                    command_file = driver_work / f".{stem}.o.cmd"
                    dependency_file = driver_work / f".{stem}.o.d"
                    command_rel = ""
                    dependency_rel = ""
                    if command_file.is_file():
                        command_rel = f"preprocessed/{release}/{profile}/{stem}.o.cmd"
                        write_bytes(capture_root / command_rel, sanitize_preprocessor_bytes(command_file.read_bytes(), replacements))
                    if dependency_file.is_file():
                        dependency_rel = f"preprocessed/{release}/{profile}/{stem}.o.d"
                        write_bytes(capture_root / dependency_rel, sanitize_preprocessor_bytes(dependency_file.read_bytes(), replacements))
                    input_rows.append(
                        (
                            release,
                            profile,
                            translation_unit,
                            f"preprocessed/{release}/{profile}/{stem}.i",
                            sha256_file(output),
                            command_rel,
                            dependency_rel,
                        )
                    )
                results.append(
                    {
                        "kernel_release": release,
                        "profile": profile,
                        "translation_unit_count": len(policy.translation_units),
                        "module_path": f"preprocessed/{release}/{profile}/radeon.ko",
                        "module_sha256": sha256_file(retained_module),
                        "defined_symbol_count": len(defined_symbol_lines),
                        "defined_symbols_sha256": sha256_bytes(defined_symbols),
                        "status": "complete",
                    }
                )
        validate_toolchain_payload(
            toolchain_prefix,
            closure_entries,
            admitted_prefix_entries,
        )

    require(
        set(kernel_toolchain_bins) == requested_releases,
        "kernel toolchain release set differs from requested kernel roots",
    )
    write_tsv(
        capture_root / "metadata/kernel-toolchains.tsv",
        "radeon-driver-kernel-toolchains-v2",
        (
            "kernel_release",
            "tool",
            "executable_name",
            "executable_sha256",
            "version_first_line",
            "version_output_sha256",
            "resource_directory",
            "resource_include_directory",
        ),
        sorted(toolchain_rows),
    )
    write_tsv(
        capture_root / "metadata/toolchain-runtime-libraries.tsv",
        "radeon-driver-toolchain-runtime-libraries-v1",
        (
            "kernel_release",
            "command",
            "soname",
            "provider",
            "resolved_path",
            "sha256",
            "build_id",
            "package_owner",
        ),
        sorted(runtime_library_rows),
    )
    write_tsv(
        capture_root / "preprocessed/preprocessor-inputs.tsv",
        "radeon-driver-preprocessor-inputs-v1",
        (
            "kernel_release",
            "profile",
            "translation_unit",
            "preprocessed_path",
            "preprocessed_sha256",
            "command_path",
            "dependency_path",
        ),
        input_rows,
    )
    write_tsv(
        capture_root / "preprocessed/preprocessor-lanes.tsv",
        "radeon-driver-preprocessor-lanes-v1",
        (
            "kernel_release",
            "profile",
            "translation_unit_count",
            "module_path",
            "module_sha256",
            "defined_symbol_count",
            "defined_symbols_sha256",
            "status",
        ),
        [
            (
                item["kernel_release"],
                item["profile"],
                item["translation_unit_count"],
                item["module_path"],
                item["module_sha256"],
                item["defined_symbol_count"],
                item["defined_symbols_sha256"],
                item["status"],
            )
            for item in results
        ],
    )
    return results


def write_hash_ledger(root: Path) -> None:
    ledger = root / HASH_LEDGER
    paths = [
        root / relative
        for relative in sorted(regular_tree_files(root, "capture") - {HASH_LEDGER})
    ]
    rows = [f"{sha256_file(path)}  {path.relative_to(root).as_posix()}" for path in paths]
    write_text(ledger, "\n".join(rows) + "\n")


def expected_capture_files(
    policy: Policy,
    source_entries: list[SourceEntry],
    command_rows: list[list[str]],
    preprocessor_rows: list[list[str]],
    active_releases: set[str],
) -> set[str]:
    expected = {
        "UPSTREAM_BASE.toml",
        HASH_LEDGER,
        "capture-manifest.json",
        "radeon-driver-declared-bindings.tsv",
        "radeon-driver-lexical-map.tsv",
        "source-closure.toml",
        "analysis/bounded-query-matches.tsv",
        "analysis/bounded-query-summary.tsv",
        "analysis/call-candidates.tsv",
        "analysis/cflow-lexical-edges.tsv",
        "analysis/coefficient-vectors.tsv",
        "analysis/contextual-path-witnesses.tsv",
        "analysis/contextual-path-joins.tsv",
        "analysis/extracted-binding-candidates.tsv",
        "analysis/hazard-guard-identifier-census.tsv",
        "analysis/lizard.csv",
        "analysis/partition-lexical-edges.tsv",
        "analysis/profile-symbol-delta-members.tsv",
        "analysis/profile-symbol-delta-summary.tsv",
        "analysis/scc.json",
        "indexes/cscope/cscope.out",
        "indexes/ctags/tags",
        "inputs/c-and-header-files.txt",
        "inputs/c-files.txt",
        "metadata/command-metadata.tsv",
        "metadata/file-list.tsv",
        "metadata/kernel-toolchains.tsv",
        "metadata/tool-inputs.tsv",
        "metadata/tool-versions.tsv",
        "metadata/toolchain-runtime-libraries.tsv",
        "policy/build-features.toml",
        POLICY_PATH.as_posix(),
        "preprocessed/preprocessor-inputs.tsv",
        "preprocessed/preprocessor-lanes.tsv",
        "queries/cscope-root-symbols.tsv",
        "queries/ctags-root-coverage.tsv",
        "queries/readtags-root-symbols.txt",
    }
    expected.update(f"source/{entry.path}" for entry in source_entries)
    expected.update(producer_input_paths(policy).values())
    expected.update(
        f"metadata/git-source-proof/{filename}"
        for filename in {"commit.bin"}
        | {
            name
            for name, _component in source_tree_proof_paths(policy.source_root)
        }
    )

    def add_file_proof(
        prefix: str,
        retained_paths: dict[str, str],
    ) -> None:
        proof_files = {"commit.bin"} | {
            git_file_proof_tree_filename(directory_parts)
            for directory_parts in git_file_proof_directories(
                set(retained_paths)
            )
        }
        expected.update(f"{prefix}/{path}" for path in proof_files)

    add_file_proof(
        "metadata/git-producer-proof",
        producer_input_paths(policy),
    )
    add_file_proof(
        "metadata/git-source-input-proof",
        source_input_paths(),
    )
    for row in command_rows:
        require(len(row) == 8, "command row width differs in capture denominator")
        expected.add(row[4])
        expected.add(row[5])
    for release in active_releases:
        expected.update(
            {
                f"metadata/kernel-build-roots/{release}.toml",
                f"metadata/kernel-build-roots/{release}.manifest.tsv",
                f"metadata/kernel-toolchain-closures/{release}.toml",
                f"metadata/kernel-toolchain-closures/{release}.manifest.tsv",
                f"metadata/kernel-toolchain-closures/{release}.prefix-tree.tsv",
            }
        )
    for row in preprocessor_rows:
        require(
            len(row) == 7,
            "preprocessor row width differs in capture denominator",
        )
        expected.add(row[3])
        if row[5]:
            expected.add(row[5])
        if row[6]:
            expected.add(row[6])
    for lane in policy.kernel_lanes:
        if lane.release not in active_releases:
            continue
        for profile in lane.profiles:
            expected.add(
                f"preprocessed/{lane.release}/{profile}/radeon.ko"
            )
    require(
        all(
            path
            and path == Path(path).as_posix()
            and not Path(path).is_absolute()
            and "." not in Path(path).parts
            and ".." not in Path(path).parts
            for path in expected
        ),
        "expected capture denominator carries an invalid path",
    )
    return expected


def verify_capture_file_denominator(
    root: Path,
    expected_files: set[str],
) -> None:
    actual_files = regular_tree_files(root, "capture")
    require(
        actual_files == expected_files,
        "capture file denominator differs from producer-derived products",
    )
    expected_directories = {
        "/".join(Path(path).parts[:depth])
        for path in expected_files
        for depth in range(1, len(Path(path).parts))
    }
    actual_directories = regular_tree_directories(root, "capture")
    require(
        actual_directories == expected_directories,
        "capture directory denominator differs from producer-derived products",
    )


def verify_hash_ledger(root: Path) -> int:
    ledger = root / HASH_LEDGER
    actual_tree = regular_tree_files(root, "capture")
    require(HASH_LEDGER in actual_tree, f"capture hash ledger is absent: {ledger}")
    declared: dict[str, str] = {}
    ledger_content = read_bounded_file(
        ledger,
        16 * MAX_MANIFEST_BYTES,
        "capture hash ledger",
    )
    try:
        ledger_lines = ledger_content.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise SourceMapError("capture hash ledger is not ASCII") from exc
    for line_number, line in enumerate(ledger_lines, 1):
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n]+)", line)
        require(match is not None, f"hash ledger row {line_number} is malformed")
        digest, relative = match.groups()
        require(relative != HASH_LEDGER and not relative.startswith("./"), f"hash ledger row {line_number} has a forbidden path")
        require(relative not in declared, f"hash ledger repeats path: {relative}")
        require(not Path(relative).is_absolute() and ".." not in Path(relative).parts, f"hash ledger path escapes: {relative}")
        declared[relative] = digest
    actual_paths = actual_tree - {HASH_LEDGER}
    require(set(declared) == actual_paths, "hash ledger coverage differs from retained files")
    for relative, digest in declared.items():
        require(sha256_file(root / relative) == digest, f"hash ledger digest differs: {relative}")
    return len(declared)


def repository_contains(repository: Path, path: Path) -> bool:
    try:
        path.resolve().relative_to(repository.resolve())
    except ValueError:
        return False
    return True


def verify_no_host_path_leaks(root: Path, forbidden_paths: tuple[Path, ...] = ()) -> None:
    forbidden_markers = {
        str(path.resolve()).encode("utf-8")
        for path in (*forbidden_paths, Path.home())
        if len(str(path.resolve())) > 4
    }
    trusted_inputs = {
        "UPSTREAM_BASE.toml",
        "source-closure.toml",
        "policy/build-features.toml",
        POLICY_PATH.as_posix(),
    }
    runtime_library_paths: set[str] = set()
    runtime_table = root / "metadata/toolchain-runtime-libraries.tsv"
    if runtime_table.is_file():
        runtime_columns, runtime_rows = read_tsv(
            runtime_table,
            "radeon-driver-toolchain-runtime-libraries-v1",
        )
        require(
            runtime_columns
            == [
                "kernel_release",
                "command",
                "soname",
                "provider",
                "resolved_path",
                "sha256",
                "build_id",
                "package_owner",
            ],
            "runtime library columns differ during host path verification",
        )
        runtime_library_paths = {
            row[4]
            for row in runtime_rows
            if len(row) == 8 and row[3] == "host-runtime-recorded"
        }

    def under_root(candidate: str, allowed_root: str) -> bool:
        return candidate == allowed_root or candidate.startswith(allowed_root + "/")

    def allowed_candidate(relative: Path, candidate: str) -> bool:
        if any(under_root(candidate, allowed) for allowed in PORTABLE_ABSOLUTE_ROOTS):
            return True
        relative_text = relative.as_posix()
        if relative_text == "metadata/command-metadata.tsv" and candidate in {
            "/",
            "/bin",
            "/tmp",
            "/usr/bin",
            "/usr/bin/make",
        }:
            return True
        if (
            relative_text == "metadata/toolchain-runtime-libraries.tsv"
            and candidate in runtime_library_paths
        ):
            return True
        if (
            relative.parts[:1] == ("preprocessed",)
            and relative.name == "radeon.ko"
            and under_root(candidate, "/lib/firmware/radeon")
        ):
            return True
        return False

    for relative_text in sorted(regular_tree_files(root, "capture")):
        path = root / relative_text
        relative = Path(relative_text)
        if relative_text in trusted_inputs:
            continue
        if relative.parts and relative.parts[0] in {"source", "producer"}:
            continue
        if relative.parts[:2] in {
            ("metadata", "git-source-proof"),
            ("metadata", "git-source-input-proof"),
            ("metadata", "git-producer-proof"),
        }:
            continue
        content = path.read_bytes()
        leaked = set()
        for marker in forbidden_markers:
            if marker in content:
                leaked.add(marker.decode("utf-8", errors="replace"))
        if b".radeon-source-map-" in content:
            leaked.add(".radeon-source-map-")
        source_derived_raw = (
            relative.parts
            and relative.parts[0] in {"indexes", "queries", "preprocessed"}
        )
        for match in ABSOLUTE_PATH_TOKEN.finditer(content):
            candidate = match.group(0).decode("ascii")
            if source_derived_raw and not candidate.startswith(
                (
                    "/tmp/source",
                    "/tmp/capture",
                    "/gororoba/",
                )
            ):
                continue
            if not allowed_candidate(relative, candidate):
                leaked.add(candidate)
        require(
            not leaked,
            f"capture product {relative.as_posix()} retains host paths: "
            + ", ".join(sorted(leaked)),
        )


def verify_capture(
    root: Path,
    *,
    require_all_kernel_lanes: bool = False,
) -> dict[str, Any]:
    require(root.exists(), f"capture directory is absent: {root}")
    capture_files = regular_tree_files(root, "capture")
    manifest_path = root / "capture-manifest.json"
    require("capture-manifest.json" in capture_files, "capture manifest is absent")
    try:
        manifest = json.loads(
            read_bounded_file(
                manifest_path,
                MAX_MANIFEST_BYTES,
                "capture manifest",
            ).decode("utf-8")
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceMapError(f"capture manifest is invalid: {exc}") from exc
    required_manifest = {
        "schema",
        "git_object_format",
        "source_commit",
        "source_tree",
        "driver_tree",
        "producer_commit",
        "producer_tree",
        "source_commit_timestamp_utc",
        "producer_commit_timestamp_utc",
        "policy_sha256",
        "source_closure_sha256",
        "feature_policy_sha256",
        "source_file_count",
        "source_byte_count",
        "source_path_set_sha256",
        "source_manifest_sha256",
        "lexical_row_count",
        "declared_binding_count",
        "call_candidate_count",
        "path_witness_count",
        "path_witness_edge_count",
        "path_witness_join_count",
        "profile_symbol_comparison_count",
        "profile_symbol_delta_member_count",
        "preprocessor_lanes",
        "semantic_limit",
    }
    require(set(manifest) == required_manifest, "capture manifest keys differ from schema")
    require(manifest["schema"] == CAPTURE_SCHEMA, "capture manifest schema differs")
    require(manifest["git_object_format"] == "sha1", "capture Git object format differs")
    for key in (
        "source_commit",
        "source_tree",
        "driver_tree",
        "producer_commit",
        "producer_tree",
    ):
        require(isinstance(manifest[key], str) and HEX_40.fullmatch(manifest[key]) is not None, f"capture manifest {key} is invalid")
    for key in (
        "policy_sha256",
        "source_closure_sha256",
        "feature_policy_sha256",
        "source_path_set_sha256",
        "source_manifest_sha256",
    ):
        require(isinstance(manifest[key], str) and HEX_64.fullmatch(manifest[key]) is not None, f"capture manifest {key} is invalid")
    integer_bounds = {
        "source_file_count": (1, MAX_SOURCE_FILES),
        "source_byte_count": (1, MAX_SOURCE_BYTES),
        "lexical_row_count": (1, MAX_ANALYSIS_ROWS),
        "declared_binding_count": (1, MAX_ANALYSIS_ROWS),
        "call_candidate_count": (1, MAX_ANALYSIS_ROWS),
        "path_witness_count": (1, MAX_ANALYSIS_ROWS),
        "path_witness_edge_count": (1, MAX_ANALYSIS_ROWS),
        "path_witness_join_count": (1, MAX_ANALYSIS_ROWS),
        "profile_symbol_comparison_count": (0, MAX_ANALYSIS_ROWS),
        "profile_symbol_delta_member_count": (0, MAX_ANALYSIS_ROWS),
    }
    for key, (minimum, maximum) in integer_bounds.items():
        value = manifest[key]
        require(
            type(value) is int and minimum <= value <= maximum,
            f"capture manifest {key} exceeds its declared bounds",
        )
    require(manifest["semantic_limit"] == "candidate-research-graph-not-runtime-reachability", "capture semantic limit differs")
    require(
        isinstance(manifest["preprocessor_lanes"], list)
        and len(manifest["preprocessor_lanes"]) <= 64,
        "capture preprocessor lanes are invalid",
    )

    policy_path = root / POLICY_PATH
    require(POLICY_PATH.as_posix() in capture_files, "retained source-map policy is absent")
    policy_content = read_bounded_file(
        policy_path,
        MAX_MANIFEST_BYTES,
        "retained source-map policy",
    )
    require(sha256_bytes(policy_content) == manifest["policy_sha256"], "retained source-map policy digest differs")
    policy = load_policy(
        policy_path,
        accepted_comparison_schemas=RETAINED_CAPTURE_COMPARISON_SCHEMAS,
    )
    require(policy.capture_schema == manifest["schema"], "retained policy schema differs")
    require(
        manifest["source_file_count"] <= policy.max_source_files
        and manifest["source_byte_count"] <= policy.max_source_bytes,
        "capture source denominator exceeds retained policy bounds",
    )
    require(
        len(manifest["preprocessor_lanes"])
        <= sum(len(lane.profiles) for lane in policy.kernel_lanes),
        "capture preprocessor lane count exceeds retained policy",
    )
    verify_no_host_path_leaks(root, (root,))
    retained_count = verify_hash_ledger(root)
    lane_keys = {
        "kernel_release",
        "profile",
        "translation_unit_count",
        "module_path",
        "module_sha256",
        "defined_symbol_count",
        "defined_symbols_sha256",
        "status",
    }
    for lane in manifest["preprocessor_lanes"]:
        require(isinstance(lane, dict) and set(lane) == lane_keys, "preprocessor lane shape differs")
        require(
            isinstance(lane["kernel_release"], str)
            and isinstance(lane["profile"], str)
            and type(lane["translation_unit_count"]) is int
            and lane["translation_unit_count"] == len(policy.translation_units)
            and isinstance(lane["module_path"], str)
            and isinstance(lane["module_sha256"], str)
            and HEX_64.fullmatch(lane["module_sha256"]) is not None
            and type(lane["defined_symbol_count"]) is int
            and 0 < lane["defined_symbol_count"] <= MAX_ANALYSIS_ROWS
            and isinstance(lane["defined_symbols_sha256"], str)
            and HEX_64.fullmatch(lane["defined_symbols_sha256"]) is not None
            and lane["status"] == "complete",
            "preprocessor lane identity is invalid",
        )
        lane_prefix = f"preprocessed/{lane['kernel_release']}/{lane['profile']}"
        require(
            lane["module_path"] == f"{lane_prefix}/radeon.ko",
            "preprocessor module path differs",
        )
        module_path = root / lane["module_path"]
        symbols_path = root / lane_prefix / "module-defined-symbols.txt"
        require(
            module_path.is_file()
            and sha256_file(module_path) == lane["module_sha256"],
            "retained preprocessor module identity differs",
        )
        require(symbols_path.is_file(), "retained module symbol map is absent")
        symbol_content = symbols_path.read_bytes()
        require(
            sha256_bytes(symbol_content) == lane["defined_symbols_sha256"]
            and len(symbol_content.decode("utf-8", errors="strict").splitlines())
            == lane["defined_symbol_count"],
            "retained module symbol map identity differs",
        )
    require(
        len(
            {
                (lane["kernel_release"], lane["profile"])
                for lane in manifest["preprocessor_lanes"]
            }
        )
        == len(manifest["preprocessor_lanes"]),
        "preprocessor lane repeats",
    )
    for key in ("source_commit_timestamp_utc", "producer_commit_timestamp_utc"):
        require(
            isinstance(manifest[key], str)
            and UTC_TIMESTAMP.fullmatch(manifest[key]) is not None,
            f"capture {key} is invalid",
        )
    expected_lane_pairs = {
        (lane.release, profile)
        for lane in policy.kernel_lanes
        for profile in lane.profiles
    }
    observed_lane_pairs = {
        (lane["kernel_release"], lane["profile"])
        for lane in manifest["preprocessor_lanes"]
    }
    if observed_lane_pairs:
        require(
            observed_lane_pairs == expected_lane_pairs,
            "nonempty preprocessor capture does not close every policy lane",
        )
    if require_all_kernel_lanes:
        require(
            observed_lane_pairs == expected_lane_pairs,
            "required preprocessor capture does not close every policy lane",
        )
    symbol_summary_rows, symbol_member_rows = (
        verify_profile_symbol_delta_artifacts(
            root,
            policy,
            manifest["preprocessor_lanes"],
        )
    )
    require(
        manifest["profile_symbol_comparison_count"] == len(symbol_summary_rows)
        and manifest["profile_symbol_delta_member_count"]
        == len(symbol_member_rows),
        "profile symbol delta denominator differs",
    )
    source_timestamp = verify_source_tree_proof(
        root,
        manifest["source_commit"],
        manifest["source_tree"],
        manifest["driver_tree"],
        policy.source_root,
    )
    require(
        source_timestamp == manifest["source_commit_timestamp_utc"],
        "source commit timestamp differs from the proved commit object",
    )
    producer_timestamp = verify_git_file_proof(
        root,
        root / "metadata/git-producer-proof",
        manifest["producer_commit"],
        manifest["producer_tree"],
        producer_input_paths(policy),
        "retained producer Git proof",
    )
    require(
        producer_timestamp == manifest["producer_commit_timestamp_utc"],
        "producer commit timestamp differs from the proved commit object",
    )
    source_input_timestamp = verify_git_file_proof(
        root,
        root / "metadata/git-source-input-proof",
        manifest["source_commit"],
        manifest["source_tree"],
        source_input_paths(),
        "retained source input Git proof",
    )
    require(
        source_input_timestamp == manifest["source_commit_timestamp_utc"],
        "source input proof timestamp differs from the source commit",
    )
    expected_producer_files = {
        Path(retained_path).relative_to("producer").as_posix()
        for retained_path in producer_input_paths(policy).values()
        if retained_path.startswith("producer/")
    }
    require(
        regular_tree_files(root / "producer", "retained producer inputs")
        == expected_producer_files,
        "retained producer input file denominator differs",
    )
    require(
        sha256_file(root / "source-closure.toml")
        == manifest["source_closure_sha256"],
        "retained source closure digest differs",
    )
    require(
        sha256_file(root / "policy/build-features.toml")
        == manifest["feature_policy_sha256"],
        "retained feature policy digest differs",
    )

    lane_columns, retained_lane_rows = read_tsv(
        root / "preprocessed/preprocessor-lanes.tsv",
        "radeon-driver-preprocessor-lanes-v1",
    )
    require(
        lane_columns
        == [
            "kernel_release",
            "profile",
            "translation_unit_count",
            "module_path",
            "module_sha256",
            "defined_symbol_count",
            "defined_symbols_sha256",
            "status",
        ],
        "preprocessor lane columns differ",
    )
    expected_lane_rows = [
        [
            lane["kernel_release"],
            lane["profile"],
            str(lane["translation_unit_count"]),
            lane["module_path"],
            lane["module_sha256"],
            str(lane["defined_symbol_count"]),
            lane["defined_symbols_sha256"],
            lane["status"],
        ]
        for lane in manifest["preprocessor_lanes"]
    ]
    require(retained_lane_rows == expected_lane_rows, "preprocessor lane table differs from manifest")

    input_columns, preprocessor_rows = read_tsv(
        root / "preprocessed/preprocessor-inputs.tsv",
        "radeon-driver-preprocessor-inputs-v1",
    )
    require(
        input_columns
        == [
            "kernel_release",
            "profile",
            "translation_unit",
            "preprocessed_path",
            "preprocessed_sha256",
            "command_path",
            "dependency_path",
        ],
        "preprocessor input columns differ",
    )
    expected_preprocessor_keys = {
        (lane["kernel_release"], lane["profile"], translation_unit)
        for lane in manifest["preprocessor_lanes"]
        for translation_unit in policy.translation_units
    }
    require(
        len(preprocessor_rows) == len(expected_preprocessor_keys),
        "preprocessor input denominator differs",
    )
    observed_preprocessor_keys: set[tuple[str, str, str]] = set()
    for row in preprocessor_rows:
        require(len(row) == 7, "preprocessor input row width differs")
        release, profile, translation_unit, preprocessed_path, digest, command_path, dependency_path = row
        key = (release, profile, translation_unit)
        require(key in expected_preprocessor_keys, f"preprocessor input row is foreign: {key}")
        require(key not in observed_preprocessor_keys, f"preprocessor input row repeats: {key}")
        observed_preprocessor_keys.add(key)
        stem = Path(translation_unit).stem
        lane_prefix = f"preprocessed/{release}/{profile}"
        require(
            preprocessed_path == f"{lane_prefix}/{stem}.i",
            f"preprocessor product path differs: {key}",
        )
        preprocessed_file = root / preprocessed_path
        require(
            preprocessed_file.is_file()
            and HEX_64.fullmatch(digest) is not None
            and sha256_file(preprocessed_file) == digest,
            f"preprocessor product identity differs: {key}",
        )
        if command_path:
            require(
                command_path == f"{lane_prefix}/{stem}.o.cmd"
                and (root / command_path).is_file(),
                f"object command evidence differs: {key}",
            )
        if dependency_path:
            require(
                dependency_path == f"{lane_prefix}/{stem}.o.d"
                and (root / dependency_path).is_file(),
                f"object dependency evidence differs: {key}",
            )
    require(
        observed_preprocessor_keys == expected_preprocessor_keys,
        "preprocessor input set does not close",
    )

    file_list_path = root / "metadata/file-list.tsv"
    read_bounded_file(
        file_list_path,
        MAX_MANIFEST_BYTES,
        "retained source file list",
    )
    columns, source_rows = read_tsv(file_list_path, "radeon-driver-file-list-v1")
    require(
        columns == ["path", "source_class", "mode", "size", "object_id", "sha256"],
        "file-list columns differ",
    )
    require(len(source_rows) == manifest["source_file_count"], "file-list count differs from manifest")
    require(sha256_file(root / "metadata/file-list.tsv") == manifest["source_manifest_sha256"], "file-list digest differs")
    require(
        all(
            len(row) == 6
            and row[3].isdigit()
            and int(row[3]) <= policy.max_source_bytes
            for row in source_rows
        )
        and sum(int(row[3]) for row in source_rows)
        == manifest["source_byte_count"],
        "file-list byte denominator exceeds manifest or policy bounds",
    )
    total_bytes = 0
    seen_paths: set[str] = set()
    source_entries: list[SourceEntry] = []
    for row_number, row in enumerate(source_rows, 3):
        require(len(row) == 6, f"file-list row {row_number} has {len(row)} fields")
        path, source_kind, mode, size_text, object_id, digest = row
        require(path not in seen_paths, f"file-list repeats path: {path}")
        seen_paths.add(path)
        require(
            path.startswith(policy.source_root + "/")
            and not Path(path).is_absolute()
            and ".." not in Path(path).parts
            and "\n" not in path
            and "\t" not in path
            and not any(ord(character) < 32 for character in path),
            f"file-list path leaves the source root: {path!r}",
        )
        require(source_kind == source_class(policy, path), f"file-list source class differs: {path}")
        require(mode in {"100644", "100755"}, f"file-list mode is invalid: {path}")
        require(size_text.isdigit(), f"file-list size is invalid: {path}")
        require(HEX_40.fullmatch(object_id) is not None and HEX_64.fullmatch(digest) is not None, f"file-list identity is invalid: {path}")
        source_path = root / "source" / path
        require(source_path.is_file() and not source_path.is_symlink(), f"retained source is absent or symlinked: {path}")
        require(source_path.stat().st_size == int(size_text), f"retained source size differs: {path}")
        content = source_path.read_bytes()
        require(sha256_bytes(content) == digest, f"retained source digest differs: {path}")
        require(git_object_id("blob", content) == object_id, f"retained source Git blob identity differs: {path}")
        retained_mode = "100755" if source_path.stat().st_mode & 0o111 else "100644"
        require(retained_mode == mode, f"retained source mode differs: {path}")
        total_bytes += int(size_text)
        source_entries.append(SourceEntry(path, mode, object_id, int(size_text), digest, source_kind))
    require(
        source_rows == sorted(source_rows, key=lambda row: row[0].encode("utf-8")),
        "file-list rows are not canonically ordered",
    )
    require(total_bytes == manifest["source_byte_count"], "retained source byte count differs")
    path_set = b"".join(path.encode("utf-8") + b"\0" for path in sorted(seen_paths))
    require(sha256_bytes(path_set) == manifest["source_path_set_sha256"], "retained source path-set digest differs")
    require(not any(path.endswith("_reg_safe.h") for path in seen_paths), "retained source carries a generated register header")
    require(
        retained_driver_tree_id(source_entries, policy.source_root)
        == manifest["driver_tree"],
        "retained source does not reconstruct the claimed driver tree",
    )
    require(
        regular_tree_files(root / "source", "retained source") == seen_paths,
        "retained source file denominator differs from the file list",
    )

    c_and_header_paths = [
        entry.path
        for entry in source_entries
        if entry.source_class in {"c", "header"}
    ]
    c_paths = [entry.path for entry in source_entries if entry.source_class == "c"]
    source_list_path = root / "inputs/c-and-header-files.txt"
    c_list_path = root / "inputs/c-files.txt"
    expected_source_list = "\n".join(c_and_header_paths) + "\n"
    expected_c_list = "\n".join(c_paths) + "\n"
    require(
        source_list_path.read_text(encoding="utf-8") == expected_source_list,
        "C and header analyzer input denominator differs from retained source",
    )
    require(
        c_list_path.read_text(encoding="utf-8") == expected_c_list,
        "C analyzer input denominator differs from retained source",
    )
    tool_input_columns, tool_input_rows = read_tsv(
        root / "metadata/tool-inputs.tsv",
        "radeon-driver-tool-inputs-v1",
    )
    require(
        tool_input_columns
        == ["input_name", "file_count", "content_sha256", "consumers"],
        "tool-input columns differ",
    )
    require(
        tool_input_rows
        == [
            [
                "c-and-header-files",
                str(len(c_and_header_paths)),
                sha256_file(source_list_path),
                "cscope;ctags;gnu-global;lizard",
            ],
            [
                "c-files",
                str(len(c_paths)),
                sha256_file(c_list_path),
                "cflow",
            ],
        ],
        "tool-input rows differ from retained source",
    )

    lexical_columns, lexical_rows = read_tsv(root / "radeon-driver-lexical-map.tsv", LEXICAL_SCHEMA)
    require(
        lexical_columns == ["record_kind", "symbol", "source_path", "line", "source_sha256", "provenance"],
        "lexical-map columns differ",
    )
    require(len(lexical_rows) == manifest["lexical_row_count"], "lexical row count differs")
    file_rows = {row[2] for row in lexical_rows if row[0] == "file"}
    analyzer_files = {entry.path for entry in source_entries if entry.source_class in {"c", "header"}}
    require(file_rows == analyzer_files, "lexical map does not preserve the complete C and header denominator")
    entry_map = {entry.path: entry for entry in source_entries}
    expected_lexical_rows = derive_lexical_rows(
        root,
        root / "source",
        source_entries,
    )
    require(
        lexical_rows
        == [[str(value) for value in row] for row in expected_lexical_rows],
        "lexical map differs from retained GNU Global raw queries",
    )

    ctags_path = root / "indexes/ctags/tags"
    require(ctags_path.is_file(), "Ctags index is absent")
    ctags_rows = [
        line
        for line in ctags_path.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("!_TAG_")
    ]
    require(ctags_rows, "Ctags index carries no source records")
    ctags_source_classes: set[str] = set()
    ctags_records: list[tuple[str, ...]] = []
    for row_number, line in enumerate(ctags_rows, 1):
        record = canonical_ctags_record(line, "Ctags", row_number)
        source_entry = entry_map.get(record[1])
        require(
            source_entry is not None
            and source_entry.source_class in {"c", "header"},
            f"Ctags row {row_number} names a foreign source path: {record[1]}",
        )
        ctags_source_classes.add(source_entry.source_class)
        ctags_records.append(record)
    require(
        ctags_source_classes == {"c", "header"},
        "Ctags index does not cover both C and header sources",
    )
    require(
        len(set(ctags_records)) == len(ctags_records),
        "Ctags index repeats a normalized source record",
    )
    readtags_all_lines = (
        root / "indexes/ctags/readtags-all.txt"
    ).read_text(encoding="utf-8").splitlines()
    require(
        readtags_all_lines and all(readtags_all_lines),
        "readtags full selection is empty or carries an empty row",
    )
    readtags_all_records = [
        canonical_ctags_record(line, "readtags", row_number)
        for row_number, line in enumerate(readtags_all_lines, 1)
    ]
    require(
        len(set(readtags_all_records)) == len(readtags_all_records)
        and set(readtags_all_records) == set(ctags_records),
        "readtags full selection differs from the retained Ctags index",
    )
    root_symbols = policy_root_symbols(policy)
    readtags_lines = (
        root / "queries/readtags-root-symbols.txt"
    ).read_text(encoding="utf-8").splitlines()
    require(readtags_lines, "readtags root selection is empty")
    expected_readtags_lines = [
        line
        for line in readtags_all_lines
        if line.split("\t", 1)[0] in set(root_symbols)
    ]
    require(
        readtags_lines == expected_readtags_lines,
        "readtags root selection differs from the retained full query",
    )
    ctags_coverage_columns, ctags_coverage_rows = read_tsv(
        root / "queries/ctags-root-coverage.tsv",
        "radeon-driver-ctags-root-coverage-v1",
    )
    require(
        ctags_coverage_columns
        == ["symbol", "ctags_record_count", "classification"],
        "Ctags root coverage columns differ",
    )
    expected_ctags_coverage = [
        [
            symbol,
            str(
                sum(
                    line.split("\t", 1)[0] == symbol
                    for line in readtags_lines
                )
            ),
            "indexed",
        ]
        for symbol in root_symbols
    ]
    require(
        ctags_coverage_rows == expected_ctags_coverage
        and all(int(row[1]) > 0 for row in ctags_coverage_rows),
        "Ctags root coverage differs from the retained selection",
    )
    ctags_stderr = (
        root / "diagnostics/ctags-index.stderr"
    ).read_text(encoding="utf-8")
    require(
        all(
            any(re.fullmatch(pattern, line) for pattern in policy.ctags_stderr)
            for line in ctags_stderr.splitlines()
            if line
        )
        and not any(
            line.startswith("ctags: Warning:")
            for line in ctags_stderr.splitlines()
        ),
        "Ctags diagnostics exceed the exact notice policy",
    )

    cscope_columns, retained_cscope_rows = read_tsv(
        root / "queries/cscope-root-symbols.tsv",
        "radeon-driver-cscope-root-queries-v1",
    )
    require(
        cscope_columns
        == [
            "query_kind",
            "query_symbol",
            "source_path",
            "function",
            "line",
            "source_text",
        ],
        "cscope query columns differ",
    )
    cscope_symbols = root_symbols
    expected_cscope_files = {
        f"{query_kind}-{symbol}.txt"
        for symbol in cscope_symbols
        for query_kind in ("definition", "calls", "callers")
    }
    cscope_query_root = root / "queries/cscope"
    observed_cscope_files = {
        path.name for path in cscope_query_root.iterdir() if path.is_file()
    }
    require(
        observed_cscope_files == expected_cscope_files,
        "cscope raw query file denominator differs",
    )
    reparsed_cscope_rows: list[tuple[Any, ...]] = []
    for symbol in cscope_symbols:
        for query_kind in ("definition", "calls", "callers"):
            raw_path = cscope_query_root / f"{query_kind}-{symbol}.txt"
            reparsed_cscope_rows.extend(
                parse_cscope_rows(
                    raw_path.read_bytes(),
                    query_kind,
                    symbol,
                    entry_map,
                    root / "source",
                )
            )
    reparsed_cscope_rows.sort(
        key=lambda row: (row[0], row[1], row[2], row[4], row[3], row[5])
    )
    require(
        [tuple(str(value) for value in row) for row in reparsed_cscope_rows]
        == [tuple(row) for row in retained_cscope_rows],
        "retained cscope query table differs from raw query replay",
    )

    bounded_summary_columns, bounded_summary_rows = read_tsv(
        root / "analysis/bounded-query-summary.tsv",
        "radeon-driver-bounded-query-summary-v2",
    )
    require(
        bounded_summary_columns
        == [
            "query_name",
            "file_count",
            "expected_match_count",
            "match_count",
            "pattern_sha256",
            "selected_path_set_sha256",
            "rationale",
            "semantic_limit",
        ],
        "bounded query summary columns differ",
    )
    bounded_match_columns, bounded_match_rows = read_tsv(
        root / "analysis/bounded-query-matches.tsv",
        "radeon-driver-bounded-query-matches-v2",
    )
    require(
        bounded_match_columns
        == [
            "query_name",
            "source_path",
            "line",
            "source_sha256",
            "matched_text_sha256",
            "provenance",
        ],
        "bounded query match columns differ",
    )
    expected_bounded_summary, expected_bounded_matches = evaluate_bounded_queries(
        root / "source",
        source_entries,
        policy.bounded_queries,
    )
    require(
        bounded_summary_rows
        == [
            [str(value) for value in row]
            for row in expected_bounded_summary
        ],
        "bounded query summary differs from offline replay",
    )
    require(
        bounded_match_rows
        == [
            [str(value) for value in row]
            for row in expected_bounded_matches
        ],
        "bounded query matches differ from offline replay",
    )

    binding_columns, binding_rows = read_tsv(root / "radeon-driver-declared-bindings.tsv", DECLARED_BINDING_SCHEMA)
    require(
        binding_columns
        == [
            "binding_id",
            "binding_kind",
            "partition",
            "source_path",
            "line",
            "caller_symbol",
            "target_symbol",
            "source_sha256",
            "matched_text_sha256",
            "provenance",
            "match_scope",
        ],
        "declared-binding columns differ",
    )
    require(len(binding_rows) == manifest["declared_binding_count"], "declared binding count differs")
    require(len(binding_rows) == sum(item.expected_matches for item in policy.bindings), "declared binding denominator differs from retained policy")
    verified_rows = verify_declared_bindings(
        root,
        root / "source",
        entry_map,
        policy,
        write_output=False,
    )
    normalized_verified_rows = [tuple(str(value) for value in row) for row in verified_rows]
    normalized_binding_rows = [tuple(row) for row in binding_rows]
    require(normalized_verified_rows == normalized_binding_rows, "retained binding revalidation rows differ")

    (
        expected_cflow_edges,
        _expected_partition_edges,
        expected_cflow_rows,
        expected_partition_rows,
    ) = derive_cflow_products(root, policy)
    cflow_columns, cflow_rows = read_tsv(
        root / "analysis/cflow-lexical-edges.tsv",
        "radeon-driver-cflow-lexical-edges-v1",
    )
    require(
        cflow_columns
        == [
            "caller",
            "callee",
            "callee_kind",
            "provenance",
            "semantic_limit",
        ],
        "cflow lexical edge columns differ",
    )
    require(
        cflow_rows
        == [[str(value) for value in row] for row in expected_cflow_rows],
        "cflow lexical edges differ from retained raw output",
    )
    partition_columns, partition_rows = read_tsv(
        root / "analysis/partition-lexical-edges.tsv",
        "radeon-driver-partition-lexical-edges-v1",
    )
    require(
        partition_columns
        == ["partition", "caller", "callee", "callee_kind"],
        "partition lexical edge columns differ",
    )
    require(
        partition_rows
        == [[str(value) for value in row] for row in expected_partition_rows],
        "partition lexical edges differ from retained raw output",
    )

    expected_extracted_rows, expected_generated_edges = (
        extract_callback_candidates(
            root,
            root / "source",
            source_entries,
            policy,
            write_output=False,
        )
    )
    extracted_columns, extracted_rows = read_tsv(
        root / "analysis/extracted-binding-candidates.tsv",
        "radeon-driver-extracted-binding-candidates-v1",
    )
    require(
        extracted_columns
        == [
            "extractor",
            "source_path",
            "line",
            "selector",
            "target_symbol",
            "source_sha256",
        ],
        "extracted binding candidate columns differ",
    )
    require(
        extracted_rows
        == [[str(value) for value in row] for row in expected_extracted_rows],
        "extracted binding candidates differ from retained source",
    )

    call_columns, call_rows = read_tsv(
        root / "analysis/call-candidates.tsv",
        "radeon-driver-call-candidates-v1",
    )
    require(
        call_columns
        == [
            "edge_kind",
            "caller",
            "callee",
            "partition",
            "provenance",
            "classification",
        ],
        "call candidate columns differ",
    )
    expected_call_rows = verify_call_candidate_rows(
        call_rows,
        expected_cflow_edges,
        verified_rows,
        expected_generated_edges,
    )
    require(
        len(call_rows) == manifest["call_candidate_count"],
        "call candidate count differs",
    )

    expected_coefficient_rows, expected_guard_identifier_rows = (
        derive_complexity_and_coefficients(
            root,
            root / "source",
            policy,
            expected_cflow_edges,
            verified_rows,
            set(c_and_header_paths),
        )
    )
    guard_columns, guard_rows = read_tsv(
        root / "analysis/hazard-guard-identifier-census.tsv",
        "radeon-driver-hazard-guard-identifier-census-v1",
    )
    require(
        guard_columns
        == [
            "hazard_symbol",
            "guard_census_owner_symbol",
            "source_path",
            "line",
            "required_identifier",
            "source_sha256",
            "provenance",
            "semantic_limit",
        ],
        "hazard guard identifier census columns differ",
    )
    require(
        guard_rows
        == [
            [str(value) for value in row]
            for row in expected_guard_identifier_rows
        ],
        "hazard guard identifier census differs from lizard and source replay",
    )
    coefficient_columns, coefficient_rows = read_tsv(
        root / "analysis/coefficient-vectors.tsv",
        "radeon-driver-coefficient-vectors-v2",
    )
    require(
        coefficient_columns
        == [
            "symbol",
            "source_path",
            "line",
            "nloc",
            "ccn",
            "lexical_fan_in",
            "lexical_fan_out",
            "declared_indirect_edges",
            "maximum_side_effect_class",
            "guard_census_owner_count",
            "required_guard_identifier_count",
            "evidence_rank",
        ],
        "coefficient vector columns differ",
    )
    require(
        coefficient_rows
        == [[str(value) for value in row] for row in expected_coefficient_rows],
        "coefficient vectors differ from lizard, cflow, and binding replay",
    )

    command_columns, command_rows = read_tsv(
        root / "metadata/command-metadata.tsv",
        "radeon-driver-command-metadata-v1",
    )
    verify_command_records(
        command_columns,
        command_rows,
        expected_command_records(
            policy,
            source_entries,
            {
                lane["kernel_release"]
                for lane in manifest["preprocessor_lanes"]
            },
        ),
    )

    tool_columns, tool_rows = read_tsv(
        root / "metadata/tool-versions.tsv",
        "radeon-driver-tool-versions-v1",
    )
    require(
        tool_columns
        == [
            "tool",
            "required",
            "executable_name",
            "executable_sha256",
            "version",
            "version_output_sha256",
        ],
        "tool-version columns differ",
    )
    expected_tools = set(policy.required_tools) | set(policy.optional_tools)
    require({row[0] for row in tool_rows} == expected_tools, "tool-version denominator differs")
    require(all(len(row) == 6 for row in tool_rows), "tool-version row width differs")
    for row in tool_rows:
        tool, required, executable_name, executable_sha256, version, version_sha256 = row
        require(required == ("yes" if tool in policy.required_tools else "no"), f"tool requirement differs: {tool}")
        require("/" not in executable_name, f"tool executable retains a path: {tool}")
        if executable_name == "absent":
            require(tool not in policy.required_tools, f"required tool is recorded absent: {tool}")
            require(executable_sha256 == "absent" and not version and version_sha256 == "absent", f"absent tool row differs: {tool}")
        else:
            require(HEX_64.fullmatch(executable_sha256) is not None, f"tool executable digest is invalid: {tool}")
            require(version and HEX_64.fullmatch(version_sha256) is not None, f"tool version identity is invalid: {tool}")

    cscope_tool_rows = [row for row in tool_rows if row[0] == "cscope"]
    require(
        len(cscope_tool_rows) == 1
        and cscope_tool_rows[0][2] == "cscope"
        and HEX_64.fullmatch(cscope_tool_rows[0][3]) is not None,
        "retained cscope tool identity is invalid",
    )
    replay_global_queries(root, tool_rows, policy)
    replay_ctags_queries(root, tool_rows)
    replay_cflow_outputs(root, tool_rows, policy)
    replay_metric_outputs(root, tool_rows, policy)
    replay_cscope_queries(
        root,
        entry_map,
        root_symbols,
        retained_cscope_rows,
        cscope_tool_rows[0][3],
    )

    toolchain_columns, toolchain_rows = read_tsv(
        root / "metadata/kernel-toolchains.tsv",
        "radeon-driver-kernel-toolchains-v2",
    )
    require(
        toolchain_columns
        == [
            "kernel_release",
            "tool",
            "executable_name",
            "executable_sha256",
            "version_first_line",
            "version_output_sha256",
            "resource_directory",
            "resource_include_directory",
        ],
        "kernel toolchain columns differ",
    )
    lane_releases = {
        lane["kernel_release"] for lane in manifest["preprocessor_lanes"]
    }
    require(
        {row[0] for row in toolchain_rows} == lane_releases,
        "kernel toolchain release set differs from preprocessor lanes",
    )
    policy_lanes = {lane.release: lane for lane in policy.kernel_lanes}
    require(
        lane_releases.issubset(policy_lanes),
        "preprocessor lane release is absent from retained policy",
    )
    kernel_root_evidence = root / "metadata/kernel-build-roots"
    expected_kernel_root_files = {
        f"{release}.toml" for release in lane_releases
    } | {
        f"{release}.manifest.tsv" for release in lane_releases
    }
    observed_kernel_root_files = (
        regular_tree_files(kernel_root_evidence, "retained kernel root evidence")
        if kernel_root_evidence.exists()
        else set()
    )
    require(
        observed_kernel_root_files == expected_kernel_root_files,
        "retained kernel root evidence file set differs",
    )
    for release in lane_releases:
        lane = policy_lanes[release]
        require(
            (kernel_root_evidence / f"{release}.toml").read_bytes()
            == (root / f"producer/{lane.declaration}").read_bytes()
            and (kernel_root_evidence / f"{release}.manifest.tsv").read_bytes()
            == (root / f"producer/{lane.manifest}").read_bytes(),
            f"retained kernel root evidence differs from producer proof: {release}",
        )
    closure_root = root / "metadata/kernel-toolchain-closures"
    expected_closure_files = {
        f"{release}.toml" for release in lane_releases
    } | {
        f"{release}.manifest.tsv" for release in lane_releases
    } | {
        f"{release}.prefix-tree.tsv" for release in lane_releases
    }
    observed_closure_files = (
        regular_tree_files(closure_root, "retained kernel toolchain closure")
        if closure_root.exists()
        else set()
    )
    require(
        observed_closure_files == expected_closure_files,
        "retained kernel toolchain closure file set differs",
    )
    expected_toolchain_rows: list[list[str]] = []
    closure_entries_by_release: dict[str, list[ToolchainClosureEntry]] = {}
    for release in sorted(lane_releases):
        lane = policy_lanes[release]
        require(
            (closure_root / f"{release}.toml").read_bytes()
            == (root / f"producer/{lane.toolchain_declaration}").read_bytes()
            and (closure_root / f"{release}.manifest.tsv").read_bytes()
            == (root / f"producer/{lane.toolchain_manifest}").read_bytes()
            and (closure_root / f"{release}.prefix-tree.tsv").read_bytes()
            == (root / f"producer/{lane.toolchain_prefix_manifest}").read_bytes(),
            f"retained toolchain closure differs from producer proof: {release}",
        )
        (
            closure_declaration,
            closure_entries,
            _prefix_entries,
        ) = load_toolchain_closure(
            closure_root / f"{release}.toml",
            closure_root / f"{release}.manifest.tsv",
            closure_root / f"{release}.prefix-tree.tsv",
        )
        require(
            closure_declaration["manifest"] == lane.toolchain_manifest
            and closure_declaration["prefix_tree_manifest"]
            == lane.toolchain_prefix_manifest,
            f"retained toolchain closure path differs from policy: {release}",
        )
        closure_entries_by_release[release] = closure_entries
        expected_toolchain_rows.extend(
            [
                release,
                entry.logical_name,
                entry.logical_name,
                entry.resolved_sha256,
                entry.version_first_line,
                entry.version_output_sha256,
                (
                    "<kernel-toolchain-root>/lib/clang/22"
                    if entry.logical_name == "clang"
                    else "-"
                ),
                (
                    "<kernel-toolchain-root>/lib/clang/22/include"
                    if entry.logical_name == "clang"
                    else "-"
                ),
            ]
            for entry in closure_entries
            if entry.kind == "command"
        )
    require(
        toolchain_rows == sorted(expected_toolchain_rows),
        "kernel toolchain observations differ from retained trusted closure",
    )
    require(
        len(toolchain_rows) == len(lane_releases) * len(LLVM_KERNEL_TOOLS)
        and len({(row[0], row[1]) for row in toolchain_rows})
        == len(toolchain_rows),
        "kernel toolchain rows do not close the executable denominator",
    )
    for release in lane_releases:
        require(
            {row[1] for row in toolchain_rows if row[0] == release}
            == set(LLVM_KERNEL_TOOLS),
            f"kernel toolchain executable set differs: {release}",
        )
    require(
        all(
            len(row) == 8
            and row[2] == row[1]
            and HEX_64.fullmatch(row[3]) is not None
            and bool(row[4])
            and HEX_64.fullmatch(row[5]) is not None
            and (
                (
                    row[1] == "clang"
                    and row[6]
                    == "<kernel-toolchain-root>/lib/clang/22"
                    and row[7]
                    == "<kernel-toolchain-root>/lib/clang/22/include"
                )
                or (row[1] != "clang" and row[6:] == ["-", "-"])
            )
            for row in toolchain_rows
        ),
        "kernel toolchain identity row is invalid",
    )

    runtime_columns, runtime_rows = read_tsv(
        root / "metadata/toolchain-runtime-libraries.tsv",
        "radeon-driver-toolchain-runtime-libraries-v1",
    )
    require(
        runtime_columns
        == [
            "kernel_release",
            "command",
            "soname",
            "provider",
            "resolved_path",
            "sha256",
            "build_id",
            "package_owner",
        ],
        "toolchain runtime library columns differ",
    )
    validate_toolchain_runtime_rows(
        runtime_rows,
        lane_releases,
        closure_entries_by_release,
    )

    for database_name in GLOBAL_DATABASE_NAMES:
        database = root / "indexes/global" / database_name
        dump = root / "indexes/global" / f"{database_name}.dump.tsv"
        require(not database.exists(), f"capture retains nondeterministic GNU Global database: {database_name}")
        require(dump.is_file(), f"capture omits GNU Global dump: {database_name}")
        dump_lines = dump.read_text(encoding="utf-8").splitlines()
        require(dump_lines and all("\t" in line for line in dump_lines), f"GNU Global dump is invalid: {database_name}")
    cscope_database = root / "indexes/cscope/cscope.out"
    require(cscope_database.is_file(), "portable cscope cross reference is absent")
    require(
        not (root / "indexes/cscope/cscope.out.in").exists()
        and not (root / "indexes/cscope/cscope.out.po").exists(),
        "capture retains a nondeterministic cscope quick index",
    )
    scc_report = root / "analysis/scc.json"
    require(scc_report.is_file(), "normalized SCC report is absent")
    require(
        scc_report.read_text(encoding="utf-8") == normalized_scc_json(scc_report),
        "SCC report order is not normalized",
    )

    path_columns, path_rows = read_tsv(
        root / "analysis/contextual-path-witnesses.tsv",
        PATH_WITNESS_SCHEMA,
    )
    require(
        path_columns
        == [
            "witness_id",
            "entry",
            "terminal",
            "axis",
            "step",
            "edge_kind",
            "caller",
            "callee",
            "edge_partition",
            "edge_provenance",
            "edge_classification",
            "required_context_json",
            "semantic_limit",
        ],
        "contextual path witness columns differ",
    )
    join_columns, join_rows = read_tsv(
        root / "analysis/contextual-path-joins.tsv",
        PATH_WITNESS_JOIN_SCHEMA,
    )
    require(
        join_columns
        == [
            "witness_id",
            "join_step",
            "join_kind",
            "from_axis",
            "from_symbol",
            "to_axis",
            "to_symbol",
            "evidence_ids_json",
            "semantic_limit",
        ],
        "contextual path join columns differ",
    )
    expected_path_rows, expected_join_rows = build_contextual_path_witnesses(
        root,
        policy,
        expected_call_rows,
        write_output=False,
    )
    require(
        path_rows == [[str(value) for value in row] for row in expected_path_rows],
        "contextual path witnesses differ from offline replay",
    )
    require(
        join_rows == [[str(value) for value in row] for row in expected_join_rows],
        "contextual path joins differ from offline replay",
    )
    require(
        manifest["path_witness_count"] == len(policy.path_witnesses)
        and manifest["path_witness_edge_count"] == len(path_rows),
        "contextual path witness denominator differs",
    )
    require(
        manifest["path_witness_join_count"] == len(join_rows),
        "contextual path join denominator differs",
    )
    verify_capture_file_denominator(
        root,
        expected_capture_files(
            policy,
            source_entries,
            command_rows,
            preprocessor_rows,
            lane_releases,
        ),
    )
    require(retained_count > 20, "capture retained too few evidence files")
    return manifest


def capture_source_map(
    repository: Path,
    policy_path: Path,
    treeish: str,
    output: Path,
    kernel_roots: list[Path],
    kernel_toolchain_bins: dict[str, Path],
) -> dict[str, Any]:
    repository = resolve_repository(repository)
    require(not repository_contains(repository, output), "capture output must remain outside the repository")
    require(not output.exists(), f"capture output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    policy_absolute = policy_path if policy_path.is_absolute() else repository / policy_path
    policy_absolute = policy_absolute.resolve()
    require(repository_contains(repository, policy_absolute), "source-map policy is outside the repository")
    policy = load_policy(policy_absolute)

    git_object_format = str(
        git_output(repository, "rev-parse", "--show-object-format")
    ).strip()
    require(git_object_format == "sha1", "repository Git object format is not SHA-1")
    producer_commit = str(git_output(repository, "rev-parse", "HEAD^{commit}")).strip()
    producer_tree = str(git_output(repository, "rev-parse", "HEAD^{tree}")).strip()
    source_commit = str(git_output(repository, "rev-parse", f"{treeish}^{{commit}}")).strip()
    source_tree = str(git_output(repository, "rev-parse", f"{source_commit}^{{tree}}")).strip()
    driver_tree = str(git_output(repository, "rev-parse", f"{source_commit}:{policy.source_root}")).strip()
    require(all(HEX_40.fullmatch(value) for value in (producer_commit, producer_tree, source_commit, source_tree, driver_tree)), "Git identity is malformed")
    tracked_status = str(git_output(repository, "status", "--porcelain", "--untracked-files=no"))
    require(not tracked_status, "producer checkout has tracked changes")
    for path in producer_input_paths(policy):
        tracked = subprocess.run(
            ["git", "-C", str(repository), "cat-file", "-e", f"HEAD:{path}"],
            check=False,
            capture_output=True,
        )
        require(tracked.returncode == 0, f"producer commit does not carry {path}")

    stage = Path(tempfile.mkdtemp(prefix=".radeon-source-map-", dir=output.parent))
    try:
        retained_policy = stage / POLICY_PATH
        retained_policy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(policy_absolute, retained_policy)
        retained_producer_paths = retain_producer_inputs(stage, repository, policy)
        closure = load_source_closure(repository, source_commit, policy.source_root)
        write_bytes(stage / "source-closure.toml", closure)
        feature_policy, _feature_data = parse_top_level_toml(repository, source_commit, "policy/build-features.toml")
        write_bytes(stage / "policy/build-features.toml", feature_policy)
        upstream_content, upstream_data = parse_top_level_toml(repository, source_commit, "UPSTREAM_BASE.toml")
        write_bytes(stage / "UPSTREAM_BASE.toml", upstream_content)
        upstream_base = upstream_data.get("commit")
        require(isinstance(upstream_base, str) and HEX_40.fullmatch(upstream_base) is not None, "upstream base commit is invalid")

        write_git_file_proof(
            stage / "metadata/git-producer-proof",
            repository,
            producer_commit,
            producer_tree,
            set(retained_producer_paths),
        )
        write_git_file_proof(
            stage / "metadata/git-source-input-proof",
            repository,
            source_commit,
            source_tree,
            set(source_input_paths()),
        )

        source_root = stage / "source"
        entries = export_source(repository, source_commit, policy, source_root)
        require(
            retained_driver_tree_id(entries, policy.source_root) == driver_tree,
            "exported source does not reconstruct the source driver tree",
        )
        write_source_tree_proof(
            stage,
            repository,
            source_commit,
            source_tree,
            driver_tree,
            policy.source_root,
        )
        file_list = stage / "metadata/file-list.tsv"
        write_tsv(
            file_list,
            "radeon-driver-file-list-v1",
            ("path", "source_class", "mode", "size", "object_id", "sha256"),
            source_manifest_rows(entries),
        )
        source_list, c_list = write_source_inputs(stage, entries)
        capture_tool_versions(stage, policy)
        recorder = CommandRecorder(stage, repository, source_root)
        symbols = sorted({root for partition in policy.partitions for root in partition.roots} | {item.symbol for item in policy.hazards})
        lexical_rows = build_lexical_index(stage, source_root, source_list, entries, recorder)
        global_definitions = {
            row[1]
            for row in lexical_rows
            if row[0] == "definition"
        }
        missing_definitions = sorted(set(symbols) - global_definitions)
        require(
            not missing_definitions,
            "GNU Global does not define root or hazard symbols: "
            + ", ".join(missing_definitions),
        )
        build_ctags_index(stage, source_root, source_list, symbols, recorder, policy)
        build_cscope_index(
            stage,
            source_root,
            source_list,
            entries,
            symbols,
            recorder,
        )
        cflow_edges, _partition_edges = build_cflow_maps(stage, source_root, c_list, policy, recorder)
        entry_map = {entry.path: entry for entry in entries}
        declared_rows = verify_declared_bindings(stage, source_root, entry_map, policy)
        _extracted_rows, generated_edges = extract_callback_candidates(stage, source_root, entries, policy)
        call_rows = write_call_candidates(stage, cflow_edges, declared_rows, generated_edges)
        path_witness_rows, path_join_rows = build_contextual_path_witnesses(
            stage,
            policy,
            call_rows,
        )
        run_bounded_queries(stage, source_root, entries, policy)
        build_complexity_and_coefficients(stage, source_root, source_list, policy, recorder, cflow_edges, declared_rows)
        preprocessor_lanes = capture_preprocessor_views(
            stage,
            repository,
            source_root,
            policy,
            recorder,
            kernel_roots,
            source_commit,
            driver_tree,
            feature_policy,
            upstream_base,
            kernel_toolchain_bins,
        )
        profile_symbol_summary_rows, profile_symbol_member_rows = (
            build_profile_symbol_delta_artifacts(
                stage,
                policy,
                preprocessor_lanes,
            )
        )
        recorder.write_manifest()

        path_set = b"".join(entry.path.encode("utf-8") + b"\0" for entry in entries)
        manifest = {
            "schema": CAPTURE_SCHEMA,
            "git_object_format": git_object_format,
            "source_commit": source_commit,
            "source_tree": source_tree,
            "driver_tree": driver_tree,
            "producer_commit": producer_commit,
            "producer_tree": producer_tree,
            "source_commit_timestamp_utc": commit_timestamp_utc(repository, source_commit),
            "producer_commit_timestamp_utc": commit_timestamp_utc(
                repository,
                producer_commit,
            ),
            "policy_sha256": sha256_file(retained_policy),
            "source_closure_sha256": sha256_bytes(closure),
            "feature_policy_sha256": sha256_bytes(feature_policy),
            "source_file_count": len(entries),
            "source_byte_count": sum(entry.size for entry in entries),
            "source_path_set_sha256": sha256_bytes(path_set),
            "source_manifest_sha256": sha256_file(file_list),
            "lexical_row_count": len(lexical_rows),
            "declared_binding_count": len(declared_rows),
            "call_candidate_count": len(call_rows),
            "path_witness_count": len(policy.path_witnesses),
            "path_witness_edge_count": len(path_witness_rows),
            "path_witness_join_count": len(path_join_rows),
            "profile_symbol_comparison_count": len(profile_symbol_summary_rows),
            "profile_symbol_delta_member_count": len(profile_symbol_member_rows),
            "preprocessor_lanes": preprocessor_lanes,
            "semantic_limit": "candidate-research-graph-not-runtime-reachability",
        }
        write_text(stage / "capture-manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        verify_no_host_path_leaks(
            stage,
            (
                repository,
                stage,
                source_root,
                *kernel_roots,
                *(path.parent for path in kernel_toolchain_bins.values()),
            ),
        )
        write_hash_ledger(stage)
        verify_capture(stage)
        stage.rename(output)
        print(
            f"Radeon driver source map: {source_commit} {len(entries)} files, "
            f"{len(lexical_rows)} lexical rows, {len(call_rows)} call candidates"
        )
        return manifest
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def row_set(path: Path, schema: str) -> tuple[list[str], set[tuple[str, ...]]]:
    columns, rows = read_tsv(path, schema)
    normalized = {tuple(row) for row in rows}
    require(len(normalized) == len(rows), f"comparison input repeats rows: {path}")
    return columns, normalized


def require_comparison_output_separate(
    left: Path,
    right: Path,
    output: Path,
) -> None:
    """Keep a comparison product outside both immutable input captures."""
    resolved_output = output.resolve()
    for label, capture in (("left", left), ("right", right)):
        resolved_capture = capture.resolve()
        require(
            resolved_output != resolved_capture
            and resolved_capture not in resolved_output.parents,
            f"comparison output is inside the {label} input capture",
        )


def compare_captures(left: Path, right: Path, output: Path) -> dict[str, Any]:
    require_comparison_output_separate(left, right, output)
    left_manifest = verify_capture(left)
    right_manifest = verify_capture(right)
    require(not output.exists(), f"comparison output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".radeon-source-map-comparison-", dir=output.parent))
    try:
        file_columns, left_files = row_set(left / "metadata/file-list.tsv", "radeon-driver-file-list-v1")
        right_file_columns, right_files = row_set(right / "metadata/file-list.tsv", "radeon-driver-file-list-v1")
        require(file_columns == right_file_columns, "file-list comparison schemas differ")
        left_by_path = {row[0]: row for row in left_files}
        right_by_path = {row[0]: row for row in right_files}
        file_rows: list[tuple[Any, ...]] = []
        for path in sorted(set(left_by_path) | set(right_by_path)):
            left_row = left_by_path.get(path)
            right_row = right_by_path.get(path)
            if left_row is None:
                file_rows.append(("added", path, "", right_row[5], "", right_row[3]))
            elif right_row is None:
                file_rows.append(("removed", path, left_row[5], "", left_row[3], ""))
            elif left_row != right_row:
                file_rows.append(("changed", path, left_row[5], right_row[5], left_row[3], right_row[3]))
        write_tsv(
            stage / "file-delta.tsv",
            "radeon-driver-file-delta-v1",
            ("change", "source_path", "left_sha256", "right_sha256", "left_size", "right_size"),
            file_rows,
        )

        call_columns, left_calls = row_set(left / "analysis/call-candidates.tsv", "radeon-driver-call-candidates-v1")
        right_call_columns, right_calls = row_set(right / "analysis/call-candidates.tsv", "radeon-driver-call-candidates-v1")
        require(call_columns == right_call_columns, "call candidate comparison schemas differ")
        call_rows = [("removed", *row) for row in sorted(left_calls - right_calls)]
        call_rows.extend(("added", *row) for row in sorted(right_calls - left_calls))
        write_tsv(
            stage / "call-candidate-delta.tsv",
            "radeon-driver-call-candidate-delta-v1",
            ("change", *call_columns),
            call_rows,
        )

        binding_columns, left_bindings = row_set(left / "radeon-driver-declared-bindings.tsv", DECLARED_BINDING_SCHEMA)
        right_binding_columns, right_bindings = row_set(right / "radeon-driver-declared-bindings.tsv", DECLARED_BINDING_SCHEMA)
        require(binding_columns == right_binding_columns, "binding comparison schemas differ")
        binding_rows = [("removed", *row) for row in sorted(left_bindings - right_bindings)]
        binding_rows.extend(("added", *row) for row in sorted(right_bindings - left_bindings))
        write_tsv(
            stage / "declared-binding-delta.tsv",
            "radeon-driver-declared-binding-delta-v1",
            ("change", *binding_columns),
            binding_rows,
        )

        path_columns, left_paths = row_set(
            left / "analysis/contextual-path-witnesses.tsv",
            PATH_WITNESS_SCHEMA,
        )
        right_path_columns, right_paths = row_set(
            right / "analysis/contextual-path-witnesses.tsv",
            PATH_WITNESS_SCHEMA,
        )
        require(
            path_columns == right_path_columns,
            "contextual path witness comparison schemas differ",
        )
        path_rows = [
            ("removed", *row) for row in sorted(left_paths - right_paths)
        ]
        path_rows.extend(
            ("added", *row) for row in sorted(right_paths - left_paths)
        )
        write_tsv(
            stage / "contextual-path-witness-delta.tsv",
            "radeon-driver-contextual-path-witness-delta-v2",
            ("change", *path_columns),
            path_rows,
        )
        join_columns, left_joins = row_set(
            left / "analysis/contextual-path-joins.tsv",
            PATH_WITNESS_JOIN_SCHEMA,
        )
        right_join_columns, right_joins = row_set(
            right / "analysis/contextual-path-joins.tsv",
            PATH_WITNESS_JOIN_SCHEMA,
        )
        require(
            join_columns == right_join_columns,
            "contextual path join comparison schemas differ",
        )
        join_rows = [
            ("removed", *row) for row in sorted(left_joins - right_joins)
        ]
        join_rows.extend(
            ("added", *row) for row in sorted(right_joins - left_joins)
        )
        write_tsv(
            stage / "contextual-path-join-delta.tsv",
            "radeon-driver-contextual-path-join-delta-v1",
            ("change", *join_columns),
            join_rows,
        )

        symbol_summary_columns, left_symbol_summary = row_set(
            left / "analysis/profile-symbol-delta-summary.tsv",
            PROFILE_SYMBOL_DELTA_SUMMARY_SCHEMA,
        )
        right_symbol_summary_columns, right_symbol_summary = row_set(
            right / "analysis/profile-symbol-delta-summary.tsv",
            PROFILE_SYMBOL_DELTA_SUMMARY_SCHEMA,
        )
        require(
            symbol_summary_columns == right_symbol_summary_columns,
            "profile symbol summary comparison schemas differ",
        )
        symbol_summary_rows = [
            ("removed", *row)
            for row in sorted(left_symbol_summary - right_symbol_summary)
        ]
        symbol_summary_rows.extend(
            ("added", *row)
            for row in sorted(right_symbol_summary - left_symbol_summary)
        )
        write_tsv(
            stage / "profile-symbol-delta-summary-delta.tsv",
            "radeon-driver-profile-symbol-delta-summary-delta-v1",
            ("change", *symbol_summary_columns),
            symbol_summary_rows,
        )
        symbol_member_columns, left_symbol_members = row_set(
            left / "analysis/profile-symbol-delta-members.tsv",
            PROFILE_SYMBOL_DELTA_MEMBERS_SCHEMA,
        )
        right_symbol_member_columns, right_symbol_members = row_set(
            right / "analysis/profile-symbol-delta-members.tsv",
            PROFILE_SYMBOL_DELTA_MEMBERS_SCHEMA,
        )
        require(
            symbol_member_columns == right_symbol_member_columns,
            "profile symbol member comparison schemas differ",
        )
        symbol_member_rows = [
            ("removed", *row)
            for row in sorted(left_symbol_members - right_symbol_members)
        ]
        symbol_member_rows.extend(
            ("added", *row)
            for row in sorted(right_symbol_members - left_symbol_members)
        )
        write_tsv(
            stage / "profile-symbol-delta-member-delta.tsv",
            PROFILE_SYMBOL_DELTA_MEMBER_COMPARISON_SCHEMA,
            ("capture_change", *symbol_member_columns),
            symbol_member_rows,
        )

        coefficient_columns, left_coefficients = row_set(left / "analysis/coefficient-vectors.tsv", "radeon-driver-coefficient-vectors-v2")
        right_coefficient_columns, right_coefficients = row_set(right / "analysis/coefficient-vectors.tsv", "radeon-driver-coefficient-vectors-v2")
        require(coefficient_columns == right_coefficient_columns, "coefficient comparison schemas differ")
        coefficient_rows = [("removed", *row) for row in sorted(left_coefficients - right_coefficients)]
        coefficient_rows.extend(("added", *row) for row in sorted(right_coefficients - left_coefficients))
        write_tsv(
            stage / "coefficient-vector-delta.tsv",
            "radeon-driver-coefficient-vector-delta-v1",
            ("change", *coefficient_columns),
            coefficient_rows,
        )

        summary = {
            "schema": COMPARISON_SCHEMA,
            "left_capture_sha256": sha256_file(left / HASH_LEDGER),
            "left_source_commit": left_manifest["source_commit"],
            "right_capture_sha256": sha256_file(right / HASH_LEDGER),
            "right_source_commit": right_manifest["source_commit"],
            "file_delta_count": len(file_rows),
            "call_candidate_delta_count": len(call_rows),
            "declared_binding_delta_count": len(binding_rows),
            "path_witness_delta_count": len(path_rows),
            "path_witness_join_delta_count": len(join_rows),
            "profile_symbol_summary_delta_count": len(symbol_summary_rows),
            "profile_symbol_member_delta_count": len(symbol_member_rows),
            "coefficient_vector_delta_count": len(coefficient_rows),
            "semantic_limit": "normalized-candidate-delta-not-runtime-behavior",
        }
        write_text(stage / "comparison-manifest.json", json.dumps(summary, indent=2, sort_keys=True) + "\n")
        write_hash_ledger(stage)
        verify_hash_ledger(stage)
        stage.rename(output)
        print(
            f"Radeon source-map comparison: {len(file_rows)} files, "
            f"{len(call_rows)} call candidates, {len(binding_rows)} bindings, "
            f"{len(path_rows)} path witness rows"
        )
        return summary
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def self_test(repository: Path, policy_path: Path) -> int:
    failures = 0
    verdicts = 0

    def check(label: str, condition: bool) -> None:
        nonlocal failures, verdicts
        verdicts += 1
        if condition:
            print(f"  ok: {label}")
        else:
            print(f"  CALIBRATION FAIL: {label}", file=sys.stderr)
            failures += 1

    def rejects(label: str, function: Any) -> None:
        try:
            function()
        except SourceMapError:
            check(label, True)
        else:
            check(label, False)

    def accepts(label: str, function: Any) -> None:
        try:
            function()
        except SourceMapError:
            check(label, False)
        else:
            check(label, True)

    print("Radeon driver source-map calibration:")
    try:
        policy = load_policy(policy_path)
    except SourceMapError as exc:
        print(f"  CALIBRATION FAIL: live policy: {exc}", file=sys.stderr)
        return 1
    check(
        "live policy closes partitions, hazards, bindings, paths, and queries",
        bool(
            policy.partitions
            and policy.hazards
            and policy.bindings
            and policy.path_witnesses
            and policy.bounded_queries
        ),
    )
    toolchain_closures = []
    for lane in policy.kernel_lanes:
        (
            closure_declaration,
            closure_entries,
            prefix_entries,
        ) = load_toolchain_closure(
            repository / lane.toolchain_declaration,
            repository / lane.toolchain_manifest,
            repository / lane.toolchain_prefix_manifest,
        )
        toolchain_closures.append(
            (lane, closure_declaration, closure_entries, prefix_entries)
        )
    check(
        "toolchain policies close every command, local library, and symlink target",
        len(toolchain_closures) == len(policy.kernel_lanes)
        and all(
            declaration["manifest"] == lane.toolchain_manifest
            and declaration["prefix_tree_manifest"]
            == lane.toolchain_prefix_manifest
            and {entry.logical_name for entry in entries if entry.kind == "command"}
            == set(LLVM_KERNEL_TOOLS)
            and {entry.logical_name for entry in entries if entry.kind == "library"}
            == set(LLVM_KERNEL_LIBRARIES)
            and len(prefix_entries) == declaration["prefix_entry_count"]
            for lane, declaration, entries, prefix_entries in toolchain_closures
        ),
    )
    (
        runtime_lane,
        _runtime_declaration,
        runtime_entries,
        runtime_prefix_entries,
    ) = toolchain_closures[0]
    runtime_prefix_by_path = {
        entry.relative_path: entry for entry in runtime_prefix_entries
    }
    check(
        "toolchain prefix closes directories, regular files, and symlinks",
        len(runtime_prefix_entries) == 7174
        and sum(entry.entry_type == "directory" for entry in runtime_prefix_entries)
        == 355
        and sum(entry.entry_type == "regular" for entry in runtime_prefix_entries)
        == 6792
        and sum(entry.entry_type == "symlink" for entry in runtime_prefix_entries)
        == 27,
    )
    check(
        "toolchain prefix retains parent traversal and transitive symlinks",
        runtime_prefix_by_path["lib/bfd-plugins/LLVMgold.so"].link_target
        == "../LLVMgold.so"
        and runtime_prefix_by_path["lib/bfd-plugins/LLVMgold.so"].resolved_path
        == "lib/LLVMgold.so"
        and runtime_prefix_by_path["lib/libclang.so"].resolved_path
        == "lib/libclang.so.22.1.6",
    )
    accepts(
        "toolchain prefix comparator accepts the exact finite tree",
        lambda: require_exact_toolchain_prefix(
            runtime_prefix_entries,
            list(runtime_prefix_entries),
        ),
    )
    rejects(
        "toolchain prefix comparator rejects an unexpected executable",
        lambda: require_exact_toolchain_prefix(
            runtime_prefix_entries,
            [
                *runtime_prefix_entries,
                ToolchainPrefixEntry(
                    "bin/make",
                    "regular",
                    "0755",
                    1,
                    "0" * 64,
                    "-",
                    "-",
                    "-",
                ),
            ],
        ),
    )
    rejects(
        "toolchain prefix comparator rejects a missing resource header",
        lambda: require_exact_toolchain_prefix(
            runtime_prefix_entries,
            [
                entry
                for entry in runtime_prefix_entries
                if entry.relative_path != "lib/clang/22/include/stddef.h"
            ],
        ),
    )
    changed_prefix_entries = list(runtime_prefix_entries)
    first_regular_index = next(
        index
        for index, entry in enumerate(changed_prefix_entries)
        if entry.entry_type == "regular"
    )
    first_regular = changed_prefix_entries[first_regular_index]
    changed_prefix_entries[first_regular_index] = ToolchainPrefixEntry(
        first_regular.relative_path,
        first_regular.entry_type,
        first_regular.mode,
        first_regular.size,
        "0" * 64,
        first_regular.link_target,
        first_regular.resolved_path,
        first_regular.resolved_sha256,
    )
    rejects(
        "toolchain prefix comparator rejects a changed file identity",
        lambda: require_exact_toolchain_prefix(
            runtime_prefix_entries,
            changed_prefix_entries,
        ),
    )
    runtime_fixture_rows: list[tuple[Any, ...]] = [
        (
            runtime_lane.release,
            tool,
            "linux-vdso.so.1",
            "kernel-virtual",
            "<kernel-virtual>",
            "-",
            "-",
            "kernel",
        )
        for tool in LLVM_KERNEL_TOOLS
    ]
    runtime_fixture_rows.extend(
        (
            runtime_lane.release,
            LLVM_KERNEL_TOOLS[0],
            entry.logical_name,
            "toolchain-pinned",
            f"<kernel-toolchain-root>/{entry.relative_path}",
            entry.resolved_sha256,
            "a" * 40,
            "toolchain-closure-declaration",
        )
        for entry in runtime_entries
        if entry.kind == "library"
    )
    runtime_fixture_rows.sort()
    accepts(
        "toolchain runtime validator closes commands and pinned libraries",
        lambda: validate_toolchain_runtime_rows(
            runtime_fixture_rows,
            {runtime_lane.release},
            {runtime_lane.release: runtime_entries},
        ),
    )
    forged_runtime_rows = list(runtime_fixture_rows)
    forged_runtime_rows[0] = (
        *forged_runtime_rows[0][:5],
        "0" * 64,
        *forged_runtime_rows[0][6:],
    )
    forged_runtime_rows.sort()
    rejects(
        "toolchain runtime validator rejects a changed library identity",
        lambda: validate_toolchain_runtime_rows(
            forged_runtime_rows,
            {runtime_lane.release},
            {runtime_lane.release: runtime_entries},
        ),
    )
    check(
        "ELF SONAME normalizes an absolute dynamic linker alias",
        normalize_runtime_library_soname(
            "/lib64/ld-linux-x86-64.so.2",
            "0x000000000000000e (SONAME) Library soname: "
            "[ld-linux-x86-64.so.2]\n",
        )
        == "ld-linux-x86-64.so.2",
    )
    check(
        "ldd parser accepts a direct absolute dynamic loader row",
        parse_ldd_runtime_row(
            "/usr/lib/ld-linux-x86-64.so.2 (0x00007f0000000000)"
        )
        == (
            "/usr/lib/ld-linux-x86-64.so.2",
            "/usr/lib/ld-linux-x86-64.so.2",
        ),
    )
    rejects(
        "ldd parser rejects a relative direct dependency row",
        lambda: parse_ldd_runtime_row(
            "ld-linux-x86-64.so.2 (0x00007f0000000000)"
        ),
    )
    rejects(
        "ldd parser rejects an unresolved dependency",
        lambda: parse_ldd_runtime_row("libmissing.so.1 => not found"),
    )
    rejects(
        "ELF SONAME rejects a mismatched loader name",
        lambda: normalize_runtime_library_soname(
            "libforged.so.1",
            "0x000000000000000e (SONAME) Library soname: "
            "[libactual.so.1]\n",
        ),
    )
    release_paths = parse_release_paths(
        ["6.18.38-2-cachyos-lts=/tmp/llvm-22.1.6/usr/bin"]
    )
    check(
        "release path parser binds one exact kernel to one toolchain",
        set(release_paths) == {"6.18.38-2-cachyos-lts"}
        and release_paths["6.18.38-2-cachyos-lts"]
        == Path("/tmp/llvm-22.1.6/usr/bin"),
    )
    rejects(
        "release path parser rejects a duplicate kernel",
        lambda: parse_release_paths(
            [
                "kernel=/tmp/toolchain-a",
                "kernel=/tmp/toolchain-b",
            ]
        ),
    )
    rejects(
        "release path parser rejects a missing path",
        lambda: parse_release_paths(["kernel="]),
    )

    check(
        "module symbol canonicalizer strips only a terminal LLVM suffix",
        parse_module_symbol_map(
            b"feature.llvm.17 T 0 1\n",
            "terminal-suffix",
        )
        == {"feature": "feature.llvm.17"},
    )
    check(
        "module symbol canonicalizer preserves a nonterminal LLVM substring",
        parse_module_symbol_map(
            b"feature.llvm.17.extra T 0 1\n",
            "nonterminal-suffix",
        )
        == {"feature.llvm.17.extra": "feature.llvm.17.extra"},
    )
    check(
        "module symbol canonicalizer preserves the compiler prefix",
        parse_module_symbol_map(
            b"__pfx_feature T 0 1\n",
            "compiler-prefix",
        )
        == {"__pfx_feature": "__pfx_feature"},
    )
    rejects(
        "module symbol parser rejects a malformed row",
        lambda: parse_module_symbol_map(b"feature T 0\n", "malformed"),
    )
    rejects(
        "module symbol parser rejects a duplicate raw name",
        lambda: parse_module_symbol_map(
            b"feature T 0 1\nfeature T 1 1\n",
            "duplicate-raw",
        ),
    )
    rejects(
        "module symbol canonicalizer rejects a suffix collision",
        lambda: parse_module_symbol_map(
            b"feature T 0 1\nfeature.llvm.17 T 1 1\n",
            "canonical-collision",
        ),
    )

    synthetic_kernel_lanes = (
        KernelLane("kernel-a", "", "", "", "", "", ("prod", "mutate-dev")),
        KernelLane(
            "kernel-b",
            "",
            "",
            "",
            "",
            "",
            ("prod", "observe-dev", "probe-dev", "mutate-dev"),
        ),
    )

    def synthetic_symbol_content(names: tuple[str, ...]) -> bytes:
        return "".join(
            f"{name} T {index:x} 1\n" for index, name in enumerate(names)
        ).encode("ascii")

    synthetic_symbol_bytes = {
        ("kernel-a", "prod"): synthetic_symbol_content(("base.llvm.1",)),
        ("kernel-a", "mutate-dev"): synthetic_symbol_content(
            (
                "base.llvm.2",
                "observe_symbol.llvm.2",
                "probe_symbol.llvm.2",
                "mutate_symbol.llvm.2",
            )
        ),
        ("kernel-b", "prod"): synthetic_symbol_content(("base.llvm.3",)),
        ("kernel-b", "observe-dev"): synthetic_symbol_content(
            ("base.llvm.4", "observe_symbol.llvm.4")
        ),
        ("kernel-b", "probe-dev"): synthetic_symbol_content(
            (
                "base.llvm.5",
                "observe_symbol.llvm.5",
                "probe_symbol.llvm.5",
            )
        ),
        ("kernel-b", "mutate-dev"): synthetic_symbol_content(
            (
                "base.llvm.6",
                "observe_symbol.llvm.6",
                "probe_symbol.llvm.6",
                "mutate_symbol.llvm.6",
            )
        ),
    }
    synthetic_symbol_maps = {
        key: parse_module_symbol_map(content, "/".join(key))
        for key, content in synthetic_symbol_bytes.items()
    }
    synthetic_summary, synthetic_members = derive_profile_symbol_delta_rows(
        synthetic_kernel_lanes,
        synthetic_symbol_maps,
    )
    check(
        "profile symbol derivation closes every ordered profile pair",
        len(synthetic_summary) == 7
        and len(synthetic_members) == 13
        and all(row[6] == 0 for row in synthetic_summary),
    )
    removed_symbol_maps = {
        key: dict(symbol_map)
        for key, symbol_map in synthetic_symbol_maps.items()
    }
    del removed_symbol_maps[("kernel-b", "mutate-dev")]["base"]
    rejects(
        "profile symbol derivation rejects a removed canonical member",
        lambda: derive_profile_symbol_delta_rows(
            synthetic_kernel_lanes,
            removed_symbol_maps,
        ),
    )
    foreign_symbol_maps = {
        key: dict(symbol_map)
        for key, symbol_map in synthetic_symbol_maps.items()
    }
    foreign_symbol_maps[("kernel-a", "mutate-dev")]["foreign_symbol"] = (
        "foreign_symbol.llvm.1"
    )
    rejects(
        "profile symbol derivation rejects cross-kernel delta drift",
        lambda: derive_profile_symbol_delta_rows(
            synthetic_kernel_lanes,
            foreign_symbol_maps,
        ),
    )

    synthetic_policy = Policy(
        **{
            **policy.__dict__,
            "kernel_lanes": synthetic_kernel_lanes,
        }
    )
    with tempfile.TemporaryDirectory(prefix="radeon-symbol-delta-selftest-") as name:
        symbol_root = Path(name)
        synthetic_lane_rows: list[dict[str, Any]] = []
        for (release, profile), content in synthetic_symbol_bytes.items():
            output = (
                symbol_root
                / "preprocessed"
                / release
                / profile
                / "module-defined-symbols.txt"
            )
            write_bytes(output, content)
            synthetic_lane_rows.append(
                {
                    "kernel_release": release,
                    "profile": profile,
                    "defined_symbol_count": len(content.splitlines()),
                    "defined_symbols_sha256": sha256_bytes(content),
                }
            )
        build_profile_symbol_delta_artifacts(
            symbol_root,
            synthetic_policy,
            synthetic_lane_rows,
        )
        accepts(
            "profile symbol artifacts replay from raw maps",
            lambda: verify_profile_symbol_delta_artifacts(
                symbol_root,
                synthetic_policy,
                synthetic_lane_rows,
            ),
        )
        summary_path = symbol_root / "analysis/profile-symbol-delta-summary.tsv"
        summary_columns, summary_fixture_rows = read_tsv(
            summary_path,
            PROFILE_SYMBOL_DELTA_SUMMARY_SCHEMA,
        )
        forged_summary_rows = [list(row) for row in summary_fixture_rows]
        forged_summary_rows[0][5] = str(int(forged_summary_rows[0][5]) + 1)
        write_tsv(
            summary_path,
            PROFILE_SYMBOL_DELTA_SUMMARY_SCHEMA,
            tuple(summary_columns),
            [tuple(row) for row in forged_summary_rows],
        )
        rejects(
            "profile symbol verifier rejects a forged summary count",
            lambda: verify_profile_symbol_delta_artifacts(
                symbol_root,
                synthetic_policy,
                synthetic_lane_rows,
            ),
        )
        build_profile_symbol_delta_artifacts(
            symbol_root,
            synthetic_policy,
            synthetic_lane_rows,
        )
        member_path = symbol_root / "analysis/profile-symbol-delta-members.tsv"
        member_columns, member_fixture_rows = read_tsv(
            member_path,
            PROFILE_SYMBOL_DELTA_MEMBERS_SCHEMA,
        )
        write_tsv(
            member_path,
            PROFILE_SYMBOL_DELTA_MEMBERS_SCHEMA,
            tuple(member_columns),
            [tuple(row) for row in member_fixture_rows[1:]],
        )
        rejects(
            "profile symbol verifier rejects a deleted member row",
            lambda: verify_profile_symbol_delta_artifacts(
                symbol_root,
                synthetic_policy,
                synthetic_lane_rows,
            ),
        )
        build_profile_symbol_delta_artifacts(
            symbol_root,
            synthetic_policy,
            synthetic_lane_rows,
        )
        member_columns, member_fixture_rows = read_tsv(
            member_path,
            PROFILE_SYMBOL_DELTA_MEMBERS_SCHEMA,
        )
        forged_member_rows = [list(row) for row in member_fixture_rows]
        forged_member_rows[0][4] += "_forged"
        write_tsv(
            member_path,
            PROFILE_SYMBOL_DELTA_MEMBERS_SCHEMA,
            tuple(member_columns),
            [tuple(row) for row in forged_member_rows],
        )
        rejects(
            "profile symbol verifier rejects a forged member row",
            lambda: verify_profile_symbol_delta_artifacts(
                symbol_root,
                synthetic_policy,
                synthetic_lane_rows,
            ),
        )

    synthetic_cflow = (
        "    1 {   0} root: int (void), <root.c 1>\n"
        "    2 {   1}     child: void (void), <child.c 2>\n"
        "    3 {   2}         external_call: <>\n"
        "    4 {   1}     child: 2\n"
    ).encode("ascii")
    expected_edges = [("child", "external_call", "external"), ("root", "child", "driver")]
    check("cflow depth parser emits stable unique edges", parse_cflow_edges(synthetic_cflow) == expected_edges)
    rejects("cflow depth parser rejects a skipped parent", lambda: parse_cflow_edges(b"1 { 2} orphan: <>\n"))
    rejects("cflow parser rejects a nonidentifier", lambda: parse_cflow_edges(b"1 { 0} bad-name: <>\n"))

    synthetic_source = (
        'static const struct sample owner = {\n'
        '    .member = &target,\n'
        '};\n'
        'const char *literal = "// .member = wrong,";\n'
        '/* .member = wrong, */\n'
        'DEFINE_SHOW_ATTRIBUTE(sample);\n'
        'DRM_IOCTL_DEF_DRV(TEST, ioctl_target, FLAGS);\n'
        'INIT_WORK(&work, work_target);\n'
    )
    binding = Binding(
        "synthetic-binding",
        policy.partitions[0].name,
        "callback-table",
        "brace",
        "owner",
        "target",
        "drivers/gpu/drm/radeon/test.c",
        r"(?s)static const struct sample owner = \{.*?\.member = &?target",
        1,
        False,
    )
    check("binding lexer accepts one real target and ignores comment and string decoys", len(binding_matches(synthetic_source, binding)) == 1)
    changed = Binding(**{**binding.__dict__, "pattern": binding.pattern.replace("target", "wrong")})
    check("binding lexer rejects decoy-only targets", len(binding_matches(synthetic_source, changed)) == 0)
    crossed_initializer = (
        "static const struct sample owner = {\n"
        "    .member = NULL,\n"
        "};\n"
        "static const struct sample decoy = {\n"
        "    .member = target,\n"
        "};\n"
    )
    check(
        "initializer binding cannot cross from its owner into a decoy initializer",
        len(binding_matches(crossed_initializer, binding)) == 0,
    )
    reset_binding = Binding(
        "synthetic-reset-request",
        policy.partitions[0].name,
        "reset-request",
        "brace",
        "reset_owner",
        "target_reset",
        "drivers/gpu/drm/radeon/test.c",
        r"(?s)static int reset_owner\(void\)\s*\{.*?target_reset\(\);",
        1,
        False,
    )
    crossed_function = (
        "static int reset_owner(void)\n"
        "{\n"
        "    return 0;\n"
        "}\n"
        "static int decoy_reset(void)\n"
        "{\n"
        "    target_reset();\n"
        "    return 0;\n"
        "}\n"
    )
    check(
        "function-scoped binding cannot cross from its owner into a decoy function",
        len(binding_matches(crossed_function, reset_binding)) == 0,
    )
    path_candidates = [
        (
            "lexical",
            "entry",
            "callback_slot",
            "full-tree",
            "gnu-cflow",
            "driver",
        ),
        (
            "declared-indirect",
            "family",
            "callback_target",
            binding.partition,
            binding.name,
            "callback-table",
        ),
    ]
    synthetic_declared_row = (
        binding.name,
        binding.kind,
        binding.partition,
        binding.path,
        1,
        binding.caller,
        binding.callee,
        "a" * 64,
        "b" * 64,
        "policy-declared",
        binding.scope,
    )
    expected_synthetic_calls = write_call_candidates(
        Path("."),
        [("entry", "callback_slot", "driver")],
        [synthetic_declared_row],
        [],
        write_output=False,
    )
    accepts(
        "call candidate replay accepts raw and declared evidence",
        lambda: verify_call_candidate_rows(
            expected_synthetic_calls,
            [("entry", "callback_slot", "driver")],
            [synthetic_declared_row],
            [],
        ),
    )
    rejects(
        "call candidate replay rejects a forged lexical witness edge",
        lambda: verify_call_candidate_rows(
            [
                *expected_synthetic_calls,
                (
                    "lexical",
                    "forged_caller",
                    "forged_callee",
                    "full-tree",
                    "gnu-cflow",
                    "driver",
                ),
            ],
            [("entry", "callback_slot", "driver")],
            [synthetic_declared_row],
            [],
        ),
    )
    path_witness = PathWitness(
        "contextual-callback-path",
        "entry",
        "callback_target",
        ("The path requires the synthetic family target.",),
        (
            PathWitnessEdge(
                "execution",
                *path_candidates[0],
            ),
            PathWitnessEdge(
                "family-selection",
                *path_candidates[1],
            ),
        ),
        (
            PathWitnessJoin(
                "callback-selection",
                "execution",
                "callback_slot",
                "family-selection",
                "family",
                (binding.name,),
            ),
        ),
    )
    path_policy = Policy(
        **{
            **policy.__dict__,
            "bindings": (*policy.bindings, binding),
            "path_witnesses": (path_witness,),
        }
    )
    accepts(
        "contextual path witness accepts exact ordered axes",
        lambda: build_contextual_path_witnesses(
            Path("."),
            path_policy,
            path_candidates,
            write_output=False,
        ),
    )
    rejects(
        "contextual path witness rejects a missing candidate edge",
        lambda: build_contextual_path_witnesses(
            Path("."),
            path_policy,
            path_candidates[:1],
            write_output=False,
        ),
    )
    rejects(
        "contextual path witness rejects duplicate candidate evidence",
        lambda: build_contextual_path_witnesses(
            Path("."),
            path_policy,
            [*path_candidates, path_candidates[0]],
            write_output=False,
        ),
    )
    discontinuous_witness = PathWitness(
        "discontinuous-callback-path",
        path_witness.entry,
        "different_target",
        path_witness.context,
        (
            path_witness.edges[0],
            PathWitnessEdge(
                "execution",
                "lexical",
                "different_caller",
                "different_target",
                "full-tree",
                "gnu-cflow",
                "driver",
            ),
        ),
        (),
    )
    rejects(
        "contextual path witness rejects a discontinuous axis",
        lambda: validate_path_witness_shape(
            discontinuous_witness,
            "discontinuous fixture",
        ),
    )
    rejects(
        "contextual path witness rejects a wrong entry",
        lambda: validate_path_witness_shape(
            PathWitness(
                path_witness.name,
                "wrong_entry",
                path_witness.terminal,
                path_witness.context,
                path_witness.edges,
                path_witness.joins,
            ),
            "wrong entry fixture",
            {binding.name: binding},
        ),
    )
    rejects(
        "contextual path witness rejects a wrong terminal",
        lambda: validate_path_witness_shape(
            PathWitness(
                path_witness.name,
                path_witness.entry,
                "wrong_terminal",
                path_witness.context,
                path_witness.edges,
                path_witness.joins,
            ),
            "wrong terminal fixture",
            {binding.name: binding},
        ),
    )
    rejects(
        "contextual path witness rejects a free axis without a join",
        lambda: validate_path_witness_shape(
            PathWitness(
                path_witness.name,
                path_witness.entry,
                path_witness.terminal,
                path_witness.context,
                path_witness.edges,
                (),
            ),
            "missing join fixture",
            {binding.name: binding},
        ),
    )
    wrong_endpoint_join = PathWitnessJoin(
        "callback-selection",
        "execution",
        "wrong_slot",
        "family-selection",
        "family",
        (binding.name,),
    )
    rejects(
        "contextual path witness rejects a wrong join endpoint",
        lambda: validate_path_witness_shape(
            PathWitness(
                path_witness.name,
                path_witness.entry,
                path_witness.terminal,
                path_witness.context,
                path_witness.edges,
                (wrong_endpoint_join,),
            ),
            "wrong join endpoint fixture",
            {binding.name: binding},
        ),
    )
    same_axis_join = PathWitnessJoin(
        "debugfs-read-event",
        "execution",
        "callback_slot",
        "execution",
        "entry",
        (binding.name,),
    )
    rejects(
        "contextual path witness rejects registration and event axis conflation",
        lambda: validate_path_witness_shape(
            PathWitness(
                path_witness.name,
                path_witness.entry,
                path_witness.terminal,
                path_witness.context,
                path_witness.edges,
                (same_axis_join,),
            ),
            "same axis event fixture",
            {binding.name: binding},
        ),
    )
    returning_axis_witness = PathWitness(
        "returning-axis-path",
        "entry",
        "final_target",
        path_witness.context,
        (
            path_witness.edges[0],
            path_witness.edges[1],
            PathWitnessEdge(
                "execution",
                "lexical",
                "callback_target",
                "final_target",
                "full-tree",
                "gnu-cflow",
                "driver",
            ),
        ),
        path_witness.joins,
    )
    rejects(
        "contextual path witness rejects an axis A-B-A return",
        lambda: validate_path_witness_shape(
            returning_axis_witness,
            "returning axis fixture",
            {binding.name: binding},
        ),
    )
    rejects(
        "contextual path witness rejects missing context",
        lambda: validate_path_witness_shape(
            PathWitness(
                path_witness.name,
                path_witness.entry,
                path_witness.terminal,
                (),
                path_witness.edges,
                path_witness.joins,
            ),
            "missing context fixture",
            {binding.name: binding},
        ),
    )
    rejects(
        "contextual path witness rejects duplicate context",
        lambda: validate_path_witness_shape(
            PathWitness(
                path_witness.name,
                path_witness.entry,
                path_witness.terminal,
                (*path_witness.context, *path_witness.context),
                path_witness.edges,
                path_witness.joins,
            ),
            "duplicate context fixture",
            {binding.name: binding},
        ),
    )
    truncated_required_witnesses = [
        PathWitness(
            witness.name,
            witness.entry,
            (
                "evergreen_gpu_pci_config_reset_safe"
                if witness.name == "palm-debugfs-pci-config-reset"
                else witness.terminal
            ),
            witness.context,
            witness.edges,
            witness.joins,
        )
        for witness in policy.path_witnesses
    ]
    rejects(
        "required Palm path rejects a terminal before radeon_pci_config_reset",
        lambda: validate_required_path_witnesses(truncated_required_witnesses),
    )
    tricky = (
        'const char *a = "/*"; .member = target,\n'
        'const char *b = "//"; .other = next,\n'
    )
    check(
        "combined lexer preserves code after comment tokens inside strings",
        ".member = target" in strip_comments_and_literals(tricky)
        and ".other = next" in strip_comments_and_literals(tricky),
    )
    spliced = (
        "REA\\\nD_ONCE(real_guard);\n"
        "// continued comment \\\n"
        "if (commented_guard) \\\n"
        "return;\n"
        "next_statement();\n"
    )
    spliced_code = strip_comments_and_literals(spliced)
    check(
        "combined lexer applies C line splicing before comment removal",
        "READ_ONCE(real_guard)" in spliced_code
        and "commented_guard" not in spliced_code
        and "next_statement" in spliced_code,
    )
    spliced_binding_source = (
        "REA\\\nD_ONCE(real_guard);\n"
        ".member = target,\n"
    )
    spliced_binding_code = strip_comments_and_literals(spliced_binding_source)
    spliced_binding_match = FIELD_INITIALIZER.search(spliced_binding_code)
    check(
        "phase-2 offsets retain physical lines and logical match identities",
        spliced_binding_match is not None
        and physical_line_after_splicing(
            spliced_binding_source,
            spliced_binding_match.start(),
        )
        == 3
        and sha256_bytes(
            " ".join(spliced_binding_match.group(0).split()).encode("ascii")
        )
        == sha256_bytes(b".member = target,"),
    )
    guard_fixture = 'if (real_guard) return; /* comment_guard */ const char *text = "literal_guard";\n'
    check(
        "guard identifier census accepts code identifiers and rejects prose decoys",
        missing_code_identifiers(
            guard_fixture,
            ("real_guard", "comment_guard", "literal_guard"),
        )
        == ["comment_guard", "literal_guard"],
    )
    check("callback extractor sees field, show, ioctl, and work forms", bool(FIELD_INITIALIZER.search(strip_comments_and_literals(synthetic_source)) and DEFINE_SHOW.search(strip_comments_and_literals(synthetic_source)) and DRM_IOCTL.search(strip_comments_and_literals(synthetic_source)) and WORK_BINDING.search(strip_comments_and_literals(synthetic_source))))

    object_id = "1" * 40
    raw_tree = (
        f"100644 blob {object_id} 10\tdrivers/gpu/drm/radeon/a.c\0"
        f"100644 blob {object_id} 12\tdrivers/gpu/drm/radeon/a.h\0"
        f"100644 blob {object_id} 8\tdrivers/gpu/drm/radeon/Makefile\0"
        f"100644 blob {object_id} 5\tdrivers/gpu/drm/radeon/.gitignore\0"
    ).encode("ascii")
    parsed = parse_ls_tree(raw_tree, policy)
    check("tracked denominator parser retains regular source and repository metadata", len(parsed) == 4)
    rejects(
        "tracked denominator rejects a symlink",
        lambda: parse_ls_tree(f"120000 blob {object_id} 3\tdrivers/gpu/drm/radeon/link.c\0".encode("ascii"), policy),
    )
    rejects(
        "tracked denominator rejects traversal",
        lambda: parse_ls_tree(f"100644 blob {object_id} 3\tdrivers/gpu/drm/radeon/../x.c\0".encode("ascii"), policy),
    )
    rejects(
        "source classifier rejects an unknown tracked class",
        lambda: source_class(policy, f"{policy.source_root}/unknown.bin"),
    )
    check(
        "source classifier retains repository metadata outside analyzer inputs",
        source_class(policy, f"{policy.source_root}/.gitignore")
        == "repository-metadata",
    )

    alpha = b"alpha\n"
    beta = b"beta\n"
    alpha_id = "4a58007052a65fbc2fc3f910f2855f45a4058e74"
    beta_id = "65b2df87f7df3aeedef04be96703e55ac19c2cfb"
    check(
        "Git blob identity reproduces the SHA-1 object format",
        git_object_id("blob", alpha) == alpha_id
        and git_object_id("blob", beta) == beta_id,
    )
    synthetic_entries = [
        SourceEntry("root/a.txt", "100644", alpha_id, len(alpha), sha256_bytes(alpha), "test"),
        SourceEntry("root/dir/b.txt", "100755", beta_id, len(beta), sha256_bytes(beta), "test"),
    ]
    check(
        "retained files reconstruct the canonical nested Git tree",
        retained_driver_tree_id(synthetic_entries, "root")
        == "a067b33102fdbd9476046679567d3c9e736a1b0e",
    )
    forged_entries = [
        SourceEntry("root/a.txt", "100644", beta_id, len(alpha), sha256_bytes(alpha), "test"),
        synthetic_entries[1],
    ]
    check(
        "a forged blob identity changes the reconstructed Git tree",
        retained_driver_tree_id(forged_entries, "root")
        != "a067b33102fdbd9476046679567d3c9e736a1b0e",
    )

    entry = SourceEntry(f"{policy.source_root}/a.c", "100644", object_id, 10, "2" * 64, "c")
    good_global = f"address_taken 1 {entry.path} &address_taken\ndirect_call 1 {entry.path} direct_call()\n".encode("ascii")
    parsed_global = parse_global_rows(good_global, "reference", {entry.path: entry})
    check("address-taken and direct-call uses remain lexical references", len(parsed_global) == 2 and all(row[0] == "reference" for row in parsed_global))
    rejects("GNU Global parser rejects malformed output", lambda: parse_global_rows(b"short row\n", "definition", {entry.path: entry}))
    rejects("GNU Global parser rejects a foreign path", lambda: parse_global_rows(b"symbol 1 foreign.c text\n", "definition", {entry.path: entry}))
    rejects("GNU Global parser rejects an invalid identifier", lambda: parse_global_rows(f"bad-name 1 {entry.path} text\n".encode(), "definition", {entry.path: entry}))
    rejects("GNU Global parser rejects a zero line", lambda: parse_global_rows(f"symbol 0 {entry.path} text\n".encode(), "definition", {entry.path: entry}))

    command_columns = [
        "command_id",
        "tool",
        "cwd",
        "status",
        "stdout_path",
        "stderr_path",
        "argv_json",
        "environment_json",
    ]
    expected_source_commands = expected_command_records(policy, [entry], set())
    check(
        "source command contract closes the analyzer command denominator",
        len(expected_source_commands) == 156,
    )
    expected_kernel_commands = expected_command_records(
        policy,
        [entry],
        {lane.release for lane in policy.kernel_lanes},
    )
    expected_make_commands = [
        row for row in expected_kernel_commands if row[1] == "make"
    ]
    check(
        "kernel command contract pins host make, shell, and LLVM prefix",
        len(expected_kernel_commands) == 176
        and len(expected_make_commands) == 12
        and all(
            (arguments := json.loads(row[6]))[0] == "/usr/bin/make"
            and any(
                argument == "LLVM=<kernel-toolchain-root>/bin/"
                for argument in arguments
            )
            and "LLVM=1" not in arguments
            and "SHELL=/usr/bin/sh" in arguments
            and "CONFIG_SHELL=/usr/bin/sh" in arguments
            and json.loads(row[7])["PATH"] == "/usr/bin:/bin"
            for row in expected_make_commands
        ),
    )
    canonical_make_row = expected_make_commands[0]
    bare_make_row = list(canonical_make_row)
    bare_make_arguments = json.loads(bare_make_row[6])
    bare_make_arguments[0] = "make"
    bare_make_row[6] = json.dumps(bare_make_arguments, separators=(",", ":"))
    rejects(
        "kernel command contract rejects bare make",
        lambda: verify_command_records(
            command_columns,
            [bare_make_row],
            [canonical_make_row],
        ),
    )
    implicit_llvm_row = list(canonical_make_row)
    implicit_llvm_arguments = json.loads(implicit_llvm_row[6])
    implicit_llvm_arguments = [
        "LLVM=1" if argument.startswith("LLVM=") else argument
        for argument in implicit_llvm_arguments
    ]
    implicit_llvm_row[6] = json.dumps(
        implicit_llvm_arguments,
        separators=(",", ":"),
    )
    rejects(
        "kernel command contract rejects implicit LLVM discovery",
        lambda: verify_command_records(
            command_columns,
            [implicit_llvm_row],
            [canonical_make_row],
        ),
    )
    prefix_path_row = list(canonical_make_row)
    prefix_path_environment = json.loads(prefix_path_row[7])
    prefix_path_environment["PATH"] = (
        "<kernel-toolchain-root>/bin:/usr/bin:/bin"
    )
    prefix_path_row[7] = json.dumps(
        dict(sorted(prefix_path_environment.items())),
        separators=(",", ":"),
    )
    rejects(
        "kernel command contract rejects a toolchain-prefixed PATH",
        lambda: verify_command_records(
            command_columns,
            [prefix_path_row],
            [canonical_make_row],
        ),
    )
    accepts(
        "command verifier accepts the exact producer-derived rows",
        lambda: verify_command_records(
            command_columns,
            [list(row) for row in expected_source_commands],
            expected_source_commands,
        ),
    )
    forged_command = [
        "forged-success",
        "true",
        "<source-root>",
        "0",
        "",
        "",
        "[]",
        "{}",
    ]
    rejects(
        "command verifier rejects one forged success row",
        lambda: verify_command_records(
            command_columns,
            [forged_command],
            expected_source_commands,
        ),
    )
    duplicated_commands = [list(row) for row in expected_source_commands]
    duplicated_commands.append(list(expected_source_commands[0]))
    rejects(
        "command verifier rejects a duplicate command ID",
        lambda: verify_command_records(
            command_columns,
            duplicated_commands,
            expected_source_commands,
        ),
    )
    omitted_commands = [
        list(row)
        for row in expected_source_commands
        if row[0] != "cscope-definition-main"
    ]
    rejects(
        "command verifier rejects an omitted cscope command",
        lambda: verify_command_records(
            command_columns,
            omitted_commands,
            expected_source_commands,
        ),
    )
    swapped_outputs = [list(row) for row in expected_source_commands]
    swapped_outputs[0][4], swapped_outputs[1][4] = (
        swapped_outputs[1][4],
        swapped_outputs[0][4],
    )
    rejects(
        "command verifier rejects swapped stdout ownership",
        lambda: verify_command_records(
            command_columns,
            swapped_outputs,
            expected_source_commands,
        ),
    )
    wrong_tool = [list(row) for row in expected_source_commands]
    wrong_tool[0][1] = "true"
    rejects(
        "command verifier rejects a mismatched tool",
        lambda: verify_command_records(
            command_columns,
            wrong_tool,
            expected_source_commands,
        ),
    )

    with tempfile.TemporaryDirectory(prefix="radeon-source-map-selftest-") as temporary:
        temp = Path(temporary)
        bounded_reader_path = temp / "bounded-reader"
        bounded_reader_content = b"x" * 32
        write_bytes(bounded_reader_path, bounded_reader_content)
        original_path_read_bytes = Path.read_bytes

        def grow_file_on_path_reopen(candidate: Path) -> bytes:
            if candidate == bounded_reader_path:
                write_bytes(candidate, bounded_reader_content + b"x")
            return original_path_read_bytes(candidate)

        with mock.patch.object(Path, "read_bytes", grow_file_on_path_reopen):
            bounded_result = read_bounded_file(
                bounded_reader_path,
                len(bounded_reader_content),
                "bounded reader fixture",
            )
        check(
            "bounded reader retains one no-follow file descriptor",
            bounded_result == bounded_reader_content
            and bounded_reader_path.stat().st_size == len(bounded_reader_content),
        )
        original_os_open = os.open
        observed_open_flags = 0

        def record_bounded_open_flags(path: Path, flags: int) -> int:
            nonlocal observed_open_flags
            observed_open_flags = flags
            return original_os_open(path, flags)

        with mock.patch.object(os, "open", record_bounded_open_flags):
            read_bounded_file(
                bounded_reader_path,
                len(bounded_reader_content),
                "bounded reader flag fixture",
            )
        check(
            "bounded reader opens special files without blocking or terminals",
            bool(observed_open_flags & os.O_NONBLOCK)
            and bool(observed_open_flags & os.O_NOCTTY)
            and bool(observed_open_flags & os.O_NOFOLLOW),
        )

        class DuplicateColumnsWithoutCount(list[str]):
            def count(self, value: str) -> int:
                raise AssertionError(f"quadratic count invoked for {value}")

        duplicate_writer_path = temp / "duplicate-writer.tsv"
        rejects(
            "TSV writer rejects duplicate column names",
            lambda: write_tsv(
                duplicate_writer_path,
                "duplicate-column-fixture-v1",
                DuplicateColumnsWithoutCount(["change", "change"]),
                [],
            ),
        )
        check(
            "rejected duplicate TSV is not written",
            not duplicate_writer_path.exists(),
        )
        duplicate_reader_path = temp / "duplicate-reader.tsv"
        write_text(
            duplicate_reader_path,
            "# schema: duplicate-column-fixture-v1\nchange\tchange\n",
        )
        rejects(
            "TSV reader rejects duplicate column names",
            lambda: read_tsv(
                duplicate_reader_path,
                "duplicate-column-fixture-v1",
            ),
        )
        comparison_left = temp / "comparison-left"
        comparison_right = temp / "comparison-right"
        comparison_left.mkdir()
        comparison_right.mkdir()
        accepts(
            "comparison output accepts a sibling of both inputs",
            lambda: require_comparison_output_separate(
                comparison_left,
                comparison_right,
                temp / "comparison-output",
            ),
        )

        def compare_rejects_without_output(
            label: str,
            output: Path,
            expected_message: str,
        ) -> None:
            try:
                compare_captures(comparison_left, comparison_right, output)
            except SourceMapError as exc:
                check(
                    label,
                    str(exc) == expected_message and not output.parent.exists(),
                )
            else:
                check(label, False)

        compare_rejects_without_output(
            "comparison rejects a left descendant before input verification",
            comparison_left / "nested" / "comparison-output",
            "comparison output is inside the left input capture",
        )
        compare_rejects_without_output(
            "comparison rejects a right descendant before input verification",
            comparison_right / "nested" / "comparison-output",
            "comparison output is inside the right input capture",
        )
        comparison_left_alias = temp / "comparison-left-alias"
        comparison_left_alias.symlink_to(comparison_left, target_is_directory=True)
        rejects(
            "comparison output rejects a symlink alias into the left input",
            lambda: require_comparison_output_separate(
                comparison_left,
                comparison_right,
                comparison_left_alias / "comparison-output",
            ),
        )
        recorder = CommandRecorder(temp / "capture", repository, repository)
        accepts(
            "cflow diagnostic policy accepts structured conditional definitions",
            lambda: recorder._validate_stderr(
                "/usr/bin/cflow:drivers/gpu/drm/radeon/a.c:12: guarded/1 redefined\n"
                "/usr/bin/cflow:drivers/gpu/drm/radeon/a.c:7: this is the place of previous definition\n",
                policy.cflow_stderr,
            ),
        )
        rejects(
            "cflow diagnostic policy rejects an unstructured warning",
            lambda: recorder._validate_stderr(
                "/usr/bin/cflow:warning: parse failed\n",
                policy.cflow_stderr,
            ),
        )
        ctags_source_root = temp / "ctags-source"
        ctags_source_root.mkdir()
        write_text(
            ctags_source_root / "fixture.c",
            "int ctags_c_fixture(void)\n{\n\treturn 0;\n}\n",
        )
        write_text(
            ctags_source_root / "fixture.h",
            "static inline int ctags_header_fixture(void)\n{\n\treturn 1;\n}\n",
        )
        ctags_source_list = temp / "ctags-source-list.txt"
        write_text(ctags_source_list, "fixture.c\nfixture.h\n")
        try:
            ctags_fixture_rows = build_ctags_index(
                temp / "capture",
                ctags_source_root,
                ctags_source_list,
                ["ctags_c_fixture", "ctags_header_fixture"],
                recorder,
                policy,
            )
        except SourceMapError:
            ctags_fixture_rows = []
        check(
            "Ctags forced C language indexes C and header functions",
            {row.split("\t", 1)[0] for row in ctags_fixture_rows}
            == {"ctags_c_fixture", "ctags_header_fixture"},
        )
        fixture_tag_lines = [
            line
            for line in (
                temp / "capture/indexes/ctags/tags"
            ).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("!_TAG_")
        ]
        fixture_readtags_lines = (
            temp / "capture/indexes/ctags/readtags-all.txt"
        ).read_text(encoding="utf-8").splitlines()
        check(
            "readtags field ordering preserves each Ctags record identity",
            {
                canonical_ctags_record(line, "Ctags fixture", row_number)
                for row_number, line in enumerate(fixture_tag_lines, 1)
            }
            == {
                canonical_ctags_record(line, "readtags fixture", row_number)
                for row_number, line in enumerate(fixture_readtags_lines, 1)
            },
        )
        rejects(
            "Ctags record parser rejects an address and line mismatch",
            lambda: canonical_ctags_record(
                'symbol\tfixture.c\t1;"\tfunction\tline:2',
                "changed Ctags fixture",
                1,
            ),
        )
        check(
            "Ctags forced C language emits no warnings",
            not any(
                line.startswith("ctags: Warning:")
                for line in (
                    temp / "capture/diagnostics/ctags-index.stderr"
                ).read_text(encoding="utf-8").splitlines()
            ),
        )
        broad_ctags = subprocess.run(
            [
                shutil.which("ctags") or "ctags",
                "--options=NONE",
                "--languages=C",
                "-L",
                str(ctags_source_list),
                "-f",
                str(temp / "broad-language-tags"),
            ],
            cwd=ctags_source_root,
            check=False,
            capture_output=True,
            text=True,
            env={**os.environ, "LC_ALL": "C", "LANG": "C", "TZ": "UTC"},
        )
        check(
            "Ctags broad C language mutation emits a rejected warning",
            broad_ctags.returncode == 0
            and any(
                line.startswith("ctags: Warning:")
                for line in broad_ctags.stderr.splitlines()
            ),
        )
        portable_root = temp / "portable"
        write_text(portable_root / "metadata/example.tsv", "tool\t/tmp/source\n")
        accepts(
            "capture path policy accepts canonical sandbox paths",
            lambda: verify_no_host_path_leaks(portable_root, (portable_root,)),
        )
        write_text(
            portable_root / "metadata/example.tsv",
            "path\tdrivers/media/Kconfig\n",
        )
        accepts(
            "capture path policy accepts a relative media source path",
            lambda: verify_no_host_path_leaks(portable_root),
        )
        write_text(
            portable_root / "metadata/example.tsv",
            f"tool\t{portable_root}\n",
        )
        rejects(
            "capture path policy rejects a retained host path",
            lambda: verify_no_host_path_leaks(portable_root, (portable_root,)),
        )
        write_text(
            portable_root / "metadata/example.tsv",
            "tool\t/opt/private-builder/kernel/root\n",
        )
        rejects(
            "capture path policy rejects an unknown absolute host root",
            lambda: verify_no_host_path_leaks(portable_root),
        )
        write_text(
            portable_root / "metadata/example.tsv",
            "tool\t/tmp/private-builder/kernel/root\n",
        )
        rejects(
            "capture path policy rejects a noncanonical temporary root",
            lambda: verify_no_host_path_leaks(portable_root),
        )
        for escaped_path in (
            "/srv/private/build/radeon.ko",
            "/tmp/source-secret/private.c",
            "/tmp/capture-old/query.txt",
            "/home/user/private.c",
        ):
            write_text(
                portable_root / "metadata/example.tsv",
                f"tool\t{escaped_path}\n",
            )
            rejects(
                f"capture path policy rejects {escaped_path}",
                lambda: verify_no_host_path_leaks(portable_root),
            )
        write_text(
            portable_root / "metadata/example.tsv",
            "tool\t/tmp/source/drivers/gpu/drm/radeon/radeon_device.c\n"
            "capture\t/tmp/capture/queries/cscope.txt\n"
            "kernel\t/gororoba/kernel-build-root/include/linux/types.h\n"
            "toolchain\t/gororoba/kernel-toolchain/bin/clang\n"
            "work\t/gororoba/preprocessor-work/drivers/gpu/drm/radeon\n"
            "placeholder\t<source-root>/drivers/gpu/drm/radeon/radeon_device.c\n",
        )
        accepts(
            "capture path policy accepts every declared virtual root",
            lambda: verify_no_host_path_leaks(portable_root),
        )
        write_tsv(
            portable_root / "metadata/command-metadata.tsv",
            "radeon-driver-command-metadata-v1",
            command_columns,
            [canonical_make_row],
        )
        accepts(
            "capture path policy accepts the canonical host make command",
            lambda: verify_no_host_path_leaks(portable_root),
        )
        write_text(
            portable_root / "metadata/example.tsv",
            "tool\t/usr/bin/make\n",
        )
        rejects(
            "capture path policy rejects host make outside command metadata",
            lambda: verify_no_host_path_leaks(portable_root),
        )
        write_text(
            portable_root / "metadata/example.tsv",
            "tool\t/tmp/source/drivers/gpu/drm/radeon/radeon_device.c\n",
        )
        noncanonical_make_row = list(canonical_make_row)
        noncanonical_make_arguments = json.loads(noncanonical_make_row[6])
        noncanonical_make_arguments[0] = "/usr/bin/make-wrapper"
        noncanonical_make_row[6] = json.dumps(
            noncanonical_make_arguments,
            separators=(",", ":"),
        )
        write_tsv(
            portable_root / "metadata/command-metadata.tsv",
            "radeon-driver-command-metadata-v1",
            command_columns,
            [noncanonical_make_row],
        )
        rejects(
            "capture path policy rejects a noncanonical host make command",
            lambda: verify_no_host_path_leaks(portable_root),
        )
        denominator_root = temp / "capture-denominator"
        expected_denominator = {"metadata/required-empty.stderr"}
        write_text(
            denominator_root / "metadata/required-empty.stderr",
            "",
        )
        accepts(
            "capture denominator accepts its exact file and directory set",
            lambda: verify_capture_file_denominator(
                denominator_root,
                expected_denominator,
            ),
        )
        write_text(denominator_root / "extra.txt", "extra\n")
        rejects(
            "capture denominator rejects an extra top-level file",
            lambda: verify_capture_file_denominator(
                denominator_root,
                expected_denominator,
            ),
        )
        (denominator_root / "extra.txt").unlink()
        write_text(denominator_root / "foreign/extra.txt", "extra\n")
        rejects(
            "capture denominator rejects an extra nested file",
            lambda: verify_capture_file_denominator(
                denominator_root,
                expected_denominator,
            ),
        )
        (denominator_root / "foreign/extra.txt").unlink()
        (denominator_root / "foreign").rmdir()
        (denominator_root / "metadata/required-empty.stderr").unlink()
        rejects(
            "capture denominator rejects a missing empty diagnostic",
            lambda: verify_capture_file_denominator(
                denominator_root,
                expected_denominator,
            ),
        )
        cscope_source_root = temp / "cscope-source"
        cscope_path = f"{policy.source_root}/cscope_test.c"
        cscope_content = "int cscope_test(void)\n{\n\treturn 0;\n}\n"
        write_text(cscope_source_root / cscope_path, cscope_content)
        cscope_entry = SourceEntry(
            cscope_path,
            "100644",
            git_object_id("blob", cscope_content.encode("utf-8")),
            len(cscope_content.encode("utf-8")),
            sha256_bytes(cscope_content.encode("utf-8")),
            "c",
        )
        cscope_entries = {cscope_path: cscope_entry}
        good_cscope = (
            f"{cscope_path} cscope_test 3 return 0;\n"
        ).encode("ascii")
        check(
            "cscope parser accepts one admitted full path and retained source line",
            len(
                parse_cscope_rows(
                    good_cscope,
                    "definition",
                    "cscope_test",
                    cscope_entries,
                    cscope_source_root,
                )
            )
            == 1,
        )
        rejects(
            "cscope parser rejects a basename-only path",
            lambda: parse_cscope_rows(
                b"cscope_test.c cscope_test 3 return 0;\n",
                "definition",
                "cscope_test",
                cscope_entries,
                cscope_source_root,
            ),
        )
        rejects(
            "cscope parser rejects a foreign absolute path",
            lambda: parse_cscope_rows(
                b"/opt/private/source.c cscope_test 3 return 0;\n",
                "definition",
                "cscope_test",
                cscope_entries,
                cscope_source_root,
            ),
        )
        rejects(
            "cscope parser rejects a line beyond retained source",
            lambda: parse_cscope_rows(
                f"{cscope_path} cscope_test 99 return 0;\n".encode("ascii"),
                "definition",
                "cscope_test",
                cscope_entries,
                cscope_source_root,
            ),
        )
        rejects(
            "cscope parser rejects changed source text",
            lambda: parse_cscope_rows(
                f"{cscope_path} cscope_test 3 return 1;\n".encode("ascii"),
                "definition",
                "cscope_test",
                cscope_entries,
                cscope_source_root,
            ),
        )
        rejects(
            "cscope parser rejects duplicate rows",
            lambda: parse_cscope_rows(
                good_cscope + good_cscope,
                "definition",
                "cscope_test",
                cscope_entries,
                cscope_source_root,
            ),
        )
        cscope_replay_root = temp / "cscope-replay"
        replay_source_root = cscope_replay_root / "source"
        write_text(replay_source_root / cscope_path, cscope_content)
        replay_database = cscope_replay_root / "indexes/cscope/cscope.out"
        replay_database.parent.mkdir(parents=True)
        replay_source_list = cscope_replay_root / "inputs/c-and-header-files.txt"
        write_text(replay_source_list, f"{cscope_path}\n")
        cscope_executable = Path(shutil.which("cscope") or "cscope")
        cscope_build = subprocess.run(
            [
                str(cscope_executable),
                "-b",
                "-k",
                "-c",
                "-i",
                str(replay_source_list),
                "-f",
                str(replay_database),
            ],
            cwd=replay_source_root,
            env={**os.environ, "LC_ALL": "C", "LANG": "C", "TZ": "UTC"},
            capture_output=True,
            check=False,
        )
        check(
            "cscope replay fixture builds one portable database",
            cscope_build.returncode == 0 and not cscope_build.stderr,
        )
        replay_rows: list[tuple[Any, ...]] = []
        replay_raw: dict[str, bytes] = {}
        replay_display_components = len(Path(cscope_path).parts)
        for query_kind, mode in (
            ("definition", "-1"),
            ("calls", "-2"),
            ("callers", "-3"),
        ):
            query_result = subprocess.run(
                [
                    str(cscope_executable),
                    "-d",
                    "-L",
                    f"-p{replay_display_components}",
                    mode,
                    "cscope_test",
                    "-f",
                    str(replay_database),
                ],
                cwd=replay_source_root,
                env={**os.environ, "LC_ALL": "C", "LANG": "C", "TZ": "UTC"},
                capture_output=True,
                check=False,
            )
            check(
                f"cscope replay fixture emits {query_kind}",
                query_result.returncode == 0 and not query_result.stderr,
            )
            raw_relative = f"queries/cscope/{query_kind}-cscope_test.txt"
            write_bytes(cscope_replay_root / raw_relative, query_result.stdout)
            replay_raw[raw_relative] = query_result.stdout
            replay_rows.extend(
                parse_cscope_rows(
                    query_result.stdout,
                    query_kind,
                    "cscope_test",
                    cscope_entries,
                    replay_source_root,
                )
            )
        replay_rows.sort(
            key=lambda row: (row[0], row[1], row[2], row[4], row[3], row[5])
        )
        replay_table = [
            [str(value) for value in row]
            for row in replay_rows
        ]
        accepts(
            "cscope replay accepts every exact raw query",
            lambda: replay_cscope_queries(
                cscope_replay_root,
                cscope_entries,
                ["cscope_test"],
                replay_table,
                sha256_file(cscope_executable),
                executable=cscope_executable,
            ),
        )
        definition_raw = (
            cscope_replay_root
            / "queries/cscope/definition-cscope_test.txt"
        )
        definition_bytes = definition_raw.read_bytes()
        write_bytes(definition_raw, b"")
        rejects(
            "cscope replay rejects one emptied raw query",
            lambda: replay_cscope_queries(
                cscope_replay_root,
                cscope_entries,
                ["cscope_test"],
                replay_table,
                sha256_file(cscope_executable),
                executable=cscope_executable,
            ),
        )
        write_bytes(definition_raw, definition_bytes)
        for raw_relative in replay_raw:
            write_bytes(cscope_replay_root / raw_relative, b"")
        rejects(
            "cscope replay rejects an emptied raw denominator and summary",
            lambda: replay_cscope_queries(
                cscope_replay_root,
                cscope_entries,
                ["cscope_test"],
                [],
                sha256_file(cscope_executable),
                executable=cscope_executable,
            ),
        )
        for raw_relative, raw_content in replay_raw.items():
            write_bytes(cscope_replay_root / raw_relative, raw_content)
        database_bytes = replay_database.read_bytes()
        write_bytes(replay_database, b"invalid cscope database\n")
        rejects(
            "cscope replay rejects an altered database",
            lambda: replay_cscope_queries(
                cscope_replay_root,
                cscope_entries,
                ["cscope_test"],
                replay_table,
                sha256_file(cscope_executable),
                executable=cscope_executable,
            ),
        )
        write_bytes(replay_database, database_bytes)
        bounded_path = f"{policy.source_root}/bounded_test.c"
        bounded_content = (
            "void bounded_test(void)\n"
            "{\n"
            "\treal_target();\n"
            "\t/* real_target(); */\n"
            "\tconst char *text = \"real_target()\";\n"
            "}\n"
        )
        write_text(cscope_source_root / bounded_path, bounded_content)
        bounded_entry = SourceEntry(
            bounded_path,
            "100644",
            git_object_id("blob", bounded_content.encode("utf-8")),
            len(bounded_content.encode("utf-8")),
            sha256_bytes(bounded_content.encode("utf-8")),
            "c",
        )
        bounded_query = BoundedQuery(
            "bounded-code-mask-fixture",
            (bounded_path,),
            r"\breal_target\s*\(",
            1,
            "Only the code occurrence belongs to the lexical denominator.",
        )
        bounded_summary, bounded_matches = evaluate_bounded_queries(
            cscope_source_root,
            [bounded_entry],
            (bounded_query,),
        )
        check(
            "bounded query replay excludes comment and string decoys",
            bounded_summary[0][3] == 1
            and len(bounded_matches) == 1
            and bounded_matches[0][5] == "lexical-code-mask",
        )
        rejects(
            "bounded query replay rejects a forged expected count",
            lambda: evaluate_bounded_queries(
                cscope_source_root,
                [bounded_entry],
                (
                    BoundedQuery(
                        bounded_query.name,
                        bounded_query.paths,
                        bounded_query.pattern,
                        2,
                        bounded_query.rationale,
                    ),
                ),
            ),
        )
        scc_report = temp / "scc.json"
        write_text(
            scc_report,
            '[{"Name":"C","Files":[{"Location":"z.c","Filename":"z.c"},'
            '{"Location":"a.c","Filename":"a.c"}]}]\n',
        )
        normalize_scc_json(scc_report)
        normalized_scc = json.loads(scc_report.read_text(encoding="utf-8"))
        check(
            "SCC normalization orders concurrent file rows",
            [item["Location"] for item in normalized_scc[0]["Files"]]
            == ["a.c", "z.c"],
        )
        ledger_root = temp / "ledger"
        write_text(ledger_root / "a.txt", "alpha\n")
        write_text(ledger_root / "nested/b.txt", "beta\n")
        write_hash_ledger(ledger_root)
        check("hash ledger covers every retained file and excludes itself", verify_hash_ledger(ledger_root) == 2)
        write_text(ledger_root / "a.txt", "mutated\n")
        rejects("hash ledger rejects changed content", lambda: verify_hash_ledger(ledger_root))

        proof_root = temp / "source-proof"
        live_commit = str(git_output(repository, "rev-parse", "HEAD^{commit}")).strip()
        live_tree = str(git_output(repository, "rev-parse", f"{live_commit}^{{tree}}")).strip()
        live_driver_tree = str(
            git_output(repository, "rev-parse", f"{live_commit}:{policy.source_root}")
        ).strip()
        blob_export_root = temp / "blob-export"
        blob_export_entries = {
            entry.path: entry
            for entry in export_source(
                repository,
                live_commit,
                policy,
                blob_export_root,
            )
        }
        ignored_metadata_path = f"{policy.source_root}/.gitignore"
        ignored_metadata = blob_export_entries.get(ignored_metadata_path)
        check(
            "Git blob export retains tracked source metadata despite export-ignore",
            ignored_metadata is not None
            and ignored_metadata.source_class == "repository-metadata"
            and ignored_metadata.object_id
            == str(
                git_output(
                    repository,
                    "rev-parse",
                    f"{live_commit}:{ignored_metadata_path}",
                )
            ).strip()
            and (blob_export_root / ignored_metadata_path).is_file(),
        )
        write_source_tree_proof(
            proof_root,
            repository,
            live_commit,
            live_tree,
            live_driver_tree,
            policy.source_root,
        )
        accepts(
            "retained Git objects prove the commit to driver-tree Merkle path",
            lambda: verify_source_tree_proof(
                proof_root,
                live_commit,
                live_tree,
                live_driver_tree,
                policy.source_root,
            ),
        )
        commit_proof = proof_root / "metadata/git-source-proof/commit.bin"
        write_bytes(commit_proof, commit_proof.read_bytes() + b"forgery\n")
        rejects(
            "source proof rejects a changed commit object",
            lambda: verify_source_tree_proof(
                proof_root,
                live_commit,
                live_tree,
                live_driver_tree,
                policy.source_root,
            ),
        )

        symlink_tree = temp / "symlink-tree"
        symlink_target = temp / "symlink-target"
        symlink_tree.mkdir()
        symlink_target.mkdir()
        write_text(symlink_target / "source.c", "int external_source;\n")
        (symlink_tree / "linked-parent").symlink_to(
            symlink_target,
            target_is_directory=True,
        )
        rejects(
            "regular tree closure rejects a symlinked parent directory",
            lambda: regular_tree_files(symlink_tree, "symlink fixture"),
        )

        producer_proof_root = temp / "producer-proof"
        producer_fixture_paths = {
            "AGENTS.md": "producer/AGENTS.md",
            SCRIPT_PATH.as_posix(): f"producer/{SCRIPT_PATH.as_posix()}",
        }
        for repository_path, retained_path in producer_fixture_paths.items():
            content = git_output(
                repository,
                "show",
                f"{live_commit}:{repository_path}",
                text=False,
            )
            assert isinstance(content, bytes)
            target = producer_proof_root / retained_path
            write_bytes(target, content)
            mode_line = str(
                git_output(
                    repository,
                    "ls-tree",
                    live_commit,
                    "--",
                    repository_path,
                )
            ).strip()
            target.chmod(0o755 if mode_line.startswith("100755 ") else 0o644)
        write_git_file_proof(
            producer_proof_root / "metadata/proof",
            repository,
            live_commit,
            live_tree,
            set(producer_fixture_paths),
        )
        accepts(
            "producer Git proof binds retained inputs through raw tree objects",
            lambda: verify_git_file_proof(
                producer_proof_root,
                producer_proof_root / "metadata/proof",
                live_commit,
                live_tree,
                producer_fixture_paths,
                "producer fixture proof",
            ),
        )
        write_text(producer_proof_root / "metadata/proof/extra.bin", "extra\n")
        rejects(
            "producer Git proof rejects an extra proof file",
            lambda: verify_git_file_proof(
                producer_proof_root,
                producer_proof_root / "metadata/proof",
                live_commit,
                live_tree,
                producer_fixture_paths,
                "producer fixture proof",
            ),
        )
        (producer_proof_root / "metadata/proof/extra.bin").unlink()
        write_text(producer_proof_root / producer_fixture_paths["AGENTS.md"], "forged\n")
        rejects(
            "producer Git proof rejects changed retained input bytes",
            lambda: verify_git_file_proof(
                producer_proof_root,
                producer_proof_root / "metadata/proof",
                live_commit,
                live_tree,
                producer_fixture_paths,
                "producer fixture proof",
            ),
        )

        live_policy = policy_path.read_text(encoding="ascii")
        wrong_schema = temp / "wrong-schema.toml"
        write_text(wrong_schema, live_policy.replace("schema = 1", "schema = 2", 1))
        rejects("policy rejects a foreign schema", lambda: load_policy(wrong_schema))
        legacy_comparison_policy = temp / "legacy-comparison-policy.toml"
        write_text(
            legacy_comparison_policy,
            live_policy.replace(
                f'comparison_schema = "{COMPARISON_SCHEMA}"',
                'comparison_schema = "gororoba-radeon-driver-source-map-comparison-v2"',
                1,
            ),
        )
        rejects(
            "live policy rejects legacy comparison production",
            lambda: load_policy(legacy_comparison_policy),
        )
        accepts(
            "retained capture policy accepts comparison schema v2",
            lambda: load_policy(
                legacy_comparison_policy,
                accepted_comparison_schemas=RETAINED_CAPTURE_COMPARISON_SCHEMAS,
            ),
        )
        unsupported_comparison_policy = temp / "unsupported-comparison-policy.toml"
        write_text(
            unsupported_comparison_policy,
            live_policy.replace(
                f'comparison_schema = "{COMPARISON_SCHEMA}"',
                'comparison_schema = "gororoba-radeon-driver-source-map-comparison-v1"',
                1,
            ),
        )
        rejects(
            "retained capture policy rejects comparison schema v1",
            lambda: load_policy(
                unsupported_comparison_policy,
                accepted_comparison_schemas=RETAINED_CAPTURE_COMPARISON_SCHEMAS,
            ),
        )
        unknown_key = temp / "unknown-key.toml"
        write_text(unknown_key, live_policy + '\nunknown_policy_key = "rejected"\n')
        rejects("policy rejects an unknown key", lambda: load_policy(unknown_key))
        malformed = temp / "malformed.toml"
        write_text(malformed, "schema = [[[\n")
        rejects("policy rejects malformed TOML", lambda: load_policy(malformed))

        live_lane = policy.kernel_lanes[0]
        changed_toolchain_manifest = temp / "changed-toolchain-manifest.tsv"
        toolchain_manifest_text = (
            repository / live_lane.toolchain_manifest
        ).read_text(encoding="ascii")
        write_text(
            changed_toolchain_manifest,
            toolchain_manifest_text.replace(
                "daf719d20e025e07fb1de41eb34e157788141f7f531d85be10678b747a10892e",
                "0" * 64,
                1,
            ),
        )
        rejects(
            "toolchain closure rejects a changed command identity",
            lambda: load_toolchain_closure(
                repository / live_lane.toolchain_declaration,
                changed_toolchain_manifest,
                repository / live_lane.toolchain_prefix_manifest,
            ),
        )
        toolchain_declaration_text = (
            repository / live_lane.toolchain_declaration
        ).read_text(encoding="ascii")
        for field in ("runner_file_write", "extended_attributes"):
            permissive_declaration = temp / f"permissive-{field}.toml"
            write_text(
                permissive_declaration,
                toolchain_declaration_text.replace(
                    f"{field} = false",
                    f"{field} = true",
                    1,
                ),
            )
            rejects(
                f"toolchain closure rejects permissive {field}",
                lambda declaration_path=permissive_declaration: (
                    load_toolchain_closure(
                        declaration_path,
                        repository / live_lane.toolchain_manifest,
                        repository / live_lane.toolchain_prefix_manifest,
                    )
                ),
            )
        oversized_count_declaration = temp / "oversized-prefix-count.toml"
        write_text(
            oversized_count_declaration,
            toolchain_declaration_text.replace(
                "prefix_entry_count = 7174",
                f"prefix_entry_count = {MAX_TOOLCHAIN_PREFIX_ENTRIES + 1}",
                1,
            ),
        )
        rejects(
            "toolchain closure rejects an oversized prefix row declaration",
            lambda: load_toolchain_closure(
                oversized_count_declaration,
                repository / live_lane.toolchain_manifest,
                repository / live_lane.toolchain_prefix_manifest,
            ),
        )
        prefix_manifest_lines = (
            repository / live_lane.toolchain_prefix_manifest
        ).read_text(encoding="ascii").splitlines()
        unsorted_prefix_manifest = temp / "unsorted-prefix-tree.tsv"
        unsorted_lines = list(prefix_manifest_lines)
        unsorted_lines[2], unsorted_lines[3] = (
            unsorted_lines[3],
            unsorted_lines[2],
        )
        write_text(unsorted_prefix_manifest, "\n".join(unsorted_lines) + "\n")
        rejects(
            "toolchain prefix manifest rejects unsorted rows",
            lambda: load_toolchain_prefix_manifest(unsorted_prefix_manifest),
        )
        duplicate_prefix_manifest = temp / "duplicate-prefix-tree.tsv"
        write_text(
            duplicate_prefix_manifest,
            "\n".join([*prefix_manifest_lines, prefix_manifest_lines[-1]])
            + "\n",
        )
        rejects(
            "toolchain prefix manifest rejects a duplicate row",
            lambda: load_toolchain_prefix_manifest(duplicate_prefix_manifest),
        )
        oversized_prefix_manifest = temp / "oversized-prefix-tree.tsv"
        write_text(
            oversized_prefix_manifest,
            "# schema: gororoba-kernel-toolchain-prefix-tree-v1\n"
            + "x" * MAX_MANIFEST_BYTES,
        )
        rejects(
            "toolchain prefix manifest rejects an oversized byte stream",
            lambda: load_toolchain_prefix_manifest(oversized_prefix_manifest),
        )
        dot_prefix_manifest = temp / "dot-prefix-tree.tsv"
        dot_lines = list(prefix_manifest_lines)
        dot_fields = dot_lines[2].split("\t")
        dot_fields[0] = "."
        dot_lines[2] = "\t".join(dot_fields)
        write_text(dot_prefix_manifest, "\n".join(dot_lines) + "\n")
        rejects(
            "toolchain prefix manifest rejects a dot path",
            lambda: load_toolchain_prefix_manifest(dot_prefix_manifest),
        )
        del_prefix_manifest = temp / "del-prefix-tree.tsv"
        del_lines = list(prefix_manifest_lines)
        del_fields = del_lines[2].split("\t")
        del_fields[0] += "\x7f"
        del_lines[2] = "\t".join(del_fields)
        write_text(del_prefix_manifest, "\n".join(del_lines) + "\n")
        rejects(
            "toolchain prefix manifest rejects ASCII DEL",
            lambda: load_toolchain_prefix_manifest(del_prefix_manifest),
        )
        changed_prefix_manifest = temp / "changed-prefix-semantic-row.tsv"
        changed_prefix_text = "\n".join(prefix_manifest_lines) + "\n"
        require(
            changed_prefix_text.count("bin/clang\tsymlink\t0777\t") == 1,
            "toolchain semantic-prefix fixture anchor differs",
        )
        changed_prefix_text = changed_prefix_text.replace(
            "bin/clang\tsymlink\t0777\t",
            "bin/clang\tsymlink\t0700\t",
            1,
        )
        write_text(changed_prefix_manifest, changed_prefix_text)
        changed_prefix_declaration = temp / "changed-prefix-declaration.toml"
        original_prefix_sha256 = sha256_file(
            repository / live_lane.toolchain_prefix_manifest
        )
        changed_prefix_sha256 = sha256_file(changed_prefix_manifest)
        require(
            toolchain_declaration_text.count(original_prefix_sha256) == 1,
            "toolchain prefix declaration hash fixture differs",
        )
        write_text(
            changed_prefix_declaration,
            toolchain_declaration_text.replace(
                original_prefix_sha256,
                changed_prefix_sha256,
                1,
            ),
        )
        rejects(
            "toolchain closure rejects a semantic-prefix identity mismatch",
            lambda: load_toolchain_closure(
                changed_prefix_declaration,
                repository / live_lane.toolchain_manifest,
                changed_prefix_manifest,
            ),
        )
        unicode_size_prefix_manifest = temp / "unicode-size-prefix-tree.tsv"
        unicode_size = "".join(
            chr(0xFF10 + int(digit)) for digit in "798216"
        )
        canonical_prefix_text = "\n".join(prefix_manifest_lines) + "\n"
        require(
            canonical_prefix_text.count(
                "bin/FileCheck\tregular\t0755\t798216\t"
            )
            == 1,
            "toolchain Unicode-size fixture anchor differs",
        )
        write_text(
            unicode_size_prefix_manifest,
            canonical_prefix_text.replace(
                "bin/FileCheck\tregular\t0755\t798216\t",
                f"bin/FileCheck\tregular\t0755\t{unicode_size}\t",
                1,
            ),
        )
        unicode_prefix_declaration = temp / "unicode-prefix-declaration.toml"
        write_text(
            unicode_prefix_declaration,
            toolchain_declaration_text.replace(
                original_prefix_sha256,
                sha256_file(unicode_size_prefix_manifest),
                1,
            ),
        )
        rejects(
            "toolchain prefix rejects a Unicode numeric alias",
            lambda: load_toolchain_closure(
                unicode_prefix_declaration,
                repository / live_lane.toolchain_manifest,
                unicode_size_prefix_manifest,
            ),
        )
        crlf_semantic_manifest = temp / "crlf-semantic-closure.tsv"
        semantic_manifest_bytes = (
            repository / live_lane.toolchain_manifest
        ).read_bytes()
        write_bytes(
            crlf_semantic_manifest,
            semantic_manifest_bytes.replace(b"\n", b"\r\n"),
        )
        crlf_semantic_declaration = temp / "crlf-semantic-declaration.toml"
        write_text(
            crlf_semantic_declaration,
            toolchain_declaration_text.replace(
                sha256_bytes(semantic_manifest_bytes),
                sha256_file(crlf_semantic_manifest),
                1,
            ),
        )
        rejects(
            "toolchain semantic closure rejects a noncanonical CRLF alias",
            lambda: load_toolchain_closure(
                crlf_semantic_declaration,
                crlf_semantic_manifest,
                repository / live_lane.toolchain_prefix_manifest,
            ),
        )
        mutable_prefix_manifest = temp / "mutable-prefix-tree.tsv"
        write_text(
            mutable_prefix_manifest,
            "\n".join(prefix_manifest_lines) + "\n",
        )
        admitted_prefix_entries = load_toolchain_prefix_manifest(
            mutable_prefix_manifest
        )
        mutable_prefix_text = mutable_prefix_manifest.read_text(encoding="ascii")
        require(
            mutable_prefix_text.count("bin/FileCheck\tregular\t0755\t") == 1,
            "toolchain mutable-prefix fixture anchor differs",
        )
        write_text(
            mutable_prefix_manifest,
            mutable_prefix_text.replace(
                "bin/FileCheck\tregular\t0755\t",
                "bin/FileCheck\tregular\t0555\t",
                1,
            ),
        )
        reloaded_prefix_entries = load_toolchain_prefix_manifest(
            mutable_prefix_manifest
        )
        check(
            "post-build toolchain expectation retains pre-admitted entries",
            admitted_prefix_entries != reloaded_prefix_entries
            and any(
                entry.relative_path == "bin/FileCheck" and entry.mode == "0755"
                for entry in admitted_prefix_entries
            ),
        )
        fake_toolchain = temp / "fake-toolchain/usr"
        (fake_toolchain / "bin").mkdir(parents=True)
        (fake_toolchain / "lib").mkdir()
        side_effect = temp / "fake-tool-executed"
        write_text(
            fake_toolchain / "bin/clang",
            f"#!/bin/sh\ntouch {side_effect}\nprintf 'clang version 22.1.6\\n'\n",
        )
        (fake_toolchain / "bin/clang").chmod(0o755)
        rejects(
            "toolchain validator rejects a runner-writable fake root before execution",
            lambda: validate_kernel_toolchain(
                live_lane.release,
                fake_toolchain / "bin",
                repository / live_lane.declaration,
                repository / live_lane.toolchain_declaration,
                repository / live_lane.toolchain_manifest,
                repository / live_lane.toolchain_prefix_manifest,
                live_lane.toolchain_manifest,
                live_lane.toolchain_prefix_manifest,
            ),
        )
        check(
            "rejected toolchain validation does not execute a fake command",
            not side_effect.exists(),
        )

    check("policy binding IDs and normalized edges are finite and unique", len({item.name for item in policy.bindings}) == len(policy.bindings) and len({(item.kind, item.caller, item.callee) for item in policy.bindings}) == len(policy.bindings))
    check(
        "preprocessor prefix-map targets are absolute shell-safe paths",
        all(
            re.fullmatch(r"/[A-Za-z0-9._/-]+", path)
            for path in (
                CANONICAL_PREPROCESSOR_WORK,
                CANONICAL_KERNEL_BUILD_ROOT,
                CANONICAL_KERNEL_TOOLCHAIN,
            )
        ),
    )
    check("product schemas do not claim runtime or hardware verdicts", all(term not in (LEXICAL_SCHEMA + DECLARED_BINDING_SCHEMA) for term in ("runtime", "reachable", "invoked", "hardware-pass")))
    check("capture output is required outside the repository", repository_contains(repository, repository / "inside"))

    if failures:
        print(f"Radeon driver source-map calibration: FAIL ({failures})", file=sys.stderr)
        return 1
    print(f"Radeon driver source-map calibration: {verdicts} adversarial verdicts passed")
    return 0


def main() -> int:
    script_repository = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=script_repository)
    parser.add_argument("--policy", type=Path, default=POLICY_PATH)
    parser.add_argument("--treeish", default="HEAD")
    parser.add_argument("--output", "--output-dir", dest="output", type=Path)
    parser.add_argument("--kernel-build-root", action="append", type=Path, default=[])
    parser.add_argument(
        "--kernel-toolchain-bin",
        action="append",
        default=[],
        metavar="RELEASE=PATH",
    )
    parser.add_argument("--verify", type=Path)
    parser.add_argument("--compare", nargs=2, type=Path, metavar=("LEFT", "RIGHT"))
    parser.add_argument("--inventory-toolchain-prefix", type=Path)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--require-all-kernel-lanes", action="store_true")
    args = parser.parse_args()

    raw_arguments = sys.argv[1:]

    def option_present(*names: str) -> bool:
        return any(
            argument == name or argument.startswith(name + "=")
            for argument in raw_arguments
            for name in names
        )

    selected_modes = sum(
        bool(item)
        for item in (
            args.self_test,
            args.verify,
            args.compare,
            args.inventory_toolchain_prefix,
        )
    )
    if selected_modes > 1:
        parser.error("select only one of --self-test, --verify, or --compare")
    if args.self_test:
        if (
            args.output
            or args.kernel_build_root
            or args.kernel_toolchain_bin
            or args.require_all_kernel_lanes
            or option_present("--treeish")
        ):
            parser.error(
                "--self-test accepts only --repository and --policy"
            )
        repository = resolve_repository(args.repository)
        policy_path = args.policy if args.policy.is_absolute() else repository / args.policy
        return self_test(repository, policy_path)
    if args.verify:
        if (
            args.output
            or args.kernel_build_root
            or args.kernel_toolchain_bin
            or option_present("--repository", "--policy", "--treeish")
        ):
            parser.error(
                "--verify accepts only a capture path and --require-all-kernel-lanes"
            )
        manifest = verify_capture(
            args.verify,
            require_all_kernel_lanes=args.require_all_kernel_lanes,
        )
        print(
            f"Radeon driver source map verified: {manifest['source_commit']} "
            f"{manifest['source_file_count']} files"
        )
        return 0
    if args.compare:
        if not args.output:
            parser.error("--compare requires --output")
        if (
            args.kernel_build_root
            or args.kernel_toolchain_bin
            or args.require_all_kernel_lanes
            or option_present("--repository", "--policy", "--treeish")
        ):
            parser.error(
                "--compare accepts only two capture paths and --output"
            )
        compare_captures(args.compare[0], args.compare[1], args.output.resolve())
        return 0
    if args.inventory_toolchain_prefix:
        if not args.output:
            parser.error("--inventory-toolchain-prefix requires --output")
        if (
            args.kernel_build_root
            or args.kernel_toolchain_bin
            or args.require_all_kernel_lanes
            or option_present("--repository", "--policy", "--treeish")
        ):
            parser.error(
                "--inventory-toolchain-prefix accepts only one prefix and --output"
            )
        write_toolchain_prefix_manifest(
            args.inventory_toolchain_prefix.resolve(),
            args.output.resolve(),
        )
        entries = load_toolchain_prefix_manifest(args.output.resolve())
        print(
            "LLVM prefix manifest: "
            f"{len(entries)} entries {sha256_file(args.output.resolve())}"
        )
        return 0
    if not args.output:
        parser.error("live capture requires --output")
    if args.require_all_kernel_lanes:
        parser.error("--require-all-kernel-lanes applies only to --verify")
    capture_source_map(
        args.repository,
        args.policy,
        args.treeish,
        args.output.resolve(),
        args.kernel_build_root,
        parse_release_paths(args.kernel_toolchain_bin),
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SourceMapError as exc:
        print(f"Radeon driver source map: {exc}", file=sys.stderr)
        sys.exit(2)
