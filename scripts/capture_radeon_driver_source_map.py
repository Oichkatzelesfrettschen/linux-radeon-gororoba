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


CAPTURE_SCHEMA = "gororoba-radeon-driver-source-map-v1"
COMPARISON_SCHEMA = "gororoba-radeon-driver-source-map-comparison-v1"
LEXICAL_SCHEMA = "radeon-driver-lexical-map-v1"
DECLARED_BINDING_SCHEMA = "radeon-driver-declared-bindings-v1"
HASH_LEDGER = "capture-hashes.sha256"
POLICY_PATH = Path("policy/radeon-driver-source-map.toml")
SCRIPT_PATH = Path("scripts/capture_radeon_driver_source_map.py")
KERNEL_ROOT_VALIDATOR_PATH = Path("scripts/check_kernel_build_root.py")
CANONICAL_SOURCE_ROOT = "drivers/gpu/drm/radeon"
MAX_SOURCE_FILES = 256
MAX_SOURCE_BYTES = 7_000_000
MAX_MANIFEST_BYTES = 1_048_576
MAX_ANALYSIS_ROWS = 1_000_000
CANONICAL_PREPROCESSOR_WORK = "/gororoba/preprocessor-work"
CANONICAL_KERNEL_BUILD_ROOT = "/gororoba/kernel-build-root"
CANONICAL_KERNEL_TOOLCHAIN = "/gororoba/kernel-toolchain"
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
INITIALIZER_BINDING_KINDS = {
    "callback-table",
    "file-operations-table",
    "vm-operations-table",
}
BRACE_SCOPED_BINDING_KINDS = INITIALIZER_BINDING_KINDS | {
    "reset-mode",
    "reset-request",
}
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
UTC_TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
C_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
C_COMMENT_OR_LITERAL = re.compile(
    r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
    re.DOTALL,
)
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
    caller: str
    callee: str
    path: str
    pattern: str
    expected_matches: int
    match_literals: bool


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


def read_bounded_file(path: Path, maximum_size: int, label: str) -> bytes:
    try:
        status = path.lstat()
    except OSError as exc:
        raise SourceMapError(f"{label} is absent: {path}") from exc
    require(stat.S_ISREG(status.st_mode), f"{label} is not a regular file")
    require(status.st_size <= maximum_size, f"{label} exceeds its size ceiling")
    return path.read_bytes()


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


def write_tsv(path: Path, schema: str, columns: tuple[str, ...], rows: list[tuple[Any, ...]]) -> None:
    stream = io.StringIO(newline="")
    stream.write(f"# schema: {schema}\n")
    writer = csv.writer(stream, delimiter="\t", lineterminator="\n")
    writer.writerow(columns)
    for row in rows:
        writer.writerow(row)
    write_text(path, stream.getvalue())


def read_tsv(path: Path, expected_schema: str) -> tuple[list[str], list[list[str]]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    require(lines and lines[0] == f"# schema: {expected_schema}", f"invalid schema: {path}")
    require(len(lines) >= 2, f"missing columns: {path}")
    parsed = list(csv.reader(lines[1:], delimiter="\t"))
    require(parsed and parsed[0], f"empty columns: {path}")
    return parsed[0], parsed[1:]


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


def load_policy(path: Path) -> Policy:
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
        "bounded_query",
    }
    reject_unknown(data, top_keys, "policy")
    require(data.get("schema") == 1, "policy.schema must equal 1")
    capture_schema = string_value(data, "capture_schema", "policy")
    comparison_schema = string_value(data, "comparison_schema", "policy")
    require(capture_schema == CAPTURE_SCHEMA, "policy capture schema differs from the producer")
    require(comparison_schema == COMPARISON_SCHEMA, "policy comparison schema differs from the producer")
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
                string_value(item, "caller", label),
                string_value(item, "callee", label),
                path_value,
                pattern,
                expected,
                item.get("match_literals", False),
            )
        )
        require(isinstance(bindings[-1].match_literals, bool), f"{label}.match_literals must be Boolean")
    require(bindings, "policy carries no declared bindings")
    require(len({item.name for item in bindings}) == len(bindings), "binding name repeats")
    binding_edges = {(item.kind, item.caller, item.callee) for item in bindings}
    require(len(binding_edges) == len(bindings), "declared binding edge repeats")

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
        tuple(bounded_queries),
    )


def git_output(repository: Path, *args: str, text: bool = True) -> str | bytes:
    result = subprocess.run(
        ["git", "-C", str(repository), *args],
        check=False,
        capture_output=True,
        text=text,
        env={**os.environ, "LC_ALL": "C", "LANG": "C"},
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
    """Blank C comments while preserving literals, positions, and line count."""

    def blank_comment(match: re.Match[str]) -> str:
        token = match.group(0)
        if not token.startswith(("/*", "//")):
            return token
        return re.sub(r"[^\n]", " ", token)

    return C_COMMENT_OR_LITERAL.sub(blank_comment, source)


def strip_comments_and_literals(source: str) -> str:
    """Blank C comments and literals while preserving positions and lines."""

    def blank(match: re.Match[str]) -> str:
        return re.sub(r"[^\n]", " ", match.group(0))

    return C_COMMENT_OR_LITERAL.sub(blank, source)


def missing_code_identifiers(source: str, identifiers: tuple[str, ...]) -> list[str]:
    code = strip_comments_and_literals(source)
    return [
        identifier
        for identifier in identifiers
        if re.search(rf"\b{re.escape(identifier)}\b", code) is None
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
        command_environment = {
            **os.environ,
            "LC_ALL": "C",
            "LANG": "C",
            "TZ": "UTC",
            **env_additions,
        }
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
            for key, value in sorted({"LC_ALL": "C", "LANG": "C", "TZ": "UTC", **env_additions}.items())
        }
        self.records.append(
            CommandRecord(
                command_id,
                Path(argv[0]).name,
                self.sanitize(str(cwd)),
                result.returncode,
                stdout_path,
                stderr_path,
                json.dumps(
                    [Path(argv[0]).name, *[sanitize_runtime(item) for item in argv[1:]]],
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
    }
    result = subprocess.run(
        [executable, *version_args[tool]],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "LC_ALL": "C", "LANG": "C"},
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
        if binding.kind not in BRACE_SCOPED_BINDING_KINDS:
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
            line = source.count("\n", 0, match.start()) + 1
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
            ),
            rows,
        )
    return rows


def extract_callback_candidates(
    capture_root: Path,
    source_root: Path,
    entries: list[SourceEntry],
    policy: Policy,
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
            line = source.count("\n", 0, match.start()) + 1
            rows.append(("field-initializer", entry.path, line, selector, target, entry.sha256))
            counts["minimum_field_initializers"] += 1

        for match in DEFINE_SHOW.finditer(code):
            symbol = match.group(1)
            line = source.count("\n", 0, match.start()) + 1
            rows.append(("define-show-attribute", entry.path, line, f"{symbol}_fops", f"{symbol}_show", entry.sha256))
            generated_edges.add((f"{symbol}_fops", f"{symbol}_show", "macro-generated-vfs"))
            counts["minimum_define_show_attributes"] += 1

        for match in DEFINE_DEBUGFS.finditer(code):
            fops, getter, setter = match.groups()
            line = source.count("\n", 0, match.start()) + 1
            for selector, target in (("get", getter), ("set", setter)):
                rows.append(("define-debugfs-attribute", entry.path, line, f"{fops}:{selector}", target, entry.sha256))
                generated_edges.add((fops, target, "macro-generated-vfs"))

        for match in DRM_IOCTL.finditer(code):
            ioctl_name, target = match.groups()
            line = source.count("\n", 0, match.start()) + 1
            rows.append(("drm-ioctl", entry.path, line, ioctl_name, target, entry.sha256))
            generated_edges.add((f"DRM_IOCTL_{ioctl_name}", target, "macro-generated-ioctl"))
            counts["minimum_drm_ioctl_bindings"] += 1

        for match in WORK_BINDING.finditer(code):
            macro, target = match.groups()
            line = source.count("\n", 0, match.start()) + 1
            rows.append(("workqueue", entry.path, line, macro, target, entry.sha256))
            generated_edges.add((macro, target, "macro-generated-workqueue"))
            counts["minimum_work_bindings"] += 1

        for match in MODULE_BINDING.finditer(code):
            macro, target = match.groups()
            line = source.count("\n", 0, match.start()) + 1
            rows.append(("module-entry", entry.path, line, macro, target, entry.sha256))
            generated_edges.add((macro, target, "macro-generated-module-entry"))

    for minimum, expected in policy.extractor_minimums.items():
        require(counts[minimum] >= expected, f"callback extractor {minimum} fell below {expected}: {counts[minimum]}")
    rows.sort(key=lambda row: (row[0], row[1], row[2], row[3], row[4]))
    require(len(set(rows)) == len(rows), "callback extractor emitted duplicate rows")
    write_tsv(
        capture_root / "analysis/extracted-binding-candidates.tsv",
        "radeon-driver-extracted-binding-candidates-v1",
        ("extractor", "source_path", "line", "selector", "target_symbol", "source_sha256"),
        rows,
    )
    return rows, sorted(generated_edges)


def write_call_candidates(
    capture_root: Path,
    cflow_edges: list[tuple[str, str, str]],
    declared_rows: list[tuple[Any, ...]],
    generated_edges: list[tuple[str, str, str]],
) -> list[tuple[Any, ...]]:
    rows: set[tuple[Any, ...]] = set()
    for caller, callee, callee_kind in cflow_edges:
        rows.add(("lexical", caller, callee, "full-tree", "gnu-cflow", callee_kind))
    for row in declared_rows:
        rows.add(("declared-indirect", row[5], row[6], row[2], row[0], row[1]))
    for caller, callee, kind in generated_edges:
        rows.add(("extracted-indirect", caller, callee, "full-tree", kind, "candidate"))
    ordered = sorted(rows)
    write_tsv(
        capture_root / "analysis/call-candidates.tsv",
        "radeon-driver-call-candidates-v1",
        ("edge_kind", "caller", "callee", "partition", "provenance", "classification"),
        ordered,
    )
    return ordered


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
                line = source.count("\n", 0, match.start()) + 1
                normalized = " ".join(
                    source[match.start() : match.end()].split()
                )
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


def parse_lizard_rows(raw_path: Path) -> list[dict[str, Any]]:
    functions: list[dict[str, Any]] = []
    with raw_path.open("r", encoding="utf-8", newline="") as source:
        for row_number, row in enumerate(csv.reader(source), 1):
            require(len(row) == 11, f"lizard row {row_number} has {len(row)} fields")
            numeric = [int(row[index]) for index in (0, 1, 2, 3, 4, 9, 10)]
            functions.append(
                {
                    "nloc": numeric[0],
                    "ccn": numeric[1],
                    "token_count": numeric[2],
                    "parameter_count": numeric[3],
                    "length": numeric[4],
                    "path": row[6],
                    "symbol": row[7],
                    "start": numeric[5],
                    "end": numeric[6],
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
    functions = parse_lizard_rows(lizard_output)
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
        require(len(candidates) == 1, f"hazard {hazard.symbol} resolves to {len(candidates)} lizard functions")
        function = candidates[0]
        required_guard_identifier_count = 0
        for census in hazard.guard_identifier_census:
            guard_candidates = by_symbol.get(census.owner, [])
            require(
                len(guard_candidates) == 1,
                f"guard census owner {census.owner} resolves to {len(guard_candidates)} lizard functions",
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
                f"hazard {hazard.symbol} guard census owner {census.owner} lost identifiers: "
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
                len(indirect_in[hazard.symbol]) + len(indirect_out[hazard.symbol]),
                hazard.side_effect_class,
                len(hazard.guard_identifier_census),
                required_guard_identifier_count,
                hazard.evidence_rank,
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


def load_toolchain_closure(
    declaration: Path,
    manifest: Path,
) -> tuple[dict[str, Any], list[ToolchainClosureEntry]]:
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
        and declaration_data["schema"] == 1
        and declaration_data["family"] == "llvm"
        and isinstance(declaration_data["version"], str)
        and declaration_data["version"]
        and declaration_data["architecture"] == "x86_64_v3",
        "kernel toolchain declaration identity differs",
    )
    require(
        declaration_data["runtime_boundary"]
        == "exact-llvm-payload-with-recorded-host-runtime-closure",
        "kernel toolchain runtime boundary differs",
    )
    require(
        HEX_64.fullmatch(declaration_data["manifest_sha256"]) is not None
        and sha256_file(manifest) == declaration_data["manifest_sha256"],
        "kernel toolchain manifest identity differs",
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
            "special_files": False,
        },
        "kernel toolchain host policy differs",
    )

    columns, rows = read_tsv(manifest, "gororoba-kernel-toolchain-closure-v1")
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
    return declaration_data, entries


def validate_toolchain_payload(
    toolchain_prefix: Path,
    entries: list[ToolchainClosureEntry],
) -> None:
    require(toolchain_prefix.is_absolute(), "kernel toolchain root is not absolute")
    unresolved_components = [Path(toolchain_prefix.anchor)]
    for part in toolchain_prefix.parts[1:]:
        unresolved_components.append(unresolved_components[-1] / part)
    for component in unresolved_components:
        status = component.lstat()
        require(
            stat.S_ISDIR(status.st_mode),
            f"kernel toolchain ancestor is not a real directory: {component}",
        )
        require(
            status.st_uid == 0
            and status.st_gid == 0
            and stat.S_IMODE(status.st_mode) & 0o022 == 0,
            f"kernel toolchain ancestor ownership or mode differs: {component}",
        )
        require(
            not os.access(component, os.W_OK),
            f"kernel toolchain ancestor is runner writable: {component}",
        )
    resolved_prefix = toolchain_prefix.resolve(strict=True)
    require(
        resolved_prefix == toolchain_prefix,
        "kernel toolchain root resolves through an alias",
    )
    directories = {resolved_prefix}
    directories.update(resolved_prefix / Path(entry.relative_path).parent for entry in entries)
    for directory in sorted(directories):
        status = directory.lstat()
        require(stat.S_ISDIR(status.st_mode), f"kernel toolchain parent is not a directory: {directory}")
        require(status.st_uid == 0 and status.st_gid == 0, f"kernel toolchain parent ownership differs: {directory}")
        require(stat.S_IMODE(status.st_mode) & 0o022 == 0, f"kernel toolchain parent is group or other writable: {directory}")
        require(not os.access(directory, os.W_OK), f"kernel toolchain parent is runner writable: {directory}")
    for entry in entries:
        path = resolved_prefix / entry.relative_path
        status = path.lstat()
        require(status.st_uid == 0 and status.st_gid == 0, f"kernel toolchain entry ownership differs: {entry.relative_path}")
        require(f"{stat.S_IMODE(status.st_mode):04o}" == entry.mode, f"kernel toolchain entry mode differs: {entry.relative_path}")
        require(status.st_size == entry.size, f"kernel toolchain entry size differs: {entry.relative_path}")
        if entry.entry_type == "regular":
            require(stat.S_ISREG(status.st_mode), f"kernel toolchain entry is not regular: {entry.relative_path}")
            require(sha256_file(path) == entry.identity_sha256, f"kernel toolchain entry digest differs: {entry.relative_path}")
            resolved = path
        else:
            require(stat.S_ISLNK(status.st_mode), f"kernel toolchain entry is not a symlink: {entry.relative_path}")
            target = os.readlink(path)
            require(target == entry.link_target, f"kernel toolchain symlink target differs: {entry.relative_path}")
            require(sha256_bytes(target.encode("utf-8")) == entry.identity_sha256, f"kernel toolchain symlink identity differs: {entry.relative_path}")
            resolved = path.resolve(strict=True)
            try:
                resolved.relative_to(resolved_prefix)
            except ValueError as exc:
                raise SourceMapError(
                    f"kernel toolchain symlink escapes its root: {entry.relative_path}"
                ) from exc
        require(
            resolved.is_file() and sha256_file(resolved) == entry.resolved_sha256,
            f"kernel toolchain resolved payload differs: {entry.relative_path}",
        )
        if entry.kind == "command":
            require(os.access(resolved, os.X_OK), f"kernel toolchain command is not executable: {entry.logical_name}")


def validate_kernel_toolchain(
    release: str,
    bin_directory: Path,
    kernel_declaration: Path,
    toolchain_declaration: Path,
    toolchain_manifest: Path,
    expected_toolchain_manifest: str,
) -> tuple[
    list[tuple[Any, ...]],
    dict[str, str],
    Path,
    list[ToolchainClosureEntry],
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
    closure_declaration, closure_entries = load_toolchain_closure(
        toolchain_declaration,
        toolchain_manifest,
    )
    require(
        closure_declaration["manifest"] == expected_toolchain_manifest
        and closure_declaration["version"] == compiler_version == linker_version,
        f"kernel toolchain closure identity differs from policy or kernel declaration: {release}",
    )
    validate_toolchain_payload(toolchain_prefix, closure_entries)
    command_entries = {
        entry.logical_name: entry
        for entry in closure_entries
        if entry.kind == "command"
    }
    environment = {
        "PATH": f"{bin_directory}:/usr/bin:/bin",
        "LD_LIBRARY_PATH": str(library_directory),
    }
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
            env={**os.environ, **environment, "LC_ALL": "C", "LANG": "C", "TZ": "UTC"},
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
    return rows, environment, toolchain_prefix, closure_entries


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
    command_environment = {
        **os.environ,
        **environment,
        "LC_ALL": "C",
        "LANG": "C",
        "TZ": "UTC",
    }
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
            if stripped.startswith("linux-vdso.so.1 "):
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
            match = re.fullmatch(
                r"(\S+)\s+=>\s+(\S+)\s+\(0x[0-9a-fA-F]+\)",
                stripped,
            )
            require(match is not None, f"ldd emitted an unparsed row: {stripped}")
            requested_name, raw_path = match.groups()
            require(
                raw_path != "not",
                f"kernel tool runtime library is absent: {requested_name}",
            )
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
            "radeon-driver-kernel-toolchains-v1",
            (
                "kernel_release",
                "tool",
                "executable_name",
                "executable_sha256",
                "version_first_line",
                "version_output_sha256",
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
        require(
            toolchain_declaration.is_file() and toolchain_manifest.is_file(),
            f"kernel toolchain evidence is absent for {release}",
        )
        toolchain_bin = kernel_toolchain_bins.get(release)
        require(toolchain_bin is not None, f"kernel toolchain bin directory is not declared: {release}")
        (
            release_toolchain_rows,
            toolchain_environment,
            toolchain_prefix,
            closure_entries,
        ) = validate_kernel_toolchain(
            release,
            toolchain_bin,
            declaration,
            toolchain_declaration,
            toolchain_manifest,
            lane.toolchain_manifest,
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
                sys.executable,
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
                compiler_args: list[str] = []
                auto_conf = kernel_root / "include/config/auto.conf"
                compile_header = kernel_root / "include/generated/compile.h"
                compiler_text = ""
                if auto_conf.is_file():
                    compiler_text += auto_conf.read_text(encoding="utf-8", errors="replace")
                if compile_header.is_file():
                    compiler_text += compile_header.read_text(encoding="utf-8", errors="replace")
                if "CONFIG_CC_IS_CLANG=y" in compiler_text or "clang" in compiler_text.lower():
                    compiler_args.append("LLVM=1")
                prefix_maps = (
                    f"-ffile-prefix-map={work}={CANONICAL_PREPROCESSOR_WORK} "
                    f"-fmacro-prefix-map={work}={CANONICAL_PREPROCESSOR_WORK} "
                    f"-ffile-prefix-map={kernel_root}={CANONICAL_KERNEL_BUILD_ROOT} "
                    f"-fmacro-prefix-map={kernel_root}={CANONICAL_KERNEL_BUILD_ROOT} "
                    f"-ffile-prefix-map={toolchain_prefix}={CANONICAL_KERNEL_TOOLCHAIN} "
                    f"-fmacro-prefix-map={toolchain_prefix}={CANONICAL_KERNEL_TOOLCHAIN}"
                )
                kcflags = f"-I{include_trace} -include {header} {prefix_maps}"
                make_base = [
                    "make",
                    *compiler_args,
                    f"RADEON_BUILD_PROFILE={profile}",
                    f"KCFLAGS={kcflags}",
                    "-C",
                    str(kernel_root),
                    f"M={driver_work}",
                ]
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

    require(
        set(kernel_toolchain_bins) == requested_releases,
        "kernel toolchain release set differs from requested kernel roots",
    )
    write_tsv(
        capture_root / "metadata/kernel-toolchains.tsv",
        "radeon-driver-kernel-toolchains-v1",
        (
            "kernel_release",
            "tool",
            "executable_name",
            "executable_sha256",
            "version_first_line",
            "version_output_sha256",
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
    markers = {
        str(path.resolve()).encode("utf-8")
        for path in (*forbidden_paths, Path.home())
        if len(str(path.resolve())) > 4
    }
    markers.update(
        {
            b".radeon-source-map-",
            b"/home/",
            b"/root/",
            b"/opt/",
            b"/var/tmp/",
            b"/run/user/",
            b"/mnt/",
            b"/media/",
        }
    )
    for relative_text in sorted(regular_tree_files(root, "capture")):
        path = root / relative_text
        relative = Path(relative_text)
        if relative.parts and relative.parts[0] in {"source", "producer"}:
            continue
        if relative.parts[:2] in {
            ("metadata", "git-source-proof"),
            ("metadata", "git-source-input-proof"),
            ("metadata", "git-producer-proof"),
        }:
            continue
        content = path.read_bytes()
        leaked = {
            marker.decode("utf-8")
            for marker in markers
            if (
                re.search(
                    rb"(?<![A-Za-z0-9._+-])" + re.escape(marker),
                    content,
                )
                if marker.startswith(b"/")
                else marker in content
            )
        }
        for match in re.finditer(
            rb"(?<![A-Za-z0-9._+-])/tmp/[A-Za-z0-9._+/-]+",
            content,
        ):
            candidate = match.group(0)
            if not candidate.startswith((b"/tmp/source", b"/tmp/capture")):
                leaked.add(candidate.decode("utf-8", errors="replace"))
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
    policy = load_policy(policy_path)
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
    root_symbols = sorted(
        {root_symbol for partition in policy.partitions for root_symbol in partition.roots}
        | {hazard.symbol for hazard in policy.hazards}
    )
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
    require(len(binding_columns) == 10, "declared-binding columns differ")
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

    command_columns, command_rows = read_tsv(root / "metadata/command-metadata.tsv", "radeon-driver-command-metadata-v1")
    require(len(command_columns) == 8 and command_rows, "command metadata is incomplete")
    require(all(len(row) == 8 and row[3] == "0" for row in command_rows), "command metadata carries a failed command")
    for row in command_rows:
        json.loads(row[6])
        json.loads(row[7])

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

    toolchain_columns, toolchain_rows = read_tsv(
        root / "metadata/kernel-toolchains.tsv",
        "radeon-driver-kernel-toolchains-v1",
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
            == (root / f"producer/{lane.toolchain_manifest}").read_bytes(),
            f"retained toolchain closure differs from producer proof: {release}",
        )
        closure_declaration, closure_entries = load_toolchain_closure(
            closure_root / f"{release}.toml",
            closure_root / f"{release}.manifest.tsv",
        )
        require(
            closure_declaration["manifest"] == lane.toolchain_manifest,
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
            len(row) == 6
            and row[2] == row[1]
            and HEX_64.fullmatch(row[3]) is not None
            and bool(row[4])
            and HEX_64.fullmatch(row[5]) is not None
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

    _call_columns, call_rows = read_tsv(root / "analysis/call-candidates.tsv", "radeon-driver-call-candidates-v1")
    require(len(call_rows) == manifest["call_candidate_count"], "call candidate count differs")
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


def compare_captures(left: Path, right: Path, output: Path) -> dict[str, Any]:
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
            "coefficient_vector_delta_count": len(coefficient_rows),
            "semantic_limit": "normalized-candidate-delta-not-runtime-behavior",
        }
        write_text(stage / "comparison-manifest.json", json.dumps(summary, indent=2, sort_keys=True) + "\n")
        write_hash_ledger(stage)
        verify_hash_ledger(stage)
        stage.rename(output)
        print(
            f"Radeon source-map comparison: {len(file_rows)} files, "
            f"{len(call_rows)} call candidates, {len(binding_rows)} bindings"
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
    check("live policy closes partitions, hazards, bindings, and queries", bool(policy.partitions and policy.hazards and policy.bindings and policy.bounded_queries))
    toolchain_closures = []
    for lane in policy.kernel_lanes:
        closure_declaration, closure_entries = load_toolchain_closure(
            repository / lane.toolchain_declaration,
            repository / lane.toolchain_manifest,
        )
        toolchain_closures.append((lane, closure_declaration, closure_entries))
    check(
        "toolchain policies close every command, local library, and symlink target",
        len(toolchain_closures) == len(policy.kernel_lanes)
        and all(
            declaration["manifest"] == lane.toolchain_manifest
            and {entry.logical_name for entry in entries if entry.kind == "command"}
            == set(LLVM_KERNEL_TOOLS)
            and {entry.logical_name for entry in entries if entry.kind == "library"}
            == set(LLVM_KERNEL_LIBRARIES)
            for lane, declaration, entries in toolchain_closures
        ),
    )
    runtime_lane, _runtime_declaration, runtime_entries = toolchain_closures[0]
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
    tricky = 'const char *a = "/*"; .member = target,\nconst char *b = "//"; .other = next,\n'
    check("combined lexer preserves code after comment tokens inside strings", ".member = target" in strip_comments_and_literals(tricky) and ".other = next" in strip_comments_and_literals(tricky))
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

    with tempfile.TemporaryDirectory(prefix="radeon-source-map-selftest-") as temporary:
        temp = Path(temporary)
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
                live_lane.toolchain_manifest,
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

    selected_modes = sum(bool(item) for item in (args.self_test, args.verify, args.compare))
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
