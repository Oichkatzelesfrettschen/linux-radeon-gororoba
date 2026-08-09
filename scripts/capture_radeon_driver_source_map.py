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
import subprocess
import sys
import tarfile
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
class GuardContract:
    owner: str
    identifiers: tuple[str, ...]


@dataclass(frozen=True)
class Hazard:
    symbol: str
    side_effect_class: str
    guard_contracts: tuple[GuardContract, ...]
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
    rationale: str


@dataclass(frozen=True)
class KernelLane:
    release: str
    declaration: str
    manifest: str
    profiles: tuple[str, ...]


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
    require(source_root == source_root.strip("/") and ".." not in Path(source_root).parts, "invalid source root")
    max_source_files = data.get("max_source_files")
    max_source_bytes = data.get("max_source_bytes")
    require(isinstance(max_source_files, int) and max_source_files > 0, "max_source_files must be positive")
    require(isinstance(max_source_bytes, int) and max_source_bytes > 0, "max_source_bytes must be positive")
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
    reject_unknown(ctags_policy, {"allowed_stderr_patterns"}, "tool.ctags")
    global_version = string_value(global_policy, "version", "tool.gnu_global")
    global_config_sha256 = string_value(global_policy, "config_sha256", "tool.gnu_global")
    require(HEX_64.fullmatch(global_config_sha256) is not None, "GNU Global config digest is invalid")
    cflow_stderr = string_list(cflow_policy, "allowed_stderr_patterns", "tool.cflow")
    ctags_stderr = string_list(ctags_policy, "allowed_stderr_patterns", "tool.ctags")
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
        reject_unknown(kernel, {"release", "declaration", "manifest", "profiles"}, label)
        kernel_lanes.append(
            KernelLane(
                string_value(kernel, "release", label),
                string_value(kernel, "declaration", label),
                string_value(kernel, "manifest", label),
                string_list(kernel, "profiles", label),
            )
        )
    require(len({lane.release for lane in kernel_lanes}) == len(kernel_lanes), "kernel release repeats")

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
        reject_unknown(item, {"symbol", "side_effect_class", "guard_contracts", "evidence_rank"}, label)
        symbol = string_value(item, "symbol", label)
        require(C_IDENTIFIER.fullmatch(symbol) is not None, f"{label}.symbol is invalid")
        raw_guard_contracts = item.get("guard_contracts")
        require(isinstance(raw_guard_contracts, list), f"{label}.guard_contracts must be a list")
        guard_contracts: list[GuardContract] = []
        for guard_index, contract in enumerate(raw_guard_contracts):
            guard_label = f"{label}.guard_contracts[{guard_index}]"
            require(isinstance(contract, dict), f"{guard_label} must be a table")
            reject_unknown(contract, {"owner", "identifiers"}, guard_label)
            owner = string_value(contract, "owner", guard_label)
            identifiers = string_list(contract, "identifiers", guard_label)
            require(C_IDENTIFIER.fullmatch(owner) is not None, f"{guard_label}.owner is invalid")
            require(all(C_IDENTIFIER.fullmatch(identifier) for identifier in identifiers), f"{guard_label}.identifiers contains an invalid C identifier")
            require(len(set(identifiers)) == len(identifiers), f"{guard_label}.identifiers repeats a value")
            guard_contracts.append(GuardContract(owner, identifiers))
        require(len({contract.owner for contract in guard_contracts}) == len(guard_contracts), f"{label}.guard_contracts repeats an owner")
        hazards.append(
            Hazard(
                symbol,
                string_value(item, "side_effect_class", label),
                tuple(guard_contracts),
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
        reject_unknown(item, {"name", "paths", "pattern", "rationale"}, label)
        pattern = string_value(item, "pattern", label)
        try:
            re.compile(pattern, re.MULTILINE | re.DOTALL)
        except re.error as exc:
            raise SourceMapError(f"{label}.pattern is invalid: {exc}") from exc
        paths = string_list(item, "paths", label)
        require(all(path.startswith(source_root + "/") for path in paths), f"{label}.paths leave the source root")
        bounded_queries.append(
            BoundedQuery(
                string_value(item, "name", label),
                paths,
                pattern,
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
    raw = str(git_output(repository, "show", "-s", "--format=%ct", commit)).strip()
    require(raw.isdigit(), f"source commit timestamp is invalid: {raw}")
    return datetime.fromtimestamp(int(raw), UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


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
        return None
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
    require(len(tree_entries) == len(admitted) + 1, "source closure contains more than the repository-only .gitignore exclusion")

    archive = git_output(repository, "archive", "--format=tar", commit, policy.source_root, text=False)
    assert isinstance(archive, bytes)
    allowed = {entry[4]: entry for entry in admitted}
    seen: set[str] = set()
    source_entries: list[SourceEntry] = []
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        for member in tar.getmembers():
            if member.isdir():
                continue
            if member.name not in allowed:
                continue
            require(member.isfile(), f"archive carries a nonregular admitted member: {member.name}")
            require(member.name not in seen, f"archive repeats admitted member: {member.name}")
            extracted = tar.extractfile(member)
            require(extracted is not None, f"cannot read archive member: {member.name}")
            content = extracted.read()
            mode, _object_type, object_id, size, path = allowed[member.name]
            require(len(content) == size, f"archive size differs for {path}")
            target = destination / path
            write_bytes(target, content)
            target.chmod(0o755 if mode == "100755" else 0o644)
            source_entries.append(
                SourceEntry(path, mode, object_id, size, sha256_bytes(content), source_class(policy, path) or "")
            )
            seen.add(path)
    missing = sorted(set(allowed) - seen)
    require(not missing, f"archive omitted admitted paths: {', '.join(missing)}")
    return sorted(source_entries, key=lambda item: item.path.encode("utf-8"))


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
            "--languages=C",
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
    write_tsv(
        capture_root / "queries/ctags-root-coverage.tsv",
        "radeon-driver-ctags-root-coverage-v1",
        ("symbol", "ctags_record_count", "classification"),
        [
            (
                symbol,
                sum(1 for line in selected if line.split("\t", 1)[0] == symbol),
                "supplemental-index-omission" if symbol in missing else "indexed",
            )
            for symbol in symbols
        ],
    )
    return selected


def parse_cscope_rows(raw: bytes, query_kind: str, query_symbol: str) -> list[tuple[Any, ...]]:
    rows: list[tuple[Any, ...]] = []
    for row_number, line in enumerate(raw.decode("utf-8", errors="strict").splitlines(), 1):
        fields = line.split(maxsplit=3)
        require(len(fields) == 4, f"cscope {query_symbol} row {row_number} is malformed")
        source_path, function, line_text, source_text = fields
        require(line_text.isdigit() and int(line_text) > 0, f"cscope line is invalid for {query_symbol}")
        rows.append((query_kind, query_symbol, source_path, function, int(line_text), source_text.strip()))
    return rows


def build_cscope_index(
    capture_root: Path,
    source_root: Path,
    source_list: Path,
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
                    mode,
                    symbol,
                    "-f",
                    sandbox_database,
                ],
                source_root,
                f"queries/cscope/{query_kind}-{symbol}.txt",
                f"diagnostics/cscope/{query_kind}-{symbol}.stderr",
            )
            rows.extend(parse_cscope_rows(raw, query_kind, symbol))
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
    return [
        match
        for match in matches
        if match.start() < len(code_mask) and not code_mask[match.start()].isspace()
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


def run_bounded_queries(
    capture_root: Path,
    source_root: Path,
    entries: list[SourceEntry],
    policy: Policy,
) -> None:
    paths = [entry.path for entry in entries]
    summary_rows: list[tuple[Any, ...]] = []
    match_rows: list[tuple[Any, ...]] = []
    for query in policy.bounded_queries:
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
            comment_free = strip_comments(source)
            code_mask = strip_comments_and_literals(source)
            for match in expression.finditer(comment_free):
                if match.start() >= len(code_mask) or code_mask[match.start()].isspace():
                    continue
                line = source.count("\n", 0, match.start()) + 1
                normalized = " ".join(match.group(0).split())
                match_rows.append((query.name, path, line, sha256_bytes(normalized.encode("utf-8"))))
                match_count += 1
        summary_rows.append((query.name, len(selected), match_count, query.rationale))
    write_tsv(
        capture_root / "analysis/bounded-query-summary.tsv",
        "radeon-driver-bounded-query-summary-v1",
        ("query_name", "file_count", "match_count", "rationale"),
        summary_rows,
    )
    write_tsv(
        capture_root / "analysis/bounded-query-matches.tsv",
        "radeon-driver-bounded-query-matches-v1",
        ("query_name", "source_path", "line", "matched_text_sha256"),
        sorted(match_rows),
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
    guard_rows: list[tuple[Any, ...]] = []
    for hazard in policy.hazards:
        candidates = by_symbol.get(hazard.symbol, [])
        require(len(candidates) == 1, f"hazard {hazard.symbol} resolves to {len(candidates)} lizard functions")
        function = candidates[0]
        required_guard_count = 0
        for contract in hazard.guard_contracts:
            guard_candidates = by_symbol.get(contract.owner, [])
            require(
                len(guard_candidates) == 1,
                f"guard owner {contract.owner} resolves to {len(guard_candidates)} lizard functions",
            )
            guard_function = guard_candidates[0]
            guard_path = source_root / guard_function["path"]
            guard_source = guard_path.read_text(encoding="utf-8")
            guard_body = "\n".join(
                guard_source.splitlines()[
                    guard_function["start"] - 1 : guard_function["end"]
                ]
            )
            missing_guards = missing_code_identifiers(guard_body, contract.identifiers)
            require(
                not missing_guards,
                f"hazard {hazard.symbol} guard owner {contract.owner} lost identifiers: "
                + ", ".join(missing_guards),
            )
            required_guard_count += len(contract.identifiers)
            for identifier in contract.identifiers:
                guard_rows.append(
                    (
                        hazard.symbol,
                        contract.owner,
                        guard_function["path"],
                        guard_function["start"],
                        identifier,
                        sha256_file(guard_path),
                        "policy-declared-direct-function-body",
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
                len(hazard.guard_contracts),
                required_guard_count,
                hazard.evidence_rank,
            )
        )
    write_tsv(
        capture_root / "analysis/hazard-guard-contracts.tsv",
        "radeon-driver-hazard-guard-contracts-v1",
        (
            "hazard_symbol",
            "guard_owner_symbol",
            "source_path",
            "line",
            "required_identifier",
            "source_sha256",
            "provenance",
        ),
        guard_rows,
    )
    write_tsv(
        capture_root / "analysis/coefficient-vectors.tsv",
        "radeon-driver-coefficient-vectors-v1",
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
            "guard_owner_count",
            "required_guard_count",
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


def validate_kernel_toolchain(
    release: str,
    bin_directory: Path,
    declaration: Path,
) -> tuple[list[tuple[Any, ...]], dict[str, str], Path]:
    require(bin_directory.is_dir(), f"kernel toolchain bin directory is absent: {bin_directory}")
    toolchain_prefix = bin_directory.parent
    library_directory = toolchain_prefix / "lib"
    require(library_directory.is_dir(), f"kernel toolchain library directory is absent: {library_directory}")
    try:
        declaration_data = tomllib.loads(declaration.read_text(encoding="ascii"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise SourceMapError(f"kernel root declaration is invalid: {declaration}: {exc}") from exc
    compiler_version = declaration_data.get("compiler_version")
    linker_version = declaration_data.get("linker_version")
    require(
        declaration_data.get("compiler_family") == "clang"
        and isinstance(compiler_version, str)
        and compiler_version,
        f"kernel root declaration has no Clang identity: {release}",
    )
    require(
        declaration_data.get("linker_family") == "lld"
        and isinstance(linker_version, str)
        and linker_version,
        f"kernel root declaration has no LLD identity: {release}",
    )
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
        version_outputs[tool] = combined
        rows.append(
            (
                release,
                tool,
                executable.name,
                sha256_file(executable),
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
    return rows, environment, toolchain_prefix


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
        return []

    lane_by_release = {lane.release: lane for lane in policy.kernel_lanes}
    require(
        len(kernel_toolchain_bins) == len(kernel_roots)
        and set(kernel_toolchain_bins).issubset(lane_by_release),
        "kernel toolchain declarations do not match the requested kernel root count",
    )
    requested_releases: set[str] = set()
    results: list[dict[str, Any]] = []
    input_rows: list[tuple[Any, ...]] = []
    toolchain_rows: list[tuple[Any, ...]] = []
    for root_input in kernel_roots:
        kernel_root = root_input.resolve()
        release_path = kernel_root / "include/config/kernel.release"
        require(release_path.is_file(), f"kernel build root has no release: {kernel_root}")
        release = release_path.read_text(encoding="ascii").strip()
        lane = lane_by_release.get(release)
        require(lane is not None, f"kernel release is not declared by source-map policy: {release}")
        require(release not in requested_releases, f"kernel release repeats: {release}")
        requested_releases.add(release)
        declaration = repository / lane.declaration
        manifest = repository / lane.manifest
        require(declaration.is_file() and manifest.is_file(), f"kernel root evidence is absent for {release}")
        toolchain_bin = kernel_toolchain_bins.get(release)
        require(toolchain_bin is not None, f"kernel toolchain bin directory is not declared: {release}")
        release_toolchain_rows, toolchain_environment, toolchain_prefix = validate_kernel_toolchain(
            release,
            toolchain_bin,
            declaration,
        )
        toolchain_rows.extend(release_toolchain_rows)
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
    paths = sorted(
        (path for path in root.rglob("*") if path.is_file() and path != ledger),
        key=lambda path: path.relative_to(root).as_posix().encode("utf-8"),
    )
    rows = [f"{sha256_file(path)}  {path.relative_to(root).as_posix()}" for path in paths]
    write_text(ledger, "\n".join(rows) + "\n")


def verify_hash_ledger(root: Path) -> int:
    ledger = root / HASH_LEDGER
    require(ledger.is_file(), f"capture hash ledger is absent: {ledger}")
    declared: dict[str, str] = {}
    for line_number, line in enumerate(ledger.read_text(encoding="ascii").splitlines(), 1):
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n]+)", line)
        require(match is not None, f"hash ledger row {line_number} is malformed")
        digest, relative = match.groups()
        require(relative != HASH_LEDGER and not relative.startswith("./"), f"hash ledger row {line_number} has a forbidden path")
        require(relative not in declared, f"hash ledger repeats path: {relative}")
        require(not Path(relative).is_absolute() and ".." not in Path(relative).parts, f"hash ledger path escapes: {relative}")
        declared[relative] = digest
    actual_paths = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path != ledger
    }
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
    markers.add(b".radeon-source-map-")
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root)
        if relative.parts and relative.parts[0] == "source":
            continue
        content = path.read_bytes()
        leaked = [marker.decode("utf-8") for marker in markers if marker in content]
        require(
            not leaked,
            f"capture product {relative.as_posix()} retains host paths: "
            + ", ".join(sorted(leaked)),
        )


def verify_capture(root: Path) -> dict[str, Any]:
    require(root.is_dir(), f"capture directory is absent: {root}")
    verify_no_host_path_leaks(root, (root,))
    retained_count = verify_hash_ledger(root)
    manifest_path = root / "capture-manifest.json"
    require(manifest_path.is_file(), "capture manifest is absent")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceMapError(f"capture manifest is invalid: {exc}") from exc
    required_manifest = {
        "schema",
        "source_commit",
        "source_tree",
        "driver_tree",
        "producer_commit",
        "producer_tree",
        "source_commit_timestamp_utc",
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
    require(manifest["semantic_limit"] == "candidate-research-graph-not-runtime-reachability", "capture semantic limit differs")
    require(isinstance(manifest["preprocessor_lanes"], list), "capture preprocessor lanes are invalid")
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
            and isinstance(lane["translation_unit_count"], int)
            and lane["translation_unit_count"] > 0
            and isinstance(lane["module_path"], str)
            and isinstance(lane["module_sha256"], str)
            and HEX_64.fullmatch(lane["module_sha256"]) is not None
            and isinstance(lane["defined_symbol_count"], int)
            and lane["defined_symbol_count"] > 0
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
    require(
        isinstance(manifest["source_commit_timestamp_utc"], str)
        and UTC_TIMESTAMP.fullmatch(manifest["source_commit_timestamp_utc"]) is not None,
        "capture source commit timestamp is invalid",
    )

    policy_path = root / POLICY_PATH
    require(policy_path.is_file(), "retained source-map policy is absent")
    require(sha256_file(policy_path) == manifest["policy_sha256"], "retained source-map policy digest differs")
    policy = load_policy(policy_path)
    require(policy.capture_schema == manifest["schema"], "retained policy schema differs")

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

    columns, source_rows = read_tsv(root / "metadata/file-list.tsv", "radeon-driver-file-list-v1")
    require(
        columns == ["path", "source_class", "mode", "size", "object_id", "sha256"],
        "file-list columns differ",
    )
    require(len(source_rows) == manifest["source_file_count"], "file-list count differs from manifest")
    require(sha256_file(root / "metadata/file-list.tsv") == manifest["source_manifest_sha256"], "file-list digest differs")
    total_bytes = 0
    seen_paths: set[str] = set()
    source_entries: list[SourceEntry] = []
    for row_number, row in enumerate(source_rows, 3):
        require(len(row) == 6, f"file-list row {row_number} has {len(row)} fields")
        path, source_kind, mode, size_text, object_id, digest = row
        require(path not in seen_paths, f"file-list repeats path: {path}")
        seen_paths.add(path)
        require(size_text.isdigit(), f"file-list size is invalid: {path}")
        require(HEX_40.fullmatch(object_id) is not None and HEX_64.fullmatch(digest) is not None, f"file-list identity is invalid: {path}")
        source_path = root / "source" / path
        require(source_path.is_file() and not source_path.is_symlink(), f"retained source is absent or symlinked: {path}")
        require(source_path.stat().st_size == int(size_text), f"retained source size differs: {path}")
        require(sha256_file(source_path) == digest, f"retained source digest differs: {path}")
        total_bytes += int(size_text)
        source_entries.append(SourceEntry(path, mode, object_id, int(size_text), digest, source_kind))
    require(total_bytes == manifest["source_byte_count"], "retained source byte count differs")
    path_set = b"".join(path.encode("utf-8") + b"\0" for path in sorted(seen_paths))
    require(sha256_bytes(path_set) == manifest["source_path_set_sha256"], "retained source path-set digest differs")
    require(not any(path.endswith("_reg_safe.h") for path in seen_paths), "retained source carries a generated register header")

    lexical_columns, lexical_rows = read_tsv(root / "radeon-driver-lexical-map.tsv", LEXICAL_SCHEMA)
    require(
        lexical_columns == ["record_kind", "symbol", "source_path", "line", "source_sha256", "provenance"],
        "lexical-map columns differ",
    )
    require(len(lexical_rows) == manifest["lexical_row_count"], "lexical row count differs")
    file_rows = {row[2] for row in lexical_rows if row[0] == "file"}
    analyzer_files = {entry.path for entry in source_entries if entry.source_class in {"c", "header"}}
    require(file_rows == analyzer_files, "lexical map does not preserve the complete C and header denominator")

    binding_columns, binding_rows = read_tsv(root / "radeon-driver-declared-bindings.tsv", DECLARED_BINDING_SCHEMA)
    require(len(binding_columns) == 10, "declared-binding columns differ")
    require(len(binding_rows) == manifest["declared_binding_count"], "declared binding count differs")
    require(len(binding_rows) == sum(item.expected_matches for item in policy.bindings), "declared binding denominator differs from retained policy")
    entry_map = {entry.path: entry for entry in source_entries}
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

    producer_commit = str(git_output(repository, "rev-parse", "HEAD^{commit}")).strip()
    producer_tree = str(git_output(repository, "rev-parse", "HEAD^{tree}")).strip()
    source_commit = str(git_output(repository, "rev-parse", f"{treeish}^{{commit}}")).strip()
    source_tree = str(git_output(repository, "rev-parse", f"{source_commit}^{{tree}}")).strip()
    driver_tree = str(git_output(repository, "rev-parse", f"{source_commit}:{policy.source_root}")).strip()
    require(all(HEX_40.fullmatch(value) for value in (producer_commit, producer_tree, source_commit, source_tree, driver_tree)), "Git identity is malformed")
    tracked_status = str(git_output(repository, "status", "--porcelain", "--untracked-files=no"))
    require(not tracked_status, "producer checkout has tracked changes")
    for path in (POLICY_PATH, SCRIPT_PATH):
        tracked = subprocess.run(
            ["git", "-C", str(repository), "cat-file", "-e", f"HEAD:{path.as_posix()}"],
            check=False,
            capture_output=True,
        )
        require(tracked.returncode == 0, f"producer commit does not carry {path}")

    stage = Path(tempfile.mkdtemp(prefix=".radeon-source-map-", dir=output.parent))
    try:
        retained_policy = stage / POLICY_PATH
        retained_policy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(policy_absolute, retained_policy)
        closure = load_source_closure(repository, source_commit, policy.source_root)
        write_bytes(stage / "source-closure.toml", closure)
        feature_policy, _feature_data = parse_top_level_toml(repository, source_commit, "policy/build-features.toml")
        write_bytes(stage / "policy/build-features.toml", feature_policy)
        upstream_content, upstream_data = parse_top_level_toml(repository, source_commit, "UPSTREAM_BASE.toml")
        write_bytes(stage / "UPSTREAM_BASE.toml", upstream_content)
        upstream_base = upstream_data.get("commit")
        require(isinstance(upstream_base, str) and HEX_40.fullmatch(upstream_base) is not None, "upstream base commit is invalid")

        source_root = stage / "source"
        entries = export_source(repository, source_commit, policy, source_root)
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
        build_cscope_index(stage, source_root, source_list, symbols, recorder)
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
            "source_commit": source_commit,
            "source_tree": source_tree,
            "driver_tree": driver_tree,
            "producer_commit": producer_commit,
            "producer_tree": producer_tree,
            "source_commit_timestamp_utc": commit_timestamp_utc(repository, source_commit),
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

        coefficient_columns, left_coefficients = row_set(left / "analysis/coefficient-vectors.tsv", "radeon-driver-coefficient-vectors-v1")
        right_coefficient_columns, right_coefficients = row_set(right / "analysis/coefficient-vectors.tsv", "radeon-driver-coefficient-vectors-v1")
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
    tricky = 'const char *a = "/*"; .member = target,\nconst char *b = "//"; .other = next,\n'
    check("combined lexer preserves code after comment tokens inside strings", ".member = target" in strip_comments_and_literals(tricky) and ".other = next" in strip_comments_and_literals(tricky))
    guard_fixture = 'if (real_guard) return; /* comment_guard */ const char *text = "literal_guard";\n'
    check(
        "guard contracts accept code identifiers and reject prose decoys",
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
    check("source classifier excludes repository-only .gitignore", source_class(policy, f"{policy.source_root}/.gitignore") is None)

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
        portable_root = temp / "portable"
        write_text(portable_root / "metadata/example.tsv", "tool\t/tmp/source\n")
        accepts(
            "capture path policy accepts canonical sandbox paths",
            lambda: verify_no_host_path_leaks(portable_root, (portable_root,)),
        )
        write_text(
            portable_root / "metadata/example.tsv",
            f"tool\t{portable_root}\n",
        )
        rejects(
            "capture path policy rejects a retained host path",
            lambda: verify_no_host_path_leaks(portable_root, (portable_root,)),
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
    args = parser.parse_args()

    selected_modes = sum(bool(item) for item in (args.self_test, args.verify, args.compare))
    if selected_modes > 1:
        parser.error("select only one of --self-test, --verify, or --compare")
    if args.self_test:
        repository = resolve_repository(args.repository)
        policy_path = args.policy if args.policy.is_absolute() else repository / args.policy
        return self_test(repository, policy_path)
    if args.verify:
        if args.output or args.kernel_build_root or args.kernel_toolchain_bin:
            parser.error(
                "--verify does not accept --output, --kernel-build-root, or --kernel-toolchain-bin"
            )
        manifest = verify_capture(args.verify)
        print(
            f"Radeon driver source map verified: {manifest['source_commit']} "
            f"{manifest['source_file_count']} files"
        )
        return 0
    if args.compare:
        if not args.output:
            parser.error("--compare requires --output")
        if args.kernel_build_root or args.kernel_toolchain_bin:
            parser.error(
                "--compare does not accept --kernel-build-root or --kernel-toolchain-bin"
            )
        compare_captures(args.compare[0], args.compare[1], args.output.resolve())
        return 0
    if not args.output:
        parser.error("live capture requires --output")
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
