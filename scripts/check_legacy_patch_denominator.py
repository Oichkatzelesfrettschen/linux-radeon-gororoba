#!/usr/bin/env python3
"""Prove the legacy patch denominator and exceptional supersession ledger.

The pinned transition inputs contain 70 declared patches and 124 effect atoms.
The exceptional ledger adds baked-base patch 0001 and two physical 0023 files.
Together they form 72 numeric IDs and 73 physical files. The checker also
proves 0001 maps to B13, all transition atoms have one M01 through M24
allocation, the later deployed-source 0023 rebase supersedes the original,
neither 0023 is declared or allocated, and neither historical experiment
appears in active source.

The retained patch-set manifest enumerates every recursive patch path from the
pinned radeon-custom tree and applies one exact top-level numeric selector. It
binds each selected path to its Git blob and SHA-256. Local source checks do
not turn those historical bytes into active behavior.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import re
import shutil
import sys
import tempfile
from pathlib import Path

import check_rs4xx_gart_cache_policy as gart_policy

LEDGER = Path("docs/legacy-patch-denominator-supersession.tsv")
TRANSITIONS = Path("migration/input/legacy-patch-transitions.tsv")
MECHANISM_MAP = Path("migration/input/legacy-patch-mechanism-map.tsv")
ASSIGNMENTS = Path("docs/reconstruction-effect-assignments.tsv")
PLAN = Path("docs/reconstruction-commit-plan.tsv")
BASE_MAP = Path("migration/input/base-delta-map.tsv")
BASE_ASSIGNMENTS = Path("docs/base-reconstruction-effect-assignments.tsv")
INPUT_INVENTORY = Path("docs/reconstruction-input-inventory.tsv")
PATCH_SET_MANIFEST = Path("docs/legacy-rs480-patch-set.tsv")
RADEON_SUBTREE = Path("drivers/gpu/drm/radeon")
PINNED_SOURCE_COMMIT = "210e2b06c0266e316f08eb0b2b3e9832884c43de"
PATCH_TREE = "ae78a215fffcc2f6cc40a89169830f7b875f815b"
PATCH_LIST_SHA256 = "e01359cf7b484df13ff0e0d5475988093ecf6575c662bff81d6042ef165b6c86"
PATCH_MANIFEST_SHA256 = (
    "8426ad92e44695eff420e86d33dc6baf468b65dd90e9b605d7722f9d275605be"
)
PATCH_SELECTOR_TEXT = "^patches/rs480/[0-9]{4}-[^/]+[.]patch$"
PATCH_SELECTOR = re.compile(PATCH_SELECTOR_TEXT)
EXCLUDED_DRAFT = (
    "patches/rs480/drafts/rad06-tcl-bypass-vtx-output-crosscheck.draft.patch"
)
ORIGINAL_0023 = "0023-rs480-gart-snoop-and-atomic-rmw-experiment.patch"
CORRECTED_0023 = "0023-rs480-gart-snoop-atomic-rmw-f3x40-mca-nb-control.patch"
PATCH_0001 = "0001-rs480-safe-regs-debugfs.patch"
PATCH_0001_BLOB = "f2732fae3e7c9e53fd5243750f75a3be46bc80a2"
PATCH_0001_SHA256 = "f7db1a39d7b2138940dcf7a90d4cedf4cffe6b5cea02c94e47302cc5d2b7b99d"
ORIGINAL_0023_BLOB = "2389f0a355d0596047814bd25ad0836f0fd755e4"
CORRECTED_0023_BLOB = "7b7a8cb2e5ef4e4416c6ed872c85004697c623a0"
ORIGINAL_0023_DISPOSITION = (
    "superseded by deployed-source rebase and excluded historical experiment"
)
CORRECTED_0023_DISPOSITION = "excluded deployed-source rebase"
ORIGINAL_0023_SHA256 = (
    "b141532fbd0ec17f4a155d3699f40cdd2a33873ef3ed3848812ac4db98077feb"
)
CORRECTED_0023_SHA256 = (
    "73ef697d9f37c1f977435e4c89406abcd13edb732fbf5aec503bd9340ecf6b0f"
)
INACTIVE_TOKENS = (
    "radeon_rs480_gart_snoop",
    "radeon_rs480_atomic_rmw_report",
    "radeon_rs480_snoop_status",
)
INPUT_PATHS = (
    LEDGER,
    TRANSITIONS,
    MECHANISM_MAP,
    ASSIGNMENTS,
    PLAN,
    BASE_MAP,
    BASE_ASSIGNMENTS,
    INPUT_INVENTORY,
    PATCH_SET_MANIFEST,
)


class DenominatorError(Exception):
    """A denominator count, allocation, supersession, or source fact differs."""


def read_tsv(path: Path) -> list[dict[str, str]]:
    try:
        text = path.read_text(encoding="ascii")
    except FileNotFoundError as exc:
        raise DenominatorError(f"missing input {path}") from exc
    content = "\n".join(line for line in text.splitlines() if not line.startswith("#"))
    reader = csv.DictReader(io.StringIO(content), delimiter="\t")
    if not reader.fieldnames:
        raise DenominatorError(f"{path}: missing header")
    return list(reader)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DenominatorError(message)


def record_map(root: Path) -> dict[str, dict[str, str]]:
    rows = read_tsv(root / LEDGER)
    records: dict[str, dict[str, str]] = {}
    for row in rows:
        record = row["record"]
        require(record not in records, f"{LEDGER}: duplicate record {record}")
        records[record] = row
    expected = {
        "numeric-id-denominator",
        "physical-file-denominator",
        "declared-transition-denominator",
        "transition-effect-atom-denominator",
        "approved-native-boundary-denominator",
        "exception-0001",
        "exception-0023-original",
        "exception-0023-corrected",
    }
    require(set(records) == expected, f"{LEDGER}: record set differs")
    return records


def check_patch_set_manifest(root: Path) -> dict[str, dict[str, str]]:
    """Return the selected patch set after proving the recursive denominator."""

    path = root / PATCH_SET_MANIFEST
    try:
        text = path.read_text(encoding="ascii")
    except FileNotFoundError as exc:
        raise DenominatorError(f"missing input {path}") from exc
    required_metadata = {
        "# source-repository: Oichkatzelesfrettschen/radeon-custom",
        f"# source-commit: {PINNED_SOURCE_COMMIT}",
        f"# source-tree: {PATCH_TREE}",
        f"# selector-regex: {PATCH_SELECTOR_TEXT}",
    }
    require(
        required_metadata.issubset(set(text.splitlines())),
        f"{PATCH_SET_MANIFEST}: source or selector metadata differs",
    )
    rows = read_tsv(path)
    expected_fields = {
        "path",
        "numeric_id",
        "git_blob_oid",
        "sha256",
        "denominator_selected",
        "selection_reason",
    }
    require(len(rows) == 74, f"{PATCH_SET_MANIFEST}: recursive patch count differs")
    require(
        all(set(row) == expected_fields for row in rows),
        f"{PATCH_SET_MANIFEST}: columns differ from schema",
    )

    by_path: dict[str, dict[str, str]] = {}
    selected: dict[str, dict[str, str]] = {}
    for row in rows:
        patch_path = row["path"]
        require(
            patch_path not in by_path, f"{PATCH_SET_MANIFEST}: duplicate {patch_path}"
        )
        by_path[patch_path] = row
        require(
            re.fullmatch(r"[0-9a-f]{40}", row["git_blob_oid"]) is not None,
            f"{patch_path}: invalid Git blob OID",
        )
        require(
            re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is not None,
            f"{patch_path}: invalid SHA-256",
        )
        selector_match = PATCH_SELECTOR.fullmatch(patch_path)
        expected_selected = selector_match is not None
        require(
            row["denominator_selected"] == str(expected_selected).lower(),
            f"{patch_path}: selected flag disagrees with exact selector",
        )
        expected_reason = (
            "top-level numeric patch selector"
            if expected_selected
            else "nested non-numeric draft outside selector"
        )
        require(
            row["selection_reason"] == expected_reason,
            f"{patch_path}: selection reason differs",
        )
        expected_id = (
            selector_match.group(0).split("/")[-1][:4] if selector_match else ""
        )
        require(row["numeric_id"] == expected_id, f"{patch_path}: numeric ID differs")
        if expected_selected:
            selected[patch_path] = row

    excluded = set(by_path) - set(selected)
    require(
        excluded == {EXCLUDED_DRAFT},
        f"{PATCH_SET_MANIFEST}: recursive exclusions differ from the one nested draft",
    )
    require(len(selected) == 73, "top-level numeric patch denominator differs from 73")
    path_list = "".join(f"{patch_path}\n" for patch_path in sorted(selected))
    require(
        hashlib.sha256(path_list.encode("ascii")).hexdigest() == PATCH_LIST_SHA256,
        "selected patch path-list SHA-256 differs",
    )
    numeric_ids = [int(row["numeric_id"]) for row in selected.values()]
    require(set(numeric_ids) == set(range(1, 73)), "selected numeric IDs differ")
    require(numeric_ids.count(23) == 2, "selected patch ID 0023 is not duplicated once")
    require(
        all(
            numeric_ids.count(identifier) == 1
            for identifier in set(range(1, 73)) - {23}
        ),
        "a selected numeric patch ID other than 0023 is duplicated",
    )
    require(
        sha256(path) == PATCH_MANIFEST_SHA256,
        f"{PATCH_SET_MANIFEST}: complete path, Git OID, and SHA-256 manifest differs",
    )
    return selected


def numeric_id(patch: str) -> int:
    prefix = patch.split("-", 1)[0]
    require(len(prefix) == 4 and prefix.isdigit(), f"invalid patch ID in {patch}")
    return int(prefix)


def check_denominators(
    root: Path,
    records: dict[str, dict[str, str]],
    selected_paths: dict[str, dict[str, str]],
) -> None:
    transitions = read_tsv(root / TRANSITIONS)
    require(len(transitions) == 70, "declared transition count differs from 70")
    require(
        [int(row["patch_index"]) for row in transitions] == list(range(70)),
        "transition indexes differ from 0 through 69",
    )
    transition_patches = [row["patch"] for row in transitions]
    require(
        len(set(transition_patches)) == 70,
        "declared transition patch names are not unique",
    )
    transition_ids = {numeric_id(patch) for patch in transition_patches}
    require(
        transition_ids == (set(range(2, 73)) - {23}),
        "declared transition IDs are not 0002 through 0072 excluding 0023",
    )
    selected_by_file = {
        patch_path.rsplit("/", 1)[-1]: row for patch_path, row in selected_paths.items()
    }
    require(
        len(selected_by_file) == len(selected_paths),
        "selected top-level patch basenames are not unique",
    )
    for transition in transitions:
        manifest_row = selected_by_file.get(transition["patch"])
        require(
            manifest_row is not None,
            f"declared transition absent from selected patch set: {transition['patch']}",
        )
        require(
            manifest_row["sha256"] == transition["patch_sha256"],
            f"declared transition SHA-256 differs: {transition['patch']}",
        )

    mechanism_rows = read_tsv(root / MECHANISM_MAP)
    require(len(mechanism_rows) == 124, "mechanism-map atom count differs from 124")
    atoms = [row["effect_atom"] for row in mechanism_rows]
    require(len(set(atoms)) == 124, "mechanism-map effect atoms are not unique")
    require(
        {row["patch"] for row in mechanism_rows} == set(transition_patches),
        "mechanism-map patches differ from declared transitions",
    )

    assignments = read_tsv(root / ASSIGNMENTS)
    require(len(assignments) == 124, "approved assignment count differs from 124")
    require(
        {row["effect_atom"] for row in assignments} == set(atoms),
        "approved assignments do not cover each effect atom exactly once",
    )

    plan = read_tsv(root / PLAN)
    plan_ids = {row["commit_id"] for row in plan}
    expected_plan = {f"M{index:02d}" for index in range(1, 25)}
    require(plan_ids == expected_plan, "approved native boundaries differ from M01-M24")

    exceptions = [
        records["exception-0001"],
        records["exception-0023-original"],
        records["exception-0023-corrected"],
    ]
    expected_exception_identity = {
        "exception-0001": ("0001", PATCH_0001),
        "exception-0023-original": ("0023", ORIGINAL_0023),
        "exception-0023-corrected": ("0023", CORRECTED_0023),
    }
    for record, (expected_id, expected_file) in expected_exception_identity.items():
        row = records[record]
        require(row["count"] == "1", f"{record}: exceptional physical count differs")
        require(row["numeric_id"] == expected_id, f"{record}: numeric ID differs")
        require(row["patch_file"] == expected_file, f"{record}: patch filename differs")
    exceptional_files = {row["patch_file"] for row in exceptions}
    require(
        set(selected_by_file) == set(transition_patches) | exceptional_files,
        "selected physical patch set differs from transitions plus exceptions",
    )
    for row in exceptions:
        manifest_row = selected_by_file[row["patch_file"]]
        require(
            manifest_row["sha256"] == row["sha256"],
            f"{row['record']}: manifest and ledger SHA-256 differ",
        )
        expected_blobs = {
            PATCH_0001: PATCH_0001_BLOB,
            ORIGINAL_0023: ORIGINAL_0023_BLOB,
            CORRECTED_0023: CORRECTED_0023_BLOB,
        }
        require(
            manifest_row["git_blob_oid"] == expected_blobs[row["patch_file"]],
            f"{row['record']}: manifest Git blob OID differs",
        )
    physical_ids = {int(row["numeric_id"]) for row in selected_paths.values()}
    require(physical_ids == set(range(1, 73)), "numeric ID denominator differs from 72")
    require(
        len(selected_paths) == 73,
        "physical patch denominator differs from 73",
    )
    expected_counts = {
        "numeric-id-denominator": "72",
        "physical-file-denominator": "73",
        "declared-transition-denominator": "70",
        "transition-effect-atom-denominator": "124",
        "approved-native-boundary-denominator": "24",
    }
    for record, count in expected_counts.items():
        require(
            records[record]["count"] == count, f"{record}: count differs from {count}"
        )

    require(
        records["numeric-id-denominator"]["source_tree_or_list_hash"] == PATCH_TREE,
        "physical patch tree object differs",
    )
    require(
        records["physical-file-denominator"]["source_tree_or_list_hash"]
        == PATCH_LIST_SHA256,
        "physical patch path-list hash differs",
    )
    require(
        PATCH_MANIFEST_SHA256 in records["physical-file-denominator"]["authority"],
        "physical patch authority omits the complete manifest SHA-256",
    )
    require(
        records["declared-transition-denominator"]["source_tree_or_list_hash"]
        == sha256(root / TRANSITIONS),
        "transition ledger hash differs",
    )
    require(
        records["transition-effect-atom-denominator"]["source_tree_or_list_hash"]
        == sha256(root / MECHANISM_MAP),
        "mechanism-map hash differs",
    )
    require(
        records["approved-native-boundary-denominator"]["source_tree_or_list_hash"]
        == sha256(root / PLAN),
        "approved plan hash differs",
    )


def check_base_owner(root: Path, records: dict[str, dict[str, str]]) -> None:
    base_rows = read_tsv(root / BASE_MAP)
    patch_rows = [
        row
        for row in base_rows
        if "0001-radeon-rs480-safe-regs-debugfs.patch" in row["legacy_origin"]
    ]
    require(bool(patch_rows), "base map has no patch 0001 materialization")
    hunk_ids = {row["hunk_id"] for row in patch_rows}
    assignments = {
        row["effect_atom"]: row["commit_id"]
        for row in read_tsv(root / BASE_ASSIGNMENTS)
    }
    require(
        all(assignments.get(hunk_id) == "B13" for hunk_id in hunk_ids),
        "patch 0001 base atoms are not all owned by B13",
    )
    row = records["exception-0001"]
    require(row["patch_file"] == PATCH_0001, "exception 0001 filename differs")
    require(row["sha256"] == PATCH_0001_SHA256, "exception 0001 SHA-256 differs")
    require(
        row["source_tree_or_list_hash"] == PATCH_0001_BLOB,
        "exception 0001 Git blob OID differs",
    )
    require(row["reconstruction_owner"] == "B13", "exception 0001 owner is not B13")
    require(
        row["legacy_patch_applied_as_transition"] == "none",
        "exception 0001 incorrectly claims transition application",
    )
    for phrase in (
        "sources and installs this file",
        "PATCH[] starts at 0002",
        "baked into the legacy base",
        "not applied as a transition",
    ):
        require(
            phrase in row["non_port_reason"],
            f"exception 0001 package account omits {phrase!r}",
        )


def check_supersession(records: dict[str, dict[str, str]]) -> None:
    original = records["exception-0023-original"]
    corrected = records["exception-0023-corrected"]
    require(original["patch_file"] == ORIGINAL_0023, "original 0023 filename differs")
    require(
        corrected["patch_file"] == CORRECTED_0023,
        "corrected 0023 filename differs",
    )
    require(
        original["sha256"] == ORIGINAL_0023_SHA256,
        "original 0023 SHA-256 differs",
    )
    require(
        corrected["sha256"] == CORRECTED_0023_SHA256,
        "corrected 0023 SHA-256 differs",
    )
    require(
        original["source_tree_or_list_hash"] == ORIGINAL_0023_BLOB,
        "original 0023 Git blob OID differs",
    )
    require(
        corrected["source_tree_or_list_hash"] == CORRECTED_0023_BLOB,
        "corrected 0023 Git blob OID differs",
    )
    require(
        original["superseded_by"] == CORRECTED_0023,
        "original 0023 does not point to the corrected superseding file",
    )
    require(
        original["disposition"] == ORIGINAL_0023_DISPOSITION,
        "original 0023 disposition differs from the exact superseded state",
    )
    require(
        corrected["disposition"] == CORRECTED_0023_DISPOSITION,
        "corrected 0023 disposition differs from the exact excluded state",
    )
    for row in (original, corrected):
        require(row["reconstruction_owner"] == "none", "0023 has a native owner")
        require(
            row["legacy_patch_applied_as_transition"] == "none",
            "0023 incorrectly claims transition application",
        )
    original_reason = original["non_port_reason"]
    for phrase in (
        "already names F3x40 offset 0x40",
        "explicitly rejects F3x44",
        "deployed-0.3 source rebase",
        "wires rs480_snoop_status_debugfs_init into rs400_init",
        "contradicted by the pinned original bytes",
    ):
        require(phrase in original_reason, f"original 0023 account omits {phrase!r}")
    reason = corrected["non_port_reason"]
    for phrase in (
        "does not supply a register-offset correction relative to the pinned original",
        "AGP_MODE_CNTL = 0x00400000",
        "GART remained not-ready",
        "GTT and GEM allocations failed",
        "canonical reported operational negative",
        "raw decision-grade replay remains unavailable",
        "does not independently prove silicon behavior",
        "F3x40 = 0x00043bff",
        "MCA error reporting",
        "does not enable atomic execution",
        "outside the 70 declared transitions and 124 allocated atoms",
    ):
        require(phrase in reason, f"corrected 0023 non-port reason omits {phrase!r}")


def check_provenance(root: Path, records: dict[str, dict[str, str]]) -> None:
    inventory = read_tsv(root / INPUT_INVENTORY)
    owned = {
        row["copied_path"]: row
        for row in inventory
        if row["source_repository"] == "Oichkatzelesfrettschen/radeon-custom"
    }
    for path in (TRANSITIONS, MECHANISM_MAP, BASE_MAP):
        row = owned.get(str(path))
        require(row is not None, f"{path}: absent from reconstruction input inventory")
        require(
            row["source_commit"] == PINNED_SOURCE_COMMIT,
            f"{path}: source commit differs from the denominator ledger",
        )
        require(row["sha256"] == sha256(root / path), f"{path}: inventory hash differs")
    for record in records.values():
        if record["source_commit"]:
            require(
                record["source_commit"] == PINNED_SOURCE_COMMIT,
                f"{record['record']}: source commit differs",
            )


def check_inactive_source(root: Path) -> None:
    source_root = root / RADEON_SUBTREE
    require(source_root.is_dir(), f"missing Radeon source {source_root}")
    source_paths = [
        path
        for path in sorted(source_root.rglob("*"))
        if path.is_file() and path.suffix in {".c", ".h"}
    ]
    require(bool(source_paths), f"no Radeon C source under {source_root}")
    joined = b"\n".join(path.read_bytes() for path in source_paths)
    for token in INACTIVE_TOKENS:
        require(
            token.encode("ascii") not in joined,
            f"excluded historical token is active: {token}",
        )
    try:
        gart_policy.check_global_snoop_disable(root)
    except gart_policy.PolicyError as exc:
        raise DenominatorError(f"active global snoop policy differs: {exc}") from exc


def check_tree(root: Path) -> None:
    records = record_map(root)
    selected_paths = check_patch_set_manifest(root)
    check_denominators(root, records, selected_paths)
    check_base_owner(root, records)
    check_supersession(records)
    check_provenance(root, records)
    check_inactive_source(root)


def copy_fixture(source_root: Path, fixture_root: Path) -> None:
    for relative in INPUT_PATHS:
        destination = fixture_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_root / relative, destination)
    source = fixture_root / RADEON_SUBTREE / "rs400.c"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(
        "int rs400_gart_enable(void)\n"
        "{\n"
        "\tWREG32_MC(RS480_AGP_MODE_CNTL,\n"
        "\t\t  (1 << RS480_REQ_TYPE_SNOOP_SHIFT) | "
        "RS480_REQ_TYPE_SNOOP_DIS);\n"
        "\treturn 0;\n"
        "}\n",
        encoding="ascii",
    )


def remove_last_data_row(path: Path) -> None:
    lines = path.read_text(encoding="ascii").splitlines()
    path.write_text("\n".join(lines[:-1]) + "\n", encoding="ascii")


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="ascii")
    require(text.count(old) == 1, f"selftest fixture does not contain one {old!r}")
    path.write_text(text.replace(old, new, 1), encoding="ascii")


def selftest(source_root: Path, fixture_root: Path) -> int:
    copy_fixture(source_root, fixture_root)
    try:
        check_tree(fixture_root)
    except DenominatorError as exc:
        print(f"selftest known-good REJECTED: {exc}", file=sys.stderr)
        return 1
    print("selftest known-good accepted: denominator and supersession ledger")

    mutations = (
        (
            "physical count changed",
            LEDGER,
            "physical-file-denominator\t73",
            "physical-file-denominator\t72",
        ),
        ("recursive patch manifest row removed", PATCH_SET_MANIFEST, None, None),
        (
            "nested draft admitted by denominator",
            PATCH_SET_MANIFEST,
            (
                f"{EXCLUDED_DRAFT}\t\te10fc869288d9b1c03ff31d11dcb1aade0770e95\t"
                "ca74fa2f3ec9c5a851df57aef795115b1cc5032e6fc1348b7758cc644cb4da6e\tfalse\t"
                "nested non-numeric draft outside selector"
            ),
            (
                f"{EXCLUDED_DRAFT}\t0023\te10fc869288d9b1c03ff31d11dcb1aade0770e95\t"
                "ca74fa2f3ec9c5a851df57aef795115b1cc5032e6fc1348b7758cc644cb4da6e\ttrue\t"
                "top-level numeric patch selector"
            ),
        ),
        ("transition removed", TRANSITIONS, None, None),
        ("effect atom removed", MECHANISM_MAP, None, None),
        ("allocation removed", ASSIGNMENTS, None, None),
        ("native boundary removed", PLAN, None, None),
        (
            "0001 owner changed",
            BASE_ASSIGNMENTS,
            "2487b056b005759f\tB13\t",
            "2487b056b005759f\tB12\t",
        ),
        ("0001 ledger hash changed", LEDGER, PATCH_0001_SHA256, "2" * 64),
        ("0001 ledger blob changed", LEDGER, PATCH_0001_BLOB, "3" * 40),
        (
            "0001 manifest hash changed",
            PATCH_SET_MANIFEST,
            PATCH_0001_SHA256,
            "4" * 64,
        ),
        (
            "0001 manifest blob changed",
            PATCH_SET_MANIFEST,
            PATCH_0001_BLOB,
            "5" * 40,
        ),
        (
            "ordinary transition manifest blob changed",
            PATCH_SET_MANIFEST,
            "c54244c5349c307899fe1205384805f90719e6d5",
            "0" * 40,
        ),
        (
            "0001 package account inverted",
            LEDGER,
            "sources and installs this file",
            "does not source or install this file",
        ),
        ("original 0023 hash changed", LEDGER, ORIGINAL_0023_SHA256, "0" * 64),
        ("corrected 0023 hash changed", LEDGER, CORRECTED_0023_SHA256, "1" * 64),
        (
            "original 0023 disposition sign inverted",
            LEDGER,
            ORIGINAL_0023_DISPOSITION,
            "not superseded but excluded historical experiment",
        ),
        (
            "original 0023 register account inverted",
            LEDGER,
            "already names F3x40 offset 0x40 and explicitly rejects F3x44",
            "names F3x44 and does not identify F3x40",
        ),
        (
            "corrected 0023 disposition sign inverted",
            LEDGER,
            CORRECTED_0023_DISPOSITION,
            "not excluded corrected historical experiment",
        ),
        (
            "corrected 0023 numeric identity changed",
            LEDGER,
            "exception-0023-corrected\t1\t0023\t",
            "exception-0023-corrected\t1\t0001\t",
        ),
        ("0023 supersession removed", LEDGER, f"\t{CORRECTED_0023}\tnone", "\t\tnone"),
        (
            "0023 marked transition-applied",
            LEDGER,
            f"{CORRECTED_0023_SHA256}\t{CORRECTED_0023_DISPOSITION}\tnone\t\tnone",
            f"{CORRECTED_0023_SHA256}\t{CORRECTED_0023_DISPOSITION}\tnone\t\tyes",
        ),
        (
            "0023 hardware reason removed",
            LEDGER,
            "GART remained not-ready",
            "GART state was unresolved",
        ),
        (
            "global snoop experiment activated",
            RADEON_SUBTREE / "rs400.c",
            "\tWREG32_MC",
            "\tradeon_rs480_gart_snoop = 1;\n\tWREG32_MC",
        ),
        (
            "later write re-enables global snooping",
            RADEON_SUBTREE / "rs400.c",
            "\treturn 0;\n}",
            (
                "\tWREG32_MC(RS480_AGP_MODE_CNTL,\n"
                "\t\t  (1 << RS480_REQ_TYPE_SNOOP_SHIFT));\n"
                "\treturn 0;\n}"
            ),
        ),
    )
    failures = 0
    for label, relative, old, new in mutations:
        shutil.rmtree(fixture_root)
        fixture_root.mkdir()
        copy_fixture(source_root, fixture_root)
        path = fixture_root / relative
        if old is None:
            remove_last_data_row(path)
        else:
            try:
                replace_once(path, old, new or "")
            except DenominatorError as exc:
                print(f"selftest fixture error: {label}: {exc}", file=sys.stderr)
                failures += 1
                continue
        try:
            check_tree(fixture_root)
        except DenominatorError:
            print(f"selftest known-bad rejected: {label}")
        else:
            print(f"selftest known-bad ACCEPTED: {label}", file=sys.stderr)
            failures += 1
    if failures:
        print(f"selftest: {failures} fixture(s) misclassified", file=sys.stderr)
        return 1
    print(f"selftest: 1 good and {len(mutations)} bad fixtures classified")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="mutate copied denominator inputs and require rejection",
    )
    args = parser.parse_args()

    if args.selftest:
        with tempfile.TemporaryDirectory() as directory:
            return selftest(args.root, Path(directory))
    try:
        check_tree(args.root)
    except DenominatorError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1
    print(
        "legacy patch denominator: 72 IDs, 73 files, 70 transitions, "
        "124 atoms, and 24 native boundaries proven"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
