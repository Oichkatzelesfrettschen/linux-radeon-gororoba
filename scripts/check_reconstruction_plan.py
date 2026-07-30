#!/usr/bin/env python3
"""Validate reconstruction plans, effect assignments, and frozen inputs."""

from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import re
import sys
import tomllib
from collections import Counter
from pathlib import Path


HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
BASE_IDS = [f"B{number:02d}" for number in range(1, 15)]
MECHANISM_IDS = [f"M{number:02d}" for number in range(1, 25)]
PROFILES = {"prod", "observe-dev", "probe-dev", "mutate-dev"}
ALLOCATIONS = {"whole", "safe-list-part", "hazard-reader-part", "final-effect"}
SIDE_EFFECTS = {
    "build-only",
    "software-state",
    "telemetry",
    "cpu-memory-read",
    "direct-mmio-read",
    "indirect-selector-read",
    "hardware-control-write",
    "command-submission",
    "microcode-write",
    "reset-execution",
    "command-policy-mutation",
    "generated-input",
}
MUTATING = {
    "hardware-control-write",
    "command-submission",
    "microcode-write",
    "reset-execution",
    "command-policy-mutation",
}
PROD_EXCEPTIONS = {"production-correctness", "containment"}
BASE_SPLITS = {
    "71d8848947f0c762",
    "aab5dacf202723e8",
    "ac7fd7e292117e7f",
}


class PlanError(Exception):
    """The approved plan fails a reconstruction invariant."""


def split_list(value: str) -> list[str]:
    if value in {"", "none"}:
        return []
    return value.split(",")


def read_tsv(path: Path, *, comments: bool = False) -> list[dict[str, str]]:
    text = path.read_text(encoding="ascii")
    lines = [
        line
        for line in text.splitlines()
        if line and (not comments or not line.startswith("#"))
    ]
    if not lines:
        raise PlanError(f"TSV is empty: {path}")
    return list(csv.DictReader(lines, delimiter="\t"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_state(root: Path) -> dict[str, object]:
    base_plan = read_tsv(root / "docs/base-reconstruction-commit-plan.tsv")
    mechanism_plan = read_tsv(root / "docs/reconstruction-commit-plan.tsv")
    base_assignments = read_tsv(
        root / "docs/base-reconstruction-effect-assignments.tsv"
    )
    mechanism_assignments = read_tsv(
        root / "docs/reconstruction-effect-assignments.tsv"
    )
    mechanism_map = read_tsv(
        root / "migration/input/legacy-patch-mechanism-map.tsv",
        comments=True,
    )
    base_map = read_tsv(root / "migration/input/base-delta-map.tsv", comments=True)
    return {
        "root": root,
        "base_plan": base_plan,
        "mechanism_plan": mechanism_plan,
        "base_assignments": base_assignments,
        "mechanism_assignments": mechanism_assignments,
        "mechanism_map": mechanism_map,
        "base_map": base_map,
    }


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PlanError(message)


def index_rows(rows: list[dict[str, str]]) -> dict[str, dict[str, str]]:
    return {row["commit_id"]: row for row in rows}


def dependencies(row: dict[str, str]) -> set[str]:
    return set(split_list(row["depends_on"]))


def ancestors(
    commit_id: str,
    plans: dict[str, dict[str, str]],
    visiting: set[str] | None = None,
) -> set[str]:
    visiting = set() if visiting is None else visiting
    if commit_id in visiting:
        raise PlanError(f"cyclic dependency at {commit_id}")
    visiting.add(commit_id)
    result: set[str] = set()
    for dependency in dependencies(plans[commit_id]):
        result.add(dependency)
        if dependency in plans:
            result.update(ancestors(dependency, plans, visiting.copy()))
    return result


def validate_ids_and_order(
    base_plan: list[dict[str, str]],
    mechanism_plan: list[dict[str, str]],
) -> dict[str, dict[str, str]]:
    require(
        [row["commit_id"] for row in base_plan] == BASE_IDS,
        "base plan must contain exactly B01 through B14",
    )
    mechanism_ids = [row["commit_id"] for row in mechanism_plan]
    require(
        set(mechanism_ids) == set(MECHANISM_IDS) and len(mechanism_ids) == 24,
        "mechanism plan must contain exactly M01 through M24",
    )
    combined = base_plan + mechanism_plan
    plans = index_rows(combined)
    require(len(plans) == 38, "commit IDs are duplicated")
    subjects = [row["subject"] for row in combined]
    require(len(subjects) == len(set(subjects)), "duplicate subject")

    for phase_name, rows in (("base", base_plan), ("mechanism", mechanism_plan)):
        sequence = [int(row["sequence"]) for row in rows]
        require(
            sequence == list(range(1, len(rows) + 1)),
            f"{phase_name} sequence is not contiguous",
        )

    positions = {row["commit_id"]: index for index, row in enumerate(combined)}
    for row in combined:
        for column in ("depends_on", "order_after", "evidence_depends_on"):
            for predecessor in split_list(row[column]):
                require(
                    predecessor in plans,
                    f"{row['commit_id']}: unknown {column} ID {predecessor}",
                )
                require(
                    positions[predecessor] < positions[row["commit_id"]],
                    f"{row['commit_id']}: {column} predecessor {predecessor} "
                    "does not precede it",
                )
        ancestors(row["commit_id"], plans)
    return plans


def validate_profiles(
    base_plan: list[dict[str, str]],
    mechanism_plan: list[dict[str, str]],
) -> None:
    for row in base_plan + mechanism_plan:
        profile = row["future_profile"]
        require(profile in PROFILES, f"{row['commit_id']}: invalid profile name")
        require(
            profile == "prod" or profile.endswith("-dev"),
            f"{row['commit_id']}: non-production profile lacks -dev",
        )
        require(
            len(profile.split("-")) <= 4,
            f"{row['commit_id']}: profile has more than four words",
        )
        effect = row["side_effect_class"]
        require(effect in SIDE_EFFECTS, f"{row['commit_id']}: invalid side effect")
        if effect in MUTATING and profile != "prod":
            require(
                profile == "mutate-dev",
                f"{row['commit_id']}: mutating mechanism below mutate-dev",
            )
        if effect in MUTATING and profile == "prod":
            require(
                row["profile_exception"] in PROD_EXCEPTIONS
                and row["exception_basis"] not in {"", "none"},
                f"{row['commit_id']}: mutating prod row lacks structured exception",
            )

    expected_base_lanes = {
        commit_id: ("6.18" if number <= 8 else "6.18,7.1")
        for number, commit_id in enumerate(BASE_IDS, 1)
    }
    for row in base_plan:
        require(
            row["kernel_lanes"] == expected_base_lanes[row["commit_id"]],
            f"{row['commit_id']}: kernel lane violates the B09 frontier",
        )
    for row in mechanism_plan:
        require(
            row["kernel_lanes"] == "6.18,7.1",
            f"{row['commit_id']}: every mechanism commit needs both kernels",
        )


def validate_assignments(
    state: dict[str, object],
    plans: dict[str, dict[str, str]],
) -> tuple[Counter[str], Counter[str]]:
    base_assignments = state["base_assignments"]
    mechanism_assignments = state["mechanism_assignments"]
    base_map = state["base_map"]
    mechanism_map = state["mechanism_map"]
    assert isinstance(base_assignments, list)
    assert isinstance(mechanism_assignments, list)
    assert isinstance(base_map, list)
    assert isinstance(mechanism_map, list)

    known_base = {row["hunk_id"] for row in base_map} - BASE_SPLITS
    for atom in BASE_SPLITS:
        known_base.update({f"{atom}.palm", f"{atom}.safe"})
    assigned_base = [row["effect_atom"] for row in base_assignments]
    require(len(assigned_base) == len(set(assigned_base)), "duplicated base effect atom")
    require(set(assigned_base) == known_base, "missing or unknown base effect atom")

    known_mechanism = {row["effect_atom"] for row in mechanism_map}
    assigned_mechanism = [row["effect_atom"] for row in mechanism_assignments]
    require(
        len(assigned_mechanism) == len(set(assigned_mechanism)),
        "duplicated effect atom",
    )
    require(
        set(assigned_mechanism) == known_mechanism,
        "missing or unknown effect atom",
    )
    for row in mechanism_assignments:
        require(
            row["allocation"] in ALLOCATIONS,
            f"{row['effect_atom']}: invalid allocation",
        )
    assignment_owners = {
        row["effect_atom"]: row["commit_id"] for row in mechanism_assignments
    }
    for effect_atom in ("0031.0", "0031.1", "0031.2"):
        require(
            assignment_owners[effect_atom] == "M11",
            f"{effect_atom}: gated control-state read must belong to M11",
        )

    base_counts = Counter(row["commit_id"] for row in base_assignments)
    mechanism_counts = Counter(row["commit_id"] for row in mechanism_assignments)
    require(
        set(base_counts) == set(BASE_IDS),
        "unused base commit ID or assignment to unknown ID",
    )
    require(
        set(mechanism_counts) == set(MECHANISM_IDS),
        "unused commit ID or assignment to unknown ID",
    )

    for commit_id, row in plans.items():
        if commit_id.startswith("M"):
            assigned_patches = sorted(
                {item["effect_atom"].split(".", 1)[0]
                 for item in mechanism_assignments
                 if item["commit_id"] == commit_id}
            )
            require(
                sorted(split_list(row["legacy_patches"])) == assigned_patches,
                f"{commit_id}: commit patch list inconsistent with assigned atoms",
            )

    frozen_patches = {
        row["effect_atom"].split(".", 1)[0] for row in mechanism_map
    }
    represented_patches = {
        patch
        for row in state["mechanism_plan"]
        for patch in split_list(row["legacy_patches"])
    }
    require(
        represented_patches == frozen_patches,
        "not all legacy patches are represented",
    )
    return base_counts, mechanism_counts


def validate_semantics(plans: dict[str, dict[str, str]]) -> None:
    required_ancestors = {
        "M24": {"M20"},
        "M19": {"M16", "M17"},
        "M18": {"M01", "M16", "M17"},
        "M07": {"M06"},
        "M01": {"M04"},
        "M03": {"M04"},
    }
    for commit_id, required in required_ancestors.items():
        missing = required - ancestors(commit_id, plans)
        require(
            not missing,
            f"{commit_id}: missing semantic dependency {','.join(sorted(missing))}",
        )
    require(dependencies(plans["M04"]) == {"B13"}, "M04 must depend on B13")
    require(dependencies(plans["B14"]) == {"B09"}, "B14 must depend on B09")
    require(
        set(split_list(plans["B14"]["order_after"])) == {"B13"},
        "B14 must order after B13",
    )
    require(
        set(split_list(plans["M08"]["evidence_depends_on"])) == {"M03"},
        "M08 must record M03 as its evidence dependency",
    )
    require(
        dependencies(plans["M10"]) == {"M03", "M04"},
        "M10 must depend on candidate-read helpers and debugfs registration",
    )
    require(
        "devm_drm_dev_alloc" in plans["M18"]["exception_basis"]
        and "kzalloc" in plans["M18"]["exception_basis"],
        "M18 must prove gpu_parked zero initialization by allocation site",
    )


def validate_prefix_artifacts(
    root: Path,
    base_plan: list[dict[str, str]],
    mechanism_plan: list[dict[str, str]],
) -> None:
    for row in base_plan + mechanism_plan:
        require(
            bool(HEX_40.fullmatch(row["expected_driver_tree"])),
            f"{row['commit_id']}: invalid expected driver tree",
        )
        require(
            bool(HEX_64.fullmatch(row["expected_manifest_sha256"])),
            f"{row['commit_id']}: invalid expected manifest SHA-256",
        )
        manifest_path = root / row["expected_manifest"]
        bundle_path = root / row["effect_bundle"]
        require(manifest_path.is_file(), f"{row['commit_id']}: missing manifest")
        require(bundle_path.is_file(), f"{row['commit_id']}: missing effect bundle")
        require(
            sha256_file(manifest_path) == row["expected_manifest_sha256"],
            f"{row['commit_id']}: recorded manifest hash differs",
        )
    require(
        (root / base_plan[-1]["expected_manifest"]).read_bytes()
        == (root / "migration/input/legacy-base-source-manifest.tsv").read_bytes(),
        "B14 manifest differs from the base oracle",
    )
    require(
        (root / mechanism_plan[-1]["expected_manifest"]).read_bytes()
        == (
            root
            / "migration/input/migration-oracle-0.3-91-exact-context-manifest.tsv"
        ).read_bytes(),
        "M24 manifest differs from the migration oracle",
    )


def validate_input_inventory(root: Path) -> None:
    inventory = read_tsv(root / "docs/reconstruction-input-inventory.tsv")
    require(len(inventory) == 7, "input inventory must contain seven frozen files")
    migration = tomllib.loads(
        (root / "MIGRATION_INPUT.toml").read_text(encoding="ascii")
    )
    expected = {
        "base-delta-map.tsv": migration["base_delta_map_sha256"],
        "legacy-base-source-manifest.tsv": migration["base_manifest_sha256"],
        "legacy-patch-mechanism-map.tsv": migration["mechanism_map_sha256"],
        "legacy-patch-transitions.tsv": migration["patch_transitions_sha256"],
        "legacy-payload-0.3-91-exact-context-manifest.tsv":
            migration["legacy_payload_manifest_sha256"],
        "migration-oracle-0.3-91-exact-context-manifest.tsv":
            migration["migration_manifest_sha256"],
        "migration-oracle-0.3-91-exact-context-normalization.tsv":
            migration["generated_output_proof_sha256"],
    }
    for row in inventory:
        copied = root / row["copied_path"]
        require(
            row["source_repository"] == migration["packaging_repository"]
            and row["source_commit"] == migration["packaging_commit"],
            f"{row['copied_path']}: provenance differs from MIGRATION_INPUT.toml",
        )
        require(copied.is_file(), f"missing frozen input copy: {copied}")
        actual = sha256_file(copied)
        require(actual == row["sha256"], f"{row['copied_path']}: copied hash differs")
        require(
            expected.get(copied.name) == actual,
            f"{row['copied_path']}: hash differs from MIGRATION_INPUT.toml",
        )


def validate_feature_policy(root: Path) -> None:
    policy = tomllib.loads(
        (root / "docs/post-tag-feature-policy.toml").read_text(encoding="ascii")
    )
    seen: set[str] = set()
    for feature in policy["feature"]:
        require(feature["id"] not in seen, f"duplicate feature ID {feature['id']}")
        seen.add(feature["id"])
        profile = feature["tier"]
        require(profile in PROFILES, f"{feature['id']}: invalid feature profile")
        require(
            profile == "prod" or feature["setting"].endswith("-dev"),
            f"{feature['id']}: non-production setting lacks -dev",
        )
        require(
            len(feature["setting"].split("-")) <= 4,
            f"{feature['id']}: setting has more than four profile words",
        )
        effect = feature["side_effect_class"]
        require(effect in SIDE_EFFECTS, f"{feature['id']}: invalid feature side effect")
        if effect in MUTATING:
            require(
                profile == "mutate-dev",
                f"{feature['id']}: mutating feature below mutate-dev",
            )
        for key in (
            "availability_default",
            "runtime_profile_default",
            "operation_arm_default",
            "arming_model",
        ):
            require(bool(feature[key]), f"{feature['id']}: missing {key}")


def validate(state: dict[str, object], *, files: bool = True) -> tuple[Counter[str], Counter[str]]:
    root = state["root"]
    base_plan = state["base_plan"]
    mechanism_plan = state["mechanism_plan"]
    assert isinstance(root, Path)
    assert isinstance(base_plan, list)
    assert isinstance(mechanism_plan, list)
    plans = validate_ids_and_order(base_plan, mechanism_plan)
    validate_profiles(base_plan, mechanism_plan)
    counts = validate_assignments(state, plans)
    validate_semantics(plans)
    if files:
        validate_prefix_artifacts(root, base_plan, mechanism_plan)
        validate_input_inventory(root)
        validate_feature_policy(root)
    return counts


def self_test(root: Path) -> int:
    try:
        state = load_state(root)
        validate(state)
        cases = []

        duplicate = copy.deepcopy(state)
        duplicate["mechanism_assignments"][1]["effect_atom"] = (
            duplicate["mechanism_assignments"][0]["effect_atom"]
        )
        cases.append(("duplicated effect atom", duplicate))

        cycle = copy.deepcopy(state)
        cycle["mechanism_plan"][0]["depends_on"] = "M24"
        cases.append(("cyclic dependency", cycle))

        profile = copy.deepcopy(state)
        profile["mechanism_plan"][0]["future_profile"] = "observe"
        cases.append(("invalid profile", profile))

        mutation = copy.deepcopy(state)
        row = next(item for item in mutation["mechanism_plan"]
                   if item["commit_id"] == "M12")
        row["future_profile"] = "probe-dev"
        cases.append(("mutation tier", mutation))

        patch_list = copy.deepcopy(state)
        patch_list["mechanism_plan"][0]["legacy_patches"] = "0008"
        cases.append(("patch list", patch_list))

        lanes = copy.deepcopy(state)
        lanes["mechanism_plan"][0]["kernel_lanes"] = "7.1"
        cases.append(("kernel lanes", lanes))

        exception = copy.deepcopy(state)
        row = next(item for item in exception["mechanism_plan"]
                   if item["commit_id"] == "M16")
        row["profile_exception"] = "none"
        cases.append(("production exception", exception))

        gated_read = copy.deepcopy(state)
        for assignment in gated_read["mechanism_assignments"]:
            if assignment["effect_atom"].startswith("0031."):
                assignment["commit_id"] = "M09"
        row = next(item for item in gated_read["mechanism_plan"]
                   if item["commit_id"] == "M09")
        row["legacy_patches"] = "0015,0022,0031"
        row = next(item for item in gated_read["mechanism_plan"]
                   if item["commit_id"] == "M11")
        row["legacy_patches"] = "0025,0029,0030,0032,0033,0034,0035,0037"
        cases.append(("gated read ownership", gated_read))

        for label, broken in cases:
            try:
                validate(broken, files=False)
            except PlanError:
                continue
            raise PlanError(f"self-test accepted {label}")
    except (KeyError, OSError, PlanError, UnicodeDecodeError, ValueError) as exc:
        print(f"reconstruction-plan calibration: FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"reconstruction-plan calibration: {len(cases)} invalid classes rejected")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    root = args.repository.resolve()
    if args.self_test:
        return self_test(root)
    try:
        state = load_state(root)
        base_counts, mechanism_counts = validate(state)
    except (KeyError, OSError, PlanError, UnicodeDecodeError, ValueError) as exc:
        print(f"reconstruction plan: {exc}", file=sys.stderr)
        return 1

    base_order = " ".join(row["commit_id"] for row in state["base_plan"])
    mechanism_order = " ".join(
        row["commit_id"] for row in state["mechanism_plan"]
    )
    print(f"base topological order: {base_order}")
    print(f"mechanism topological order: {mechanism_order}")
    for commit_id in BASE_IDS:
        print(f"{commit_id}: {base_counts[commit_id]} base effect atoms")
    for commit_id in (row["commit_id"] for row in state["mechanism_plan"]):
        print(f"{commit_id}: {mechanism_counts[commit_id]} effect atoms")
    print("124 effect atoms assigned exactly once")
    print("24 approved source commits")
    print("dependency graph acyclic")
    print("profile names valid")
    print("all legacy patches represented")
    return 0


if __name__ == "__main__":
    sys.exit(main())
