#!/usr/bin/env python3
"""Validate build-feature classification, dependencies, and plan coverage."""

from __future__ import annotations

import argparse
import copy
import csv
import re
import sys
import tomllib
from collections.abc import Callable
from pathlib import Path


PROFILES = ("prod", "observe-dev", "probe-dev", "mutate-dev")
PROFILE_RANK = {profile: rank for rank, profile in enumerate(PROFILES)}
MUTATING = {
    "hardware-control-write",
    "command-submission",
    "microcode-write",
    "reset-execution",
    "command-policy-mutation",
}
SIDE_EFFECTS = {
    "build-only",
    "software-state",
    "telemetry",
    "cpu-memory-read",
    "direct-mmio-read",
    "indirect-selector-read",
    *MUTATING,
    "generated-input",
}
INTERFACES = {
    "build",
    "kernel-path",
    "error-telemetry",
    "debugfs-infrastructure",
    "raw-hardware-reader",
    "raw-hardware-writer",
    "diagnostic-oracle",
    "command-policy",
    "generated-input",
    "cpu-memory-reader",
}
PROD_EXCEPTIONS = {"production-correctness", "containment"}
TEST_CLASSES = {"normal", "boundary", "failure", "adversarial"}
SCOPE_RELATIONS = {
    "equal",
    "broader-than-evidence",
    "infrastructure-only",
    "matches-exclusion-evidence",
}
SPLIT_MECHANISMS = {
    "B11": {"production", "unsafe"},
    "M03": {"passive", "hazard"},
    "M10": {"pll", "first-read"},
}
SPLIT_TIERS = {
    "B11": {"production": "prod", "unsafe": "mutate-dev"},
    "M03": {"passive": "observe-dev", "hazard": "probe-dev"},
    "M10": {"pll": "probe-dev", "first-read": "probe-dev"},
}
SPLIT_PLAN_PART = {"B11": "production", "M03": "hazard", "M10": "pll"}
KEBAB = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
MECHANISM = re.compile(r"^([BM][0-9]{2})(?:\.([a-z0-9-]+))?$")
REQUIRED_FIELDS = {
    "id",
    "setting",
    "tier",
    "source_objects",
    "source_mechanisms",
    "dependencies",
    "evidence_dependencies",
    "runtime_profile",
    "operation_gate",
    "availability_default",
    "runtime_profile_default",
    "operation_arm_default",
    "arming_model",
    "privilege",
    "execution_scope",
    "evidence_scope",
    "scope_refs",
    "scope_relation",
    "scope_decision",
    "side_effect_class",
    "interface_class",
    "resource_bounds",
    "locking",
    "error_contract",
    "tests",
    "production_promotion_condition",
    "profile_exception",
    "exception_basis",
    "package_projection",
    "rollback",
}


class PolicyError(Exception):
    """The build-feature policy violates a declared invariant."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PolicyError(message)


def read_tsv(path: Path) -> list[dict[str, str]]:
    text = path.read_text(encoding="ascii")
    lines = [line for line in text.splitlines() if line]
    require(bool(lines), f"TSV is empty: {path}")
    return list(csv.DictReader(lines, delimiter="\t"))


def load_policy(root: Path) -> dict[str, object]:
    return tomllib.loads(
        (root / "policy/build-features.toml").read_text(encoding="ascii")
    )


def load_plans(root: Path) -> dict[str, dict[str, str]]:
    rows = read_tsv(root / "docs/base-reconstruction-commit-plan.tsv")
    rows += read_tsv(root / "docs/reconstruction-commit-plan.tsv")
    return {row["commit_id"]: row for row in rows}


def load_guard_scope(root: Path) -> dict[str, dict[str, str]]:
    return {
        row["guard_id"]: row
        for row in read_tsv(root / "policy/rs4xx-guard-scope.tsv")
    }


def string_list(feature: dict[str, object], field: str) -> list[str]:
    value = feature[field]
    require(isinstance(value, list), f"{feature['id']}: {field} must be an array")
    require(
        all(isinstance(item, str) and item for item in value),
        f"{feature['id']}: {field} contains an empty or non-string item",
    )
    return value


def mechanism_parts(token: str) -> tuple[str, str | None]:
    match = MECHANISM.fullmatch(token)
    require(match is not None, f"invalid source mechanism {token}")
    return match.group(1), match.group(2)


def validate_profile_model(policy: dict[str, object]) -> None:
    require(policy.get("schema") == 1, "unsupported build-feature policy schema")
    model = policy.get("profile_model")
    require(isinstance(model, dict), "missing profile_model table")
    require(model.get("ordered") == list(PROFILES), "profile order is not monotone")
    require(model.get("build_alias") == "all-dev", "build alias must be all-dev")
    require(
        model.get("build_alias_resolves_to") == "mutate-dev",
        "all-dev must resolve to mutate-dev",
    )
    require(model.get("runtime_default") == "off", "runtime default must be off")
    require(
        model.get("runtime_allowed")
        == ["off", "observe-dev", "probe-dev", "mutate-dev"],
        "runtime profile set is invalid",
    )


def validate_feature_shape(
    feature: dict[str, object],
    root: Path,
    guard_scope: dict[str, dict[str, str]],
    *,
    files: bool,
) -> None:
    feature_id = feature.get("id")
    require(isinstance(feature_id, str), "feature lacks a string id")
    missing = REQUIRED_FIELDS - feature.keys()
    require(not missing, f"{feature_id}: missing fields {','.join(sorted(missing))}")
    require(KEBAB.fullmatch(feature_id) is not None, f"{feature_id}: invalid feature ID")

    setting = feature["setting"]
    tier = feature["tier"]
    require(isinstance(setting, str), f"{feature_id}: setting must be a string")
    require(isinstance(tier, str) and tier in PROFILES, f"{feature_id}: unknown tier")
    require(
        setting == "prod" or KEBAB.fullmatch(setting) is not None,
        f"{feature_id}: invalid canonical setting",
    )
    if tier != "prod":
        require(setting.endswith("-dev"), f"{feature_id}: setting lacks -dev suffix")
        require(
            len(setting.split("-")) <= 4,
            f"{feature_id}: setting has more than four words",
        )
    else:
        require(setting == "prod", f"{feature_id}: production setting must be prod")

    runtime_profile = feature["runtime_profile"]
    require(runtime_profile == tier, f"{feature_id}: runtime profile differs from tier")
    availability = feature["availability_default"]
    runtime_default = feature["runtime_profile_default"]
    if tier == "prod":
        require(
            availability == "present-in-prod",
            f"{feature_id}: production feature is absent by default",
        )
        require(runtime_default == "active", f"{feature_id}: prod runtime is not active")
        require(
            feature["package_projection"] == "production",
            f"{feature_id}: prod package projection is invalid",
        )
    else:
        require(
            availability == "absent-in-prod",
            f"{feature_id}: development feature is present in prod",
        )
        require(runtime_default == "off", f"{feature_id}: dev runtime default is not off")
        require(
            feature["package_projection"] == "development",
            f"{feature_id}: dev package projection is invalid",
        )

    for field in (
        "operation_gate",
        "operation_arm_default",
        "arming_model",
        "privilege",
        "execution_scope",
        "evidence_scope",
        "scope_relation",
        "scope_decision",
        "resource_bounds",
        "locking",
        "error_contract",
        "production_promotion_condition",
        "rollback",
    ):
        require(
            isinstance(feature[field], str) and bool(feature[field]),
            f"{feature_id}: missing {field}",
        )
    require(
        feature["scope_relation"] in SCOPE_RELATIONS,
        f"{feature_id}: unknown scope relation",
    )

    effect = feature["side_effect_class"]
    interface = feature["interface_class"]
    require(effect in SIDE_EFFECTS, f"{feature_id}: unknown side-effect class")
    require(interface in INTERFACES, f"{feature_id}: unknown interface class")
    if effect in MUTATING and tier != "prod":
        require(tier == "mutate-dev", f"{feature_id}: mutation below mutate-dev")
    if interface == "raw-hardware-reader":
        require(tier != "prod", f"{feature_id}: raw reader appears in prod")

    exception = feature["profile_exception"]
    basis = feature["exception_basis"]
    if effect in MUTATING and tier == "prod":
        require(
            exception in PROD_EXCEPTIONS,
            f"{feature_id}: mutating prod feature lacks structured exception",
        )
        require(
            isinstance(basis, str) and basis not in {"", "none"},
            f"{feature_id}: mutating prod feature lacks exception basis",
        )
    else:
        require(exception == "none", f"{feature_id}: unexpected profile exception")
        require(basis == "none", f"{feature_id}: unexpected exception basis")

    source_objects = string_list(feature, "source_objects")
    require(bool(source_objects), f"{feature_id}: source_objects is empty")
    for source in source_objects:
        path = Path(source)
        require(
            not path.is_absolute() and ".." not in path.parts,
            f"{feature_id}: invalid source object path {source}",
        )
        if files:
            require((root / path).is_file(), f"{feature_id}: missing source object {source}")

    source_mechanisms = string_list(feature, "source_mechanisms")
    require(bool(source_mechanisms), f"{feature_id}: source_mechanisms is empty")
    string_list(feature, "dependencies")
    string_list(feature, "evidence_dependencies")

    tests = string_list(feature, "tests")
    classes = {
        test.split(":", 1)[0]
        for test in tests
        if ":" in test and test.split(":", 1)[1].strip()
    }
    require(
        len(tests) == 4 and classes == TEST_CLASSES,
        f"{feature_id}: tests must cover normal, boundary, failure, and adversarial",
    )

    scope_refs = string_list(feature, "scope_refs")
    if scope_refs:
        require(
            feature["execution_scope"] == "scope_refs"
            and feature["evidence_scope"] == "scope_refs",
            f"{feature_id}: referenced scopes must use scope_refs",
        )
        require(
            feature["scope_decision"] == "resolve policy/rs4xx-guard-scope.tsv",
            f"{feature_id}: scope decision must resolve the guard ledger",
        )
        relations = set()
        for guard_id in scope_refs:
            require(guard_id in guard_scope, f"{feature_id}: unknown scope ref {guard_id}")
            relations.add(guard_scope[guard_id]["scope_relation"])
            require(
                bool(guard_scope[guard_id]["scope_decision"]),
                f"{feature_id}: guard scope {guard_id} lacks a decision",
            )
        require(len(relations) == 1, f"{feature_id}: scope refs disagree on relation")
        require(
            feature["scope_relation"] == relations.pop(),
            f"{feature_id}: scope relation differs from guard ledger",
        )
    elif feature["scope_relation"] == "broader-than-evidence":
        require(
            feature["scope_decision"] not in {"", "none"},
            f"{feature_id}: broader execution scope lacks a decision",
        )

    if feature_id == "parked-entry-containment":
        initialization = feature.get("state_initialization")
        source = feature.get("initialization_source")
        require(
            isinstance(initialization, str)
            and "radeon_pci_probe" in initialization
            and "devm_drm_dev_alloc" in initialization
            and "kzalloc" in initialization,
            "parked-entry-containment: gpu_parked false initialization is unproven",
        )
        require(
            isinstance(source, str)
            and "radeon_drv.c:radeon_pci_probe" in source
            and "drm_drv.c:__devm_drm_dev_alloc" in source,
            "parked-entry-containment: initialization sources are incomplete",
        )
        if files:
            radeon_driver = (
                root / "drivers/gpu/drm/radeon/radeon_drv.c"
            ).read_text(encoding="ascii")
            require(
                "rdev = devm_drm_dev_alloc(" in radeon_driver,
                "parked-entry-containment: allocation site no longer uses "
                "devm_drm_dev_alloc",
            )
            radeon_header = (
                root / "drivers/gpu/drm/radeon/radeon.h"
            ).read_text(encoding="ascii")
            require(
                re.search(r"\bbool\s+gpu_parked;", radeon_header) is not None,
                "parked-entry-containment: gpu_parked field is absent",
            )


def validate_dependencies(features: dict[str, dict[str, object]]) -> None:
    for feature_id, feature in features.items():
        for dependency in string_list(feature, "dependencies"):
            require(dependency in features, f"{feature_id}: unknown dependency {dependency}")
            require(
                PROFILE_RANK[features[dependency]["tier"]]
                <= PROFILE_RANK[feature["tier"]],
                f"{feature_id}: depends on higher-tier feature {dependency}",
            )
        for dependency in string_list(feature, "evidence_dependencies"):
            require(
                dependency in features,
                f"{feature_id}: unknown evidence dependency {dependency}",
            )

    def visit(feature_id: str, active: set[str], complete: set[str]) -> None:
        require(feature_id not in active, f"cyclic feature dependency at {feature_id}")
        if feature_id in complete:
            return
        active.add(feature_id)
        for dependency in string_list(features[feature_id], "dependencies"):
            visit(dependency, active, complete)
        active.remove(feature_id)
        complete.add(feature_id)

    complete: set[str] = set()
    for feature_id in features:
        visit(feature_id, set(), complete)


def validate_plan_coverage(
    features: dict[str, dict[str, object]],
    plans: dict[str, dict[str, str]],
) -> None:
    owners: dict[str, str] = {}
    tiers: dict[str, list[str]] = {commit_id: [] for commit_id in plans}
    parts: dict[str, set[str | None]] = {commit_id: set() for commit_id in plans}
    part_tiers: dict[str, dict[str, str]] = {
        commit_id: {} for commit_id in SPLIT_MECHANISMS
    }
    for feature_id, feature in features.items():
        for token in string_list(feature, "source_mechanisms"):
            commit_id, part = mechanism_parts(token)
            require(commit_id in plans, f"{feature_id}: unknown source mechanism {commit_id}")
            expected_parts = SPLIT_MECHANISMS.get(commit_id)
            if expected_parts is None:
                require(part is None, f"{feature_id}: unexpected split mechanism {token}")
            else:
                require(part in expected_parts, f"{feature_id}: invalid mechanism part {token}")
            require(token not in owners, f"{token}: duplicated source mechanism")
            owners[token] = feature_id
            tiers[commit_id].append(feature["tier"])
            parts[commit_id].add(part)
            if part is not None:
                part_tiers[commit_id][part] = feature["tier"]

    for commit_id, plan in plans.items():
        expected_parts = SPLIT_MECHANISMS.get(commit_id, {None})
        require(parts[commit_id] == expected_parts, f"{commit_id}: missing source mechanism")
        if commit_id in SPLIT_TIERS:
            require(
                part_tiers[commit_id] == SPLIT_TIERS[commit_id],
                f"{commit_id}: split policy tiers are invalid",
            )
            require(
                plan["future_profile"]
                == SPLIT_TIERS[commit_id][SPLIT_PLAN_PART[commit_id]],
                f"{commit_id}: plan profile differs from its retained mechanism part",
            )
            continue
        actual_tier = max(tiers[commit_id], key=PROFILE_RANK.__getitem__)
        require(
            actual_tier == plan["future_profile"],
            f"{commit_id}: policy tier {actual_tier} differs from plan "
            f"{plan['future_profile']}",
        )


def validate(
    policy: dict[str, object],
    root: Path,
    plans: dict[str, dict[str, str]],
    guard_scope: dict[str, dict[str, str]],
    *,
    files: bool = True,
) -> dict[str, dict[str, object]]:
    validate_profile_model(policy)
    feature_rows = policy.get("feature")
    require(isinstance(feature_rows, list) and feature_rows, "feature table is empty")
    features: dict[str, dict[str, object]] = {}
    for feature in feature_rows:
        require(isinstance(feature, dict), "feature row is not a table")
        validate_feature_shape(feature, root, guard_scope, files=files)
        feature_id = feature["id"]
        require(feature_id not in features, f"duplicate feature ID {feature_id}")
        features[feature_id] = feature
    validate_dependencies(features)
    validate_plan_coverage(features, plans)
    return features


def self_test(root: Path) -> int:
    policy = load_policy(root)
    plans = load_plans(root)
    guard_scope = load_guard_scope(root)
    validate(policy, root, plans, guard_scope)

    cases: list[tuple[str, Callable[[dict[str, object]], None]]] = []

    def add(label: str, mutation: Callable[[dict[str, object]], None]) -> None:
        cases.append((label, mutation))

    add("duplicate feature ID", lambda value: value["feature"][1].update(
        id=value["feature"][0]["id"]
    ))
    add("missing dev suffix", lambda value: value["feature"][3].update(
        setting="palm-reset"
    ))
    add("too many setting words", lambda value: value["feature"][3].update(
        setting="palm-unsafe-reset-trigger-dev"
    ))
    add("unknown tier", lambda value: value["feature"][3].update(tier="unsafe-dev"))
    add("missing operation gate", lambda value: value["feature"][3].update(
        operation_gate=""
    ))
    add("mutation below mutate", lambda value: value["feature"][3].update(
        tier="probe-dev", runtime_profile="probe-dev"
    ))
    add("raw reader in prod", lambda value: value["feature"][5].update(
        tier="prod",
        setting="prod",
        runtime_profile="prod",
        availability_default="present-in-prod",
        runtime_profile_default="active",
        package_projection="production",
    ))
    add("prod dependency on dev", lambda value: value["feature"][1].update(
        dependencies=["safe-registers"]
    ))
    add("broader scope without decision", lambda value: value["feature"][6].update(
        scope_decision=""
    ))
    add("unknown dependency", lambda value: value["feature"][3].update(
        dependencies=["missing-feature"]
    ))
    add("dependency cycle", lambda value: value["feature"][4].update(
        dependencies=["safe-registers"]
    ))
    add("unknown mechanism", lambda value: value["feature"][1].update(
        source_mechanisms=["B99"]
    ))
    add("missing mechanism", lambda value: value["feature"][0].update(
        source_mechanisms=value["feature"][0]["source_mechanisms"][1:]
    ))
    add("plan tier mismatch", lambda value: value["feature"][17].update(
        tier="observe-dev",
        setting="cs-parser-dev",
        runtime_profile="observe-dev",
        availability_default="absent-in-prod",
        runtime_profile_default="off",
        package_projection="development",
    ))
    add("missing prod exception", lambda value: value["feature"][2].update(
        profile_exception="none", exception_basis="none"
    ))
    add("missing adversarial test", lambda value: value["feature"][3].update(
        tests=value["feature"][3]["tests"][:3]
    ))
    add("guard relation mismatch", lambda value: value["feature"][4].update(
        scope_relation="equal"
    ))
    add("unknown scope relation", lambda value: value["feature"][0].update(
        scope_relation="approximate"
    ))
    add("duplicated source mechanism", lambda value: value["feature"][1].update(
        source_mechanisms=["B10", "B01"]
    ))
    add("swapped split tiers", lambda value: (
        value["feature"][2].update(source_mechanisms=["B11.unsafe"]),
        value["feature"][3].update(
            source_mechanisms=["B11.production", "B12"]
        ),
    ))
    add("missing parked initialization", lambda value: value["feature"][10].update(
        state_initialization=""
    ))

    for label, mutation in cases:
        candidate = copy.deepcopy(policy)
        mutation(candidate)
        try:
            validate(candidate, root, plans, guard_scope, files=False)
        except PolicyError:
            continue
        raise PolicyError(f"self-test accepted {label}")

    missing_source = copy.deepcopy(policy)
    missing_source["feature"][0]["source_objects"] = ["drivers/missing.c"]
    try:
        validate(missing_source, root, plans, guard_scope)
    except PolicyError:
        pass
    else:
        raise PolicyError("self-test accepted missing source object")

    print(f"build-feature policy self-test: {len(cases) + 1} rejection cases")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        if args.self_test:
            return self_test(root)
        features = validate(
            load_policy(root),
            root,
            load_plans(root),
            load_guard_scope(root),
        )
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, PolicyError) as error:
        print(f"build-feature policy: {error}", file=sys.stderr)
        return 1

    counts = {
        profile: sum(feature["tier"] == profile for feature in features.values())
        for profile in PROFILES
    }
    print(f"{len(features)} build features classified")
    print("38 reconstruction mechanisms covered")
    print("profile dependency graph acyclic")
    print("side-effect tiers valid")
    print("guard scope decisions resolved")
    print(
        "profile counts: "
        + ", ".join(f"{profile}={counts[profile]}" for profile in PROFILES)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
