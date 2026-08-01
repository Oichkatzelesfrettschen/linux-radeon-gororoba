#!/usr/bin/env python3
"""Verify the exact legacy-equivalent development interface inventory."""

from __future__ import annotations

import argparse
import copy
import csv
import re
import subprocess
import sys
import tomllib
from pathlib import Path


MARKER_TYPES = {
    "module-parameter",
    "debugfs-file",
    "source-symbol",
    "generated-input",
}
MANIFEST_FIELDS = {
    "feature_id",
    "marker_type",
    "marker",
    "source_path",
    "source_mechanism",
}
MODULE_PARAMETER = re.compile(
    r"\bmodule_param_named\(\s*([A-Za-z0-9_]+)"
    r"|\bmodule_param\(\s*([A-Za-z0-9_]+)"
)
DEBUGFS_FILE = re.compile(r'debugfs_create_file\(\s*"([^"]+)"')
PROFILE_RANK = {
    "prod": 0,
    "observe-dev": 1,
    "probe-dev": 2,
    "mutate-dev": 3,
}
RUNTIME_RANK = {
    "off": -1,
    "observe-dev": 1,
    "probe-dev": 2,
    "mutate-dev": 3,
}
RUNTIME_SOURCE_PATTERNS = {
    "drivers/gpu/drm/radeon/radeon_dev.c": (
        r'\{ "off", RADEON_DEV_PROFILE_OFF \}',
        r'\{ "observe-dev", RADEON_DEV_PROFILE_OBSERVE \}',
        r'\{ "probe-dev", RADEON_DEV_PROFILE_PROBE \}',
        r'\{ "mutate-dev", RADEON_DEV_PROFILE_MUTATE \}',
        r"profile > RADEON_DEV_COMPILED_PROFILE",
        r"module_param_cb\(profile_dev, &radeon_dev_profile_ops, NULL, 0444\)",
        r"cmpxchg\(&radeon_dev_arm_holder, NULL, rdev\)",
        r"rdev->dev_context\.profile = profile",
    ),
    "drivers/gpu/drm/radeon/radeon_rs4xx_dev.c": (
        r"void radeon_rs480_re_debugfs_register\(.*?\)\n\{.*?"
        r"RADEON_DEV_PROFILE_OBSERVE",
        r"static void rs480_candidate_regs_debugfs_init\(.*?\)\n\{.*?"
        r"RADEON_DEV_PROFILE_PROBE",
        r"static void rs480_candidate_regs_debugfs_init\(.*?\)\n\{.*?"
        r"RADEON_DEV_PROFILE_MUTATE",
        r"u32 radeon_rs4xx_dev_reset_mask\(.*?\)\n\{.*?"
        r"RADEON_DEV_PROFILE_MUTATE",
        r"bool radeon_rs4xx_dev_apply_r400_us_reg_safe\(.*?\)\n\{.*?"
        r"RADEON_DEV_PROFILE_MUTATE",
    ),
    "drivers/gpu/drm/radeon/radeon_evergreen_dev.c": (
        r"void radeon_evergreen_dev_debugfs_init\(.*?\)\n\{.*?"
        r"RADEON_DEV_PROFILE_MUTATE",
    ),
    "drivers/gpu/drm/radeon/evergreen_cs.c": (
        r"evergreen_dev_reg_safe_bm",
        r"radeon_dev_profile_enabled\(.*?"
        r"RADEON_DEV_PROFILE_MUTATE",
    ),
}
MUTATION_AUDIT_PATTERNS = {
    "palm-reset-controls": (
        (
            "drivers/gpu/drm/radeon/radeon_dev.c",
            r'radeon_dev_mark_mutation\(rdev, "Palm unsafe PCI reset override"\)',
            1,
        ),
        (
            "drivers/gpu/drm/radeon/radeon_evergreen_dev.c",
            r'radeon_dev_mark_mutation\(rdev, "Evergreen debugfs PCI reset"\)',
            1,
        ),
    ),
    "smx-dc-ctl0-policy": (
        (
            "drivers/gpu/drm/radeon/evergreen_cs.c",
            r'radeon_dev_mark_mutation\(.*?p->rdev,.*?'
            r'"Evergreen SMX_DC_CTL0 command policy"\)',
            1,
        ),
    ),
    "cache-drain": (
        (
            "drivers/gpu/drm/radeon/radeon_rs4xx_dev.c",
            r'radeon_dev_mark_mutation\(rdev, "RS4xx CP cache drain"\)',
            1,
        ),
    ),
    "reset-recovery-probes": (
        (
            "drivers/gpu/drm/radeon/radeon_rs4xx_dev.c",
            r'radeon_dev_mark_mutation\(rdev, "RS4xx GPU reset recovery probe"\)',
            1,
        ),
        (
            "drivers/gpu/drm/radeon/radeon_rs4xx_dev.c",
            r'radeon_dev_mark_mutation\(rdev, "RS4xx reset hang probe"\)',
            3,
        ),
    ),
    "reset-mask-selector": (
        (
            "drivers/gpu/drm/radeon/radeon_rs4xx_dev.c",
            r'radeon_dev_mark_mutation\(rdev, "RS4xx nonbaseline reset mask"\)',
            1,
        ),
    ),
    "cp-me-write": (
        (
            "drivers/gpu/drm/radeon/radeon_rs4xx_dev.c",
            r'radeon_dev_mark_mutation\(rdev, "RS4xx CP-ME RAM injection"\)',
            1,
        ),
    ),
    "force-clock": (
        (
            "drivers/gpu/drm/radeon/radeon_rs4xx_dev.c",
            r'radeon_dev_mark_mutation\(rdev, "RS4xx force-clock read"\)',
            1,
        ),
        (
            "drivers/gpu/drm/radeon/radeon_rs4xx_dev.c",
            r'radeon_dev_mark_mutation\(rdev, "RS4xx force-clock 3D read"\)',
            1,
        ),
        (
            "drivers/gpu/drm/radeon/radeon_rs4xx_dev.c",
            r'radeon_dev_mark_mutation\(rdev, "RS4xx gated-state read"\)',
            1,
        ),
    ),
    "r400-us-allowlist": (
        (
            "drivers/gpu/drm/radeon/radeon_rs4xx_dev.c",
            r'radeon_dev_mark_mutation\(rdev, "RS4xx R400-US command policy"\)',
            1,
        ),
    ),
    "scratch-oracle": (
        (
            "drivers/gpu/drm/radeon/radeon_rs4xx_dev.c",
            r'radeon_dev_mark_mutation\(rdev, "RS4xx CP scratch oracle"\)',
            1,
        ),
    ),
}


class InterfaceError(Exception):
    """The all-development interface inventory differs from its declaration."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise InterfaceError(message)


def read_manifest(path: Path) -> list[dict[str, str]]:
    text = path.read_text(encoding="ascii")
    lines = [line for line in text.splitlines() if line]
    require(bool(lines), "all-dev interface manifest is empty")
    rows = list(csv.DictReader(lines, delimiter="\t"))
    require(
        set(rows[0]) == MANIFEST_FIELDS,
        "all-dev interface manifest schema is invalid",
    )
    return rows


def read_features(path: Path) -> dict[str, dict[str, object]]:
    policy = tomllib.loads(path.read_text(encoding="ascii"))
    return {feature["id"]: feature for feature in policy["feature"]}


def custom_module_parameters(driver_root: Path) -> set[str]:
    parameters: set[str] = set()
    for source in driver_root.glob("*.c"):
        text = source.read_text(encoding="utf-8")
        for match in MODULE_PARAMETER.finditer(text):
            name = match.group(1) or match.group(2)
            if name == "palm_pci_reset_unsafe" or name.startswith("rs480_"):
                parameters.add(name)
    return parameters


def custom_debugfs_files(driver_root: Path) -> set[str]:
    files: set[str] = set()
    for source in driver_root.glob("*.c"):
        text = source.read_text(encoding="utf-8")
        for name in DEBUGFS_FILE.findall(text):
            if name == "radeon_force_pci_reset_safe" or name.startswith(
                "radeon_rs480_"
            ):
                files.add(name)
    return files


def validate_source_marker(root: Path, row: dict[str, str]) -> None:
    path = Path(row["source_path"])
    require(
        not path.is_absolute() and ".." not in path.parts,
        f"{row['marker']}: invalid source path",
    )
    source = root / path
    require(source.is_file(), f"{row['marker']}: source path is absent")
    text = source.read_text(encoding="utf-8")
    marker_type = row["marker_type"]
    marker = row["marker"]
    if marker_type == "module-parameter":
        require(
            marker in custom_module_parameters(root / "drivers/gpu/drm/radeon"),
            f"{marker}: module parameter declaration is absent",
        )
    elif marker_type == "debugfs-file":
        require(
            marker in custom_debugfs_files(root / "drivers/gpu/drm/radeon"),
            f"{marker}: debugfs declaration is absent",
        )
    elif marker_type == "source-symbol":
        require(
            re.search(rf"\b{re.escape(marker)}\b", text) is not None,
            f"{marker}: source symbol is absent",
        )
    else:
        require(marker in text, f"{marker}: generated input marker is absent")


def profile_rows(
    rows: list[dict[str, str]],
    features: dict[str, dict[str, object]],
    profile: str,
) -> list[dict[str, str]]:
    require(profile in PROFILE_RANK, f"unknown compiled profile: {profile}")
    ceiling = PROFILE_RANK[profile]
    selected: list[dict[str, str]] = []
    for row in rows:
        tier = str(features[row["feature_id"]]["tier"])
        require(tier in PROFILE_RANK, f"unknown feature tier: {tier}")
        if PROFILE_RANK[tier] <= ceiling:
            selected.append(row)
    return selected


def runtime_rows(
    rows: list[dict[str, str]],
    features: dict[str, dict[str, object]],
    compiled_profile: str,
    runtime_profile: str,
) -> list[dict[str, str]]:
    require(
        compiled_profile in PROFILE_RANK,
        f"unknown compiled profile: {compiled_profile}",
    )
    require(
        runtime_profile in RUNTIME_RANK,
        f"unknown runtime profile: {runtime_profile}",
    )
    require(
        RUNTIME_RANK[runtime_profile] <= PROFILE_RANK[compiled_profile],
        f"runtime profile {runtime_profile} exceeds {compiled_profile}",
    )
    ceiling = RUNTIME_RANK[runtime_profile]
    return [
        row
        for row in profile_rows(rows, features, compiled_profile)
        if PROFILE_RANK[str(features[row["feature_id"]]["tier"])] <= ceiling
    ]


def runtime_source_texts(root: Path) -> dict[str, str]:
    return {
        path: (root / path).read_text(encoding="ascii")
        for path in RUNTIME_SOURCE_PATTERNS
    }


def validate_runtime_sources(texts: dict[str, str]) -> None:
    for path, patterns in RUNTIME_SOURCE_PATTERNS.items():
        require(path in texts, f"runtime gate source is absent: {path}")
        for pattern in patterns:
            require(
                re.search(pattern, texts[path], re.DOTALL) is not None,
                f"runtime gate is absent from {path}: {pattern}",
            )


def validate_mutation_audit(
    texts: dict[str, str],
    features: dict[str, dict[str, object]],
) -> None:
    source = texts["drivers/gpu/drm/radeon/radeon_dev.c"]
    for pattern in (
        r"atomic_cmpxchg\(&rdev->dev_context\.mutation_tainted, 0, 1\)",
        r"add_taint\(TAINT_USER, LOCKDEP_STILL_OK\)",
    ):
        require(
            re.search(pattern, source) is not None,
            f"mutation audit primitive is absent: {pattern}",
        )

    mutating_features = {
        feature_id
        for feature_id, feature in features.items()
        if feature["tier"] == "mutate-dev"
    }
    require(
        set(MUTATION_AUDIT_PATTERNS) == mutating_features,
        "mutation audit feature coverage differs: "
        + ",".join(sorted(set(MUTATION_AUDIT_PATTERNS) ^ mutating_features)),
    )
    for feature_id, audit_sites in MUTATION_AUDIT_PATTERNS.items():
        for path, pattern, expected_count in audit_sites:
            require(path in texts, f"{feature_id}: mutation audit source is absent")
            require(
                len(re.findall(pattern, texts[path], re.DOTALL)) >= expected_count,
                f"{feature_id}: mutation audit call is absent",
            )


def debugfs_fops_symbol(root: Path, row: dict[str, str]) -> str:
    source = root / row["source_path"]
    text = source.read_text(encoding="ascii")
    pattern = re.compile(
        rf'debugfs_create_file\(\s*"{re.escape(row["marker"])}"'
        rf".*?&([A-Za-z0-9_]+)\s*\)",
        re.DOTALL,
    )
    match = pattern.search(text)
    require(match is not None, f"{row['marker']}: debugfs fops is absent")
    return match.group(1)


def module_symbols(module: Path) -> set[str]:
    result = subprocess.run(
        ["nm", "-a", str(module)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    require(result.returncode == 0, "nm rejected the built module")
    return {
        line.split()[-1]
        for line in result.stdout.splitlines()
        if len(line.split()) >= 2
    }


def carries_symbol(symbols: set[str], expected: str) -> bool:
    return expected in symbols or any(
        symbol.startswith(expected + ".") for symbol in symbols
    )


def validate_generated_outputs(
    driver_root: Path,
    profile: str,
) -> None:
    generator = driver_root / "mkregtable"
    require(generator.is_file(), "built mkregtable is absent")

    def expected_header(source_name: str) -> bytes:
        result = subprocess.run(
            [str(generator), str(driver_root / "reg_srcs" / source_name)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        require(
            result.returncode == 0,
            f"mkregtable rejected reg_srcs/{source_name}",
        )
        return result.stdout

    evergreen_header = driver_root / "evergreen_reg_safe.h"
    require(evergreen_header.is_file(), "built evergreen safe table is absent")
    require(
        evergreen_header.read_bytes() == expected_header("evergreen_prod"),
        "built Evergreen production table differs from its input",
    )

    evergreen_dev_header = driver_root / "evergreen_dev_reg_safe.h"
    rs480_header = driver_root / "rs480_reg_safe.h"
    if profile == "mutate-dev":
        require(
            evergreen_dev_header.is_file(),
            "mutate-dev Evergreen development table is absent",
        )
        require(
            evergreen_dev_header.read_bytes() == expected_header("evergreen"),
            "built Evergreen development table differs from its input",
        )
        require(rs480_header.is_file(), "mutate-dev RS480 safe table is absent")
        require(
            rs480_header.read_bytes() == expected_header("rs480"),
            "built RS480 safe table differs from its development input",
        )
    else:
        require(
            not evergreen_dev_header.exists(),
            "lower profile generated the mutate-dev Evergreen table",
        )
        require(
            not rs480_header.exists(),
            "lower profile generated the mutate-dev RS480 safe table",
        )


def validate_module(
    root: Path,
    module: Path,
    rows: list[dict[str, str]],
    features: dict[str, dict[str, object]],
    profile: str,
    driver_root: Path | None,
) -> None:
    require(module.is_file(), f"module is absent: {module}")
    expected_rows = profile_rows(rows, features, profile)
    result = subprocess.run(
        ["modinfo", "-p", str(module)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    require(result.returncode == 0, "modinfo rejected the built module")
    module_parameters = {
        line.split(":", 1)[0]
        for line in result.stdout.splitlines()
        if ":" in line
    }
    require(
        ("profile_dev" in module_parameters) == (profile != "prod"),
        f"built module runtime-profile parameter differs for {profile}",
    )
    parameters = {
        name
        for name in module_parameters
        if (
            name == "palm_pci_reset_unsafe"
            or name.startswith("rs480_")
        )
    }
    expected_parameters = {
        row["marker"]
        for row in expected_rows
        if row["marker_type"] == "module-parameter"
    }
    require(
        parameters == expected_parameters,
        "built module parameter projection differs: "
        + ",".join(sorted(parameters ^ expected_parameters)),
    )

    symbols = module_symbols(module)
    for row in rows:
        if row["marker_type"] == "debugfs-file":
            symbol = debugfs_fops_symbol(root, row)
        elif row["marker_type"] == "source-symbol":
            symbol = row["marker"]
        else:
            continue
        expected = row in expected_rows
        require(
            carries_symbol(symbols, symbol) == expected,
            f"{row['marker']}: compiled symbol projection differs for {profile}",
        )

    result = subprocess.run(
        ["strings", str(module)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    require(result.returncode == 0, "strings rejected the built module")
    strings = set(result.stdout.splitlines())
    expected_debugfs = {
        row["marker"]
        for row in expected_rows
        if row["marker_type"] == "debugfs-file"
    }
    declared_debugfs = {
        row["marker"]
        for row in rows
        if row["marker_type"] == "debugfs-file"
    }
    actual_debugfs = declared_debugfs & strings
    require(
        actual_debugfs == expected_debugfs,
        "built module debugfs projection differs: "
        + ",".join(sorted(actual_debugfs ^ expected_debugfs)),
    )
    if driver_root is not None:
        validate_generated_outputs(driver_root, profile)


def validate(
    root: Path,
    rows: list[dict[str, str]],
    features: dict[str, dict[str, object]],
    *,
    module: Path | None = None,
    profile: str = "mutate-dev",
    driver_root: Path | None = None,
    files: bool = True,
) -> None:
    require(bool(rows), "all-dev interface manifest has no rows")
    keys: set[tuple[str, str]] = set()
    covered_features: set[str] = set()
    for row in rows:
        require(
            all(row[field] for field in MANIFEST_FIELDS),
            "all-dev interface manifest carries an empty field",
        )
        feature_id = row["feature_id"]
        require(feature_id in features, f"{feature_id}: unknown feature")
        require(
            features[feature_id]["tier"] != "prod",
            f"{feature_id}: production feature appears in all-dev interface manifest",
        )
        require(
            row["marker_type"] in MARKER_TYPES,
            f"{row['marker']}: unknown marker type",
        )
        require(
            row["source_mechanism"] in features[feature_id]["source_mechanisms"],
            f"{row['marker']}: source mechanism differs from feature policy",
        )
        key = (row["marker_type"], row["marker"])
        require(key not in keys, f"{row['marker']}: duplicate interface marker")
        keys.add(key)
        covered_features.add(feature_id)
        if files:
            validate_source_marker(root, row)

    development_features = {
        feature_id
        for feature_id, feature in features.items()
        if feature["tier"] != "prod"
    }
    require(
        covered_features == development_features,
        "all-dev manifest feature coverage differs: "
        + ",".join(sorted(development_features - covered_features)),
    )

    declared_parameters = {
        row["marker"] for row in rows if row["marker_type"] == "module-parameter"
    }
    actual_parameters = custom_module_parameters(root / "drivers/gpu/drm/radeon")
    require(
        declared_parameters == actual_parameters,
        "custom module-parameter inventory differs",
    )
    declared_debugfs = {
        row["marker"] for row in rows if row["marker_type"] == "debugfs-file"
    }
    actual_debugfs = custom_debugfs_files(root / "drivers/gpu/drm/radeon")
    require(declared_debugfs == actual_debugfs, "custom debugfs inventory differs")
    if files:
        source_texts = runtime_source_texts(root)
        validate_runtime_sources(source_texts)
        validate_mutation_audit(source_texts, features)

    if module is not None:
        validate_module(
            root,
            module,
            rows,
            features,
            profile,
            driver_root,
        )


def self_test(root: Path) -> int:
    rows = read_manifest(root / "policy/all-dev-interface-manifest.tsv")
    features = read_features(root / "policy/build-features.toml")
    validate(root, rows, features)

    cases: list[tuple[str, list[dict[str, str]]]] = []

    duplicate = copy.deepcopy(rows)
    duplicate[1]["marker_type"] = duplicate[0]["marker_type"]
    duplicate[1]["marker"] = duplicate[0]["marker"]
    cases.append(("duplicate marker", duplicate))

    unknown_feature = copy.deepcopy(rows)
    unknown_feature[0]["feature_id"] = "missing-feature"
    cases.append(("unknown feature", unknown_feature))

    production_feature = copy.deepcopy(rows)
    production_feature[0]["feature_id"] = "kernel-compatibility"
    cases.append(("production feature", production_feature))

    unknown_type = copy.deepcopy(rows)
    unknown_type[0]["marker_type"] = "hardware-file"
    cases.append(("unknown marker type", unknown_type))

    wrong_mechanism = copy.deepcopy(rows)
    wrong_mechanism[0]["source_mechanism"] = "M01"
    cases.append(("wrong source mechanism", wrong_mechanism))

    missing_feature = [
        row for row in copy.deepcopy(rows) if row["feature_id"] != "pll-probes"
    ]
    cases.append(("missing feature coverage", missing_feature))

    undeclared_parameter = [
        row
        for row in copy.deepcopy(rows)
        if row["marker"] != "rs480_reset_mask"
    ]
    cases.append(("undeclared source interface", undeclared_parameter))

    for label, candidate in cases:
        try:
            validate(root, candidate, features, files=False)
        except InterfaceError:
            continue
        raise InterfaceError(f"self-test accepted {label}")

    absent_path = copy.deepcopy(rows)
    absent_path[0]["source_path"] = "drivers/gpu/drm/radeon/absent.c"
    try:
        validate(root, absent_path, features)
    except InterfaceError:
        pass
    else:
        raise InterfaceError("self-test accepted absent source path")

    absent_marker = copy.deepcopy(rows)
    absent_marker[-1]["marker"] = "absent_marker"
    try:
        validate(root, absent_marker, features)
    except InterfaceError:
        pass
    else:
        raise InterfaceError("self-test accepted absent source marker")

    expected_counts = {
        "prod": (0, 0, 0),
        "observe-dev": (4, 2, 18),
        "probe-dev": (10, 8, 24),
        "mutate-dev": (19, 18, 33),
    }
    for profile, expected in expected_counts.items():
        selected = profile_rows(rows, features, profile)
        observed = (
            len({row["feature_id"] for row in selected}),
            sum(
                row["marker_type"] == "module-parameter"
                for row in selected
            ),
            sum(row["marker_type"] == "debugfs-file" for row in selected),
        )
        require(
            observed == expected,
            f"self-test profile count differs for {profile}",
        )

    runtime_counts = {
        ("observe-dev", "off"): (0, 0, 0),
        ("observe-dev", "observe-dev"): (4, 2, 18),
        ("probe-dev", "off"): (0, 0, 0),
        ("probe-dev", "observe-dev"): (4, 2, 18),
        ("probe-dev", "probe-dev"): (10, 8, 24),
        ("mutate-dev", "off"): (0, 0, 0),
        ("mutate-dev", "observe-dev"): (4, 2, 18),
        ("mutate-dev", "probe-dev"): (10, 8, 24),
        ("mutate-dev", "mutate-dev"): (19, 18, 33),
    }
    for selection, expected in runtime_counts.items():
        selected = runtime_rows(rows, features, *selection)
        observed = (
            len({row["feature_id"] for row in selected}),
            sum(
                row["marker_type"] == "module-parameter"
                for row in selected
            ),
            sum(row["marker_type"] == "debugfs-file" for row in selected),
        )
        require(
            observed == expected,
            "self-test runtime count differs for "
            + "/".join(selection),
        )

    try:
        profile_rows(rows, features, "development")
    except InterfaceError:
        pass
    else:
        raise InterfaceError("self-test accepted an unknown profile")

    invalid_tier_features = copy.deepcopy(features)
    first_feature = rows[0]["feature_id"]
    invalid_tier_features[first_feature]["tier"] = "development"
    try:
        profile_rows(rows, invalid_tier_features, "mutate-dev")
    except InterfaceError:
        pass
    else:
        raise InterfaceError("self-test accepted an unknown feature tier")

    try:
        runtime_rows(rows, features, "observe-dev", "probe-dev")
    except InterfaceError:
        pass
    else:
        raise InterfaceError("self-test accepted runtime above compiled ceiling")

    try:
        runtime_rows(rows, features, "mutate-dev", "all-dev")
    except InterfaceError:
        pass
    else:
        raise InterfaceError("self-test accepted an unknown runtime profile")

    source_texts = runtime_source_texts(root)
    validate_runtime_sources(source_texts)
    validate_mutation_audit(source_texts, features)
    missing_gate = copy.deepcopy(source_texts)
    missing_gate["drivers/gpu/drm/radeon/evergreen_cs.c"] = re.sub(
        r"radeon_dev_profile_enabled",
        "removed_profile_gate",
        missing_gate["drivers/gpu/drm/radeon/evergreen_cs.c"],
    )
    try:
        validate_runtime_sources(missing_gate)
    except InterfaceError:
        pass
    else:
        raise InterfaceError("self-test accepted a missing runtime source gate")

    missing_mutation_audit = copy.deepcopy(source_texts)
    missing_mutation_audit["drivers/gpu/drm/radeon/radeon_dev.c"] = re.sub(
        r"add_taint\(TAINT_USER, LOCKDEP_STILL_OK\)",
        "removed_mutation_taint",
        missing_mutation_audit["drivers/gpu/drm/radeon/radeon_dev.c"],
    )
    try:
        validate_mutation_audit(missing_mutation_audit, features)
    except InterfaceError:
        pass
    else:
        raise InterfaceError("self-test accepted a missing mutation audit")

    missing_mutation_call = copy.deepcopy(source_texts)
    missing_mutation_call["drivers/gpu/drm/radeon/radeon_rs4xx_dev.c"] = re.sub(
        r'radeon_dev_mark_mutation\(rdev, "RS4xx CP cache drain"\)',
        "removed_mutation_call",
        missing_mutation_call["drivers/gpu/drm/radeon/radeon_rs4xx_dev.c"],
    )
    try:
        validate_mutation_audit(missing_mutation_call, features)
    except InterfaceError:
        pass
    else:
        raise InterfaceError("self-test accepted a missing mutation call")

    require(
        carries_symbol({"reader_fops"}, "reader_fops"),
        "self-test rejected an exact compiler symbol",
    )
    require(
        carries_symbol({"reader_fops.llvm.123"}, "reader_fops"),
        "self-test rejected a compiler-suffixed symbol",
    )
    require(
        not carries_symbol({"reader_fops_extra"}, "reader_fops"),
        "self-test accepted an unrelated symbol prefix",
    )

    print(
        "all-dev interface self-test: 9 manifest rejection, "
        "6 build-profile, 12 runtime-profile, 2 mutation-audit, and "
        "3 compiler-symbol cases"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--module", type=Path)
    parser.add_argument(
        "--profile",
        choices=tuple(PROFILE_RANK),
        default="mutate-dev",
    )
    parser.add_argument("--driver-root", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        if args.self_test:
            return self_test(root)
        rows = read_manifest(root / "policy/all-dev-interface-manifest.tsv")
        features = read_features(root / "policy/build-features.toml")
        validate(
            root,
            rows,
            features,
            module=args.module,
            profile=args.profile,
            driver_root=args.driver_root,
        )
    except (
        OSError,
        UnicodeError,
        ValueError,
        tomllib.TOMLDecodeError,
        InterfaceError,
    ) as error:
        print(f"all-dev interfaces: {error}", file=sys.stderr)
        return 1

    reported_rows = (
        profile_rows(rows, features, args.profile) if args.module else rows
    )
    parameter_count = sum(
        row["marker_type"] == "module-parameter" for row in reported_rows
    )
    debugfs_count = sum(
        row["marker_type"] == "debugfs-file" for row in reported_rows
    )
    feature_count = len({row["feature_id"] for row in reported_rows})
    report_name = (
        f"{args.profile} compiled interfaces"
        if args.module
        else "all-dev source interfaces"
    )
    print(
        f"{report_name}: {feature_count} development features, "
        f"{parameter_count} module parameters, {debugfs_count} debugfs files"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
