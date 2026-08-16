#!/usr/bin/env python3
"""Validate build-feature classification, dependencies, and plan coverage."""

from __future__ import annotations

import argparse
import copy
import csv
import hashlib
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
CANONICAL_PLAN_MECHANISMS = {
    "B01": "external-module-source-root",
    "B02": "clock-info-bounds-backport",
    "B03": "drm-print-include-backport",
    "B04": "set-base-api-bridge",
    "B05": "drm-client-lifecycle-bridge",
    "B06": "fbdev-allocation-bridge",
    "B07": "ttm-bo-finalization-bridge",
    "B08": "pci-msi-mask-bridge",
    "B09": "ttm-device-init-bridge",
    "B10": "firmware-presence-gate",
    "B11": "bounded-palm-reset",
    "B12": "palm-reset-trigger",
    "B13": "rs48x-safe-register-snapshot",
    "B14": "smx-dc-ctl0-command-policy",
    "M01": "cp-cache-drain",
    "M02": "cs-parser-failure-telemetry",
    "M03": "candidate-register-snapshots",
    "M04": "rs4xx-debugfs-registration",
    "M05": "cp-me-ram-dump",
    "M06": "cp-me-ram-injection",
    "M07": "cp-me-oracle",
    "M08": "safe-register-promotion",
    "M09": "indexed-diagnostic-probes",
    "M10": "pll-and-first-read-probes",
    "M11": "force-clock-register-probes",
    "M12": "r400-us-command-allowlist",
    "M13": "panic-breadcrumb",
    "M14": "igp-mc-idle-wait",
    "M15": "cp-scratch-oracle",
    "M16": "rs4xx-reset-clock-control",
    "M17": "bounded-reset-state-readback",
    "M18": "parked-hardware-entry-guards",
    "M19": "parked-display-guards",
    "M20": "parked-memory-containment",
    "M21": "parked-state-activation",
    "M22": "reset-recovery-probes",
    "M23": "one-shot-reset-mask-selection",
    "M24": "bounded-gart-table-reader",
}
CANONICAL_PLAN_IDS = set(CANONICAL_PLAN_MECHANISMS)
CANONICAL_GUARD_IDS = {"B13"} | {f"M{number:02d}" for number in range(1, 25)}
CANONICAL_GUARD_SOURCE_DIGESTS = {
    "B13": "92361c118d8b0019f432981312d6560d6f7002978ee59743a91994fb739acf31",
    "M01": "4c317f62859f556123f91e89e26576e0a30dc411b79ed5952cd7e53dbcf845f1",
    "M02": "0fdd9ada88a336511d78b4ce0fd474a11ff52ac37bb7b3e5e1300390f6fbe09f",
    "M03": "05f1fe531d7c5dac789724758f11c0f3d9f4af1ca63a667074b81e2faa3619b1",
    "M04": "66c75e2b0f924e9cc34f5bb36ba2c8e8c875fe7c90de7e328a4af99e01fbc065",
    "M05": "37a2c5b864419ea08870f95a1ad1808cf6f84ae54b068b5e57fc0f4fa479cfad",
    "M06": "536c389149f908638ef8eaeb6a7fcde7616e27c793dc0f98fab0975c479a3b8a",
    "M07": "7c78d020883a891cbd47efc7709f1d2e05eb0584966fa5e300bbe7dcc87cf5ac",
    "M08": "1b13b602167edf4b55a2c6fd8e2d731e5c25a9757202c855ee9c0f1936cdfd7b",
    "M09": "797344b12bbbb2f9db281b9fc84cfcbe92c7ac83c576c31f3dede1ad33f84e65",
    "M10": "875b767bbea4e83e1727e83a1c9229c23ec24084b686de7edb871c9cd01ef9fb",
    "M11": "0653c8483807fd2cb78d456a22a60ebd41e89aaa31666ae04eb979fd02cd5faf",
    "M12": "17d97eee18664f01fb5d024edff75915323042e1edadd5443917d00cd769cb5c",
    "M13": "470b6491cb7b2459daa36fa3197d54b8f0cc7541d6e8c4b3b9a65ed64022f199",
    "M14": "5f450d0b66bcee6cefab7d30c7d3aa9e24fb378ce467f4080b5940c0db1706a2",
    "M15": "58ff3aba794b9fa1c062c6a3610c787a962dedd2a7391c3fbead8be0fc051884",
    "M16": "5f450d0b66bcee6cefab7d30c7d3aa9e24fb378ce467f4080b5940c0db1706a2",
    "M17": "862211a74128f8c0d68fe3b51535a69f072ff640325faa0c71e64fd0ad1b757a",
    "M18": "ee2d7d1c2d39b971badef4b5d2141cd429a1015383f6082111a7d4de49991afe",
    "M19": "5e9e2d4266f0d2ed33a450513f8ea6f8203002fcfbd060095a619fc1e97067f4",
    "M20": "0b852d5322f6b924a5fa01518970d364615db02d0e68e3b56bb5a5961dcc79df",
    "M21": "79f5fc980ada7c73d2352adc10b0ee9e548181e56788af520691fac4687209e9",
    "M22": "f782b5d8150a4009e736262c52c1aab9fc8332a69afc94b293ab484b9766af08",
    "M23": "5f450d0b66bcee6cefab7d30c7d3aa9e24fb378ce467f4080b5940c0db1706a2",
    "M24": "491e37e8def3b99858fb66b021339b1c3a02a8ffee6b903b79936547f4612268",
}
RS4XX_HARDWARE_ADMISSION_CONSUMERS = {
    "safe-registers",
    "cache-drain",
    "parked-display-containment",
    "parked-memory-containment",
    "wedged-3d-reset-probes",
    "gart-table-reader",
    "candidate-registers",
    "hazard-readers",
    "cp-me-dump",
    "cp-me-write",
    "pll-probes",
    "first-read",
    "indexed-probes",
    "force-clock",
    "scratch-oracle",
}
STALE_PARKED_ADMISSION_PHRASES = (
    "unparked device",
    "parked-state refusal",
    "gpu_parked checked before",
    "latent-until-parked",
)
PARKED_MEMORY_OPERATION_GATE = (
    "the source-admitted RS400 and RS480 fbdev callback refuses before "
    "fb_io_mmap mapping selection; hardware transaction admission spans fault, "
    "placement, move, creation, and callback-bearing destruction; wait-capable "
    "teardown owns a transaction only after successful admission; refusal-only "
    "retention closes later admission without draining earlier work"
)
PARKED_MEMORY_RESOURCE_BOUNDS = (
    "the RS4xx branch returns -ENODEV before fb_io_mmap; finite transaction and "
    "reservation lifetimes; TTM destruction requires zero live BOs, retained "
    "BOs, retained tables, transactions, and readers"
)
PARKED_MEMORY_ADVERSARIAL_TEST = (
    "adversarial: conditional guard, broken device provenance, and displaced "
    "callback assignment mutations fail; delayed BO deletion keeps "
    "rs4xx_live_bos nonzero until final destruction"
)
FAILED_RESET_SOURCE_OBJECTS = (
    "drivers/gpu/drm/radeon/r300.c",
    "drivers/gpu/drm/radeon/radeon_device.c",
    "drivers/gpu/drm/radeon/radeon_fence.c",
    "drivers/gpu/drm/radeon/radeon_ib.c",
    "drivers/gpu/drm/radeon/radeon_irq_kms.c",
    "drivers/gpu/drm/radeon/radeon_kms.c",
    "drivers/gpu/drm/radeon/radeon_ring.c",
    "drivers/gpu/drm/radeon/rs400.c",
)
SPLIT_MECHANISMS = {
    "B11": {"production", "unsafe"},
    "M03": {"passive", "hazard"},
    "M10": {"pll", "first-read", "status-pair", "status-census"},
}
SPLIT_TIERS = {
    "B11": {"production": "prod", "unsafe": "mutate-dev"},
    "M03": {"passive": "observe-dev", "hazard": "probe-dev"},
    "M10": {"pll": "probe-dev", "first-read": "probe-dev",
            "status-pair": "probe-dev", "status-census": "probe-dev"},
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


def index_plan_rows(rows: list[dict[str, str]]) -> dict[str, dict[str, str]]:
    require(
        all(row.get("commit_id") for row in rows),
        "reconstruction plan carries an empty identifier",
    )
    require(
        len({row["commit_id"] for row in rows}) == len(rows),
        "reconstruction plan repeats an identifier",
    )
    require(
        {row["commit_id"] for row in rows} == CANONICAL_PLAN_IDS,
        "reconstruction plan identifier denominator differs",
    )
    return {row["commit_id"]: row for row in rows}


def load_plans(root: Path) -> dict[str, dict[str, str]]:
    rows = read_tsv(root / "docs/base-reconstruction-commit-plan.tsv")
    rows += read_tsv(root / "docs/reconstruction-commit-plan.tsv")
    return index_plan_rows(rows)


def load_guard_scope(root: Path) -> dict[str, dict[str, str]]:
    rows = read_tsv(root / "policy/rs4xx-guard-scope.tsv")
    require(
        all(row.get("guard_id") for row in rows),
        "guard scope carries an empty identifier",
    )
    require(
        len({row["guard_id"] for row in rows}) == len(rows),
        "guard scope repeats an identifier",
    )
    require(
        {row["guard_id"] for row in rows} == CANONICAL_GUARD_IDS,
        "guard scope identifier denominator differs",
    )
    return {row["guard_id"]: row for row in rows}


def validate_guard_scope_sources(
    root: Path, guard_scope: dict[str, dict[str, str]]
) -> None:
    for guard_id, row in guard_scope.items():
        references: set[str] = set()
        raw_references = row.get("source_symbols", "").split(";")
        require(
            raw_references and all(raw_references),
            f"{guard_id}: source symbol set is empty",
        )
        for reference in raw_references:
            path_text, separator, symbol = reference.rpartition(":")
            require(
                separator == ":" and path_text and symbol,
                f"{guard_id}: malformed source symbol {reference}",
            )
            path = Path(path_text)
            require(
                not path.is_absolute()
                and ".." not in path.parts
                and path.parts[:4] == ("drivers", "gpu", "drm", "radeon"),
                f"{guard_id}: source symbol leaves the Radeon tree {reference}",
            )
            require(
                reference not in references,
                f"duplicate guard source symbol {reference}",
            )
            references.add(reference)
            source_path = root / path
            require(
                source_path.is_file(), f"{guard_id}: source file is absent {path_text}"
            )
            source = source_path.read_text(encoding="utf-8")
            require(
                re.search(
                    rf"(?m)^(?=[A-Za-z_])[^;\n]*\b{re.escape(symbol)}\s*\(",
                    source,
                )
                is not None,
                f"{guard_id}: source function is absent {reference}",
            )


def validate_guard_scope_mechanisms(
    guard_scope: dict[str, dict[str, str]],
    plans: dict[str, dict[str, str]],
) -> None:
    """Bind every reconstruction-backed guard row to its canonical mechanism."""

    require(
        set(plans) == CANONICAL_PLAN_IDS,
        "reconstruction plan identifier denominator differs",
    )
    require(
        set(guard_scope) == CANONICAL_GUARD_IDS,
        "guard scope identifier denominator differs",
    )
    for commit_id, mechanism in CANONICAL_PLAN_MECHANISMS.items():
        require(
            plans[commit_id]["mechanism"] == mechanism,
            f"{commit_id}: reconstruction plan mechanism differs",
        )
    for guard_id, row in guard_scope.items():
        plan = plans.get(guard_id)
        require(
            plan is not None, f"{guard_id}: guard is absent from reconstruction plan"
        )
        source_digest = hashlib.sha256(
            row["source_symbols"].encode("ascii")
        ).hexdigest()
        require(
            source_digest == CANONICAL_GUARD_SOURCE_DIGESTS[guard_id],
            f"{guard_id}: guard source-symbol identity differs",
        )
        require(
            row["mechanism"] == plan["mechanism"],
            f"{guard_id}: guard mechanism {row['mechanism']} differs from "
            f"plan mechanism {plan['mechanism']}",
        )


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
    require(
        KEBAB.fullmatch(feature_id) is not None, f"{feature_id}: invalid feature ID"
    )

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
        require(
            runtime_default == "active", f"{feature_id}: prod runtime is not active"
        )
        require(
            feature["package_projection"] == "production",
            f"{feature_id}: prod package projection is invalid",
        )
    else:
        require(
            availability == "absent-in-prod",
            f"{feature_id}: development feature is present in prod",
        )
        require(
            runtime_default == "off", f"{feature_id}: dev runtime default is not off"
        )
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
    descriptive_contract = "\n".join(
        str(feature[field])
        for field in (
            "operation_gate",
            "operation_arm_default",
            "arming_model",
            "locking",
            "error_contract",
            "tests",
        )
    )
    for stale_phrase in STALE_PARKED_ADMISSION_PHRASES:
        require(
            stale_phrase not in descriptive_contract,
            f"{feature_id}: stale Boolean-only admission phrase {stale_phrase}",
        )
    if feature_id in RS4XX_HARDWARE_ADMISSION_CONSUMERS:
        require(
            "hardware transaction" in str(feature["operation_gate"]),
            f"{feature_id}: operation gate omits hardware transaction admission",
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
            require(
                (root / path).is_file(), f"{feature_id}: missing source object {source}"
            )

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
    if feature_id == "parked-memory-containment":
        require(
            feature["operation_gate"] == PARKED_MEMORY_OPERATION_GATE,
            "parked-memory-containment: fbdev operation boundary differs",
        )
        require(
            feature["resource_bounds"] == PARKED_MEMORY_RESOURCE_BOUNDS,
            "parked-memory-containment: fbdev or TTM resource boundary differs",
        )
        require(
            PARKED_MEMORY_ADVERSARIAL_TEST in tests,
            "parked-memory-containment: adversarial lifetime witness differs",
        )
    if feature_id == "failed-reset-parking":
        require(
            source_objects == list(FAILED_RESET_SOURCE_OBJECTS),
            "failed-reset-parking: source object denominator differs",
        )

    scope_refs = string_list(feature, "scope_refs")
    require(
        (feature["execution_scope"] == "scope_refs") == bool(scope_refs)
        and (feature["evidence_scope"] == "scope_refs") == bool(scope_refs),
        f"{feature_id}: scope_refs and scope fields disagree",
    )
    if scope_refs:
        require(
            len(set(scope_refs)) == len(scope_refs),
            f"{feature_id}: scope_refs repeats an identifier",
        )
        source_mechanism_ids = {
            mechanism_parts(token)[0] for token in source_mechanisms
        }
        require(
            set(scope_refs) <= source_mechanism_ids,
            f"{feature_id}: scope_refs leave the feature source mechanisms",
        )
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
            require(
                guard_id in guard_scope, f"{feature_id}: unknown scope ref {guard_id}"
            )
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
            "radeon_device_init" in initialization
            and "RADEON_RS4XX_HARDWARE_RUNNING" in initialization
            and "rs4xx_hardware_closing" in initialization
            and "rs4xx_hardware_transactions" in initialization
            and "rs4xx_hardware_readers" in initialization,
            "parked-entry-containment: admission state initialization is incomplete",
        )
        require(
            isinstance(source, str)
            and "radeon_drv.c:radeon_pci_probe" in source
            and "radeon_device.c:radeon_device_init" in source
            and "drm_drv.c:__devm_drm_dev_alloc" in source,
            "parked-entry-containment: initialization sources are incomplete",
        )
        if files:
            radeon_driver = (root / "drivers/gpu/drm/radeon/radeon_drv.c").read_text(
                encoding="ascii"
            )
            require(
                "rdev = devm_drm_dev_alloc(" in radeon_driver,
                "parked-entry-containment: allocation site no longer uses "
                "devm_drm_dev_alloc",
            )
            radeon_header = (root / "drivers/gpu/drm/radeon/radeon.h").read_text(
                encoding="ascii"
            )
            require(
                re.search(r"\bbool\s+gpu_parked;", radeon_header) is not None,
                "parked-entry-containment: gpu_parked field is absent",
            )


def validate_dependencies(features: dict[str, dict[str, object]]) -> None:
    for feature_id, feature in features.items():
        for dependency in string_list(feature, "dependencies"):
            require(
                dependency in features, f"{feature_id}: unknown dependency {dependency}"
            )
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
            require(
                commit_id in plans,
                f"{feature_id}: unknown source mechanism {commit_id}",
            )
            expected_parts = SPLIT_MECHANISMS.get(commit_id)
            if expected_parts is None:
                require(
                    part is None, f"{feature_id}: unexpected split mechanism {token}"
                )
            else:
                require(
                    part in expected_parts,
                    f"{feature_id}: invalid mechanism part {token}",
                )
            require(token not in owners, f"{token}: duplicated source mechanism")
            owners[token] = feature_id
            tiers[commit_id].append(feature["tier"])
            parts[commit_id].add(part)
            if part is not None:
                part_tiers[commit_id][part] = feature["tier"]

    for commit_id, plan in plans.items():
        expected_parts = SPLIT_MECHANISMS.get(commit_id, {None})
        require(
            parts[commit_id] == expected_parts, f"{commit_id}: missing source mechanism"
        )
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
    validate_guard_scope_mechanisms(guard_scope, plans)
    if files:
        validate_guard_scope_sources(root, guard_scope)
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

    add(
        "duplicate feature ID",
        lambda value: value["feature"][1].update(id=value["feature"][0]["id"]),
    )
    add(
        "missing dev suffix",
        lambda value: value["feature"][3].update(setting="palm-reset"),
    )
    add(
        "too many setting words",
        lambda value: value["feature"][3].update(
            setting="palm-unsafe-reset-trigger-dev"
        ),
    )
    add("unknown tier", lambda value: value["feature"][3].update(tier="unsafe-dev"))
    add(
        "missing operation gate",
        lambda value: value["feature"][3].update(operation_gate=""),
    )
    add(
        "mutation below mutate",
        lambda value: value["feature"][3].update(
            tier="probe-dev", runtime_profile="probe-dev"
        ),
    )
    add(
        "raw reader in prod",
        lambda value: value["feature"][5].update(
            tier="prod",
            setting="prod",
            runtime_profile="prod",
            availability_default="present-in-prod",
            runtime_profile_default="active",
            package_projection="production",
        ),
    )
    add(
        "prod dependency on dev",
        lambda value: value["feature"][1].update(dependencies=["safe-registers"]),
    )
    add(
        "broader scope without decision",
        lambda value: value["feature"][6].update(scope_decision=""),
    )
    add(
        "unknown dependency",
        lambda value: value["feature"][3].update(dependencies=["missing-feature"]),
    )
    add(
        "dependency cycle",
        lambda value: value["feature"][4].update(dependencies=["safe-registers"]),
    )
    add(
        "unknown mechanism",
        lambda value: value["feature"][1].update(source_mechanisms=["B99"]),
    )
    add(
        "missing mechanism",
        lambda value: value["feature"][0].update(
            source_mechanisms=value["feature"][0]["source_mechanisms"][1:]
        ),
    )
    add(
        "plan tier mismatch",
        lambda value: value["feature"][17].update(
            tier="observe-dev",
            setting="cs-parser-dev",
            runtime_profile="observe-dev",
            availability_default="absent-in-prod",
            runtime_profile_default="off",
            package_projection="development",
        ),
    )
    add(
        "missing prod exception",
        lambda value: value["feature"][2].update(
            profile_exception="none", exception_basis="none"
        ),
    )
    add(
        "missing adversarial test",
        lambda value: value["feature"][3].update(
            tests=value["feature"][3]["tests"][:3]
        ),
    )
    add(
        "guard relation mismatch",
        lambda value: value["feature"][4].update(scope_relation="equal"),
    )
    add(
        "unknown scope relation",
        lambda value: value["feature"][0].update(scope_relation="approximate"),
    )
    add(
        "duplicated source mechanism",
        lambda value: value["feature"][1].update(source_mechanisms=["B10", "B01"]),
    )
    add(
        "swapped split tiers",
        lambda value: (
            value["feature"][2].update(source_mechanisms=["B11.unsafe"]),
            value["feature"][3].update(source_mechanisms=["B11.production", "B12"]),
        ),
    )
    add(
        "missing parked initialization",
        lambda value: value["feature"][10].update(state_initialization=""),
    )
    add(
        "stale Boolean-only hardware admission",
        lambda value: next(
            feature for feature in value["feature"] if feature["id"] == "safe-registers"
        ).update(
            operation_gate=(
                "compiled observe profile, supported family, and unparked device"
            )
        ),
    )
    add(
        "parked entry scope points at memory containment",
        lambda value: next(
            feature
            for feature in value["feature"]
            if feature["id"] == "parked-entry-containment"
        ).update(scope_refs=["M20"]),
    )
    add(
        "parked memory scope points at entry containment",
        lambda value: next(
            feature
            for feature in value["feature"]
            if feature["id"] == "parked-memory-containment"
        ).update(scope_refs=["M18"]),
    )
    add(
        "parked memory restores the zero VMA operation claim",
        lambda value: next(
            feature
            for feature in value["feature"]
            if feature["id"] == "parked-memory-containment"
        ).update(
            operation_gate=(
                "RS400 and RS480 refuse fbdev framebuffer or MMIO VMA creation "
                "before fb_io_mmap; hardware transaction admission spans fault, "
                "placement, move, creation, and callback-bearing destruction; "
                "wait-capable teardown owns a transaction only after successful "
                "admission; refusal-only retention closes later admission without "
                "draining earlier work"
            )
        ),
    )
    add(
        "parked memory restores the zero VMA resource claim",
        lambda value: next(
            feature
            for feature in value["feature"]
            if feature["id"] == "parked-memory-containment"
        ).update(
            resource_bounds=(
                "RS4xx admits zero persistent fbdev mapping VMAs; finite "
                "transaction and reservation lifetimes; TTM destruction "
                "requires zero live BOs, retained BOs, retained tables, "
                "transactions, and readers"
            )
        ),
    )
    add(
        "parked memory drops the delayed BO lifetime witness",
        lambda value: next(
            feature
            for feature in value["feature"]
            if feature["id"] == "parked-memory-containment"
        ).update(
            tests=[
                test
                if not test.startswith("adversarial:")
                else (
                    "adversarial: conditional guard, broken device provenance, "
                    "and displaced callback assignment mutations fail"
                )
                for test in next(
                    feature
                    for feature in value["feature"]
                    if feature["id"] == "parked-memory-containment"
                )["tests"]
            ]
        ),
    )
    add(
        "failed reset drops the IB failure publisher",
        lambda value: next(
            feature
            for feature in value["feature"]
            if feature["id"] == "failed-reset-parking"
        ).update(
            source_objects=[
                source
                for source in FAILED_RESET_SOURCE_OBJECTS
                if source != "drivers/gpu/drm/radeon/radeon_ib.c"
            ]
        ),
    )
    add(
        "safe registers scope points at unrelated mechanisms",
        lambda value: next(
            feature for feature in value["feature"] if feature["id"] == "safe-registers"
        ).update(scope_refs=["M01", "M02"]),
    )
    add(
        "GART table scope points outside the plan",
        lambda value: next(
            feature
            for feature in value["feature"]
            if feature["id"] == "gart-table-reader"
        ).update(scope_refs=["M25"]),
    )
    add(
        "duplicate scope reference",
        lambda value: next(
            feature for feature in value["feature"] if feature["id"] == "rs4xx-debugfs"
        ).update(scope_refs=["M04", "M04"]),
    )
    add(
        "scope reference deletion retains ledger scope",
        lambda value: next(
            feature for feature in value["feature"] if feature["id"] == "safe-registers"
        ).update(scope_refs=[]),
    )

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

    missing_guard_symbol = copy.deepcopy(guard_scope)
    first_guard = next(iter(missing_guard_symbol.values()))
    first_guard["source_symbols"] = (
        "drivers/gpu/drm/radeon/radeon_device.c:missing_guard_symbol"
    )
    try:
        validate_guard_scope_sources(root, missing_guard_symbol)
    except PolicyError:
        pass
    else:
        raise PolicyError("self-test accepted a missing guard source symbol")

    mismatched_guard = copy.deepcopy(guard_scope)
    guarded_plan_id = next(
        guard_id for guard_id in mismatched_guard if guard_id in plans
    )
    mismatched_guard[guarded_plan_id]["mechanism"] = "wrong-mechanism"
    try:
        validate(policy, root, plans, mismatched_guard, files=False)
    except PolicyError:
        pass
    else:
        raise PolicyError("self-test accepted a mismatched guard mechanism")

    swapped_guard_sources = copy.deepcopy(guard_scope)
    (
        swapped_guard_sources["M18"]["source_symbols"],
        swapped_guard_sources["M20"]["source_symbols"],
    ) = (
        swapped_guard_sources["M20"]["source_symbols"],
        swapped_guard_sources["M18"]["source_symbols"],
    )
    try:
        validate(policy, root, plans, swapped_guard_sources, files=False)
    except PolicyError:
        pass
    else:
        raise PolicyError("self-test accepted swapped guard source symbols")

    unplanned_guard = copy.deepcopy(guard_scope)
    unplanned_guard["M25"] = copy.deepcopy(next(iter(unplanned_guard.values())))
    unplanned_guard["M25"]["guard_id"] = "M25"
    try:
        validate(policy, root, plans, unplanned_guard, files=False)
    except PolicyError:
        pass
    else:
        raise PolicyError("self-test accepted a guard outside the plan")

    duplicate_plan_rows = [copy.deepcopy(row) for row in plans.values()]
    duplicate_plan_rows.append(copy.deepcopy(duplicate_plan_rows[-1]))
    try:
        index_plan_rows(duplicate_plan_rows)
    except PolicyError:
        pass
    else:
        raise PolicyError("self-test accepted a duplicate plan identifier")

    renamed_base_policy = copy.deepcopy(policy)
    renamed_base_plans = copy.deepcopy(plans)
    renamed_base_row = renamed_base_plans.pop("B14")
    renamed_base_row["commit_id"] = "B15"
    renamed_base_plans["B15"] = renamed_base_row
    base_feature = next(
        feature
        for feature in renamed_base_policy["feature"]
        if feature["id"] == "smx-dc-ctl0-policy"
    )
    base_feature["source_mechanisms"] = ["B15"]
    try:
        validate(
            renamed_base_policy,
            root,
            renamed_base_plans,
            guard_scope,
            files=False,
        )
    except PolicyError:
        pass
    else:
        raise PolicyError("self-test accepted a coordinated base plan rename")

    renamed_guard_policy = copy.deepcopy(policy)
    renamed_guard_plans = copy.deepcopy(plans)
    renamed_guard_scope = copy.deepcopy(guard_scope)
    renamed_guard_plan = renamed_guard_plans.pop("M24")
    renamed_guard_plan["commit_id"] = "M25"
    renamed_guard_plans["M25"] = renamed_guard_plan
    renamed_guard_row = renamed_guard_scope.pop("M24")
    renamed_guard_row["guard_id"] = "M25"
    renamed_guard_scope["M25"] = renamed_guard_row
    guard_feature = next(
        feature
        for feature in renamed_guard_policy["feature"]
        if feature["id"] == "gart-table-reader"
    )
    guard_feature["source_mechanisms"] = ["M25"]
    guard_feature["scope_refs"] = ["M25"]
    try:
        validate(
            renamed_guard_policy,
            root,
            renamed_guard_plans,
            renamed_guard_scope,
            files=False,
        )
    except PolicyError:
        pass
    else:
        raise PolicyError("self-test accepted a coordinated guard plan rename")

    renamed_mechanism_plans = copy.deepcopy(plans)
    renamed_mechanism_plans["B14"]["mechanism"] = "changed-mechanism"
    try:
        validate(
            policy,
            root,
            renamed_mechanism_plans,
            guard_scope,
            files=False,
        )
    except PolicyError:
        pass
    else:
        raise PolicyError("self-test accepted a changed plan mechanism")

    print(f"build-feature policy self-test: {len(cases) + 9} rejection cases")
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
