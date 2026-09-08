#!/usr/bin/env python3
"""Prove that Radeon debugfs nodes inherit the DRM primary-minor lifetime."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


RADEON_SOURCE_DIRECTORY = Path("drivers/gpu/drm/radeon")
HEADER_PATH = RADEON_SOURCE_DIRECTORY / "radeon.h"
DEVICE_PATH = RADEON_SOURCE_DIRECTORY / "radeon_device.c"
DRIVER_PATH = RADEON_SOURCE_DIRECTORY / "radeon_drv.c"
TTM_PATH = RADEON_SOURCE_DIRECTORY / "radeon_ttm.c"

STATIC_COMPONENTS = {
    "r100_cp_csq_fifo": ("r100.c", "0444", "rdev", "r100_debugfs_cp_csq_fifo_fops"),
    "r100_cp_ring_info": ("r100.c", "0444", "rdev", "r100_debugfs_cp_ring_info_fops"),
    "r100_mc_info": ("r100.c", "0444", "rdev", "r100_debugfs_mc_info_fops"),
    "r100_rbbm_info": ("r100.c", "0444", "rdev", "r100_debugfs_rbbm_info_fops"),
    "r420_pipes_info": ("r420.c", "0444", "rdev", "r420_debugfs_pipes_info_fops"),
    "r600_mc_info": ("r600.c", "0444", "rdev", "r600_debugfs_mc_info_fops"),
    "radeon_fence_info": (
        "radeon_fence.c",
        "0444",
        "rdev",
        "radeon_debugfs_fence_info_fops",
    ),
    "radeon_gem_info": ("radeon_gem.c", "0444", "rdev", "radeon_debugfs_gem_info_fops"),
    "radeon_gpu_reset": (
        "radeon_fence.c",
        "0444",
        "rdev",
        "radeon_debugfs_gpu_reset_fops",
    ),
    "radeon_gtt": ("radeon_ttm.c", "0444", "rdev", "radeon_ttm_gtt_fops"),
    "radeon_pm_info": ("radeon_pm.c", "0444", "rdev", "radeon_debugfs_pm_info_fops"),
    "radeon_sa_info": ("radeon_ib.c", "0444", "rdev", "radeon_debugfs_sa_info_fops"),
    "radeon_vram": ("radeon_ttm.c", "0444", "rdev", "radeon_ttm_vram_fops"),
    "rs400_gart_info": ("rs400.c", "0444", "rdev", "rs400_debugfs_gart_info_fops"),
    "rv370_pcie_gart_info": (
        "r300.c",
        "0444",
        "rdev",
        "rv370_debugfs_pcie_gart_info_fops",
    ),
    "rv515_ga_info": ("rv515.c", "0444", "rdev", "rv515_debugfs_ga_info_fops"),
    "rv515_pipes_info": ("rv515.c", "0444", "rdev", "rv515_debugfs_pipes_info_fops"),
    "ttm_page_pool": ("radeon_ttm.c", "0444", "rdev", "radeon_ttm_page_pool_fops"),
}
DIRECT_CREATION_COUNTS = {
    "radeon_drv.c": 1,
    "radeon_evergreen_dev.c": 1,
    "radeon_rs4xx_dev.c": 41,
}
RING_COMPONENT_COUNT = 8
TTM_MANAGER_COUNT = 2

C_COMMENT_OR_LITERAL = re.compile(
    r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
    re.DOTALL,
)
C_COMMENT = re.compile(r"/\*.*?\*/|//[^\n]*", re.DOTALL)
C_CONDITIONAL_DIRECTIVE = re.compile(
    r"(?m)^[ \t]*(?:#|%:)[ \t]*"
    r"(?P<kind>if|ifdef|ifndef|elif|else|endif)\b"
    r"(?P<tail>[^\r\n]*)"
)
STATIC_COMPONENT_CALL = re.compile(
    r"\bradeon_debugfs_add_component\(\s*rdev\s*,\s*"
    r'"(?P<name>[^"]+)"\s*,\s*(?P<mode>0[0-7]+)\s*,\s*'
    r"(?P<data>[A-Za-z_][A-Za-z0-9_]*)\s*,\s*&"
    r"(?P<fops>[A-Za-z_][A-Za-z0-9_]*)\s*\)",
    re.DOTALL,
)
RING_COMPONENT_CALL = re.compile(
    r"\bradeon_debugfs_add_component\(\s*rdev\s*,\s*ring_name\s*,\s*"
    r"0444\s*,\s*ring\s*,\s*&radeon_debugfs_ring_info_fops\s*\)",
    re.DOTALL,
)


class ContractError(RuntimeError):
    """One source-static debugfs lifetime invariant fails."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def replace_match_with_space(match: re.Match[str]) -> str:
    return "".join("\n" if character == "\n" else " " for character in match.group(0))


def strip_comments_and_literals(source: str) -> str:
    return C_COMMENT_OR_LITERAL.sub(replace_match_with_space, source)


def strip_comments(source: str) -> str:
    return C_COMMENT.sub(replace_match_with_space, source)


def load_texts(root: Path) -> dict[str, str]:
    source_root = root / RADEON_SOURCE_DIRECTORY
    texts = {
        path.name: path.read_text(encoding="utf-8")
        for path in sorted(source_root.glob("*.c"))
    }
    texts["radeon.h"] = (root / HEADER_PATH).read_text(encoding="utf-8")
    texts["radeon_ttm.h"] = (root / RADEON_SOURCE_DIRECTORY / "radeon_ttm.h").read_text(
        encoding="utf-8"
    )
    return texts


def function_body(source: str, name: str) -> str:
    searchable = strip_comments_and_literals(source)
    definition = re.search(
        rf"(?m)^(?:[A-Za-z_].*\b)?{re.escape(name)}\s*\(", searchable
    )
    require(definition is not None, f"function {name} is absent")
    opening = searchable.find("{", definition.start())
    require(opening >= 0, f"function {name} has no body")
    depth = 0
    for offset in range(opening, len(searchable)):
        if searchable[offset] == "{":
            depth += 1
        elif searchable[offset] == "}":
            depth -= 1
            if depth == 0:
                return source[definition.start() : offset + 1]
    raise ContractError(f"function {name} has an unterminated body")


def conditional_stack_at(
    source: str, offset: int, label: str
) -> list[tuple[str, str, str]]:
    stack: list[tuple[str, str, str]] = []
    for directive in C_CONDITIONAL_DIRECTIVE.finditer(source, 0, offset):
        kind = directive.group("kind")
        tail = directive.group("tail").strip()
        if kind in {"if", "ifdef", "ifndef"}:
            stack.append((kind, tail, "initial"))
        elif kind in {"elif", "else"}:
            require(bool(stack), f"{label} follows unmatched #{kind}")
            opening_kind, opening_tail, _branch = stack[-1]
            stack[-1] = (opening_kind, opening_tail, kind)
        else:
            require(bool(stack), f"{label} follows unmatched #endif")
            stack.pop()
    return stack


def require_order(body: str, labels_and_patterns: tuple[tuple[str, str], ...]) -> None:
    position = -1
    for label, pattern in labels_and_patterns:
        match = re.compile(pattern, re.DOTALL).search(body, position + 1)
        require(match is not None, f"{label} is absent")
        position = match.start()


def validate_static_components(texts: dict[str, str]) -> None:
    observed: dict[str, tuple[str, str, str, str]] = {}
    for filename, source in texts.items():
        if not filename.endswith(".c"):
            continue
        for match in STATIC_COMPONENT_CALL.finditer(strip_comments(source)):
            name = match.group("name")
            require(name not in observed, f"debugfs component {name} is duplicated")
            observed[name] = (
                filename,
                match.group("mode"),
                match.group("data"),
                match.group("fops"),
            )
    require(observed == STATIC_COMPONENTS, "static debugfs component map differs")

    ring_source = texts["radeon_ring.c"]
    require(
        len(RING_COMPONENT_CALL.findall(strip_comments(ring_source))) == 1,
        "ring debugfs component registration differs",
    )
    ring_names_body = function_body(ring_source, "radeon_debugfs_ring_idx_to_name")
    ring_names = re.findall(r'return\s+"radeon_ring_[^"]+"\s*;', ring_names_body)
    require(
        len(ring_names) == RING_COMPONENT_COUNT
        and len(set(ring_names)) == len(ring_names),
        "ring debugfs component denominator differs",
    )


def validate_direct_creation_topology(texts: dict[str, str]) -> None:
    observed_counts: dict[str, int] = {}
    for filename, source in texts.items():
        if not filename.endswith(".c"):
            continue
        call_count = len(
            re.findall(
                r"\bdebugfs_create_file\s*\(", strip_comments_and_literals(source)
            )
        )
        if call_count:
            observed_counts[filename] = call_count
    require(
        observed_counts == DIRECT_CREATION_COUNTS,
        "direct debugfs creation owner denominator differs",
    )

    for filename, source in texts.items():
        if filename in {"radeon_rs4xx_dev.c", "radeon_evergreen_dev.c"}:
            continue
        if filename == "radeon_drv.c":
            require(
                "primary->debugfs_root" not in strip_comments_and_literals(source),
                "dispatcher bypasses the primary-minor root argument",
            )
            continue
        require(
            "debugfs_root" not in strip_comments_and_literals(source),
            f"{filename} reaches a debugfs root outside registration",
        )


def validate_component_registry(texts: dict[str, str]) -> None:
    header = texts["radeon.h"]
    require(
        re.search(r"#define\s+RADEON_DEBUGFS_MAX_COMPONENTS\s+32\b", header)
        is not None,
        "debugfs component capacity differs",
    )
    ring_count_match = re.search(r"#define\s+RADEON_NUM_RINGS\s+(\d+)\b", header)
    require(ring_count_match is not None, "Radeon ring denominator is absent")
    maximum_components = 32
    maximum_rings = int(ring_count_match.group(1))
    require(maximum_rings == RING_COMPONENT_COUNT, "Radeon ring denominator differs")
    require(
        len(STATIC_COMPONENTS) + maximum_rings <= maximum_components,
        "debugfs component capacity cannot hold the finite denominator",
    )
    for field in (
        "debugfs_component_lock",
        "debugfs_component_count",
        "debugfs_registration_complete",
        "debugfs_components",
    ):
        require(field in header, f"debugfs registry field {field} is absent")

    driver_source = texts["radeon_drv.c"]
    add_body = function_body(driver_source, "radeon_debugfs_add_component")
    require(
        "debugfs_create_file" not in strip_comments_and_literals(add_body),
        "component request creates a debugfs file before registration",
    )
    for pattern, label in (
        (r"mutex_lock\(&rdev->debugfs_component_lock\);", "component registry lock"),
        (r"strcmp\(component->name, name\)", "component identity deduplication"),
        (r"component->mode != mode", "duplicate component mode identity"),
        (r"component->data != data", "duplicate component data identity"),
        (r"component->fops != fops", "duplicate component fops identity"),
        (r"rdev->debugfs_registration_complete", "late component refusal"),
        (
            r"rdev->debugfs_component_count\s*>=\s*RADEON_DEBUGFS_MAX_COMPONENTS",
            "component capacity refusal",
        ),
        (
            r"&rdev->debugfs_components\[rdev->debugfs_component_count\+\+\]",
            "component registry insertion",
        ),
    ):
        require(re.search(pattern, add_body, re.DOTALL) is not None, f"{label} differs")
    refusal = add_body.find("rdev->debugfs_registration_complete")
    insertion = add_body.find(
        "rdev->debugfs_components[rdev->debugfs_component_count++]"
    )
    require(0 <= refusal < insertion, "component insertion precedes fail-closed checks")

    dispatcher_body = function_body(driver_source, "radeon_dev_debugfs_register")
    require_order(
        dispatcher_body,
        (
            ("primary-minor validation", r"minor->type\s*!=\s*DRM_MINOR_PRIMARY"),
            ("debugfs root validation", r"!minor->debugfs_root"),
            ("driver-private validation", r"if\s*\(!rdev\)"),
            (
                "dispatcher registry lock",
                r"mutex_lock\(&rdev->debugfs_component_lock\);",
            ),
            ("duplicate dispatcher refusal", r"rdev->debugfs_registration_complete"),
            (
                "finite component loop",
                r"component_index\s*<\s*rdev->debugfs_component_count",
            ),
            (
                "primary-root component creation",
                r"debugfs_create_file\(component->name, component->mode,\s*"
                r"minor->debugfs_root, component->data,\s*component->fops\);",
            ),
            (
                "registration completion publication",
                r"rdev->debugfs_registration_complete\s*=\s*true;",
            ),
            (
                "dispatcher registry unlock",
                r"mutex_unlock\(&rdev->debugfs_component_lock\);",
            ),
            (
                "TTM manager registration",
                r"radeon_ttm_debugfs_register_managers\(rdev, minor->debugfs_root\);",
            ),
        ),
    )

    callback_match = re.search(
        r"\.debugfs_init\s*=\s*radeon_dev_debugfs_register", driver_source
    )
    require(callback_match is not None, "DRM debugfs callback is absent")
    require(
        conditional_stack_at(
            driver_source, callback_match.start(), "DRM debugfs callback"
        )
        == [],
        "DRM debugfs callback is profile-conditional",
    )

    device_source = texts["radeon_device.c"]
    device_init_body = function_body(device_source, "radeon_device_init")
    require_order(
        device_init_body,
        (
            (
                "component denominator initialization",
                r"debugfs_component_count\s*=\s*0;",
            ),
            (
                "component registration state initialization",
                r"debugfs_registration_complete\s*=\s*false;",
            ),
            (
                "component mutex initialization",
                r"mutex_init\(&rdev->debugfs_component_lock\);",
            ),
            ("ASIC initialization", r"r\s*=\s*radeon_init\(rdev\);"),
        ),
    )


def validate_ttm_manager_registration(texts: dict[str, str]) -> None:
    ttm_source = texts["radeon_ttm.c"]
    manager_body = function_body(ttm_source, "radeon_ttm_debugfs_register_managers")
    require(
        re.search(r"if\s*\(!rdev->mman.initialized\)\s*return;", manager_body)
        is not None,
        "TTM debugfs manager initialization guard differs",
    )
    require(
        len(re.findall(r"\bttm_resource_manager_create_debugfs\s*\(", manager_body))
        == TTM_MANAGER_COUNT,
        "TTM debugfs manager denominator differs",
    )
    require(
        'root, "radeon_vram_mm"' in manager_body
        and 'root, "radeon_gtt_mm"' in manager_body,
        "TTM debugfs manager root bindings differ",
    )
    all_c_source = "\n".join(
        source for filename, source in texts.items() if filename.endswith(".c")
    )
    require(
        len(re.findall(r"\bradeon_ttm_debugfs_register_managers\s*\(", all_c_source))
        == 2,
        "TTM debugfs manager caller denominator differs",
    )


def validate_texts(texts: dict[str, str]) -> None:
    validate_static_components(texts)
    validate_direct_creation_topology(texts)
    validate_component_registry(texts)
    validate_ttm_manager_registration(texts)


def mutate_once(text: str, old: str, new: str, label: str) -> str:
    require(text.count(old) == 1, f"selftest mutation anchor differs: {label}")
    return text.replace(old, new, 1)


def selftest(root: Path) -> int:
    texts = load_texts(root)
    validate_texts(texts)
    print("selftest known-good accepted: finite post-registration debugfs topology")

    mutations: list[tuple[str, str, str, str]] = [
        (
            "early GEM direct creation",
            "radeon_gem.c",
            'radeon_debugfs_add_component(rdev, "radeon_gem_info", 0444, rdev,',
            'debugfs_create_file("escaped_gem", 0444, NULL, rdev,',
        ),
        (
            "profile-conditional DRM callback",
            "radeon_drv.c",
            "\t.debugfs_init = radeon_dev_debugfs_register,",
            "#if RADEON_OBSERVE_DEV\n\t.debugfs_init = radeon_dev_debugfs_register,\n#endif",
        ),
        (
            "missing primary-minor guard",
            "radeon_drv.c",
            "minor->type != DRM_MINOR_PRIMARY || ",
            "",
        ),
        (
            "missing debugfs root guard",
            "radeon_drv.c",
            " ||\n\t    !minor->debugfs_root",
            "",
        ),
        (
            "component creation loses primary root",
            "radeon_drv.c",
            "minor->debugfs_root, component->data,",
            "NULL, component->data,",
        ),
        (
            "late component refusal removed",
            "radeon_drv.c",
            "rdev->debugfs_registration_complete ||\n\t\t\t ",
            "",
        ),
        (
            "component capacity reduced below denominator",
            "radeon.h",
            "#define RADEON_DEBUGFS_MAX_COMPONENTS\t\t32",
            "#define RADEON_DEBUGFS_MAX_COMPONENTS\t\t8",
        ),
        (
            "static component omitted",
            "radeon_gem.c",
            'radeon_debugfs_add_component(rdev, "radeon_gem_info", 0444, rdev,',
            'radeon_debugfs_add_component(rdev, "radeon_gem_other", 0444, rdev,',
        ),
        (
            "ring component route omitted",
            "radeon_ring.c",
            "radeon_debugfs_add_component(rdev, ring_name, 0444, ring,",
            "radeon_debugfs_add_component(rdev, NULL, 0444, ring,",
        ),
        (
            "TTM manager dispatcher omitted",
            "radeon_drv.c",
            "\tradeon_ttm_debugfs_register_managers(rdev, minor->debugfs_root);",
            "",
        ),
        (
            "TTM manager initialization guard omitted",
            "radeon_ttm.c",
            "#if defined(CONFIG_DEBUG_FS)\n\tif (!rdev->mman.initialized)\n\t\treturn;\n\n",
            "#if defined(CONFIG_DEBUG_FS)\n",
        ),
        (
            "duplicate component identity check weakened",
            "radeon_drv.c",
            "component->mode != mode || component->data != data ||\n\t\t\t     component->fops != fops",
            "component->mode != mode",
        ),
    ]

    rejected = 0
    for label, filename, old, new in mutations:
        candidate = dict(texts)
        candidate[filename] = mutate_once(candidate[filename], old, new, label)
        try:
            validate_texts(candidate)
        except ContractError as error:
            rejected += 1
            print(f"selftest known-bad rejected: {label}: {error}")
        else:
            raise ContractError(f"selftest known-bad accepted: {label}")

    print(f"selftest: 1 good and {rejected} bad debugfs fixtures classified")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()

    try:
        if args.selftest:
            return selftest(args.root.resolve())
        validate_texts(load_texts(args.root.resolve()))
    except (ContractError, OSError, UnicodeError) as error:
        print(f"Radeon debugfs registration: FAIL: {error}", file=sys.stderr)
        return 1

    print(
        "Radeon debugfs registration: PASS "
        f"({len(STATIC_COMPONENTS)} static components, "
        f"{RING_COMPONENT_COUNT} ring slots, {TTM_MANAGER_COUNT} TTM managers)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
