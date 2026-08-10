#!/usr/bin/env python3
"""Verify the exact legacy-equivalent development interface inventory."""

from __future__ import annotations

import argparse
import copy
import csv
import hashlib
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
REGISTRATION_FIELDS = {
    "interface_name",
    "registration_symbol",
    "source_path",
    "parent_expression",
    "lifetime_owner",
    "teardown_mechanism",
    "mode",
    "compiled_profile",
    "runtime_profile",
    "family_predicate",
    "execution_device_ids",
    "evidence_device_ids",
    "scope_relation",
}
PALM_RESET_REGISTRATION = {
    "interface_name": "radeon_force_pci_reset_safe",
    "registration_symbol": "radeon_evergreen_dev_debugfs_register",
    "source_path": "drivers/gpu/drm/radeon/radeon_evergreen_dev.c",
    "parent_expression": "minor->debugfs_root",
    "lifetime_owner": "DRM primary minor",
    "teardown_mechanism": (
        "DRM core removes the primary debugfs tree during device unregister"
    ),
    "mode": "0200",
    "compiled_profile": "mutate-dev",
    "runtime_profile": "mutate-dev",
    "family_predicate": "rdev->family == CHIP_PALM",
    "execution_device_ids": (
        "1002:9802;1002:9803;1002:9804;1002:9805;1002:9806;"
        "1002:9807;1002:9808;1002:9809;1002:980a"
    ),
    "evidence_device_ids": "none",
    "scope_relation": "broader-than-evidence",
}
MODULE_PARAMETER = re.compile(
    r"\bmodule_param_named\(\s*([A-Za-z0-9_]+)"
    r"|\bmodule_param\(\s*([A-Za-z0-9_]+)"
)
DEBUGFS_FILE = re.compile(r'debugfs_create_file\(\s*"([^"]+)"')
FUNCTION_END = re.compile(r"^\}")
C_COMMENT_OR_LITERAL = re.compile(
    r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
    re.DOTALL,
)
C_LINE_SPLICE = re.compile(r"\\(?:\r\n|\n|\r)")
C_CONDITIONAL_DIRECTIVE = re.compile(
    r"(?m)^[ \t\v\f]*(?:#|%:)[ \t\v\f]*"
    r"(?P<kind>if|ifdef|ifndef|elif|else|endif)\b"
    r"(?P<tail>[^\r\n]*)"
)
C_MACRO_OVERRIDE = re.compile(
    r"(?m)^[ \t\v\f]*(?:#|%:)[ \t\v\f]*(?:define|undef)"
    r"[ \t\v\f]+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
)
C_IDENTIFIER = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
PALM_REGISTRATION_PROTECTED_MACROS = (
    "CHIP_PALM",
    "DRM_MINOR_PRIMARY",
    "RADEON_DEV_PROFILE_MUTATE",
    "copy_from_user",
    "debugfs_create_file",
    "down_write",
    "evergreen_gpu_pci_config_reset_safe",
    "radeon_dev_hardware_available",
    "radeon_dev_profile_enabled",
    "sysfs_streq",
    "up_write",
)
PALM_RESET_PROTECTED_MACROS = (
    "CHIP_PALM",
    "CP_ME_CNTL",
    "CP_ME_HALT",
    "CP_PFP_HALT",
    "RREG32",
    "WREG32",
    "lockdep_assert_held_write",
    "radeon_dev_hardware_available",
    "radeon_dev_mark_mutation",
    "radeon_palm_dev_pci_reset_unsafe",
    "radeon_pci_config_reset",
)
PALM_RESET_HARDWARE_ACCESS = re.compile(
    r"\b(?:WREG32|RREG32|r600_rlc_stop|rv770_set_clk_bypass_mode|"
    r"pci_clear_master|evergreen_mc_stop|evergreen_mc_wait_for_idle|"
    r"evergreen_mc_resume|radeon_pci_config_reset)\s*\("
)
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
    "drivers/gpu/drm/radeon/radeon_device.c": (),
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
        r"static bool rs480_debugfs_refuse_if_parked\(.*?\)\n\{.*?"
        r"RADEON_DEV_OUTPUT_SCHEMA_LINE",
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
        r"void radeon_evergreen_dev_debugfs_register\(.*?\)\n\{.*?"
        r"RADEON_DEV_PROFILE_MUTATE",
    ),
    "drivers/gpu/drm/radeon/radeon_drv.c": (
        r"static void radeon_dev_debugfs_register\(.*?\)\n\{.*?"
        r"radeon_rs480_re_debugfs_register\(minor\);.*?"
        r"radeon_evergreen_dev_debugfs_register\(minor\);.*?\}",
        r"\.debugfs_init = radeon_dev_debugfs_register",
    ),
    "drivers/gpu/drm/radeon/radeon_kms.c": (),
    "drivers/gpu/drm/radeon/evergreen.c": (
        r"int evergreen_gpu_pci_config_reset_safe\(.*?\)\n\{.*?"
        r"radeon_palm_dev_pci_reset_unsafe",
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
            "drivers/gpu/drm/radeon/evergreen.c",
            r'radeon_dev_mark_mutation\(rdev, "Palm PCI config reset"\)',
            1,
        ),
    ),
    "smx-dc-ctl0-policy": (
        (
            "drivers/gpu/drm/radeon/evergreen_cs.c",
            r"radeon_dev_mark_mutation\(.*?p->rdev,.*?"
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
    "wedged-3d-reset-probes": (
        (
            "drivers/gpu/drm/radeon/radeon_rs4xx_dev.c",
            r'radeon_dev_mark_mutation\(rdev, "RS4xx reset hang probe"\)',
            1,
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

RETIRED_RESET_PROBE_MARKERS = {
    "drivers/gpu/drm/radeon/radeon_dev.c": (
        "radeon_rs480_gpu_reset_recover_probe",
    ),
    "drivers/gpu/drm/radeon/radeon_dev.h": (
        "radeon_rs480_gpu_reset_recover_probe",
    ),
    "drivers/gpu/drm/radeon/radeon_rs4xx_dev.c": (
        "RS480_GPU_RESET_RECOVER_PROBE_ARM_TOKEN",
        "RS480_RESET_HANG_PROBE_SOFT_RESET_TOKEN",
        "RS480_RESET_HANG_PROBE_BLIT_RESET_TOKEN",
        "rs480_gpu_reset_recover_probe_show",
        "rs480_soft_reset",
        "rs480_blit_busy_reset",
        "0x52435652u",
        "0x53525354u",
        "0x48414e47u",
        "r100_copy_blit(",
        "r100_cp_init(rdev,",
    ),
}
RETIRED_RESET_PROBE_MARKER_COUNT = 13
RETIRED_RESET_PROBE_MARKER_SHA256 = (
    "e1770eb360d89524585a715ecad78fbcbd02114f8dccf749c9e40ab61046feae"
)
C_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
C_LINE_COMMENT = re.compile(r"//[^\n]*")
ADVERTISED_INTERFACE_TOTAL_PATTERNS = {
    "docs/dev-interface-surface-audit.md": re.compile(
        r"The development surface is (?P<debugfs>\d+) fork-added debugfs "
        r"nodes and (?P<parameters>\d+) module\s+parameters"
    ),
    "docs/reconstruction-roadmap.md": re.compile(
        r"all (?P<features>\d+) development\s+capabilities through an exact "
        r"inventory of (?P<parameters>\d+) module parameters, "
        r"(?P<debugfs>\d+) debugfs\s+files"
    ),
}


class InterfaceError(Exception):
    """The all-development interface inventory differs from its declaration."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise InterfaceError(message)


def strip_comments(source: str) -> str:
    """Apply C line splicing, then blank comments while retaining literals."""

    def blank_comment(match: re.Match[str]) -> str:
        token = match.group(0)
        if not token.startswith(("/*", "//")):
            return token
        return re.sub(r"[^\n]", " ", match.group(0))

    return C_COMMENT_OR_LITERAL.sub(blank_comment, C_LINE_SPLICE.sub("", source))


def strip_comments_and_literals(source: str) -> str:
    """Apply C line splicing, then blank comments and C literals."""

    def blank(match: re.Match[str]) -> str:
        return re.sub(r"[^\n]", " ", match.group(0))

    blanked = C_COMMENT_OR_LITERAL.sub(blank, C_LINE_SPLICE.sub("", source))
    return blanked.replace("<%", "{ ").replace("%>", "} ")


def normalized_code(source: str) -> str:
    """Return a whitespace-normalized C token mask for exact intervals."""
    return re.sub(r"\s+", " ", strip_comments_and_literals(source)).strip()


def brace_depth_at(source: str, position: int) -> int:
    """Return lexical brace depth before a position in comment-free C."""
    prefix = strip_comments_and_literals(source[:position])
    depth = 0
    for character in prefix:
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
        require(depth >= 0, "C source carries an unmatched closing brace")
    return depth


def require_outer_function_match(
    body: str,
    match: re.Match[str],
    label: str,
    allowed_label: str | None = None,
    expected_depth: int = 1,
) -> None:
    code = strip_comments_and_literals(body)
    require(
        brace_depth_at(code, match.start()) == expected_depth,
        f"{label} is not a direct statement at depth {expected_depth}",
    )
    function_open = code.find("{")
    require(function_open >= 0, f"{label} function body is absent")
    boundary = function_open + 1
    depth = 1
    parenthesis_depth = 0
    bracket_depth = 0
    for offset in range(function_open + 1, match.start()):
        token = code[offset]
        if token == "{":
            depth += 1
        elif token == "}":
            depth -= 1
            if depth == expected_depth:
                boundary = offset + 1
        elif token == "(":
            parenthesis_depth += 1
        elif token == ")":
            parenthesis_depth -= 1
            require(
                parenthesis_depth >= 0,
                f"{label} carries invalid parenthesis order",
            )
        elif token == "[":
            bracket_depth += 1
        elif token == "]":
            bracket_depth -= 1
            require(
                bracket_depth >= 0,
                f"{label} carries invalid bracket order",
            )
        elif (
            token == ";"
            and depth == expected_depth
            and parenthesis_depth == 0
            and bracket_depth == 0
        ):
            boundary = offset + 1
    direct_prefix = code[boundary : match.start()].strip()
    require(
        not direct_prefix or direct_prefix == f"{allowed_label}:",
        f"{label} is controlled by an unbraced statement",
    )


CONTROL_FLOW_KEYWORDS = (
    "if",
    "else",
    "for",
    "while",
    "do",
    "switch",
    "case",
    "default",
    "break",
    "continue",
    "goto",
    "return",
)
OPAQUE_CONTROL_IDENTIFIERS = frozenset(
    {
        "BUG",
        "BUG_ON",
        "__asm",
        "__asm__",
        "__builtin_trap",
        "__builtin_unreachable",
        "asm",
        "do_exit",
        "make_task_dead",
        "panic",
        "unreachable",
    }
)


def require_no_opaque_control(body: str, label: str) -> None:
    """Reject finite nonlocal exits and inline assembly from a critical path."""
    identifiers = set(C_IDENTIFIER.findall(strip_comments_and_literals(body)))
    opaque_controls = sorted(identifiers & OPAQUE_CONTROL_IDENTIFIERS)
    require(
        not opaque_controls,
        f"{label} carries opaque control: {opaque_controls}",
    )


def require_control_flow_census(
    body: str,
    expected_counts: tuple[int, ...],
    expected_returns: tuple[tuple[str, int], ...],
    label: str,
) -> None:
    """Require lexical control under the stated returning-call assumption."""
    code = strip_comments_and_literals(body)
    actual_counts = tuple(
        len(re.findall(rf"\b{keyword}\b", code))
        for keyword in CONTROL_FLOW_KEYWORDS
    )
    require(
        actual_counts == expected_counts,
        f"{label} control-keyword census differs",
    )
    returns = tuple(
        (normalized_code(match.group(0)), brace_depth_at(code, match.start()))
        for match in re.finditer(r"\breturn\b[^;{}]*;", code)
    )
    require(returns == expected_returns, f"{label} return set differs")
    labels = re.findall(
        r"(?m)^[ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*:",
        code,
    )
    require(not labels, f"{label} carries a source label")


def require_exact_code_interval(
    body: str,
    start_marker: str,
    end_marker: str,
    expected_code: str,
    expected_depth: int,
    label: str,
) -> tuple[int, int]:
    """Require one direct, closed C interval between exact source anchors."""
    start_match = require_one_match(body, re.escape(start_marker), label)
    require_outer_function_match(
        body,
        start_match,
        label,
        expected_depth=expected_depth,
    )
    interval_end = body.find(end_marker, start_match.start())
    require(interval_end >= 0, f"{label} end marker is absent")
    interval_end += len(end_marker)
    actual_code = normalized_code(body[start_match.start() : interval_end])
    require(actual_code == expected_code, f"{label} exact interval differs")
    return start_match.start(), interval_end


def require_no_conditional_preprocessor(body: str, label: str) -> None:
    """Reject conditional preprocessing inside one audited function."""
    require(
        C_CONDITIONAL_DIRECTIVE.search(body) is None,
        f"{label} contains a conditional preprocessing directive",
    )


def require_definition_outside_conditional(
    code: str,
    definition_offset: int,
    label: str,
) -> None:
    """Reject a function definition enclosed by conditional preprocessing."""
    conditional_stack = conditional_stack_at(code, definition_offset, label)
    require(
        not conditional_stack,
        f"{label} is enclosed by conditional preprocessing",
    )


def conditional_stack_at(
    code: str,
    offset: int,
    label: str,
) -> list[tuple[str, str, str]]:
    """Return the exact conditional preprocessing stack at one offset."""
    conditional_stack: list[tuple[str, str, str]] = []
    for directive in C_CONDITIONAL_DIRECTIVE.finditer(code, 0, offset):
        kind = directive.group("kind")
        tail = directive.group("tail").strip()
        if kind in {"if", "ifdef", "ifndef"}:
            conditional_stack.append((kind, tail, "initial"))
        elif kind in {"elif", "else"}:
            require(
                bool(conditional_stack),
                f"{label} follows an unmatched #{kind}",
            )
            opening_kind, opening_tail, _branch = conditional_stack[-1]
            conditional_stack[-1] = (opening_kind, opening_tail, kind)
        elif conditional_stack:
            conditional_stack.pop()
        else:
            raise InterfaceError(f"{label} follows an unmatched #endif")
    return conditional_stack


def require_no_local_macro_overrides(
    source: str,
    protected_names: tuple[str, ...],
    label: str,
) -> None:
    """Reject primary source file overrides of protected identifiers."""
    code = strip_comments_and_literals(source)
    overridden = sorted(
        {
            match.group("name")
            for match in C_MACRO_OVERRIDE.finditer(code)
            if match.group("name") in protected_names
        }
    )
    require(not overridden, f"{label} overrides protected macros: {overridden}")


def identifier_counts(texts: dict[str, str], identifier: str) -> dict[str, int]:
    """Count a C identifier across the driver corpus outside comments and literals."""
    pattern = re.compile(rf"\b{re.escape(identifier)}\b")
    return {
        path: len(pattern.findall(strip_comments_and_literals(source)))
        for path, source in texts.items()
        if pattern.search(strip_comments_and_literals(source))
    }


def function_body(
    source: str,
    name: str,
    *,
    require_unconditional: bool = False,
    expected_enclosing_condition: str | None = None,
    expected_enclosing_stack: tuple[tuple[str, str, str], ...] | None = None,
    protect_identifiers: bool = False,
) -> str:
    """Return one column-zero C function definition, brace to brace."""
    code = strip_comments(source)
    definition = re.search(
        rf"(?m)^(?:[A-Za-z_].*\b)?{re.escape(name)}\s*\(",
        code,
    )
    require(definition is not None, f"function {name} is absent")
    conditional_requirements = sum(
        (
            require_unconditional,
            expected_enclosing_condition is not None,
            expected_enclosing_stack is not None,
        )
    )
    require(
        conditional_requirements <= 1,
        f"function {name} has conflicting conditional requirements",
    )
    definition_code = strip_comments_and_literals(source)
    if require_unconditional:
        require_definition_outside_conditional(
            definition_code,
            definition.start(),
            f"function {name}",
        )
    elif expected_enclosing_condition is not None:
        require(
            conditional_stack_at(
                definition_code,
                definition.start(),
                f"function {name}",
            )
            == [("if", expected_enclosing_condition, "initial")],
            f"function {name} conditional scope differs",
        )
    elif expected_enclosing_stack is not None:
        require(
            conditional_stack_at(
                definition_code,
                definition.start(),
                f"function {name}",
            )
            == list(expected_enclosing_stack),
            f"function {name} conditional scope differs",
        )
    lines = code.splitlines()
    start = code.count("\n", 0, definition.start())
    for index in range(start, len(lines)):
        if FUNCTION_END.match(lines[index]):
            function_text = "\n".join(lines[start : index + 1])
            if protect_identifiers:
                protected_identifier_set = set(
                    C_IDENTIFIER.findall(
                        strip_comments_and_literals(function_text)
                    )
                )
                enclosing_conditions = []
                if expected_enclosing_condition is not None:
                    enclosing_conditions.append(expected_enclosing_condition)
                if expected_enclosing_stack is not None:
                    enclosing_conditions.extend(
                        condition_tail
                        for _kind, condition_tail, _branch
                        in expected_enclosing_stack
                    )
                for condition in enclosing_conditions:
                    protected_identifier_set.update(
                        C_IDENTIFIER.findall(condition)
                    )
                protected_identifier_set.discard("defined")
                require_no_local_macro_overrides(
                    source,
                    tuple(sorted(protected_identifier_set)),
                    f"function {name}",
                )
            return function_text
    raise InterfaceError(f"function {name} has no closing brace")


def initializer_body(
    source: str,
    name: str,
    *,
    protect_identifiers: bool = False,
) -> str:
    """Return one unconditional C initializer through its closing brace."""
    code = strip_comments_and_literals(source)
    definition = re.search(
        rf"(?m)^[A-Za-z_][^\n]*\b{re.escape(name)}\s*=\s*\{{",
        code,
    )
    require(definition is not None, f"initializer {name} is absent")
    require_definition_outside_conditional(
        code,
        definition.start(),
        f"initializer {name}",
    )
    opening = code.find("{", definition.start())
    require(opening >= 0, f"initializer {name} has no opening brace")
    depth = 0
    for offset in range(opening, len(code)):
        if code[offset] == "{":
            depth += 1
        elif code[offset] == "}":
            depth -= 1
            if depth == 0:
                initializer_text = code[definition.start() : offset + 1]
                if protect_identifiers:
                    protected_identifiers = tuple(
                        sorted(set(C_IDENTIFIER.findall(initializer_text)))
                    )
                    require_no_local_macro_overrides(
                        source,
                        protected_identifiers,
                        f"initializer {name}",
                    )
                return initializer_text
            require(depth >= 0, f"initializer {name} has invalid brace order")
    raise InterfaceError(f"initializer {name} has no closing brace")


def require_one_match(body: str, pattern: str, label: str) -> re.Match[str]:
    matches = list(re.finditer(pattern, body, re.DOTALL))
    require(len(matches) == 1, f"{label} count is {len(matches)}, expected 1")
    return matches[0]


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


def read_registration_contract(path: Path) -> list[dict[str, str]]:
    text = path.read_text(encoding="ascii")
    lines = [line for line in text.splitlines() if line]
    require(bool(lines), "development interface registration contract is empty")
    rows = list(csv.DictReader(lines, delimiter="\t"))
    require(
        bool(rows) and set(rows[0]) == REGISTRATION_FIELDS,
        "development interface registration contract schema is invalid",
    )
    return rows


def read_features(path: Path) -> dict[str, dict[str, object]]:
    policy = tomllib.loads(path.read_text(encoding="ascii"))
    return {feature["id"]: feature for feature in policy["feature"]}


def advertised_interface_texts(root: Path) -> dict[str, str]:
    return {
        path: (root / path).read_text(encoding="ascii")
        for path in ADVERTISED_INTERFACE_TOTAL_PATTERNS
    }


def validate_advertised_interface_totals(
    texts: dict[str, str],
    rows: list[dict[str, str]],
    features: dict[str, dict[str, object]],
) -> None:
    expected = {
        "features": sum(feature["tier"] != "prod" for feature in features.values()),
        "parameters": sum(
            row["marker_type"] == "module-parameter" for row in rows
        ),
        "debugfs": sum(row["marker_type"] == "debugfs-file" for row in rows),
    }
    for path, pattern in ADVERTISED_INTERFACE_TOTAL_PATTERNS.items():
        require(path in texts, f"advertised interface summary is absent: {path}")
        matches = list(pattern.finditer(texts[path]))
        require(
            len(matches) == 1,
            f"advertised interface summary shape differs in {path}",
        )
        for field, value in matches[0].groupdict().items():
            require(
                int(value) == expected[field],
                f"advertised {field} total differs in {path}",
            )


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
    texts = {
        path: (root / path).read_text(encoding="ascii")
        for path in RUNTIME_SOURCE_PATTERNS
    }
    driver_root = root / "drivers/gpu/drm/radeon"
    for source in driver_root.glob("*.c"):
        path = source.relative_to(root).as_posix()
        texts.setdefault(path, source.read_text(encoding="utf-8"))
    return texts


def retired_reset_probe_source_texts(root: Path) -> dict[str, str]:
    return {
        path: (root / path).read_text(encoding="ascii")
        for path in RETIRED_RESET_PROBE_MARKERS
    }


def validate_output_schema_version(root: Path) -> None:
    """The schema version has one home per artifact class: the macro in
    radeon_dev.h drives every emitted line, and build-features.toml pins
    the value a probe runner may accept, so drift between them fails."""
    header = (root / "drivers/gpu/drm/radeon/radeon_dev.h").read_text(encoding="ascii")
    macro = re.search(r"#define RADEON_DEV_OUTPUT_SCHEMA_VERSION (\d+)", header)
    require(macro is not None, "RADEON_DEV_OUTPUT_SCHEMA_VERSION is absent")
    line = re.search(
        r'#define RADEON_DEV_OUTPUT_SCHEMA_LINE "schema rs480-dev v(\d+)'
        r'\\n"',
        header,
    )
    require(line is not None, "RADEON_DEV_OUTPUT_SCHEMA_LINE is absent")
    require(
        macro.group(1) == line.group(1),
        "schema line version differs from RADEON_DEV_OUTPUT_SCHEMA_VERSION",
    )
    features = (root / "policy/build-features.toml").read_text(encoding="ascii")
    pinned = re.search(r"^output_schema_version = (\d+)$", features, re.M)
    require(
        pinned is not None,
        "output_schema_version is absent from build-features.toml",
    )
    require(
        pinned.group(1) == macro.group(1),
        "build-features.toml output_schema_version differs from "
        "RADEON_DEV_OUTPUT_SCHEMA_VERSION",
    )


def validate_runtime_sources(texts: dict[str, str]) -> None:
    for path, patterns in RUNTIME_SOURCE_PATTERNS.items():
        require(path in texts, f"runtime gate source is absent: {path}")
        for pattern in patterns:
            require(
                re.search(pattern, texts[path], re.DOTALL) is not None,
                f"runtime gate is absent from {path}: {pattern}",
            )


def validate_palm_reset_registration(
    rows: list[dict[str, str]],
    texts: dict[str, str],
) -> None:
    require(
        len(rows) == 1,
        "development interface registration contract must contain one Palm row",
    )
    row = rows[0]
    require(
        all(row[field] for field in REGISTRATION_FIELDS),
        "development interface registration contract carries an empty field",
    )
    require(
        row == PALM_RESET_REGISTRATION,
        "Palm reset registration contract differs from its canonical values",
    )

    driver_source = texts["drivers/gpu/drm/radeon/radeon_drv.c"]
    dispatcher_body = function_body(
        driver_source,
        "radeon_dev_debugfs_register",
        expected_enclosing_condition="RADEON_OBSERVE_DEV",
        protect_identifiers=True,
    )
    require_one_match(
        dispatcher_body,
        r"^static void radeon_dev_debugfs_register\(struct drm_minor \*minor\)"
        r"\n\{\s*radeon_rs480_re_debugfs_register\(minor\);\s*"
        r"radeon_evergreen_dev_debugfs_register\(minor\);\s*\}$",
        "development debugfs dispatcher",
    )
    kms_driver_body = initializer_body(driver_source, "kms_driver")
    kms_directives = list(C_CONDITIONAL_DIRECTIVE.finditer(kms_driver_body))
    require(
        [
            (directive.group("kind"), directive.group("tail").strip())
            for directive in kms_directives
        ]
        == [("if", "RADEON_OBSERVE_DEV"), ("endif", "")],
        "DRM development debugfs callback conditional region differs",
    )
    kms_debugfs_match = require_one_match(
        kms_driver_body,
        r"\.debugfs_init = radeon_dev_debugfs_register",
        "DRM development debugfs callback",
    )
    require(
        conditional_stack_at(
            kms_driver_body,
            kms_debugfs_match.start(),
            "DRM development debugfs callback",
        )
        == [("if", "RADEON_OBSERVE_DEV", "initial")],
        "DRM development debugfs callback branch differs",
    )
    callback_region = kms_driver_body[
        kms_directives[0].start() : kms_directives[-1].end()
    ]
    require_no_local_macro_overrides(
        driver_source,
        tuple(sorted(set(C_IDENTIFIER.findall(callback_region)))),
        "DRM development debugfs callback",
    )
    require(
        identifier_counts(texts, "radeon_evergreen_dev_debugfs_register")
        == {
            "drivers/gpu/drm/radeon/radeon_evergreen_dev.c": 1,
            "drivers/gpu/drm/radeon/radeon_drv.c": 1,
        },
        "Palm reset registration has an unbound source reference",
    )

    palm_source = texts["drivers/gpu/drm/radeon/radeon_evergreen_dev.c"]
    require_no_local_macro_overrides(
        palm_source,
        PALM_REGISTRATION_PROTECTED_MACROS,
        "Palm reset registration source",
    )
    reset_fops_body = initializer_body(
        palm_source,
        "radeon_force_pci_reset_safe_fops",
        protect_identifiers=True,
    )
    require_no_conditional_preprocessor(
        reset_fops_body,
        "Palm reset file operations",
    )
    require_one_match(
        reset_fops_body,
        r"\.write\s*=\s*radeon_force_pci_reset_safe_write\s*,",
        "Palm reset file operations write callback",
    )
    write_body = function_body(
        palm_source,
        "radeon_force_pci_reset_safe_write",
        require_unconditional=True,
        protect_identifiers=True,
    )
    require_no_conditional_preprocessor(write_body, "Palm reset write body")
    write_position_gate = require_one_match(
        write_body,
        r"if \(\*ppos != 0\)\s*return -ESPIPE;",
        "Palm reset repeated-write refusal",
    )
    write_count_gate = require_one_match(
        write_body,
        r"if \(count == 0 \|\| count > sizeof\(input\) - 1\)\s*"
        r"return -EINVAL;",
        "Palm reset input length refusal",
    )
    write_copy_gate = require_one_match(
        write_body,
        r"if \(copy_from_user\(input, buf, count\)\)\s*return -EFAULT;",
        "Palm reset input copy refusal",
    )
    write_token_gate = require_one_match(
        write_body,
        r'if \(!sysfs_streq\(input, "1"\)\)\s*return -EINVAL;',
        "Palm reset exact token refusal",
    )
    write_family = require_one_match(
        write_body,
        r"if \(!rdev \|\| rdev->family != CHIP_PALM\)\s*return -ENODEV;",
        "Palm reset write family refusal",
    )
    write_lock = require_one_match(
        write_body,
        r"down_write\(&rdev->exclusive_lock\);",
        "Palm reset writer lock acquisition",
    )
    write_available = require_one_match(
        write_body,
        r"rc = radeon_dev_hardware_available\(rdev\);\s*"
        r"if \(rc\)\s*goto out_unlock;",
        "Palm reset write availability refusal",
    )
    write_admission = require_one_match(
        write_body,
        r"if \(!rdev \|\| rdev->family != CHIP_PALM\)\s*return -ENODEV;\s*"
        r"down_write\(&rdev->exclusive_lock\);\s*"
        r"rc = radeon_dev_hardware_available\(rdev\);\s*"
        r"if \(rc\)\s*goto out_unlock;",
        "Palm reset unconditional writer admission sequence",
    )
    require(
        re.findall(r"\bgoto\s+([A-Za-z_][A-Za-z0-9_]*)\s*;", write_body)
        == ["out_unlock"],
        "Palm reset write body carries an unbound control transfer",
    )
    require(
        re.findall(
            r"^\s*([A-Za-z_][A-Za-z0-9_]*):",
            write_body,
            re.MULTILINE,
        )
        == ["out_unlock"],
        "Palm reset write body carries an unbound label",
    )
    write_position = require_one_match(
        write_body,
        r"\*ppos = 1;",
        "Palm reset write position consumption",
    )
    write_reset = require_one_match(
        write_body,
        r"rc = evergreen_gpu_pci_config_reset_safe\(rdev\);",
        "Palm reset write invocation",
    )
    write_unlock = require_one_match(
        write_body,
        r"up_write\(&rdev->exclusive_lock\);",
        "Palm reset writer lock release",
    )
    write_return = require_one_match(
        write_body,
        r"return rc \? rc : \(ssize_t\)count;",
        "Palm reset write result",
    )
    for match, label in (
        (write_position_gate, "Palm reset repeated-write refusal"),
        (write_count_gate, "Palm reset input length refusal"),
        (write_copy_gate, "Palm reset input copy refusal"),
        (write_token_gate, "Palm reset exact token refusal"),
        (write_family, "Palm reset write family refusal"),
        (write_lock, "Palm reset writer lock acquisition"),
        (write_available, "Palm reset write availability refusal"),
        (write_admission, "Palm reset writer admission sequence"),
        (write_position, "Palm reset write position consumption"),
        (write_reset, "Palm reset write invocation"),
        (write_unlock, "Palm reset writer lock release"),
        (write_return, "Palm reset write result"),
    ):
        require_outer_function_match(
            write_body,
            match,
            label,
            allowed_label="out_unlock" if match is write_unlock else None,
        )
    write_code = strip_comments_and_literals(write_body)
    require(
        re.findall(
            r"\b(?:if|for|while|switch|do|goto|break|continue)\b",
            write_code,
        )
        == ["if", "if", "if", "if", "if", "if", "goto"],
        "Palm reset write control flow differs from its bounded sequence",
    )
    require(
        len(re.findall(r"\breturn\b", write_code)) == 6,
        "Palm reset write return set differs from its bounded sequence",
    )
    require(
        write_family.start()
        < write_lock.start()
        < write_available.start()
        < write_position.start()
        < write_reset.start()
        < write_unlock.start(),
        "Palm reset write gate, lock, admission, reset, and unlock order differs",
    )
    require(
        identifier_counts(texts, "evergreen_gpu_pci_config_reset_safe")
        == {
            "drivers/gpu/drm/radeon/radeon_evergreen_dev.c": 1,
            "drivers/gpu/drm/radeon/evergreen.c": 1,
        },
        "Palm reset execution has an unbound source reference",
    )

    register_body = function_body(
        palm_source,
        "radeon_evergreen_dev_debugfs_register",
        require_unconditional=True,
        protect_identifiers=True,
    )
    require_no_conditional_preprocessor(
        register_body,
        "Palm reset registration body",
    )
    register_minor = require_one_match(
        register_body,
        r"if \(!minor \|\| minor->type != DRM_MINOR_PRIMARY \|\| !minor->dev \|\|"
        r"\s*!minor->debugfs_root\)\s*return;",
        "Palm reset primary minor refusal",
    )
    register_device = require_one_match(
        register_body,
        r"rdev = minor->dev->dev_private;",
        "Palm reset device lookup",
    )
    register_scope = require_one_match(
        register_body,
        r"if \(!rdev \|\| rdev->family != CHIP_PALM \|\|\s*"
        r"!radeon_dev_profile_enabled\(rdev, RADEON_DEV_PROFILE_MUTATE\)\)"
        r"\s*return;",
        "Palm reset registration scope refusal",
    )
    register_file = require_one_match(
        register_body,
        r'debugfs_create_file\("radeon_force_pci_reset_safe", 0200,\s*'
        r"minor->debugfs_root, rdev,\s*"
        r"&radeon_force_pci_reset_safe_fops\);",
        "Palm reset per-device debugfs file",
    )
    require(
        register_minor.start()
        < register_device.start()
        < register_scope.start()
        < register_file.start(),
        "Palm reset minor, device, scope, and registration order differs",
    )
    register_code = strip_comments_and_literals(register_body)
    require(
        re.fullmatch(
            r"void\s+radeon_evergreen_dev_debugfs_register\s*"
            r"\(\s*struct\s+drm_minor\s*\*minor\s*\)\s*\{\s*"
            r"struct\s+radeon_device\s*\*rdev\s*;\s*"
            r"if\s*\(\s*!minor\s*\|\|\s*"
            r"minor->type\s*!=\s*DRM_MINOR_PRIMARY\s*\|\|\s*"
            r"!minor->dev\s*\|\|\s*!minor->debugfs_root\s*\)\s*"
            r"return\s*;\s*"
            r"rdev\s*=\s*minor->dev->dev_private\s*;\s*"
            r"if\s*\(\s*!rdev\s*\|\|\s*"
            r"rdev->family\s*!=\s*CHIP_PALM\s*\|\|\s*"
            r"!radeon_dev_profile_enabled\s*\(\s*rdev\s*,\s*"
            r"RADEON_DEV_PROFILE_MUTATE\s*\)\s*\)\s*return\s*;\s*"
            r"debugfs_create_file\s*\(\s*,\s*0200\s*,\s*"
            r"minor->debugfs_root\s*,\s*rdev\s*,\s*"
            r"&radeon_force_pci_reset_safe_fops\s*\)\s*;\s*"
            r"\}\s*",
            register_code,
        )
        is not None,
        "Palm reset registration statement sequence differs",
    )

    reset_source = texts["drivers/gpu/drm/radeon/evergreen.c"]
    require_no_local_macro_overrides(
        reset_source,
        PALM_RESET_PROTECTED_MACROS,
        "Palm reset implementation source",
    )
    reset_body = function_body(
        reset_source,
        "evergreen_gpu_pci_config_reset_safe",
        require_unconditional=True,
        protect_identifiers=True,
    )
    require_no_conditional_preprocessor(reset_body, "Palm reset body")
    reset_family = require_one_match(
        reset_body,
        r"^int evergreen_gpu_pci_config_reset_safe"
        r"\(struct radeon_device \*rdev\)\n\{\s*"
        r"struct evergreen_mc_save save;\s*u32 tmp, i;\s*int r;\s*"
        r"if \(!rdev \|\| rdev->family != CHIP_PALM\)\s*return -ENODEV;",
        "Palm reset family refusal before executable code",
    )
    reset_lock = require_one_match(
        reset_body,
        r"lockdep_assert_held_write\(&rdev->exclusive_lock\);",
        "Palm reset writer lock assertion",
    )
    require(
        re.search(
            r"\b(?:down_write(?:_killable|_trylock)?|up_write|downgrade_write)\b",
            strip_comments_and_literals(reset_body),
        )
        is None,
        "Palm reset body changes the caller-owned writer lock",
    )
    reset_available = require_one_match(
        reset_body,
        r"r = radeon_dev_hardware_available\(rdev\);\s*"
        r"if \(r\)\s*return r;",
        "Palm reset body availability refusal",
    )
    reset_unsafe = require_one_match(
        reset_body,
        r"if \(!radeon_palm_dev_pci_reset_unsafe\(rdev\)\)\s*\{.*?"
        r"return -EPERM;\s*\}",
        "Palm reset exact unsafe Boolean refusal",
    )
    reset_marker = require_one_match(
        reset_body,
        r'radeon_dev_mark_mutation\(rdev, "Palm PCI config reset"\);',
        "Palm reset mutation marker",
    )
    for match, label in (
        (reset_lock, "Palm reset writer lock assertion"),
        (reset_available, "Palm reset body availability refusal"),
        (reset_unsafe, "Palm reset exact unsafe Boolean refusal"),
        (reset_marker, "Palm reset mutation marker"),
    ):
        require_outer_function_match(reset_body, match, label)
    hardware_accesses = list(PALM_RESET_HARDWARE_ACCESS.finditer(reset_body))
    require(
        bool(hardware_accesses), "Palm reset body has no classified hardware access"
    )
    first_hardware = hardware_accesses[0]
    require_outer_function_match(
        reset_body,
        first_hardware,
        "Palm reset first classified hardware access",
    )
    require(
        first_hardware.group(0).startswith("WREG32("),
        "Palm reset first classified hardware access is not CP halt",
    )
    reset_code = strip_comments_and_literals(reset_body)
    reset_prefix = re.match(
        r"int\s+evergreen_gpu_pci_config_reset_safe\s*"
        r"\(\s*struct\s+radeon_device\s*\*rdev\s*\)\s*\{\s*"
        r"struct\s+evergreen_mc_save\s+save\s*;\s*"
        r"u32\s+tmp\s*,\s*i\s*;\s*int\s+r\s*;\s*"
        r"if\s*\(\s*!rdev\s*\|\|\s*rdev->family\s*!=\s*CHIP_PALM\s*\)\s*"
        r"return\s+-ENODEV\s*;\s*"
        r"lockdep_assert_held_write\s*\(\s*&rdev->exclusive_lock\s*\)\s*;\s*"
        r"r\s*=\s*radeon_dev_hardware_available\s*\(\s*rdev\s*\)\s*;\s*"
        r"if\s*\(\s*r\s*\)\s*return\s+r\s*;\s*"
        r"if\s*\(\s*!radeon_palm_dev_pci_reset_unsafe\s*"
        r"\(\s*rdev\s*\)\s*\)\s*\{\s*"
        r"dev_warn\s*\(\s*rdev->dev\s*,\s*\)\s*;\s*"
        r"return\s+-EPERM\s*;\s*\}\s*"
        r"radeon_dev_mark_mutation\s*\(\s*rdev\s*,\s*\)\s*;\s*"
        r"dev_info\s*\(\s*rdev->dev\s*,\s*\)\s*;\s*"
        r"(?P<first_hardware>WREG32\s*\(\s*CP_ME_CNTL\s*,\s*"
        r"CP_ME_HALT\s*\|\s*CP_PFP_HALT\s*\)\s*;)",
        reset_code,
    )
    require(
        reset_prefix is not None
        and reset_prefix.start("first_hardware") == first_hardware.start(),
        "Palm reset pre-hardware statement sequence differs",
    )
    require(
        not re.findall(r"\bgoto\s+[A-Za-z_][A-Za-z0-9_]*\s*;", reset_code)
        and not re.findall(
            r"(?m)^[ \t]*[A-Za-z_][A-Za-z0-9_]*\s*:",
            reset_code,
        ),
        "Palm reset body carries a goto or label",
    )
    require(
        reset_family.end()
        < reset_lock.start()
        < reset_available.start()
        < reset_unsafe.start()
        < reset_marker.start()
        < first_hardware.start(),
        "Palm reset family, lock, availability, Boolean, marker, and hardware order differs",
    )

    require(
        not re.search(
            r'debugfs_create_file\("radeon_force_pci_reset_safe", 0200,\s*NULL,',
            texts["drivers/gpu/drm/radeon/radeon_evergreen_dev.c"],
            re.DOTALL,
        ),
        "Palm reset interface uses the global debugfs root",
    )


def validate_retired_reset_probe_denominator(
    markers_by_path: dict[str, tuple[str, ...]],
) -> None:
    identities = [
        (path, marker)
        for path in sorted(markers_by_path)
        for marker in sorted(markers_by_path[path])
    ]
    require(
        len(identities) == RETIRED_RESET_PROBE_MARKER_COUNT,
        "retired reset-probe marker count differs from its pinned denominator",
    )
    require(
        len(set(identities)) == len(identities),
        "retired reset-probe marker denominator contains a duplicate identity",
    )
    serialized = "".join(
        f"{path}\t{marker}\n" for path, marker in identities
    ).encode("ascii")
    require(
        hashlib.sha256(serialized).hexdigest()
        == RETIRED_RESET_PROBE_MARKER_SHA256,
        "retired reset-probe marker identities differ from their pinned digest",
    )


def validate_retired_reset_probes(texts: dict[str, str]) -> None:
    validate_retired_reset_probe_denominator(RETIRED_RESET_PROBE_MARKERS)
    for path, markers in RETIRED_RESET_PROBE_MARKERS.items():
        require(path in texts, f"retired reset-probe source is absent: {path}")
        for marker in markers:
            require(
                marker.casefold() not in texts[path].casefold(),
                f"retired reset-probe marker is present in {path}: {marker}",
            )


def validate_wedged_reset_probe_post_state(texts: dict[str, str]) -> None:
    path = "drivers/gpu/drm/radeon/radeon_rs4xx_dev.c"
    require(path in texts, f"wedged reset-probe source is absent: {path}")
    source = texts[path]
    wedged_body = function_body(
        source,
        "rs480_wedged_3d_reset",
        expected_enclosing_stack=(
            ("if", "defined(CONFIG_DEBUG_FS)", "initial"),
            ("if", "RADEON_MUTATE_DEV", "initial"),
        ),
        protect_identifiers=True,
    )
    require_no_conditional_preprocessor(
        wedged_body,
        "wedged reset-probe function",
    )
    reset_call = "reset_result = radeon_gpu_reset_forced(rdev);"
    read_lock = "down_read(&rdev->exclusive_lock);"
    parked_branch = "if (rdev->gpu_parked) {"
    parked_sentinel = "post_reset_status = 0x5041524B;"
    else_branch = "} else {"
    status_read = "post_reset_status = RREG32(R_000E40_RBBM_STATUS);"
    branch_close = "}\n\tup_read(&rdev->exclusive_lock);"
    read_unlock = "up_read(&rdev->exclusive_lock);"
    for marker in (
        reset_call,
        read_lock,
        parked_branch,
        parked_sentinel,
        else_branch,
        status_read,
        branch_close,
        read_unlock,
    ):
        require(
            wedged_body.count(marker) == 1,
            f"wedged reset-probe carries an invalid marker count: {marker}",
        )

    reset_call_end = wedged_body.find(reset_call) + len(reset_call)
    wedged_prefix = normalized_code(wedged_body[:reset_call_end])
    expected_wedged_prefix = (
        "static int rs480_wedged_3d_reset(struct radeon_device *rdev, "
        "struct seq_file *m, bool require_backend_idle) { const char "
        "*state_name = require_backend_idle ? : ; const char *verdict; "
        "u32 pre_reset_status, post_reset_status; int reset_result; "
        "pre_reset_status = RREG32(R_000E40_RBBM_STATUS); if "
        "(require_backend_idle ? !rs480_frontend_wedged(pre_reset_status) "
        ": !rs480_frontend_busy(pre_reset_status)) { seq_printf(m, , "
        "state_name, pre_reset_status, require_backend_idle ? : ); "
        "return 0; } radeon_dev_mark_mutation(rdev, ); reset_result = "
        "radeon_gpu_reset_forced(rdev);"
    )
    require(
        wedged_prefix == expected_wedged_prefix,
        "wedged reset-probe pre-reset transaction differs",
    )
    require_control_flow_census(
        wedged_body,
        (4, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2),
        (("return 0;", 2), ("return 0;", 1)),
        "wedged reset-probe function",
    )
    require_no_opaque_control(wedged_body, "wedged reset-probe function")

    post_reset = wedged_body.split(reset_call, 1)[1]
    read_lock_at = post_reset.find(read_lock)
    parked_branch_at = post_reset.find(parked_branch)
    parked_sentinel_at = post_reset.find(parked_sentinel)
    else_branch_at = post_reset.find(else_branch)
    status_read_at = post_reset.find(status_read)
    branch_close_at = post_reset.find(branch_close)
    read_unlock_at = post_reset.find(read_unlock)
    require(
        read_lock_at
        < parked_branch_at
        < parked_sentinel_at
        < else_branch_at
        < status_read_at
        < branch_close_at
        < read_unlock_at,
        "wedged reset-probe post-state transaction order differs",
    )
    marker_depths = (
        (reset_call, 1),
        (read_lock, 1),
        (parked_branch, 1),
        (parked_sentinel, 2),
        (else_branch, 2),
        (status_read, 2),
        (read_unlock, 1),
    )
    for marker, expected_depth in marker_depths:
        require(
            brace_depth_at(wedged_body, wedged_body.find(marker))
            == expected_depth,
            f"wedged reset-probe marker is not at depth {expected_depth}: {marker}",
        )

    before_read_lock = C_LINE_COMMENT.sub(
        "", C_BLOCK_COMMENT.sub("", post_reset[:read_lock_at])
    )
    between_lock_and_branch = C_LINE_COMMENT.sub(
        "",
        C_BLOCK_COMMENT.sub(
            "", post_reset[read_lock_at + len(read_lock) : parked_branch_at]
        ),
    )
    require(
        not before_read_lock.strip() and not between_lock_and_branch.strip(),
        "wedged reset-probe executes code before the locked parked-state branch",
    )
    require(
        "RREG" not in post_reset[parked_branch_at:else_branch_at],
        "wedged reset-probe parked branch reads a register",
    )
    require(
        post_reset[else_branch_at:branch_close_at].count("RREG") == 1,
        "wedged reset-probe status read differs from the unparked branch",
    )


def validate_forced_gpu_reset_transaction(texts: dict[str, str]) -> None:
    path = "drivers/gpu/drm/radeon/radeon_device.c"
    require(path in texts, f"forced GPU-reset source is absent: {path}")
    source = texts[path]
    reset_function_body = function_body(
        source,
        "radeon_gpu_reset_internal",
        require_unconditional=True,
        protect_identifiers=True,
    )
    require_no_conditional_preprocessor(
        reset_function_body,
        "forced GPU-reset implementation",
    )
    wrapper_body = function_body(
        source,
        "radeon_gpu_reset_forced",
        expected_enclosing_condition="RADEON_MUTATE_DEV",
        protect_identifiers=True,
    )
    require_no_conditional_preprocessor(
        wrapper_body,
        "forced GPU-reset wrapper",
    )
    transaction_pattern = (
        r"down_write\(&rdev->exclusive_lock\);\s*"
        r"if \(!force_reset && !rdev->needs_reset\) \{\s*"
        r"up_write\(&rdev->exclusive_lock\);\s*return 0;\s*\}\s*"
        r"if \(rdev->gpu_parked\) \{\s*"
        r"rdev->needs_reset = false;\s*"
        r"up_write\(&rdev->exclusive_lock\);\s*"
        r"dev_err_once\(rdev->dev,\s*"
        r'"parked: refusing radeon_gpu_reset re-entry\\n"\);\s*'
        r"return -EIO;\s*\}\s*"
        r"if \(force_reset\)\s*rdev->needs_reset = true;\s*"
        r"atomic_inc\(&rdev->gpu_reset_counter\)"
    )
    wrapper_pattern = (
        r"int radeon_gpu_reset_forced\(struct radeon_device \*rdev\)\s*"
        r"\{\s*return radeon_gpu_reset_internal\(rdev, true\);\s*\}"
    )
    transaction_match = require_one_match(
        reset_function_body,
        transaction_pattern,
        "forced GPU-reset writer transaction",
    )
    require_outer_function_match(
        reset_function_body,
        transaction_match,
        "forced GPU-reset writer transaction",
    )
    reset_counter = "atomic_inc(&rdev->gpu_reset_counter);"
    reset_counter_at = reset_function_body.find(reset_counter)
    require(
        reset_counter_at >= 0,
        "forced GPU-reset counter transition is absent",
    )
    expected_reset_prefix = (
        "static int radeon_gpu_reset_internal(struct radeon_device *rdev, "
        "bool force_reset) { unsigned ring_sizes[RADEON_NUM_RINGS]; "
        "uint32_t *ring_data[RADEON_NUM_RINGS]; bool saved = false; "
        "bool gpu_parked; int i, r; down_write(&rdev->exclusive_lock); "
        "if (!force_reset && !rdev->needs_reset) { "
        "up_write(&rdev->exclusive_lock); return 0; } if "
        "(rdev->gpu_parked) { rdev->needs_reset = false; "
        "up_write(&rdev->exclusive_lock); dev_err_once(rdev->dev, ); "
        "return -EIO; } if (force_reset) rdev->needs_reset = true; "
        "atomic_inc(&rdev->gpu_reset_counter);"
    )
    require(
        normalized_code(
            reset_function_body[: reset_counter_at + len(reset_counter)]
        )
        == expected_reset_prefix,
        "forced GPU-reset declaration and writer transaction prefix differs",
    )
    require_control_flow_census(
        reset_function_body,
        (19, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 4),
        (
            ("return 0;", 2),
            ("return -EIO;", 2),
            ("return r;", 2),
            ("return r;", 1),
        ),
        "forced GPU-reset implementation",
    )
    require_no_opaque_control(
        reset_function_body,
        "forced GPU-reset implementation",
    )
    require(
        brace_depth_at(reset_function_body, reset_counter_at) == 1,
        "forced GPU-reset counter transition is not an outer function statement",
    )
    reset_body = reset_function_body[reset_counter_at + len(reset_counter):]
    require(
        "up_write(&rdev->exclusive_lock);" not in reset_body,
        "forced GPU-reset writer lock ends before a legitimate downgrade",
    )
    require(
        reset_body.count("downgrade_write(&rdev->exclusive_lock);") == 2,
        "forced GPU-reset writer-to-reader downgrade paths differ",
    )
    require(
        reset_body.count("up_read(&rdev->exclusive_lock);") == 2,
        "forced GPU-reset read-lock release paths differ",
    )
    parked_exit_start = (
        'dev_err(rdev->dev, "parked: async agents quiesced, '
        'entering quiet epoch\\n");'
    )
    expected_parked_exit = (
        "dev_err(rdev->dev, ); rdev->in_reset = true; "
        "rdev->needs_reset = false; msleep(1); dev_err(rdev->dev, ); "
        "downgrade_write(&rdev->exclusive_lock); msleep(1); "
        "dev_info(rdev->dev, ); rdev->in_reset = false; "
        "up_read(&rdev->exclusive_lock); msleep(1); "
        "dev_err(rdev->dev, , r); return r;"
    )
    require_exact_code_interval(
        reset_function_body,
        parked_exit_start,
        "return r;",
        expected_parked_exit,
        2,
        "forced GPU-reset parked exit",
    )
    expected_ordinary_exit = (
        "radeon_hpd_init(rdev); rdev->in_reset = true; "
        "rdev->needs_reset = false; "
        "downgrade_write(&rdev->exclusive_lock); "
        "drm_helper_resume_force_mode(rdev_to_drm(rdev)); if "
        "((rdev->pm.pm_method == PM_METHOD_DPM) && rdev->pm.dpm_enabled) "
        "radeon_pm_compute_clocks(rdev); if (!r) { "
        "r = radeon_ib_ring_tests(rdev); if (r && saved) r = -EAGAIN; "
        "} else { dev_info(rdev->dev, ); } "
        "rdev->needs_reset = r == -EAGAIN; rdev->in_reset = false; "
        "up_read(&rdev->exclusive_lock); return r;"
    )
    require_exact_code_interval(
        reset_function_body,
        "radeon_hpd_init(rdev);",
        "return r;",
        expected_ordinary_exit,
        1,
        "forced GPU-reset ordinary exit",
    )
    require(
        re.fullmatch(wrapper_pattern, wrapper_body, re.DOTALL) is not None,
        "forced GPU-reset entry does not select the forced transaction",
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
        line.split(":", 1)[0] for line in result.stdout.splitlines() if ":" in line
    }
    require(
        ("profile_dev" in module_parameters) == (profile != "prod"),
        f"built module runtime-profile parameter differs for {profile}",
    )
    parameters = {
        name
        for name in module_parameters
        if (name == "palm_pci_reset_unsafe" or name.startswith("rs480_"))
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
        row["marker"] for row in expected_rows if row["marker_type"] == "debugfs-file"
    }
    declared_debugfs = {
        row["marker"] for row in rows if row["marker_type"] == "debugfs-file"
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
        validate_advertised_interface_totals(
            advertised_interface_texts(root), rows, features
        )
        source_texts = runtime_source_texts(root)
        registration_rows = read_registration_contract(
            root / "policy/dev-interface-registration-contract.tsv"
        )
        validate_output_schema_version(root)
        validate_runtime_sources(source_texts)
        validate_palm_reset_registration(registration_rows, source_texts)
        validate_mutation_audit(source_texts, features)
        validate_retired_reset_probes(retired_reset_probe_source_texts(root))
        validate_wedged_reset_probe_post_state(source_texts)
        validate_forced_gpu_reset_transaction(source_texts)

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
    summary_texts = advertised_interface_texts(root)
    summary_rejection_count = 0
    for path, pattern in ADVERTISED_INTERFACE_TOTAL_PATTERNS.items():
        wrong_summary = copy.deepcopy(summary_texts)
        match = pattern.search(wrong_summary[path])
        require(match is not None, f"self-test summary fixture is absent: {path}")
        count_start, count_end = match.span("debugfs")
        wrong_summary[path] = (
            wrong_summary[path][:count_start]
            + str(int(match.group("debugfs")) + 1)
            + wrong_summary[path][count_end:]
        )
        try:
            validate_advertised_interface_totals(wrong_summary, rows, features)
        except InterfaceError:
            summary_rejection_count += 1
        else:
            raise InterfaceError(
                f"self-test accepted a stale interface summary in {path}"
            )

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
        row for row in copy.deepcopy(rows) if row["marker"] != "rs480_reset_mask"
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
        "mutate-dev": (19, 17, 32),
    }
    for profile, expected in expected_counts.items():
        selected = profile_rows(rows, features, profile)
        observed = (
            len({row["feature_id"] for row in selected}),
            sum(row["marker_type"] == "module-parameter" for row in selected),
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
        ("mutate-dev", "mutate-dev"): (19, 17, 32),
    }
    for selection, expected in runtime_counts.items():
        selected = runtime_rows(rows, features, *selection)
        observed = (
            len({row["feature_id"] for row in selected}),
            sum(row["marker_type"] == "module-parameter" for row in selected),
            sum(row["marker_type"] == "debugfs-file" for row in selected),
        )
        require(
            observed == expected,
            "self-test runtime count differs for " + "/".join(selection),
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
    registration_rows = read_registration_contract(
        root / "policy/dev-interface-registration-contract.tsv"
    )
    validate_runtime_sources(source_texts)
    validate_palm_reset_registration(registration_rows, source_texts)
    validate_mutation_audit(source_texts, features)
    registration_source_mutations = (
        (
            "conditional dispatcher selects an active empty definition",
            "drivers/gpu/drm/radeon/radeon_drv.c",
            "static void radeon_dev_debugfs_register(struct drm_minor *minor)\n"
            "{\n"
            "\tradeon_rs480_re_debugfs_register(minor);\n"
            "\tradeon_evergreen_dev_debugfs_register(minor);\n"
            "}",
            "#if 0\n"
            "static void radeon_dev_debugfs_register(struct drm_minor *minor)\n"
            "{\n"
            "\tradeon_rs480_re_debugfs_register(minor);\n"
            "\tradeon_evergreen_dev_debugfs_register(minor);\n"
            "}\n"
            "#else\n"
            "static void radeon_dev_debugfs_register(struct drm_minor *minor)\n"
            "{\n"
            "}\n"
            "#endif",
        ),
        (
            "conditional DRM callback selects a null field",
            "drivers/gpu/drm/radeon/radeon_drv.c",
            ".debugfs_init = radeon_dev_debugfs_register,",
            "#if 0\n"
            "\t.debugfs_init = radeon_dev_debugfs_register,\n"
            "#else\n"
            "\t.debugfs_init = NULL,\n"
            "#endif",
        ),
        (
            "conditional file operations select a null write callback",
            "drivers/gpu/drm/radeon/radeon_evergreen_dev.c",
            ".write = radeon_force_pci_reset_safe_write,",
            "#if 0\n"
            "\t.write = radeon_force_pci_reset_safe_write,\n"
            "#else\n"
            "\t.write = NULL,\n"
            "#endif",
        ),
        (
            "direct RS4xx callback",
            "drivers/gpu/drm/radeon/radeon_drv.c",
            ".debugfs_init = radeon_dev_debugfs_register",
            ".debugfs_init = radeon_rs480_re_debugfs_register",
        ),
        (
            "global debugfs parent",
            "drivers/gpu/drm/radeon/radeon_evergreen_dev.c",
            "minor->debugfs_root, rdev,",
            "NULL, rdev,",
        ),
        (
            "missing registration family gate",
            "drivers/gpu/drm/radeon/radeon_evergreen_dev.c",
            "if (!rdev || rdev->family != CHIP_PALM ||",
            "if (!rdev ||",
        ),
        (
            "missing write family gate",
            "drivers/gpu/drm/radeon/radeon_evergreen_dev.c",
            "if (!rdev || rdev->family != CHIP_PALM)\n\t\treturn -ENODEV;",
            "if (!rdev)\n\t\treturn -ENODEV;",
        ),
        (
            "missing exclusive lock",
            "drivers/gpu/drm/radeon/radeon_evergreen_dev.c",
            "down_write(&rdev->exclusive_lock);",
            "removed_exclusive_lock;",
        ),
        (
            "conditional exclusive lock",
            "drivers/gpu/drm/radeon/radeon_evergreen_dev.c",
            "down_write(&rdev->exclusive_lock);",
            "if (false)\n\t\tdown_write(&rdev->exclusive_lock);",
        ),
        (
            "conditional writer admission block",
            "drivers/gpu/drm/radeon/radeon_evergreen_dev.c",
            "if (!rdev || rdev->family != CHIP_PALM)\n"
            "\t\treturn -ENODEV;\n\n"
            "\tdown_write(&rdev->exclusive_lock);\n"
            "\trc = radeon_dev_hardware_available(rdev);\n"
            "\tif (rc)\n"
            "\t\tgoto out_unlock;",
            "if (false) {\n"
            "\t\tif (!rdev || rdev->family != CHIP_PALM)\n"
            "\t\t\treturn -ENODEV;\n\n"
            "\t\tdown_write(&rdev->exclusive_lock);\n"
            "\t\trc = radeon_dev_hardware_available(rdev);\n"
            "\t\tif (rc)\n"
            "\t\t\tgoto out_unlock;\n"
            "\t}",
        ),
        (
            "missing reset family gate",
            "drivers/gpu/drm/radeon/evergreen.c",
            "if (!rdev || rdev->family != CHIP_PALM)\n\t\treturn -ENODEV;",
            "if (!rdev)\n\t\treturn -ENODEV;",
        ),
        (
            "missing lock assertion",
            "drivers/gpu/drm/radeon/evergreen.c",
            "lockdep_assert_held_write(&rdev->exclusive_lock);",
            "removed_lock_assertion;",
        ),
        (
            "conditional lock assertion without braces",
            "drivers/gpu/drm/radeon/evergreen.c",
            "lockdep_assert_held_write(&rdev->exclusive_lock);",
            "if (false)\n"
            "\t\tlockdep_assert_held_write(&rdev->exclusive_lock);",
        ),
        (
            "reset body releases caller lock",
            "drivers/gpu/drm/radeon/evergreen.c",
            "lockdep_assert_held_write(&rdev->exclusive_lock);",
            "lockdep_assert_held_write(&rdev->exclusive_lock);\n"
            "\tup_write(&rdev->exclusive_lock);",
        ),
        (
            "reset body downgrades caller lock",
            "drivers/gpu/drm/radeon/evergreen.c",
            "lockdep_assert_held_write(&rdev->exclusive_lock);",
            "lockdep_assert_held_write(&rdev->exclusive_lock);\n"
            "\tdowngrade_write(&rdev->exclusive_lock);",
        ),
        (
            "reset body releases parenthesized caller lock",
            "drivers/gpu/drm/radeon/evergreen.c",
            "lockdep_assert_held_write(&rdev->exclusive_lock);",
            "lockdep_assert_held_write(&rdev->exclusive_lock);\n"
            "\tup_write(&((rdev)->exclusive_lock));",
        ),
        (
            "reset body releases caller lock after comment marker literal",
            "drivers/gpu/drm/radeon/evergreen.c",
            "lockdep_assert_held_write(&rdev->exclusive_lock);",
            "lockdep_assert_held_write(&rdev->exclusive_lock);\n"
            '\tdev_info(rdev->dev, "//");\n'
            "\tup_write(&((rdev)->exclusive_lock));",
        ),
        (
            "missing runtime profile gate",
            "drivers/gpu/drm/radeon/radeon_evergreen_dev.c",
            "!radeon_dev_profile_enabled(rdev, RADEON_DEV_PROFILE_MUTATE)",
            "false",
        ),
        (
            "ignored write availability result",
            "drivers/gpu/drm/radeon/radeon_evergreen_dev.c",
            "rc = radeon_dev_hardware_available(rdev);\n"
            "\tif (rc)\n\t\tgoto out_unlock;",
            "rc = radeon_dev_hardware_available(rdev);\n"
            "\tif (false)\n\t\tgoto out_unlock;",
        ),
        (
            "ignored reset availability result",
            "drivers/gpu/drm/radeon/evergreen.c",
            "r = radeon_dev_hardware_available(rdev);\n\tif (r)\n\t\treturn r;",
            "r = radeon_dev_hardware_available(rdev);\n\tif (false)\n\t\treturn r;",
        ),
        (
            "conditional reset availability assignment without braces",
            "drivers/gpu/drm/radeon/evergreen.c",
            "r = radeon_dev_hardware_available(rdev);",
            "if (false)\n\t\tr = radeon_dev_hardware_available(rdev);",
        ),
        (
            "conditional unsafe Boolean refusal without braces",
            "drivers/gpu/drm/radeon/evergreen.c",
            "if (!radeon_palm_dev_pci_reset_unsafe(rdev)) {",
            "if (false)\n"
            "\t\tif (!radeon_palm_dev_pci_reset_unsafe(rdev)) {",
        ),
        (
            "conditional mutation marker without braces",
            "drivers/gpu/drm/radeon/evergreen.c",
            'radeon_dev_mark_mutation(rdev, "Palm PCI config reset");',
            "if (false)\n"
            '\t\tradeon_dev_mark_mutation(rdev, "Palm PCI config reset");',
        ),
        (
            "unlock before reset",
            "drivers/gpu/drm/radeon/radeon_evergreen_dev.c",
            "\t*ppos = 1;\n\trc = evergreen_gpu_pci_config_reset_safe(rdev);",
            "\t*ppos = 1;\n"
            "\tup_write(&rdev->exclusive_lock);\n"
            "\trc = evergreen_gpu_pci_config_reset_safe(rdev);",
        ),
        (
            "hardware access before reset family gate",
            "drivers/gpu/drm/radeon/evergreen.c",
            "\tif (!rdev || rdev->family != CHIP_PALM)\n\t\treturn -ENODEV;",
            "\tWREG32(CP_ME_CNTL, 0);\n"
            "\tif (!rdev || rdev->family != CHIP_PALM)\n"
            "\t\treturn -ENODEV;",
        ),
        (
            "first reset hardware access is conditional without braces",
            "drivers/gpu/drm/radeon/evergreen.c",
            'dev_info(rdev->dev, "GPU pci config reset '
            '(bounded MC-wait safe variant)\\n");\n\n'
            "\tWREG32(CP_ME_CNTL, CP_ME_HALT | CP_PFP_HALT);",
            'dev_info(rdev->dev, "GPU pci config reset '
            '(bounded MC-wait safe variant)\\n");\n\n'
            "\tif (false)\n"
            "\t\tWREG32(CP_ME_CNTL, CP_ME_HALT | CP_PFP_HALT);",
        ),
        (
            "continued comment hides first reset hardware access",
            "drivers/gpu/drm/radeon/evergreen.c",
            'dev_info(rdev->dev, "GPU pci config reset '
            '(bounded MC-wait safe variant)\\n");\n\n'
            "\tWREG32(CP_ME_CNTL, CP_ME_HALT | CP_PFP_HALT);",
            'dev_info(rdev->dev, "GPU pci config reset '
            '(bounded MC-wait safe variant)\\n");\n\n'
            "\t// continued comment \\\n"
            "\tWREG32(CP_ME_CNTL, CP_ME_HALT | CP_PFP_HALT);",
        ),
        (
            "registration primary-minor refusal is conditional without braces",
            "drivers/gpu/drm/radeon/radeon_evergreen_dev.c",
            "if (!minor || minor->type != DRM_MINOR_PRIMARY || !minor->dev ||\n"
            "\t    !minor->debugfs_root)\n"
            "\t\treturn;",
            "if (false)\n"
            "\t\tif (!minor || minor->type != DRM_MINOR_PRIMARY || "
            "!minor->dev ||\n"
            "\t\t    !minor->debugfs_root)\n"
            "\t\t\treturn;",
        ),
        (
            "registration device lookup is conditional without braces",
            "drivers/gpu/drm/radeon/radeon_evergreen_dev.c",
            "rdev = minor->dev->dev_private;",
            "if (false)\n\t\trdev = minor->dev->dev_private;",
        ),
        (
            "registration scope refusal is conditional without braces",
            "drivers/gpu/drm/radeon/radeon_evergreen_dev.c",
            "if (!rdev || rdev->family != CHIP_PALM ||\n"
            "\t    !radeon_dev_profile_enabled(rdev, "
            "RADEON_DEV_PROFILE_MUTATE))\n"
            "\t\treturn;",
            "if (false)\n"
            "\t\tif (!rdev || rdev->family != CHIP_PALM ||\n"
            "\t\t    !radeon_dev_profile_enabled(rdev, "
            "RADEON_DEV_PROFILE_MUTATE))\n"
            "\t\t\treturn;",
        ),
        (
            "registration file creation is conditional without braces",
            "drivers/gpu/drm/radeon/radeon_evergreen_dev.c",
            'debugfs_create_file("radeon_force_pci_reset_safe", 0200,\n'
            "\t\t\t    minor->debugfs_root, rdev,\n"
            "\t\t\t    &radeon_force_pci_reset_safe_fops);",
            "if (false)\n"
            '\t\tdebugfs_create_file("radeon_force_pci_reset_safe", 0200,\n'
            "\t\t\t\t    minor->debugfs_root, rdev,\n"
                "\t\t\t\t    &radeon_force_pci_reset_safe_fops);",
        ),
        (
            "local debugfs_create_file override",
            "drivers/gpu/drm/radeon/radeon_evergreen_dev.c",
            "void radeon_evergreen_dev_debugfs_register(struct drm_minor *minor)",
            "#undef debugfs_create_file\n"
            "#define debugfs_create_file(...) ((void)0)\n"
            "void radeon_evergreen_dev_debugfs_register(struct drm_minor *minor)",
        ),
        (
            "local WREG32 override",
            "drivers/gpu/drm/radeon/evergreen.c",
            "int evergreen_gpu_pci_config_reset_safe(struct radeon_device *rdev)",
            "#undef WREG32\n"
            "#define WREG32(reg, value) do { } while (0)\n"
            "int evergreen_gpu_pci_config_reset_safe(struct radeon_device *rdev)",
        ),
        (
            "local digraph debugfs_create_file override",
            "drivers/gpu/drm/radeon/radeon_evergreen_dev.c",
            "void radeon_evergreen_dev_debugfs_register(struct drm_minor *minor)",
            "%:undef debugfs_create_file\n"
            "%:define debugfs_create_file(...) ((void)0)\n"
            "void radeon_evergreen_dev_debugfs_register(struct drm_minor *minor)",
        ),
        (
            "local digraph WREG32 override",
            "drivers/gpu/drm/radeon/evergreen.c",
            "int evergreen_gpu_pci_config_reset_safe(struct radeon_device *rdev)",
            "%:undef WREG32\n"
            "%:define WREG32(reg, value) do { } while (0)\n"
            "int evergreen_gpu_pci_config_reset_safe(struct radeon_device *rdev)",
        ),
        (
            "local DRM_MINOR_PRIMARY override",
            "drivers/gpu/drm/radeon/radeon_evergreen_dev.c",
            "void radeon_evergreen_dev_debugfs_register(struct drm_minor *minor)",
            "#undef DRM_MINOR_PRIMARY\n"
            "#define DRM_MINOR_PRIMARY DRM_MINOR_RENDER\n"
            "void radeon_evergreen_dev_debugfs_register(struct drm_minor *minor)",
        ),
        (
            "local CP_ME_CNTL override",
            "drivers/gpu/drm/radeon/evergreen.c",
            "int evergreen_gpu_pci_config_reset_safe(struct radeon_device *rdev)",
            "#undef CP_ME_CNTL\n"
            "#define CP_ME_CNTL DMA_RB_CNTL\n"
            "int evergreen_gpu_pci_config_reset_safe(struct radeon_device *rdev)",
        ),
        (
            "local ENODEV override",
            "drivers/gpu/drm/radeon/radeon_evergreen_dev.c",
            "static ssize_t\nradeon_force_pci_reset_safe_write",
            "#undef ENODEV\n"
            "#define ENODEV 0\n"
            "static ssize_t\nradeon_force_pci_reset_safe_write",
        ),
        (
            "local EPERM override",
            "drivers/gpu/drm/radeon/evergreen.c",
            "int evergreen_gpu_pci_config_reset_safe(struct radeon_device *rdev)",
            "#undef EPERM\n"
            "#define EPERM 0\n"
            "int evergreen_gpu_pci_config_reset_safe(struct radeon_device *rdev)",
        ),
        (
            "first reset hardware access is a disabled for expression",
            "drivers/gpu/drm/radeon/evergreen.c",
            'dev_info(rdev->dev, "GPU pci config reset '
            '(bounded MC-wait safe variant)\\n");\n\n'
            "\tWREG32(CP_ME_CNTL, CP_ME_HALT | CP_PFP_HALT);",
            'dev_info(rdev->dev, "GPU pci config reset '
            '(bounded MC-wait safe variant)\\n");\n\n'
            "\tfor (; false; WREG32(CP_ME_CNTL, "
            "CP_ME_HALT | CP_PFP_HALT))\n\t\t;",
        ),
        (
            "first reset hardware access is disabled by preprocessing",
            "drivers/gpu/drm/radeon/evergreen.c",
            'dev_info(rdev->dev, "GPU pci config reset '
            '(bounded MC-wait safe variant)\\n");\n\n'
            "\tWREG32(CP_ME_CNTL, CP_ME_HALT | CP_PFP_HALT);",
            'dev_info(rdev->dev, "GPU pci config reset '
            '(bounded MC-wait safe variant)\\n");\n\n'
            "\t;\n#if 0\n"
            "\tWREG32(CP_ME_CNTL, CP_ME_HALT | CP_PFP_HALT);\n"
            "#endif\n\t;",
        ),
        (
            "first reset hardware access follows an early return",
            "drivers/gpu/drm/radeon/evergreen.c",
            'dev_info(rdev->dev, "GPU pci config reset '
            '(bounded MC-wait safe variant)\\n");\n\n'
            "\tWREG32(CP_ME_CNTL, CP_ME_HALT | CP_PFP_HALT);",
            'dev_info(rdev->dev, "GPU pci config reset '
            '(bounded MC-wait safe variant)\\n");\n\n'
            "\treturn 0;\n"
            "\tWREG32(CP_ME_CNTL, CP_ME_HALT | CP_PFP_HALT);",
        ),
        (
            "first reset hardware access follows an infinite loop",
            "drivers/gpu/drm/radeon/evergreen.c",
            'dev_info(rdev->dev, "GPU pci config reset '
            '(bounded MC-wait safe variant)\\n");\n\n'
            "\tWREG32(CP_ME_CNTL, CP_ME_HALT | CP_PFP_HALT);",
            'dev_info(rdev->dev, "GPU pci config reset '
            '(bounded MC-wait safe variant)\\n");\n\n'
            "\tfor (;;)\n\t\t;\n"
            "\tWREG32(CP_ME_CNTL, CP_ME_HALT | CP_PFP_HALT);",
        ),
    )
    for label, path, needle, replacement in registration_source_mutations:
        require(
            source_texts[path].count(needle) == 1,
            f"self-test source mutation is ambiguous: {label}",
        )
        candidate_texts = copy.deepcopy(source_texts)
        candidate_texts[path] = candidate_texts[path].replace(needle, replacement, 1)
        try:
            validate_palm_reset_registration(registration_rows, candidate_texts)
        except InterfaceError:
            pass
        else:
            raise InterfaceError(f"self-test accepted {label}")

    conditionally_disabled_functions = (
        (
            "Palm reset write function",
            "drivers/gpu/drm/radeon/radeon_evergreen_dev.c",
            "static ssize_t\nradeon_force_pci_reset_safe_write",
            "\n\nstatic const struct file_operations",
            "#",
        ),
        (
            "Palm reset registration function",
            "drivers/gpu/drm/radeon/radeon_evergreen_dev.c",
            "void radeon_evergreen_dev_debugfs_register",
            None,
            "#",
        ),
        (
            "Palm reset implementation function",
            "drivers/gpu/drm/radeon/evergreen.c",
            "int evergreen_gpu_pci_config_reset_safe",
            "\n\nint evergreen_asic_reset",
            "#",
        ),
        (
            "Palm reset implementation function under a digraph conditional",
            "drivers/gpu/drm/radeon/evergreen.c",
            "int evergreen_gpu_pci_config_reset_safe",
            "\n\nint evergreen_asic_reset",
            "%:",
        ),
        (
            "Palm reset registration function under form-feed whitespace",
            "drivers/gpu/drm/radeon/radeon_evergreen_dev.c",
            "void radeon_evergreen_dev_debugfs_register",
            None,
            "#\f",
        ),
    )
    for (
        label,
        path,
        start_anchor,
        end_anchor,
        directive_prefix,
    ) in conditionally_disabled_functions:
        candidate_texts = copy.deepcopy(source_texts)
        candidate_source = candidate_texts[path]
        require(
            candidate_source.count(start_anchor) == 1,
            f"self-test conditional start is ambiguous: {label}",
        )
        function_start = candidate_source.find(start_anchor)
        function_end = (
            len(candidate_source)
            if end_anchor is None
            else candidate_source.find(end_anchor, function_start)
        )
        require(
            function_end > function_start,
            f"self-test conditional end is absent: {label}",
        )
        candidate_texts[path] = (
            candidate_source[:function_start]
            + f"{directive_prefix}if 0\n"
            + candidate_source[function_start:function_end]
            + f"{directive_prefix}endif\n"
            + candidate_source[function_end:]
        )
        try:
            validate_palm_reset_registration(registration_rows, candidate_texts)
        except InterfaceError:
            pass
        else:
            raise InterfaceError(f"self-test accepted disabled {label}")

    bypassed_palm_reset = copy.deepcopy(source_texts)
    palm_reset_path = "drivers/gpu/drm/radeon/evergreen.c"
    family_refusal = (
        "if (!rdev || rdev->family != CHIP_PALM)\n"
        "\t\treturn -ENODEV;"
    )
    first_hardware_context = (
        'dev_info(rdev->dev, "GPU pci config reset '
        '(bounded MC-wait safe variant)\\n");\n\n'
        "\tWREG32(CP_ME_CNTL, CP_ME_HALT | CP_PFP_HALT);"
    )
    palm_reset_source = bypassed_palm_reset[palm_reset_path]
    require(
        palm_reset_source.count(family_refusal) == 1
        and palm_reset_source.count(first_hardware_context) == 1,
        "self-test Palm reset bypass anchors differ from the source",
    )
    palm_reset_source = palm_reset_source.replace(
        family_refusal,
        family_refusal + "\n\tgoto bypass_safety;",
        1,
    )
    bypassed_palm_reset[palm_reset_path] = palm_reset_source.replace(
        first_hardware_context,
        first_hardware_context.replace(
            "\tWREG32",
            "bypass_safety:\n\t;\n\tWREG32",
            1,
        ),
        1,
    )
    try:
        validate_palm_reset_registration(registration_rows, bypassed_palm_reset)
    except InterfaceError:
        pass
    else:
        raise InterfaceError("self-test accepted a goto over Palm reset safety gates")

    unreachable_palm_reset = copy.deepcopy(source_texts)
    palm_reset_source = unreachable_palm_reset[palm_reset_path]
    palm_reset_start = palm_reset_source.find(
        "\tlockdep_assert_held_write(&rdev->exclusive_lock);"
    )
    palm_reset_end = palm_reset_source.find(
        "\n}\n\nint evergreen_asic_reset",
        palm_reset_start,
    )
    require(
        palm_reset_start >= 0 and palm_reset_end > palm_reset_start,
        "self-test Palm reset body boundary differs from the source",
    )
    unreachable_palm_reset[palm_reset_path] = (
        palm_reset_source[:palm_reset_start]
        + "\tif (false) {\n"
        + palm_reset_source[palm_reset_start:palm_reset_end]
        + "\n\t}\n\treturn -EPERM;"
        + palm_reset_source[palm_reset_end:]
    )
    try:
        validate_palm_reset_registration(registration_rows, unreachable_palm_reset)
    except InterfaceError:
        pass
    else:
        raise InterfaceError("self-test accepted an unreachable Palm reset body")

    early_registration = copy.deepcopy(source_texts)
    early_registration["drivers/gpu/drm/radeon/radeon_kms.c"] += (
        "\nradeon_evergreen_dev_debugfs_register(NULL);\n"
    )
    try:
        validate_palm_reset_registration(registration_rows, early_registration)
    except InterfaceError:
        pass
    else:
        raise InterfaceError("self-test accepted early Palm reset registration")

    second_reset_caller = copy.deepcopy(source_texts)
    second_reset_caller["drivers/gpu/drm/radeon/radeon_kms.c"] += (
        "\nevergreen_gpu_pci_config_reset_safe(other_rdev);\n"
    )
    try:
        validate_palm_reset_registration(registration_rows, second_reset_caller)
    except InterfaceError:
        pass
    else:
        raise InterfaceError("self-test accepted an unbound Palm reset caller")

    parenthesized_reset_caller = copy.deepcopy(source_texts)
    parenthesized_reset_caller["drivers/gpu/drm/radeon/radeon_kms.c"] += (
        "\n(evergreen_gpu_pci_config_reset_safe)(other_rdev);\n"
    )
    try:
        validate_palm_reset_registration(
            registration_rows,
            parenthesized_reset_caller,
        )
    except InterfaceError:
        pass
    else:
        raise InterfaceError("self-test accepted a parenthesized Palm reset caller")

    second_registration_caller = copy.deepcopy(source_texts)
    second_registration_caller["drivers/gpu/drm/radeon/radeon_ttm.c"] += (
        "\nradeon_evergreen_dev_debugfs_register(minor);\n"
    )
    try:
        validate_palm_reset_registration(
            registration_rows,
            second_registration_caller,
        )
    except InterfaceError:
        pass
    else:
        raise InterfaceError("self-test accepted an unbound registration caller")

    registration_contract_mutations = (
        ("parent_expression", "NULL"),
        ("lifetime_owner", "module lifetime"),
        ("mode", "0644"),
        ("family_predicate", "rdev->family >= CHIP_PALM"),
    )
    for field, value in registration_contract_mutations:
        candidate_rows = copy.deepcopy(registration_rows)
        candidate_rows[0][field] = value
        try:
            validate_palm_reset_registration(candidate_rows, source_texts)
        except InterfaceError:
            pass
        else:
            raise InterfaceError(
                f"self-test accepted registration contract field {field}"
            )

    validate_wedged_reset_probe_post_state(source_texts)
    validate_forced_gpu_reset_transaction(source_texts)
    retired_source_texts = retired_reset_probe_source_texts(root)
    validate_retired_reset_probes(retired_source_texts)
    shrunk_retired_denominator = copy.deepcopy(RETIRED_RESET_PROBE_MARKERS)
    first_retired_path = sorted(shrunk_retired_denominator)[0]
    shrunk_retired_denominator[first_retired_path] = (
        shrunk_retired_denominator[first_retired_path][1:]
    )
    try:
        validate_retired_reset_probe_denominator(shrunk_retired_denominator)
    except InterfaceError:
        pass
    else:
        raise InterfaceError("self-test accepted a shrunk retired-probe denominator")
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

    reset_source_path = "drivers/gpu/drm/radeon/radeon_rs4xx_dev.c"
    reset_source = source_texts[reset_source_path]
    wedged_function_start = reset_source.find(
        "static int rs480_wedged_3d_reset("
    )
    wedged_function_end = reset_source.find(
        "\nstatic int rs480_reset_hang_probe_show(",
        wedged_function_start,
    )
    require(
        wedged_function_start >= 0
        and wedged_function_end > wedged_function_start,
        "self-test wedged reset function boundary differs from the source",
    )

    overridden_forced_reset = copy.deepcopy(source_texts)
    overridden_forced_reset[reset_source_path] = (
        reset_source[:wedged_function_start]
        + "#undef radeon_gpu_reset_forced\n"
        + "#define radeon_gpu_reset_forced radeon_gpu_reset\n"
        + reset_source[wedged_function_start:]
    )
    try:
        validate_wedged_reset_probe_post_state(overridden_forced_reset)
    except InterfaceError:
        pass
    else:
        raise InterfaceError(
            "self-test accepted an overridden wedged forced-reset call"
        )

    inactive_wedged_reset = copy.deepcopy(source_texts)
    inactive_wedged_reset[reset_source_path] = (
        reset_source[:wedged_function_start]
        + "#if 0\n"
        + reset_source[wedged_function_start:wedged_function_end]
        + "\n#else\n"
        + "static int rs480_wedged_3d_reset(struct radeon_device *rdev, "
        + "struct seq_file *m, bool require_backend_idle)\n"
        + "{\n"
        + "\t(void)rdev;\n"
        + "\t(void)m;\n"
        + "\t(void)require_backend_idle;\n"
        + "\treturn 0;\n"
        + "}\n"
        + "#endif"
        + reset_source[wedged_function_end:]
    )
    try:
        validate_wedged_reset_probe_post_state(inactive_wedged_reset)
    except InterfaceError:
        pass
    else:
        raise InterfaceError(
            "self-test accepted an inactive wedged reset implementation"
        )

    early_return_before_wedged_reset = copy.deepcopy(source_texts)
    early_return_before_wedged_reset[reset_source_path] = reset_source.replace(
        "\treset_result = radeon_gpu_reset_forced(rdev);",
        "\treturn 0;\n\treset_result = radeon_gpu_reset_forced(rdev);",
        1,
    )
    try:
        validate_wedged_reset_probe_post_state(early_return_before_wedged_reset)
    except InterfaceError:
        pass
    else:
        raise InterfaceError(
            "self-test accepted an early return before the wedged reset"
        )

    conditional_wedged_reset = copy.deepcopy(source_texts)
    conditional_wedged_reset[reset_source_path] = reset_source.replace(
        "\treset_result = radeon_gpu_reset_forced(rdev);",
        "\treset_result = 0;\n"
        "\tif (false)\n"
        "\t\treset_result = radeon_gpu_reset_forced(rdev);",
        1,
    )
    try:
        validate_wedged_reset_probe_post_state(conditional_wedged_reset)
    except InterfaceError:
        pass
    else:
        raise InterfaceError(
            "self-test accepted an unbraced conditional wedged reset"
        )

    goto_wedged_body = reset_source[
        wedged_function_start:wedged_function_end
    ].replace(
        "\treset_result = radeon_gpu_reset_forced(rdev);",
        "\tgoto bypass_wd3;\n"
        "\treset_result = radeon_gpu_reset_forced(rdev);",
        1,
    ).replace(
        "\tup_read(&rdev->exclusive_lock);",
        "\tup_read(&rdev->exclusive_lock);\n"
        "bypass_wd3:\n"
        "\t;",
        1,
    )
    bypassed_wedged_reset = copy.deepcopy(source_texts)
    bypassed_wedged_reset[reset_source_path] = (
        reset_source[:wedged_function_start]
        + goto_wedged_body
        + reset_source[wedged_function_end:]
    )
    try:
        validate_wedged_reset_probe_post_state(bypassed_wedged_reset)
    except InterfaceError:
        pass
    else:
        raise InterfaceError("self-test accepted a goto over the wedged reset")

    config_guard_start = reset_source.rfind(
        "#if defined(CONFIG_DEBUG_FS)",
        0,
        wedged_function_start,
    )
    mutate_guard_start = reset_source.rfind(
        "#if RADEON_MUTATE_DEV",
        0,
        wedged_function_start,
    )
    require(
        config_guard_start >= 0 and mutate_guard_start > config_guard_start,
        "self-test wedged enclosing guards differ from the source",
    )
    disabled_wedged_debugfs = copy.deepcopy(source_texts)
    disabled_wedged_debugfs[reset_source_path] = (
        reset_source[:config_guard_start]
        + "#undef CONFIG_DEBUG_FS\n"
        + reset_source[config_guard_start:]
    )
    try:
        validate_wedged_reset_probe_post_state(disabled_wedged_debugfs)
    except InterfaceError:
        pass
    else:
        raise InterfaceError(
            "self-test accepted an overridden WD3 debugfs condition"
        )

    disabled_wedged_mutation = copy.deepcopy(source_texts)
    disabled_wedged_mutation[reset_source_path] = (
        reset_source[:mutate_guard_start]
        + "#undef RADEON_MUTATE_DEV\n"
        + "#define RADEON_MUTATE_DEV 0\n"
        + reset_source[mutate_guard_start:]
    )
    try:
        validate_wedged_reset_probe_post_state(disabled_wedged_mutation)
    except InterfaceError:
        pass
    else:
        raise InterfaceError(
            "self-test accepted an overridden WD3 mutation condition"
        )

    unreachable_wedged_body = reset_source[
        wedged_function_start:wedged_function_end
    ].replace(
        "\tup_read(&rdev->exclusive_lock);",
        "\tunreachable();\n\tup_read(&rdev->exclusive_lock);",
        1,
    )
    unreachable_wedged_exit = copy.deepcopy(source_texts)
    unreachable_wedged_exit[reset_source_path] = (
        reset_source[:wedged_function_start]
        + unreachable_wedged_body
        + reset_source[wedged_function_end:]
    )
    try:
        validate_wedged_reset_probe_post_state(unreachable_wedged_exit)
    except InterfaceError:
        pass
    else:
        raise InterfaceError(
            "self-test accepted unreachable before the wedged unlock"
        )

    wrong_post_state = copy.deepcopy(source_texts)
    wrong_post_state[reset_source_path] = re.sub(
        r"(reset_result = radeon_gpu_reset_forced\(rdev\);.*?)"
        r"if \(rdev->gpu_parked\)",
        r"\1if (reset_result)",
        wrong_post_state[reset_source_path],
        count=1,
        flags=re.DOTALL,
    )
    try:
        validate_wedged_reset_probe_post_state(wrong_post_state)
    except InterfaceError:
        pass
    else:
        raise InterfaceError("self-test accepted return-code post-state gate")

    unreachable_post_state = copy.deepcopy(source_texts)
    unreachable_source = unreachable_post_state[reset_source_path]
    unreachable_start = unreachable_source.find(
        '\tradeon_dev_mark_mutation(rdev, "RS4xx reset hang probe");'
    )
    unreachable_unlock = unreachable_source.find(
        "\tup_read(&rdev->exclusive_lock);",
        unreachable_start,
    )
    unreachable_end = unreachable_unlock + len(
        "\tup_read(&rdev->exclusive_lock);"
    )
    require(
        unreachable_start >= 0 and unreachable_unlock > unreachable_start,
        "self-test wedged reset transaction boundary differs from the source",
    )
    unreachable_post_state[reset_source_path] = (
        unreachable_source[:unreachable_start]
        + "\tif (false) {\n"
        + unreachable_source[unreachable_start:unreachable_end]
        + "\n\t}\n\treset_result = -EPERM;\n\tpost_reset_status = 0;"
        + unreachable_source[unreachable_end:]
    )
    try:
        validate_wedged_reset_probe_post_state(unreachable_post_state)
    except InterfaceError:
        pass
    else:
        raise InterfaceError(
            "self-test accepted an unreachable wedged reset transaction"
        )

    intervening_post_reset_mmio = copy.deepcopy(source_texts)
    intervening_post_reset_mmio[reset_source_path] = intervening_post_reset_mmio[
        reset_source_path
    ].replace(
        "reset_result = radeon_gpu_reset_forced(rdev);",
        "reset_result = radeon_gpu_reset_forced(rdev);\n"
        "\tpost_reset_status = RREG32(R_000E40_RBBM_STATUS);",
        1,
    )
    try:
        validate_wedged_reset_probe_post_state(intervening_post_reset_mmio)
    except InterfaceError:
        pass
    else:
        raise InterfaceError("self-test accepted MMIO before the parked-state gate")

    parked_branch_mmio = copy.deepcopy(source_texts)
    parked_branch_mmio[reset_source_path] = parked_branch_mmio[
        reset_source_path
    ].replace(
        '\t\tpost_reset_status = 0x5041524B; /* "PARK" */\n',
        '\t\tpost_reset_status = 0x5041524B; /* "PARK" */\n'
        "\t\tpre_reset_status = RREG32(R_000E40_RBBM_STATUS);\n",
        1,
    )
    try:
        validate_wedged_reset_probe_post_state(parked_branch_mmio)
    except InterfaceError:
        pass
    else:
        raise InterfaceError("self-test accepted MMIO inside the parked branch")

    missing_post_reset_read_lock = copy.deepcopy(source_texts)
    missing_post_reset_read_lock[reset_source_path] = (
        missing_post_reset_read_lock[reset_source_path].replace(
            "\tdown_read(&rdev->exclusive_lock);\n", "", 1
        )
    )
    try:
        validate_wedged_reset_probe_post_state(missing_post_reset_read_lock)
    except InterfaceError:
        pass
    else:
        raise InterfaceError("self-test accepted an unlocked parked-state check")

    missing_post_reset_read_unlock = copy.deepcopy(source_texts)
    missing_post_reset_read_unlock[reset_source_path] = (
        missing_post_reset_read_unlock[reset_source_path].replace(
            "\tup_read(&rdev->exclusive_lock);\n", "", 1
        )
    )
    try:
        validate_wedged_reset_probe_post_state(missing_post_reset_read_unlock)
    except InterfaceError:
        pass
    else:
        raise InterfaceError("self-test accepted an unclosed post-state read lock")

    ordinary_reset_call = copy.deepcopy(source_texts)
    ordinary_reset_call[reset_source_path] = ordinary_reset_call[
        reset_source_path
    ].replace(
        "reset_result = radeon_gpu_reset_forced(rdev);",
        "reset_result = radeon_gpu_reset(rdev);",
        1,
    )
    try:
        validate_wedged_reset_probe_post_state(ordinary_reset_call)
    except InterfaceError:
        pass
    else:
        raise InterfaceError("self-test accepted an unserialized forced reset call")

    reset_implementation_path = "drivers/gpu/drm/radeon/radeon_device.c"
    reset_implementation_source = source_texts[reset_implementation_path]
    internal_function_start = reset_implementation_source.find(
        "static int radeon_gpu_reset_internal("
    )
    wrapper_function_start = reset_implementation_source.find(
        "int radeon_gpu_reset_forced("
    )
    wrapper_function_end = reset_implementation_source.find(
        "\n#endif",
        wrapper_function_start,
    )
    require(
        internal_function_start >= 0
        and wrapper_function_start > internal_function_start
        and wrapper_function_end > wrapper_function_start,
        "self-test forced reset function boundaries differ from the source",
    )

    overridden_writer_lock = copy.deepcopy(source_texts)
    overridden_writer_lock[reset_implementation_path] = (
        reset_implementation_source[:internal_function_start]
        + "#undef down_write\n"
        + "#define down_write down_read\n"
        + reset_implementation_source[internal_function_start:]
    )
    try:
        validate_forced_gpu_reset_transaction(overridden_writer_lock)
    except InterfaceError:
        pass
    else:
        raise InterfaceError(
            "self-test accepted an overridden forced-reset writer lock"
        )

    inactive_forced_wrapper = copy.deepcopy(source_texts)
    inactive_forced_wrapper[reset_implementation_path] = (
        reset_implementation_source[:wrapper_function_start]
        + "#if 0\n"
        + reset_implementation_source[
            wrapper_function_start:wrapper_function_end
        ]
        + "\n#else\n"
        + "int radeon_gpu_reset_forced(struct radeon_device *rdev)\n"
        + "{\n"
        + "\treturn radeon_gpu_reset_internal(rdev, false);\n"
        + "}\n"
        + "#endif"
        + reset_implementation_source[wrapper_function_end:]
    )
    try:
        validate_forced_gpu_reset_transaction(inactive_forced_wrapper)
    except InterfaceError:
        pass
    else:
        raise InterfaceError(
            "self-test accepted an inactive forced-reset wrapper"
        )

    mutate_wrapper_guard_start = reset_implementation_source.rfind(
        "#if RADEON_MUTATE_DEV",
        0,
        wrapper_function_start,
    )
    require(
        mutate_wrapper_guard_start >= 0,
        "self-test forced wrapper guard differs from the source",
    )
    disabled_forced_wrapper = copy.deepcopy(source_texts)
    disabled_forced_wrapper[reset_implementation_path] = (
        reset_implementation_source[:mutate_wrapper_guard_start]
        + "#undef RADEON_MUTATE_DEV\n"
        + "#define RADEON_MUTATE_DEV 0\n"
        + reset_implementation_source[mutate_wrapper_guard_start:]
    )
    try:
        validate_forced_gpu_reset_transaction(disabled_forced_wrapper)
    except InterfaceError:
        pass
    else:
        raise InterfaceError(
            "self-test accepted an overridden forced-wrapper condition"
        )

    early_return_before_writer = copy.deepcopy(source_texts)
    early_return_before_writer[reset_implementation_path] = (
        reset_implementation_source.replace(
            "\tdown_write(&rdev->exclusive_lock);",
            "\treturn 0;\n\tdown_write(&rdev->exclusive_lock);",
            1,
        )
    )
    try:
        validate_forced_gpu_reset_transaction(early_return_before_writer)
    except InterfaceError:
        pass
    else:
        raise InterfaceError(
            "self-test accepted an early return before the writer lock"
        )

    trapped_after_reset_counter = copy.deepcopy(source_texts)
    trapped_after_reset_counter[reset_implementation_path] = (
        reset_implementation_source.replace(
            "\tatomic_inc(&rdev->gpu_reset_counter);",
            "\tatomic_inc(&rdev->gpu_reset_counter);\n\tBUG();",
            1,
        )
    )
    try:
        validate_forced_gpu_reset_transaction(trapped_after_reset_counter)
    except InterfaceError:
        pass
    else:
        raise InterfaceError(
            "self-test accepted a nonlocal exit after the reset counter"
        )

    asm_after_reset_counter = copy.deepcopy(source_texts)
    asm_after_reset_counter[reset_implementation_path] = (
        reset_implementation_source.replace(
            "\tatomic_inc(&rdev->gpu_reset_counter);",
            "\tatomic_inc(&rdev->gpu_reset_counter);\n"
            '\t__asm__ __volatile__("ud2");',
            1,
        )
    )
    try:
        validate_forced_gpu_reset_transaction(asm_after_reset_counter)
    except InterfaceError:
        pass
    else:
        raise InterfaceError(
            "self-test accepted inline assembly after the reset counter"
        )

    parked_transition = "\t\trdev->in_reset = true;"
    early_parked_return = copy.deepcopy(source_texts)
    early_parked_return[reset_implementation_path] = (
        reset_implementation_source.replace(
            parked_transition,
            "\t\treturn r;\n" + parked_transition,
            1,
        )
    )
    try:
        validate_forced_gpu_reset_transaction(early_parked_return)
    except InterfaceError:
        pass
    else:
        raise InterfaceError("self-test accepted an early parked reset return")

    conditional_parked_exit = copy.deepcopy(source_texts)
    conditional_parked_exit[reset_implementation_path] = (
        reset_implementation_source.replace(
            parked_transition,
            "\t\tif (false)\n\t\t\t" + parked_transition.lstrip(),
            1,
        )
    )
    try:
        validate_forced_gpu_reset_transaction(conditional_parked_exit)
    except InterfaceError:
        pass
    else:
        raise InterfaceError(
            "self-test accepted a conditional parked reset transition"
        )

    looping_parked_exit = copy.deepcopy(source_texts)
    looping_parked_exit[reset_implementation_path] = (
        reset_implementation_source.replace(
            parked_transition,
            "\t\tfor (;;)\n\t\t\t;\n" + parked_transition,
            1,
        )
    )
    try:
        validate_forced_gpu_reset_transaction(looping_parked_exit)
    except InterfaceError:
        pass
    else:
        raise InterfaceError("self-test accepted a looping parked reset exit")

    ordinary_transition = (
        "\tradeon_hpd_init(rdev);\n\n"
        "\trdev->in_reset = true;"
    )
    early_ordinary_return = copy.deepcopy(source_texts)
    early_ordinary_return[reset_implementation_path] = (
        reset_implementation_source.replace(
            ordinary_transition,
            "\tradeon_hpd_init(rdev);\n\n"
            "\treturn r;\n"
            "\trdev->in_reset = true;",
            1,
        )
    )
    try:
        validate_forced_gpu_reset_transaction(early_ordinary_return)
    except InterfaceError:
        pass
    else:
        raise InterfaceError("self-test accepted an early ordinary reset return")

    conditional_ordinary_exit = copy.deepcopy(source_texts)
    conditional_ordinary_exit[reset_implementation_path] = (
        reset_implementation_source.replace(
            ordinary_transition,
            "\tradeon_hpd_init(rdev);\n\n"
            "\tif (false)\n"
            "\t\trdev->in_reset = true;",
            1,
        )
    )
    try:
        validate_forced_gpu_reset_transaction(conditional_ordinary_exit)
    except InterfaceError:
        pass
    else:
        raise InterfaceError(
            "self-test accepted a conditional ordinary reset transition"
        )

    parked_exit_start = reset_implementation_source.find(
        '\t\tdev_err(rdev->dev, "parked: async agents quiesced, '
        'entering quiet epoch\\n");'
    )
    parked_exit_return = reset_implementation_source.find(
        "\t\treturn r;",
        parked_exit_start,
    )
    parked_exit_end = parked_exit_return + len("\t\treturn r;")
    require(
        parked_exit_start >= 0 and parked_exit_return > parked_exit_start,
        "self-test parked reset exit boundary differs from the source",
    )
    digraph_parked_exit = copy.deepcopy(source_texts)
    digraph_parked_exit[reset_implementation_path] = (
        reset_implementation_source[:parked_exit_start]
        + "\t\tif (false) <%\n"
        + reset_implementation_source[parked_exit_start:parked_exit_end]
        + "\n\t\t%>"
        + reset_implementation_source[parked_exit_end:]
    )
    try:
        validate_forced_gpu_reset_transaction(digraph_parked_exit)
    except InterfaceError:
        pass
    else:
        raise InterfaceError(
            "self-test accepted a digraph-controlled parked reset exit"
        )

    missing_forced_writer = copy.deepcopy(source_texts)
    missing_forced_writer[reset_implementation_path] = re.sub(
        r"(static int radeon_gpu_reset_internal\(.*?\n\{.*?)"
        r"\tdown_write\(&rdev->exclusive_lock\);\n",
        r"\1",
        missing_forced_writer[reset_implementation_path],
        count=1,
        flags=re.DOTALL,
    )
    try:
        validate_forced_gpu_reset_transaction(missing_forced_writer)
    except InterfaceError:
        pass
    else:
        raise InterfaceError("self-test accepted a forced reset without writer lock")

    unreachable_forced_reset = copy.deepcopy(source_texts)
    forced_source = unreachable_forced_reset[reset_implementation_path]
    forced_function_start = forced_source.find(
        "static int radeon_gpu_reset_internal("
    )
    forced_function_end = forced_source.find(
        "\n/**\n * radeon_gpu_reset -",
        forced_function_start,
    )
    require(
        forced_function_start >= 0 and forced_function_end > forced_function_start,
        "self-test forced reset function boundary differs from the source",
    )
    forced_body = forced_source[forced_function_start:forced_function_end]
    forced_transaction_start = forced_body.find(
        "\tdown_write(&rdev->exclusive_lock);"
    )
    forced_transaction_return = forced_body.rfind("\treturn r;")
    forced_transaction_end = forced_transaction_return + len("\treturn r;")
    require(
        forced_transaction_start >= 0
        and forced_transaction_return > forced_transaction_start,
        "self-test forced reset transaction boundary differs from the source",
    )
    unreachable_body = (
        forced_body[:forced_transaction_start]
        + "\tif (false) {\n"
        + forced_body[forced_transaction_start:forced_transaction_end]
        + "\n\t}\n\treturn -EPERM;"
        + forced_body[forced_transaction_end:]
    )
    unreachable_forced_reset[reset_implementation_path] = (
        forced_source[:forced_function_start]
        + unreachable_body
        + forced_source[forced_function_end:]
    )
    try:
        validate_forced_gpu_reset_transaction(unreachable_forced_reset)
    except InterfaceError:
        pass
    else:
        raise InterfaceError(
            "self-test accepted an unreachable forced GPU-reset transaction"
        )

    premature_forced_unlock = copy.deepcopy(source_texts)
    premature_forced_unlock[reset_implementation_path] = premature_forced_unlock[
        reset_implementation_path
    ].replace(
        "\tif (force_reset)\n",
        "\tup_write(&rdev->exclusive_lock);\n\tif (force_reset)\n",
        1,
    )
    try:
        validate_forced_gpu_reset_transaction(premature_forced_unlock)
    except InterfaceError:
        pass
    else:
        raise InterfaceError("self-test accepted a premature forced-reset unlock")

    post_counter_forced_unlock = copy.deepcopy(source_texts)
    post_counter_forced_unlock[reset_implementation_path] = (
        post_counter_forced_unlock[reset_implementation_path].replace(
            "\tatomic_inc(&rdev->gpu_reset_counter);\n",
            "\tatomic_inc(&rdev->gpu_reset_counter);\n"
            "\tup_write(&rdev->exclusive_lock);\n",
            1,
        )
    )
    try:
        validate_forced_gpu_reset_transaction(post_counter_forced_unlock)
    except InterfaceError:
        pass
    else:
        raise InterfaceError("self-test accepted a post-counter writer unlock")

    reset_counter_line = "\tatomic_inc(&rdev->gpu_reset_counter);\n"
    early_downgrade_line = "\tdowngrade_write(&rdev->exclusive_lock);\n"
    ordinary_downgrade_context = (
        "\trdev->in_reset = true;\n"
        "\trdev->needs_reset = false;\n\n"
        "\tdowngrade_write(&rdev->exclusive_lock);\n\n"
        "\tdrm_helper_resume_force_mode(rdev_to_drm(rdev));"
    )
    ordinary_without_downgrade = (
        "\trdev->in_reset = true;\n"
        "\trdev->needs_reset = false;\n\n"
        "\tdrm_helper_resume_force_mode(rdev_to_drm(rdev));"
    )
    require(
        reset_implementation_source.count(reset_counter_line) == 1
        and reset_implementation_source.count(ordinary_downgrade_context) == 1,
        "self-test ordinary downgrade fixture differs from the source",
    )
    moved_ordinary_downgrade = copy.deepcopy(source_texts)
    moved_ordinary_source = reset_implementation_source.replace(
        reset_counter_line,
        reset_counter_line + early_downgrade_line,
        1,
    ).replace(
        ordinary_downgrade_context,
        ordinary_without_downgrade,
        1,
    )
    require(
        moved_ordinary_source.count(early_downgrade_line.strip()) == 2,
        "self-test ordinary downgrade mutant changes the downgrade denominator",
    )
    moved_ordinary_downgrade[reset_implementation_path] = moved_ordinary_source
    try:
        validate_forced_gpu_reset_transaction(moved_ordinary_downgrade)
    except InterfaceError:
        pass
    else:
        raise InterfaceError("self-test accepted a moved ordinary reset downgrade")

    parked_downgrade_context = (
        '\t\tdev_err(rdev->dev, "parked: downgrading exclusive lock\\n");\n'
        "\t\tdowngrade_write(&rdev->exclusive_lock);\n"
        "\t\tmsleep(1);"
    )
    parked_without_downgrade = (
        '\t\tdev_err(rdev->dev, "parked: downgrading exclusive lock\\n");\n'
        "\t\tmsleep(1);"
    )
    require(
        reset_implementation_source.count(parked_downgrade_context) == 1,
        "self-test parked downgrade fixture differs from the source",
    )
    moved_parked_downgrade = copy.deepcopy(source_texts)
    moved_parked_source = reset_implementation_source.replace(
        reset_counter_line,
        reset_counter_line + early_downgrade_line,
        1,
    ).replace(
        parked_downgrade_context,
        parked_without_downgrade,
        1,
    )
    require(
        moved_parked_source.count(early_downgrade_line.strip()) == 2,
        "self-test parked downgrade mutant changes the downgrade denominator",
    )
    moved_parked_downgrade[reset_implementation_path] = moved_parked_source
    try:
        validate_forced_gpu_reset_transaction(moved_parked_downgrade)
    except InterfaceError:
        pass
    else:
        raise InterfaceError("self-test accepted a moved parked reset downgrade")

    retired_rejection_count = 0
    for path, markers in RETIRED_RESET_PROBE_MARKERS.items():
        for marker in markers:
            reintroduced = copy.deepcopy(retired_source_texts)
            reintroduced[path] += f"\n{marker}\n"
            try:
                validate_retired_reset_probes(reintroduced)
            except InterfaceError:
                retired_rejection_count += 1
            else:
                raise InterfaceError(
                    f"self-test accepted retired reset-probe marker {marker}"
                )

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
        "6 build-profile, 12 runtime-profile, 2 mutation-audit, "
        f"{len(registration_source_mutations) + 11} Palm registration source, "
        "4 registration contract, "
        f"{summary_rejection_count} summary-total, "
        "15 reset-post-state, 18 forced-reset, 1 retired-denominator, "
        f"{retired_rejection_count} retired-probe, and 3 compiler-symbol cases"
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

    reported_rows = profile_rows(rows, features, args.profile) if args.module else rows
    parameter_count = sum(
        row["marker_type"] == "module-parameter" for row in reported_rows
    )
    debugfs_count = sum(row["marker_type"] == "debugfs-file" for row in reported_rows)
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
