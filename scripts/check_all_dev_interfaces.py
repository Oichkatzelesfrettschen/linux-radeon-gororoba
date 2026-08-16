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
C_TOKEN = re.compile(
    r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
    r"|[A-Za-z_][A-Za-z0-9_]*"
    r"|0[xX][0-9A-Fa-f]+[uUlL]*|[0-9]+[uUlL]*"
    r"|>>=|<<=|\+\+|--|->|==|!=|<=|>=|&&|\|\|"
    r"|[{}()\[\];,.*+\-/%&|^~!<>=?:]"
)
PALM_RESET_HARDWARE_ACCESS = re.compile(
    r"\b(?:WREG32|RREG32|r600_rlc_stop|rv770_set_clk_bypass_mode|"
    r"pci_clear_master|evergreen_mc_stop|evergreen_mc_wait_for_idle|"
    r"evergreen_mc_resume|radeon_pci_config_reset)\s*\("
)
RS4XX_CP_ME_HARDWARE_ACCESS = re.compile(
    r"\b(?:WREG32|RREG32)[A-Za-z0-9_]*\s*\("
    r"|\b(?:read[blqw]|write[blqw]|ioread[0-9]+|iowrite[0-9]+)\s*\("
    r"|->(?:rreg|wreg)\s*\("
)
RS4XX_HARDWARE_TRANSACTION_CALL_DENOMINATOR = {
    "radeon_debugfs_rs480_mc_flush_set": (0, 1, 2),
    "rs400_debugfs_gart_page_table_show": (0, 1, 2),
    "rs480_candidate_config_regs_show": (1, 0, 1),
    "rs480_candidate_gart_mc_regs_show": (1, 0, 1),
    "rs480_candidate_regs_emit": (1, 0, 1),
    "rs480_cp_ib_scratch_oracle_show": (1, 0, 1),
    "rs480_cp_me_oracle_show": (1, 0, 1),
    "rs480_cp_me_ram_inject_write": (0, 1, 2),
    "rs480_cp_me_ram_seq_show": (1, 0, 1),
    "rs480_cp_status_show": (1, 0, 1),
    "rs480_debugfs_lock_hardware": (0, 1, 0),
    "rs480_force_clock_3d_read_show": (1, 0, 1),
    "rs480_force_clock_read_show": (1, 0, 1),
    "rs480_frontier_probe_show": (1, 0, 1),
    "rs480_gated_read_show": (1, 0, 1),
    "rs480_hazard_read_show": (1, 0, 1),
    "rs480_pll_regs_show": (1, 0, 1),
    "rs480_reset_hang_probe_show": (1, 0, 3),
    "rs480_safe_regs_show": (1, 0, 1),
    "rs480_sclk_cntl_show": (1, 0, 1),
    "rs480_uma_status_show": (1, 0, 1),
    "rs480_vertex_probe_show": (1, 0, 1),
    "rs480_wedged_3d_reset": (0, 2, 3),
}
RS4XX_HARDWARE_TRANSACTION_GLOBAL_CALLS = {
    "rs480_debugfs_lock_hardware": 19,
    "radeon_device_lock_hardware": 6,
    "radeon_device_unlock_hardware": 29,
}
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
    "drivers/gpu/drm/radeon/radeon.h": (),
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
        r"static void rs480_debugfs_emit_schema\(.*?\)\n\{.*?"
        r"RADEON_DEV_OUTPUT_SCHEMA_LINE",
        r"static int rs480_debugfs_lock_hardware\(.*?\)\n\{.*?"
        r"rs480_debugfs_emit_schema",
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
        r"void radeon_debugfs_add_component\(.*?"
        r"RADEON_DEBUGFS_MAX_COMPONENTS",
        r"static void radeon_dev_debugfs_register\(.*?\)\n\{.*?"
        r"radeon_ttm_debugfs_register_managers\(rdev, minor->debugfs_root\);.*?"
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
RS4XX_OUTPUT_SCHEMA_SHOW_FUNCTIONS = frozenset(
    {
        "rs400_debugfs_gart_page_table_show",
        "rs480_candidate_config_regs_show",
        "rs480_candidate_firmware_read_regs_show",
        "rs480_candidate_ga_regs_show",
        "rs480_candidate_gart_mc_regs_show",
        "rs480_candidate_gart_status_regs_show",
        "rs480_candidate_gb_regs_show",
        "rs480_candidate_mc_benign_regs_show",
        "rs480_candidate_rb3d_regs_show",
        "rs480_candidate_sc_regs_show",
        "rs480_candidate_vap_regs_show",
        "rs480_candidate_vip_straggler_regs_show",
        "rs480_candidate_zb_regs_show",
        "rs480_cp_ib_scratch_oracle_show",
        "rs480_cp_me_oracle_show",
        "rs480_cp_me_ram_inject_show",
        "rs480_cp_me_ram_seq_show",
        "rs480_cp_status_show",
        "rs480_force_clock_3d_read_show",
        "rs480_force_clock_read_show",
        "rs480_frontier_probe_show",
        "rs480_gated_read_show",
        "rs480_hazard_read_show",
        "rs480_pll_regs_show",
        "rs480_reset_hang_probe_show",
        "rs480_safe_regs_show",
        "rs480_sclk_cntl_show",
        "rs480_uma_status_show",
        "rs480_vertex_probe_show",
    }
)
RS4XX_OUTPUT_SCHEMA_READABLE_NODE_COUNT = 31
RS4XX_DEBUGFS_NODE_COUNT = 32
RS4XX_WRITE_ONLY_DEBUGFS_NODES = frozenset({"radeon_rs480_mc_flush"})
RS4XX_WRITE_ONLY_DEBUGFS_NODE_FOPS = {
    "radeon_rs480_mc_flush": "rs480_mc_flush_fops",
}
RS4XX_OUTPUT_SCHEMA_NODE_FOPS = {
    "radeon_rs480_candidate_config_regs": "rs480_candidate_config_regs_fops",
    "radeon_rs480_candidate_firmware_read_regs": (
        "rs480_candidate_firmware_read_regs_fops"
    ),
    "radeon_rs480_candidate_ga_regs": "rs480_candidate_ga_regs_fops",
    "radeon_rs480_candidate_gart_mc_regs": "rs480_candidate_gart_mc_regs_fops",
    "radeon_rs480_candidate_gart_status_regs": (
        "rs480_candidate_gart_status_regs_fops"
    ),
    "radeon_rs480_candidate_gb_regs": "rs480_candidate_gb_regs_fops",
    "radeon_rs480_candidate_mc_benign_regs": ("rs480_candidate_mc_benign_regs_fops"),
    "radeon_rs480_candidate_rb3d_regs": "rs480_candidate_rb3d_regs_fops",
    "radeon_rs480_candidate_regs": "rs480_candidate_config_regs_fops",
    "radeon_rs480_candidate_sc_regs": "rs480_candidate_sc_regs_fops",
    "radeon_rs480_candidate_vap_regs": "rs480_candidate_vap_regs_fops",
    "radeon_rs480_candidate_vip_straggler_regs": (
        "rs480_candidate_vip_straggler_regs_fops"
    ),
    "radeon_rs480_candidate_z_regs": "rs480_candidate_zb_regs_fops",
    "radeon_rs480_candidate_zb_regs": "rs480_candidate_zb_regs_fops",
    "radeon_rs480_cp_ib_scratch_oracle": "rs480_cp_ib_scratch_oracle_fops",
    "radeon_rs480_cp_me_oracle": "rs480_cp_me_oracle_fops",
    "radeon_rs480_cp_me_ram_dump": "rs480_cp_me_ram_dump_fops",
    "radeon_rs480_cp_status": "rs480_cp_status_fops",
    "radeon_rs480_cp_me_ram_inject": "rs480_cp_me_ram_inject_fops",
    "radeon_rs480_force_clock_3d_read": "rs480_force_clock_3d_read_fops",
    "radeon_rs480_force_clock_read": "rs480_force_clock_read_fops",
    "radeon_rs480_frontier_probe": "rs480_frontier_probe_fops",
    "radeon_rs480_gart_page_table": "rs400_debugfs_gart_page_table_fops",
    "radeon_rs480_gated_read": "rs480_gated_read_fops",
    "radeon_rs480_hazard_read": "rs480_hazard_read_fops",
    "radeon_rs480_pll_regs": "rs480_pll_regs_fops",
    "radeon_rs480_reset_hang_probe": "rs480_reset_hang_probe_fops",
    "radeon_rs480_safe_regs": "rs480_safe_regs_fops",
    "radeon_rs480_sclk_cntl": "rs480_sclk_cntl_fops",
    "radeon_rs480_uma_status": "rs480_uma_status_fops",
    "radeon_rs480_vertex_probe": "rs480_vertex_probe_fops",
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
    "drivers/gpu/drm/radeon/radeon_dev.c": ("radeon_rs480_gpu_reset_recover_probe",),
    "drivers/gpu/drm/radeon/radeon_dev.h": ("radeon_rs480_gpu_reset_recover_probe",),
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


def c_tokens(source: str, label: str) -> tuple[str, ...]:
    """Tokenize the bounded C subset used by exact mechanism shapes."""
    comment_free = strip_comments(source)
    residual = C_TOKEN.sub("", comment_free)
    require(not residual.strip(), f"{label} contains an unparsed C token")
    return tuple(C_TOKEN.findall(comment_free))


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
    expected_labels: tuple[str, ...] = (),
) -> None:
    """Require lexical control under the stated returning-call assumption."""
    code = strip_comments_and_literals(body)
    actual_counts = tuple(
        len(re.findall(rf"\b{keyword}\b", code)) for keyword in CONTROL_FLOW_KEYWORDS
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
    labels = tuple(
        normalized_code(match.group(0))
        for match in re.finditer(
            r"(?m)^[ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*:",
            code,
        )
    )
    require(labels == expected_labels, f"{label} source-label set differs")


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
    definition_code = strip_comments_and_literals(source)
    definition = re.search(
        rf"(?m)^(?:[A-Za-z_].*\b)?{re.escape(name)}\s*\(",
        definition_code,
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
    scan_lines = definition_code.splitlines()
    start = code.count("\n", 0, definition.start())
    for index in range(start, len(scan_lines)):
        if FUNCTION_END.match(scan_lines[index]):
            function_text = "\n".join(lines[start : index + 1])
            if protect_identifiers:
                protected_identifier_set = set(
                    C_IDENTIFIER.findall(strip_comments_and_literals(function_text))
                )
                enclosing_conditions = []
                if expected_enclosing_condition is not None:
                    enclosing_conditions.append(expected_enclosing_condition)
                if expected_enclosing_stack is not None:
                    enclosing_conditions.extend(
                        condition_tail
                        for _kind, condition_tail, _branch in expected_enclosing_stack
                    )
                for condition in enclosing_conditions:
                    protected_identifier_set.update(C_IDENTIFIER.findall(condition))
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


def direct_call_names(body: str, function_name: str) -> tuple[str, ...]:
    """Return the direct C call names inside one parsed function body."""
    control = strip_comments_and_literals(body)
    opening_brace = control.find("{")
    require(opening_brace >= 0, f"function {function_name} has no opening brace")
    inner_body = control[opening_brace + 1 :]
    require(
        re.search(r"[\)\]]\s*\(", inner_body) is None,
        f"function {function_name} uses an indirect call",
    )
    control_keywords = {
        "_Static_assert",
        "for",
        "if",
        "sizeof",
        "switch",
        "typeof",
        "while",
    }
    return tuple(
        name
        for name in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", inner_body)
        if name not in control_keywords
    )


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
        "parameters": sum(row["marker_type"] == "module-parameter" for row in rows),
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


def validate_rs4xx_output_schema_paths(
    rows: list[dict[str, str]],
    source: str,
    expected_show_functions: frozenset[str] = RS4XX_OUTPUT_SCHEMA_SHOW_FUNCTIONS,
) -> None:
    """Prove that every readable RS4xx development node reaches the schema
    emitter before its first output or control-flow exit."""
    rs4xx_nodes = {
        row["marker"]
        for row in rows
        if row["marker_type"] == "debugfs-file"
        and row["source_path"] == "drivers/gpu/drm/radeon/radeon_rs4xx_dev.c"
    }
    readable_nodes = rs4xx_nodes - RS4XX_WRITE_ONLY_DEBUGFS_NODES
    require(
        len(readable_nodes) == RS4XX_OUTPUT_SCHEMA_READABLE_NODE_COUNT,
        "RS4xx readable debugfs node denominator differs",
    )

    source_without_comments = strip_comments(source)
    registration_pattern = re.compile(
        r'debugfs_create_file\(\s*"(?P<node>radeon_rs480_[^"]+)"\s*,'
        r"\s*(?P<mode>0[0-7]+)\s*,.*?,"
        r"\s*&(?P<fops>[A-Za-z0-9_]+)\s*\);",
        re.DOTALL,
    )
    registrations = list(registration_pattern.finditer(source_without_comments))
    registered_node_fops = {
        match.group("node"): match.group("fops") for match in registrations
    }
    expected_all_node_fops = {
        **RS4XX_OUTPUT_SCHEMA_NODE_FOPS,
        **RS4XX_WRITE_ONLY_DEBUGFS_NODE_FOPS,
    }
    require(
        len(registered_node_fops) == len(registrations),
        "RS4xx debugfs registration contains a duplicate node",
    )
    require(
        len(registered_node_fops) == RS4XX_DEBUGFS_NODE_COUNT
        and registered_node_fops == expected_all_node_fops,
        "RS4xx debugfs node-to-fops map differs",
    )
    readable_node_fops = {
        node: fops
        for node, fops in registered_node_fops.items()
        if node not in RS4XX_WRITE_ONLY_DEBUGFS_NODES
    }
    require(
        readable_node_fops == RS4XX_OUTPUT_SCHEMA_NODE_FOPS,
        "RS4xx readable debugfs node-to-fops map differs",
    )
    registered_node_modes = {
        match.group("node"): match.group("mode") for match in registrations
    }
    expected_all_node_modes = {
        node: (
            "0600"
            if node == "radeon_rs480_cp_me_ram_inject"
            else "0200"
            if node in RS4XX_WRITE_ONLY_DEBUGFS_NODES
            else "0400"
        )
        for node in expected_all_node_fops
    }
    require(
        registered_node_modes == expected_all_node_modes,
        "RS4xx debugfs node modes differ",
    )
    require(
        rs4xx_nodes == set(expected_all_node_fops)
        and readable_nodes == set(RS4XX_OUTPUT_SCHEMA_NODE_FOPS),
        "RS4xx debugfs manifest and fops maps differ",
    )

    discovered_show_functions = frozenset(
        re.findall(
            r"^static int ([A-Za-z0-9_]+_show)\s*\(",
            source_without_comments,
            re.MULTILINE,
        )
    )
    require(
        discovered_show_functions == expected_show_functions,
        "RS4xx output-schema show-function denominator differs",
    )
    custom_fops = {
        "rs480_cp_me_ram_dump_fops",
        "rs480_cp_me_ram_inject_fops",
    }
    defined_show_names = set(
        re.findall(
            r"\bDEFINE_SHOW_ATTRIBUTE\(([A-Za-z0-9_]+)\);",
            source_without_comments,
        )
    )
    require(
        {f"{name}_fops" for name in defined_show_names}
        == set(RS4XX_OUTPUT_SCHEMA_NODE_FOPS.values()) - custom_fops,
        "RS4xx DEFINE_SHOW_ATTRIBUTE fops denominator differs",
    )
    require(
        {f"{name}_show" for name in defined_show_names}
        == set(discovered_show_functions)
        - {"rs480_cp_me_ram_inject_show", "rs480_cp_me_ram_seq_show"},
        "RS4xx DEFINE_SHOW_ATTRIBUTE handler denominator differs",
    )
    require(
        len(
            re.findall(
                r"\bRADEON_DEV_OUTPUT_SCHEMA_LINE\b",
                strip_comments_and_literals(source),
            )
        )
        == 1,
        "RS4xx schema-line emission is not centralized",
    )
    output_call = re.compile(r"\bseq_[A-Za-z0-9_]+\s*\(")
    schema_output_route = re.compile(
        r"\b(?:rs480_debugfs_emit_schema|rs480_debugfs_lock_hardware)\s*\("
    )
    schema_emitter_call = re.compile(r"\brs480_debugfs_emit_schema\s*\(")
    control_exit = re.compile(r"\b(?:goto|return)\b")

    emitter_body = function_body(source, "rs480_debugfs_emit_schema")
    require_one_match(
        emitter_body,
        r"^static void rs480_debugfs_emit_schema\(struct seq_file \*m\)\s*"
        r"\{\s*if \(m->count == 0\)\s*"
        r"seq_puts\(m, RADEON_DEV_OUTPUT_SCHEMA_LINE\);\s*\}$",
        "RS4xx schema emitter",
    )

    hardware_lock_body = function_body(source, "rs480_debugfs_lock_hardware")
    hardware_schema = require_one_match(
        hardware_lock_body,
        r"\brs480_debugfs_emit_schema\(m\);",
        "RS4xx hardware transaction schema route",
    )
    hardware_root = require_one_match(
        hardware_lock_body,
        r"\bradeon_device_lock_hardware\(rdev\);",
        "RS4xx hardware transaction root",
    )
    require(
        "RADEON_DEV_OUTPUT_SCHEMA_LINE" not in hardware_lock_body
        and hardware_schema.start() < hardware_root.start(),
        "RS4xx debugfs lock bypasses its centralized transaction root",
    )
    hardware_prefix = strip_comments_and_literals(
        hardware_lock_body[: hardware_schema.start()]
    )
    require_outer_function_match(
        hardware_lock_body,
        hardware_schema,
        "RS4xx hardware transaction schema route",
    )
    require(
        output_call.search(hardware_prefix) is None
        and control_exit.search(hardware_prefix) is None,
        "RS4xx debugfs lock emits or exits before its schema route",
    )
    require_one_match(
        hardware_lock_body,
        r"if \(!r\)\s*return 0;",
        "RS4xx hardware transaction success route",
    )
    require_one_match(
        hardware_lock_body,
        r"if \(r == -EIO\)",
        "RS4xx parked-state transaction refusal",
    )
    require(
        hardware_lock_body.count("if (first)") == 3,
        "RS4xx debugfs lock refusal output is not first-record gated",
    )

    candidate_body = function_body(source, "rs480_candidate_regs_emit")
    candidate_lock = require_one_match(
        candidate_body,
        r"\bif \(rs480_debugfs_lock_hardware\(m, rdev\)\)",
        "RS4xx candidate-register transaction route",
    )
    require_outer_function_match(
        candidate_body,
        candidate_lock,
        "RS4xx candidate-register transaction route",
    )
    candidate_prefix = strip_comments_and_literals(
        candidate_body[: candidate_lock.start()]
    )
    require(
        output_call.search(candidate_prefix) is None
        and control_exit.search(candidate_prefix) is None,
        "RS4xx candidate-register helper bypasses its schema route",
    )

    route_patterns = (
        (
            "direct schema emitter",
            re.compile(r"^\trs480_debugfs_emit_schema\(m\);", re.MULTILINE),
        ),
        (
            "hardware transaction/schema route",
            re.compile(
                r"^\tif\s*\(\s*rs480_debugfs_lock_hardware\(\s*m\s*,"
                r"[^)]*\)\s*\)",
                re.MULTILINE,
            ),
        ),
        (
            "candidate-register schema route",
            re.compile(
                r"^\treturn\s+rs480_candidate_regs_emit\(\s*m\s*,",
                re.MULTILINE,
            ),
        ),
    )
    guarded_route_prefix = re.compile(
        r"\b(?:if|for|while|switch|goto|return)\b|\?|"
        r"^\s*#|^\s*[A-Za-z_][A-Za-z0-9_]*:\s*$",
        re.MULTILINE,
    )
    for function_name in sorted(discovered_show_functions):
        if function_name == "rs480_cp_me_ram_seq_show":
            continue
        body = function_body(source, function_name)
        route_search_body = strip_comments_and_literals(body)
        routes = [
            (match.start(), label, match)
            for label, pattern in route_patterns
            for match in pattern.finditer(route_search_body)
        ]
        require(bool(routes), f"{function_name} has no output-schema route")
        _, label, first_route = min(routes, key=lambda route: route[0])
        require_outer_function_match(body, first_route, f"{function_name} {label}")
        prefix = strip_comments_and_literals(body[: first_route.start()])
        require(
            control_exit.search(prefix) is None,
            f"{function_name} can exit before its output-schema route",
        )
        require(
            output_call.search(prefix) is None,
            f"{function_name} can emit output before its output-schema route",
        )
        require(
            guarded_route_prefix.search(prefix) is None,
            f"{function_name} conditionally reaches its output-schema route",
        )

    terminal_position_body = function_body(
        source, "rs480_cp_me_ram_seq_terminal_position"
    )
    terminal_position_gate = require_one_match(
        terminal_position_body,
        r"if \(READ_ONCE\(rdev->gpu_parked\)\)\s*"
        r"return RS480_CP_ME_RAM_DUMP_TERMINAL_PARKED;\s*"
        r"if \(READ_ONCE\(rdev->asic_suspended\)\)\s*"
        r"return RS480_CP_ME_RAM_DUMP_TERMINAL_SUSPENDED;\s*"
        r"if \(READ_ONCE\(radeon_rs480_cp_me_ram_dump\) != 1\)\s*"
        r"return RS480_CP_ME_RAM_DUMP_TERMINAL_DISARMED;",
        "RS4xx CP-ME terminal gate order",
    )
    require_outer_function_match(
        terminal_position_body,
        terminal_position_gate,
        "RS4xx CP-ME terminal gate order",
    )
    terminal_position_prefix = strip_comments_and_literals(
        terminal_position_body[: terminal_position_gate.start()]
    )
    terminal_position_control = strip_comments_and_literals(terminal_position_body)
    require(
        guarded_route_prefix.search(terminal_position_prefix) is None
        and ";" not in terminal_position_prefix
        and output_call.search(terminal_position_control) is None
        and schema_output_route.search(terminal_position_control) is None
        and RS4XX_CP_ME_HARDWARE_ACCESS.search(terminal_position_control) is None
        and len(re.findall(r"\breturn\b", terminal_position_control)) == 4,
        "RS4xx CP-ME terminal gate has a prefix diversion, hardware access, output, or extra exit",
    )
    require_one_match(
        source_without_comments,
        r"#define RS480_CP_ME_RAM_DUMP_LIMIT 0x100u\s*"
        r"#define RS480_CP_ME_RAM_DUMP_TERMINAL_DISARMED\s*"
        r"\(RS480_CP_ME_RAM_DUMP_LIMIT \+ 2\)\s*"
        r"#define RS480_CP_ME_RAM_DUMP_TERMINAL_PARKED\s*"
        r"\(RS480_CP_ME_RAM_DUMP_LIMIT \+ 4\)\s*"
        r"#define RS480_CP_ME_RAM_DUMP_TERMINAL_SUSPENDED\s*"
        r"\(RS480_CP_ME_RAM_DUMP_LIMIT \+ 6\)",
        "RS4xx CP-ME encoded terminal positions",
    )
    terminal_test_body = function_body(source, "rs480_cp_me_ram_seq_is_terminal")
    require_one_match(
        terminal_test_body,
        r"return position == RS480_CP_ME_RAM_DUMP_TERMINAL_DISARMED \|\|\s*"
        r"position == RS480_CP_ME_RAM_DUMP_TERMINAL_PARKED \|\|\s*"
        r"position == RS480_CP_ME_RAM_DUMP_TERMINAL_SUSPENDED;",
        "RS4xx CP-ME terminal-position predicate",
    )
    terminal_emit_body = function_body(source, "rs480_cp_me_ram_seq_emit_terminal")
    terminal_emit_control = strip_comments_and_literals(terminal_emit_body)
    terminal_mapping = require_one_match(
        terminal_emit_body,
        r"switch \(position\)\s*\{\s*"
        r"case RS480_CP_ME_RAM_DUMP_TERMINAL_DISARMED:\s*"
        r'seq_puts\(m, "terminal_status\\tstatus=disarmed\\n"\);\s*'
        r"break;\s*"
        r"case RS480_CP_ME_RAM_DUMP_TERMINAL_PARKED:\s*"
        r'seq_puts\(m, "terminal_status\\tstatus=gpu-parked\\n"\);\s*'
        r"break;\s*"
        r"case RS480_CP_ME_RAM_DUMP_TERMINAL_SUSPENDED:\s*"
        r'seq_puts\(m, "terminal_status\\tstatus=asic-suspended\\n"\);\s*'
        r"break;\s*"
        r"default:\s*"
        r'seq_puts\(m, "terminal_status\\tstatus=invalid\\n"\);\s*'
        r"break;\s*\}",
        "RS4xx CP-ME terminal position-to-status mapping",
    )
    require_outer_function_match(
        terminal_emit_body,
        terminal_mapping,
        "RS4xx CP-ME terminal position-to-status mapping",
    )
    require(
        terminal_emit_control.count("seq_puts(m,") == 4
        and terminal_emit_body.count('"terminal_status') == 4
        and '"terminal_status\\tstatus=disarmed\\n"' in terminal_emit_body
        and '"terminal_status\\tstatus=gpu-parked\\n"' in terminal_emit_body
        and '"terminal_status\\tstatus=asic-suspended\\n"' in terminal_emit_body
        and '"terminal_status\\tstatus=invalid\\n"' in terminal_emit_body
        and "RADEON_DEV_OUTPUT_SCHEMA_LINE" not in terminal_emit_body,
        "RS4xx CP-ME terminal emitter is not total and fail-closed",
    )

    dump_start_body = function_body(source, "rs480_cp_me_ram_seq_start")
    dump_header_start = require_one_match(
        dump_start_body,
        r"if \(\*pos == 0\)\s*return SEQ_START_TOKEN;",
        "RS4xx CP-ME dump header start",
    )
    dump_start_terminal = require_one_match(
        dump_start_body,
        r"if \(rs480_cp_me_ram_seq_is_terminal\(\*pos\)\)\s*"
        r"return pos;",
        "RS4xx CP-ME dump terminal replay start",
    )
    dump_start_gate = require_one_match(
        dump_start_body,
        r"terminal_position = rs480_cp_me_ram_seq_terminal_position\(rdev\);\s*"
        r"if \(terminal_position\)\s*\{\s*\*pos = terminal_position;\s*"
        r"return pos;\s*\}",
        "RS4xx CP-ME dump start terminal route",
    )
    dump_limit_start = require_one_match(
        dump_start_body,
        r"if \(\*pos > RS480_CP_ME_RAM_DUMP_LIMIT\)\s*return NULL;",
        "RS4xx CP-ME dump start bound",
    )
    for label, match in (
        ("header start", dump_header_start),
        ("terminal replay start", dump_start_terminal),
        ("start bound", dump_limit_start),
        ("start terminal route", dump_start_gate),
    ):
        require_outer_function_match(
            dump_start_body,
            match,
            f"RS4xx CP-ME dump {label}",
        )
    dump_start_returns = list(re.finditer(r"\breturn pos;", dump_start_body))
    require(
        len(dump_start_returns) == 3,
        "RS4xx CP-ME dump start record count differs",
    )
    dump_start_return = dump_start_returns[-1]
    require(
        dump_header_start.start()
        < dump_start_terminal.start()
        < dump_limit_start.start()
        < dump_start_gate.start()
        < dump_start_return.start(),
        "RS4xx CP-ME dump start gates are out of order",
    )
    dump_start_control = strip_comments_and_literals(dump_start_body)
    require(
        output_call.search(dump_start_control) is None
        and schema_output_route.search(dump_start_control) is None
        and RS4XX_CP_ME_HARDWARE_ACCESS.search(dump_start_control) is None
        and len(re.findall(r"\breturn\b", dump_start_control)) == 5
        and re.search(r"\+\+\*pos", dump_start_control) is None,
        "RS4xx CP-ME dump start reaches hardware, emits output, or changes the position",
    )

    dump_next_body = function_body(source, "rs480_cp_me_ram_seq_next")
    dump_next_snapshot = require_one_match(
        dump_next_body,
        r"bool was_terminal = rs480_cp_me_ram_seq_is_terminal\(\*pos\);",
        "RS4xx CP-ME dump terminal snapshot",
    )
    dump_next_increment = require_one_match(
        dump_next_body,
        r"\+\+\*pos;",
        "RS4xx CP-ME dump iterator increment",
    )
    dump_next_eof = require_one_match(
        dump_next_body,
        r"if \(was_terminal\)\s*return NULL;",
        "RS4xx CP-ME dump terminal EOF",
    )
    dump_next_gate = require_one_match(
        dump_next_body,
        r"terminal_position = rs480_cp_me_ram_seq_terminal_position\(rdev\);\s*"
        r"if \(terminal_position\)\s*\{\s*\*pos = terminal_position;\s*"
        r"return pos;\s*\}",
        "RS4xx CP-ME dump iterator terminal route",
    )
    dump_limit_next = require_one_match(
        dump_next_body,
        r"if \(\*pos > RS480_CP_ME_RAM_DUMP_LIMIT\)\s*return NULL;",
        "RS4xx CP-ME dump iterator bound",
    )
    for label, match in (
        ("terminal snapshot", dump_next_snapshot),
        ("iterator increment", dump_next_increment),
        ("terminal EOF", dump_next_eof),
        ("iterator bound", dump_limit_next),
        ("iterator terminal route", dump_next_gate),
    ):
        require_outer_function_match(
            dump_next_body,
            match,
            f"RS4xx CP-ME dump {label}",
        )
    dump_next_returns = list(re.finditer(r"\breturn pos;", dump_next_body))
    require(
        len(dump_next_returns) == 2,
        "RS4xx CP-ME dump next record count differs",
    )
    dump_next_return = dump_next_returns[-1]
    require(
        dump_next_snapshot.start()
        < dump_next_increment.start()
        < dump_next_eof.start()
        < dump_limit_next.start()
        < dump_next_gate.start()
        < dump_next_return.start(),
        "RS4xx CP-ME dump iterator routes are out of order",
    )
    dump_next_control = strip_comments_and_literals(dump_next_body)
    require(
        output_call.search(dump_next_control) is None
        and schema_output_route.search(dump_next_control) is None
        and RS4XX_CP_ME_HARDWARE_ACCESS.search(dump_next_control) is None
        and len(re.findall(r"\breturn\b", dump_next_control)) == 4
        and re.search(r"\bgoto\b", dump_next_control) is None,
        "RS4xx CP-ME dump iterator reaches hardware, emits output, or has extra exits",
    )

    dump_stop_body = function_body(source, "rs480_cp_me_ram_seq_stop")
    require_one_match(
        dump_stop_body,
        r"^static void rs480_cp_me_ram_seq_stop\(struct seq_file \*m, void \*v\)"
        r"\s*\{\s*\}$",
        "RS4xx CP-ME dump stop",
    )
    dump_show_body = function_body(source, "rs480_cp_me_ram_seq_show")
    expected_function_shapes = {
        "rs480_cp_me_ram_seq_terminal_position": """
static loff_t rs480_cp_me_ram_seq_terminal_position(struct radeon_device *rdev)
{
    if (READ_ONCE(rdev->gpu_parked))
        return RS480_CP_ME_RAM_DUMP_TERMINAL_PARKED;
    if (READ_ONCE(rdev->asic_suspended))
        return RS480_CP_ME_RAM_DUMP_TERMINAL_SUSPENDED;
    if (READ_ONCE(radeon_rs480_cp_me_ram_dump) != 1)
        return RS480_CP_ME_RAM_DUMP_TERMINAL_DISARMED;
    return 0;
}
""",
        "rs480_cp_me_ram_seq_is_terminal": """
static bool rs480_cp_me_ram_seq_is_terminal(loff_t position)
{
    return position == RS480_CP_ME_RAM_DUMP_TERMINAL_DISARMED ||
           position == RS480_CP_ME_RAM_DUMP_TERMINAL_PARKED ||
           position == RS480_CP_ME_RAM_DUMP_TERMINAL_SUSPENDED;
}
""",
        "rs480_cp_me_ram_seq_emit_terminal": """
static void rs480_cp_me_ram_seq_emit_terminal(struct seq_file *m,
                                               loff_t position)
{
    switch (position) {
    case RS480_CP_ME_RAM_DUMP_TERMINAL_DISARMED:
        seq_puts(m, "terminal_status\\tstatus=disarmed\\n");
        break;
    case RS480_CP_ME_RAM_DUMP_TERMINAL_PARKED:
        seq_puts(m, "terminal_status\\tstatus=gpu-parked\\n");
        break;
    case RS480_CP_ME_RAM_DUMP_TERMINAL_SUSPENDED:
        seq_puts(m, "terminal_status\\tstatus=asic-suspended\\n");
        break;
    default:
        seq_puts(m, "terminal_status\\tstatus=invalid\\n");
        break;
    }
}
""",
        "rs480_cp_me_ram_seq_start": """
static void *rs480_cp_me_ram_seq_start(struct seq_file *m, loff_t *pos)
{
    struct radeon_device *rdev = m->private;
    loff_t terminal_position;

    if (*pos == 0)
        return SEQ_START_TOKEN;
    if (rs480_cp_me_ram_seq_is_terminal(*pos))
        return pos;
    if (*pos > RS480_CP_ME_RAM_DUMP_LIMIT)
        return NULL;
    terminal_position = rs480_cp_me_ram_seq_terminal_position(rdev);
    if (terminal_position) {
        *pos = terminal_position;
        return pos;
    }
    return pos;
}
""",
        "rs480_cp_me_ram_seq_next": """
static void *rs480_cp_me_ram_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
    struct radeon_device *rdev = m->private;
    loff_t terminal_position;
    bool was_terminal = rs480_cp_me_ram_seq_is_terminal(*pos);

    ++*pos;
    if (was_terminal)
        return NULL;
    if (*pos > RS480_CP_ME_RAM_DUMP_LIMIT)
        return NULL;
    terminal_position = rs480_cp_me_ram_seq_terminal_position(rdev);
    if (terminal_position) {
        *pos = terminal_position;
        return pos;
    }
    return pos;
}
""",
        "rs480_cp_me_ram_seq_stop": """
static void rs480_cp_me_ram_seq_stop(struct seq_file *m, void *v)
{
}
""",
        "rs480_cp_me_ram_seq_show": """
static int rs480_cp_me_ram_seq_show(struct seq_file *m, void *v)
{
    struct radeon_device *rdev = m->private;
    loff_t terminal_position;
    unsigned int addr;
    u32 datah, datal;

    if (v == SEQ_START_TOKEN) {
        rs480_debugfs_emit_schema(m);
        return 0;
    }
    if (rs480_cp_me_ram_seq_is_terminal(m->index)) {
        rs480_cp_me_ram_seq_emit_terminal(m, m->index);
        return 0;
    }
    terminal_position = rs480_cp_me_ram_seq_terminal_position(rdev);
    if (terminal_position) {
        m->index = terminal_position;
        rs480_cp_me_ram_seq_emit_terminal(m, terminal_position);
        return 0;
    }
    if (rs480_debugfs_lock_hardware(m, rdev))
        return 0;
    addr = (unsigned int)m->index - 1;

    WREG32(RADEON_CP_ME_RAM_RADDR, addr);
    datah = RREG32(RADEON_CP_ME_RAM_DATAH);
    datal = RREG32(RADEON_CP_ME_RAM_DATAL);
    seq_printf(m, "%04x %08x %08x\\n", addr, datah, datal);
    radeon_device_unlock_hardware(rdev);
    return 0;
}
""",
    }
    expected_direct_calls = {
        "rs480_cp_me_ram_seq_terminal_position": (
            "READ_ONCE",
            "READ_ONCE",
            "READ_ONCE",
        ),
        "rs480_cp_me_ram_seq_is_terminal": (),
        "rs480_cp_me_ram_seq_emit_terminal": (
            "seq_puts",
            "seq_puts",
            "seq_puts",
            "seq_puts",
        ),
        "rs480_cp_me_ram_seq_start": (
            "rs480_cp_me_ram_seq_is_terminal",
            "rs480_cp_me_ram_seq_terminal_position",
        ),
        "rs480_cp_me_ram_seq_next": (
            "rs480_cp_me_ram_seq_is_terminal",
            "rs480_cp_me_ram_seq_terminal_position",
        ),
        "rs480_cp_me_ram_seq_stop": (),
        "rs480_cp_me_ram_seq_show": (
            "rs480_debugfs_emit_schema",
            "rs480_cp_me_ram_seq_is_terminal",
            "rs480_cp_me_ram_seq_emit_terminal",
            "rs480_cp_me_ram_seq_terminal_position",
            "rs480_cp_me_ram_seq_emit_terminal",
            "rs480_debugfs_lock_hardware",
            "WREG32",
            "RREG32",
            "RREG32",
            "seq_printf",
            "radeon_device_unlock_hardware",
        ),
    }
    direct_call_bodies = {
        "rs480_cp_me_ram_seq_terminal_position": terminal_position_body,
        "rs480_cp_me_ram_seq_is_terminal": terminal_test_body,
        "rs480_cp_me_ram_seq_emit_terminal": terminal_emit_body,
        "rs480_cp_me_ram_seq_start": dump_start_body,
        "rs480_cp_me_ram_seq_next": dump_next_body,
        "rs480_cp_me_ram_seq_stop": dump_stop_body,
        "rs480_cp_me_ram_seq_show": dump_show_body,
    }
    for function_name, expected_shape in expected_function_shapes.items():
        require(
            c_tokens(direct_call_bodies[function_name], function_name)
            == c_tokens(expected_shape, f"expected {function_name}"),
            f"{function_name} exact mechanism shape differs",
        )
    terminal_macro_names = {
        "RS480_CP_ME_RAM_DUMP_LIMIT",
        "RS480_CP_ME_RAM_DUMP_TERMINAL_DISARMED",
        "RS480_CP_ME_RAM_DUMP_TERMINAL_PARKED",
        "RS480_CP_ME_RAM_DUMP_TERMINAL_SUSPENDED",
    }
    mechanism_identifiers = {
        token
        for expected_shape in expected_function_shapes.values()
        for token in c_tokens(expected_shape, "expected CP-ME mechanism shape")
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token)
    }
    source_without_comments = strip_comments(source)
    for identifier in sorted(mechanism_identifiers - terminal_macro_names):
        require(
            re.search(
                rf"^[ \t]*#[ \t]*(?:define|undef)[ \t]+{re.escape(identifier)}\b",
                source_without_comments,
                re.MULTILINE,
            )
            is None,
            f"RS4xx CP-ME mechanism identifier {identifier} is redefined",
        )
    for identifier in sorted(terminal_macro_names):
        definitions = re.findall(
            rf"^[ \t]*#[ \t]*define[ \t]+{re.escape(identifier)}\b",
            source_without_comments,
            re.MULTILINE,
        )
        undefinitions = re.findall(
            rf"^[ \t]*#[ \t]*undef[ \t]+{re.escape(identifier)}\b",
            source_without_comments,
            re.MULTILINE,
        )
        require(
            len(definitions) == 1 and not undefinitions,
            f"RS4xx CP-ME terminal macro {identifier} definition differs",
        )
    critical_region_start = source.find("#define RS480_CP_ME_RAM_DUMP_LIMIT")
    critical_region_end = source.find("static const struct seq_operations ")
    require(
        0 <= critical_region_start < critical_region_end,
        "RS4xx CP-ME critical preprocessor region is absent",
    )
    critical_directives = re.findall(
        r"^[ \t]*#[ \t]*([A-Za-z_][A-Za-z0-9_]*)\b",
        strip_comments(source[critical_region_start:critical_region_end]),
        re.MULTILINE,
    )
    require(
        critical_directives == ["define", "define", "define", "define"],
        "RS4xx CP-ME critical preprocessor directive topology differs",
    )
    arm_identifier_uses = re.findall(
        r"\bradeon_rs480_cp_me_ram_dump\b",
        strip_comments_and_literals(source),
    )
    require(
        len(arm_identifier_uses) == 1,
        "RS4xx CP-ME arm state has a source-side writer or extra reader",
    )
    for function_name, expected_calls in expected_direct_calls.items():
        require(
            direct_call_names(direct_call_bodies[function_name], function_name)
            == expected_calls,
            f"{function_name} direct-call topology differs",
        )
    require(
        "rs480_debugfs_lock_hardware" in dump_show_body
        and "RADEON_DEV_OUTPUT_SCHEMA_LINE" not in dump_show_body,
        "RS4xx CP-ME dump data route can re-emit its schema",
    )
    dump_header = require_one_match(
        dump_show_body,
        r"if \(v == SEQ_START_TOKEN\)\s*\{.*?\n\t\}",
        "RS4xx CP-ME dump header record",
    )
    dump_header_schema = require_one_match(
        dump_header.group(0),
        r"\brs480_debugfs_emit_schema\(m\);",
        "RS4xx CP-ME dump header schema",
    )
    require_one_match(
        dump_header.group(0)[dump_header_schema.end() :],
        r"^\s*return 0;\s*\}$",
        "RS4xx CP-ME dump retry-stable header return",
    )
    require(
        "rs480_debugfs_lock_hardware" not in dump_header.group(0),
        "RS4xx CP-ME dump header performs a second hardware-state read",
    )
    dump_header_prefix = strip_comments_and_literals(
        dump_header.group(0)[: dump_header_schema.start()]
    )
    require(
        output_call.search(dump_header_prefix) is None
        and schema_output_route.search(dump_header_prefix) is None
        and control_exit.search(dump_header_prefix) is None,
        "RS4xx CP-ME dump header emits or exits before its schema",
    )
    require(
        ";" not in dump_header_prefix
        and RS4XX_CP_ME_HARDWARE_ACCESS.search(dump_header_prefix) is None,
        "RS4xx CP-ME dump header performs work before its schema",
    )
    dump_data_body = dump_show_body[dump_header.end() :]
    terminal_replay = require_one_match(
        dump_data_body,
        r"if \(rs480_cp_me_ram_seq_is_terminal\(m->index\)\)\s*\{\s*"
        r"rs480_cp_me_ram_seq_emit_terminal\(m, m->index\);\s*return 0;\s*\}",
        "RS4xx CP-ME dump terminal replay record",
    )
    require(
        brace_depth_at(dump_show_body, dump_header.end() + terminal_replay.start())
        == 1,
        "RS4xx CP-ME dump terminal replay record is not an unconditional outer function statement",
    )
    dump_data_gate = require_one_match(
        dump_data_body,
        r"terminal_position = rs480_cp_me_ram_seq_terminal_position\(rdev\);\s*"
        r"if \(terminal_position\)\s*\{\s*"
        r"m->index = terminal_position;\s*"
        r"rs480_cp_me_ram_seq_emit_terminal\(m, terminal_position\);\s*"
        r"return 0;\s*\}",
        "RS4xx CP-ME dump data terminal record",
    )
    require(
        brace_depth_at(dump_show_body, dump_header.end() + dump_data_gate.start()) == 1,
        "RS4xx CP-ME dump data terminal record is not an unconditional outer function statement",
    )
    dump_address = require_one_match(
        dump_data_body,
        r"addr = \(unsigned int\)m->index - 1;",
        "RS4xx CP-ME dump address bound",
    )
    dump_mmio = require_one_match(
        dump_data_body,
        r"WREG32\(RADEON_CP_ME_RAM_RADDR, addr\);\s*"
        r"datah = RREG32\(RADEON_CP_ME_RAM_DATAH\);\s*"
        r"datal = RREG32\(RADEON_CP_ME_RAM_DATAL\);",
        "RS4xx CP-ME dump MMIO sequence",
    )
    dump_hardware_calls = list(RS4XX_CP_ME_HARDWARE_ACCESS.finditer(dump_show_body))
    require(
        dump_data_body.count("rs480_cp_me_ram_seq_emit_terminal(m,") == 2
        and dump_data_gate.end() < dump_address.start()
        and dump_data_gate.end() < dump_mmio.start()
        and len(dump_hardware_calls) == 3
        and all(
            call.start() >= dump_header.end() + dump_mmio.start()
            for call in dump_hardware_calls
        )
        and schema_emitter_call.search(dump_data_body) is None
        and "RADEON_DEV_OUTPUT_SCHEMA_LINE" not in dump_data_body,
        "RS4xx CP-ME dump data terminal topology differs",
    )
    dump_data_prefix = strip_comments_and_literals(
        dump_data_body[: terminal_replay.start()]
    )
    dump_data_between_routes = strip_comments_and_literals(
        dump_data_body[terminal_replay.end() : dump_data_gate.start()]
    )
    require(
        output_call.search(dump_data_prefix) is None
        and schema_output_route.search(dump_data_prefix) is None
        and control_exit.search(dump_data_prefix) is None,
        "RS4xx CP-ME dump data emits or exits before its terminal replay route",
    )
    require(
        output_call.search(dump_data_between_routes) is None
        and schema_output_route.search(dump_data_between_routes) is None
        and RS4XX_CP_ME_HARDWARE_ACCESS.search(dump_data_between_routes) is None
        and control_exit.search(dump_data_between_routes) is None,
        "RS4xx CP-ME dump data reaches hardware, emits, or exits between terminal routes",
    )
    require(
        dump_data_gate.start() < dump_address.start() < dump_mmio.start(),
        "RS4xx CP-ME dump checks state after computing or issuing MMIO",
    )

    require_one_match(
        source_without_comments,
        r"static const struct seq_operations rs480_cp_me_ram_seq_ops = \{\s*"
        r"\.start\s*=\s*rs480_cp_me_ram_seq_start,\s*"
        r"\.next\s*=\s*rs480_cp_me_ram_seq_next,\s*"
        r"\.stop\s*=\s*rs480_cp_me_ram_seq_stop,\s*"
        r"\.show\s*=\s*rs480_cp_me_ram_seq_show,\s*\};",
        "RS4xx CP-ME dump sequence operation bindings",
    )
    require_one_match(
        source_without_comments,
        r"static int rs480_cp_me_ram_dump_open\(struct inode \*inode, "
        r"struct file \*file\)\s*\{\s*"
        r"int ret = seq_open\(file, &rs480_cp_me_ram_seq_ops\);\s*"
        r"if \(!ret\)\s*"
        r"\(\(struct seq_file \*\)file->private_data\)->private = "
        r"inode->i_private;\s*return ret;\s*\}",
        "RS4xx CP-ME dump open binding",
    )
    require_one_match(
        source_without_comments,
        r"static const struct file_operations rs480_cp_me_ram_dump_fops = \{\s*"
        r"\.owner\s*=\s*THIS_MODULE,\s*"
        r"\.open\s*=\s*rs480_cp_me_ram_dump_open,\s*"
        r"\.read\s*=\s*seq_read,\s*"
        r"\.llseek\s*=\s*seq_lseek,\s*"
        r"\.release\s*=\s*seq_release,\s*\};",
        "RS4xx CP-ME dump fops binding",
    )
    require_one_match(
        source_without_comments,
        r"static int rs480_cp_me_ram_inject_open\(struct inode \*inode, "
        r"struct file \*file\)\s*\{\s*"
        r"int r = single_open\(file, rs480_cp_me_ram_inject_show, "
        r"inode->i_private\);\s*"
        r"return r \? r : nonseekable_open\(inode, file\);\s*\}",
        "RS4xx CP-ME injection show binding",
    )
    require_one_match(
        source_without_comments,
        r"static const struct file_operations rs480_cp_me_ram_inject_fops = \{\s*"
        r"\.owner\s*=\s*THIS_MODULE,\s*"
        r"\.open\s*=\s*rs480_cp_me_ram_inject_open,\s*"
        r"\.read\s*=\s*seq_read,\s*"
        r"\.write\s*=\s*rs480_cp_me_ram_inject_write,\s*"
        r"\.release\s*=\s*single_release,\s*\};",
        "RS4xx CP-ME injection fops binding",
    )


def validate_runtime_sources(texts: dict[str, str]) -> None:
    for path, patterns in RUNTIME_SOURCE_PATTERNS.items():
        require(path in texts, f"runtime gate source is absent: {path}")
        for pattern in patterns:
            require(
                re.search(pattern, texts[path], re.DOTALL) is not None,
                f"runtime gate is absent from {path}: {pattern}",
            )


def validate_rs4xx_hardware_transaction_paths(texts: dict[str, str]) -> None:
    """Prove the centralized RS4xx admission root and debugfs lock ordering."""
    header_path = "drivers/gpu/drm/radeon/radeon.h"
    device_path = "drivers/gpu/drm/radeon/radeon_device.c"
    debugfs_path = "drivers/gpu/drm/radeon/radeon_rs4xx_dev.c"
    for path in (header_path, device_path, debugfs_path):
        require(path in texts, f"RS4xx transaction source is absent: {path}")

    lock_body = function_body(texts[header_path], "radeon_device_lock_hardware")
    require_one_match(
        lock_body,
        r"r\s*=\s*radeon_rs4xx_hardware_transaction_begin\(rdev\);\s*"
        r"if \(r\)\s*return r;\s*"
        r"if \(radeon_rs4xx_hardware_transition_owned\(rdev\)\)\s*"
        r"return 0;\s*down_read\(&rdev->exclusive_lock\);",
        "RS4xx device-lock transaction root",
    )
    require_one_match(
        lock_body,
        r"if \(radeon_rs4xx_hardware_target\(rdev\)\)\s*"
        r"r\s*=\s*0;\s*else\s*"
        r"r\s*=\s*radeon_dev_hardware_available\(rdev\);",
        "RS4xx device-lock availability split",
    )
    require_one_match(
        lock_body,
        r"if \(r\)\s*up_read\(&rdev->exclusive_lock\);\s*"
        r"if \(r\)\s*radeon_rs4xx_hardware_transaction_end\(rdev\);",
        "RS4xx device-lock failure release",
    )

    unlock_body = function_body(texts[header_path], "radeon_device_unlock_hardware")
    require_one_match(
        unlock_body,
        r"if \(!radeon_rs4xx_hardware_transition_owned\(rdev\)\)\s*"
        r"up_read\(&rdev->exclusive_lock\);\s*"
        r"radeon_rs4xx_hardware_transaction_end\(rdev\);",
        "RS4xx device-unlock transaction release",
    )

    trylock_body = function_body(texts[header_path], "radeon_device_trylock_hardware")
    require_one_match(
        trylock_body,
        r"r\s*=\s*radeon_rs4xx_hardware_transaction_try_begin\(rdev\);\s*"
        r"if \(r\)\s*return r;\s*"
        r"if \(radeon_rs4xx_hardware_transition_owned\(rdev\)\)\s*"
        r"return 0;",
        "RS4xx device-trylock transaction root",
    )

    transaction_body = function_body(
        texts[device_path], "radeon_rs4xx_hardware_transaction_begin"
    )
    require_one_match(
        transaction_body,
        r"if \(!radeon_rs4xx_hardware_target\(rdev\)\)\s*return 0;\s*"
        r"if \(READ_ONCE\(rdev->gpu_parked\)\)\s*return -EIO;\s*"
        r"state\s*=\s*atomic_read_acquire\(&rdev->rs4xx_hardware_state\);",
        "RS4xx transaction admission state gate",
    )
    require_one_match(
        transaction_body,
        r"atomic_inc\(&rdev->rs4xx_hardware_transactions\);\s*"
        r"smp_mb__after_atomic\(\);\s*"
        r"state\s*=\s*atomic_read\(&rdev->rs4xx_hardware_state\);.*?"
        r"state == RADEON_RS4XX_HARDWARE_RUNNING\s*&&\s*"
        r"!READ_ONCE\(rdev->gpu_parked\)\s*&&.*?return 0;",
        "RS4xx transaction admission revalidation",
    )
    require_one_match(
        transaction_body,
        r"if \(atomic_dec_and_test\(&rdev->rs4xx_hardware_transactions\)\)\s*"
        r"\{\s*"
        r"wake_up_all\(&rdev->rs4xx_hardware_wait\);\s*"
        r"radeon_rs4xx_queue_parked_publish\(rdev\);\s*"
        r"\}\s*"
        r"if \(state == RADEON_RS4XX_HARDWARE_RUNNING\)\s*"
        r"return -EBUSY;",
        "RS4xx transaction admission rollback",
    )

    debugfs_lock_body = function_body(
        texts[debugfs_path], "rs480_debugfs_lock_hardware"
    )
    schema = require_one_match(
        debugfs_lock_body,
        r"rs480_debugfs_emit_schema\(m\);",
        "RS4xx debugfs lock schema route",
    )
    root = require_one_match(
        debugfs_lock_body,
        r"r\s*=\s*radeon_device_lock_hardware\(rdev\);",
        "RS4xx debugfs lock transaction root",
    )
    require(schema.start() < root.start(), "RS4xx debugfs lock schema order differs")
    require_one_match(
        debugfs_lock_body,
        r"if \(!r\)\s*return 0;",
        "RS4xx debugfs lock success route",
    )
    require_one_match(
        debugfs_lock_body,
        r"if \(r == -EIO\)",
        "RS4xx debugfs lock parked-state route",
    )

    debugfs_source = texts[debugfs_path]
    debugfs_code = strip_comments_and_literals(debugfs_source)
    require_no_local_macro_overrides(
        debugfs_source,
        tuple(RS4XX_HARDWARE_TRANSACTION_GLOBAL_CALLS),
        "RS4xx debugfs hardware transaction calls",
    )
    for call_name, expected_count in RS4XX_HARDWARE_TRANSACTION_GLOBAL_CALLS.items():
        observed_count = len(
            re.findall(rf"\b{re.escape(call_name)}\s*\(", debugfs_code)
        )
        require(
            observed_count == expected_count,
            f"RS4xx debugfs {call_name} denominator is {observed_count}, "
            f"expected {expected_count}",
        )

    call_names = tuple(RS4XX_HARDWARE_TRANSACTION_GLOBAL_CALLS)
    for (
        function_name,
        expected_counts,
    ) in RS4XX_HARDWARE_TRANSACTION_CALL_DENOMINATOR.items():
        body = function_body(debugfs_source, function_name)
        body_code = strip_comments_and_literals(body)
        opening_brace = body_code.find("{")
        require(opening_brace >= 0, f"function {function_name} has no body")
        inner_body = body_code[opening_brace + 1 :]
        observed_counts = tuple(
            len(re.findall(rf"\b{re.escape(call_name)}\s*\(", inner_body))
            for call_name in call_names
        )
        require(
            observed_counts == expected_counts,
            f"{function_name} hardware transaction calls are {observed_counts}, "
            f"expected {expected_counts}",
        )
        unlock_matches = list(
            re.finditer(r"\bradeon_device_unlock_hardware\s*\(", inner_body)
        )
        if not unlock_matches:
            continue
        lock_matches = [
            *re.finditer(r"\brs480_debugfs_lock_hardware\s*\(", inner_body),
            *re.finditer(r"\bradeon_device_lock_hardware\s*\(", inner_body),
        ]
        require(bool(lock_matches), f"{function_name} unlocks without admission")
        first_lock = min(match.start() for match in lock_matches)
        last_unlock = max(match.start() for match in unlock_matches)
        require(
            first_lock < last_unlock,
            f"{function_name} releases hardware admission before acquiring it",
        )
        hardware_matches = list(RS4XX_CP_ME_HARDWARE_ACCESS.finditer(inner_body))
        if hardware_matches:
            require(
                first_lock < min(match.start() for match in hardware_matches)
                and max(match.start() for match in hardware_matches) < last_unlock,
                f"{function_name} hardware access escapes its transaction",
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
        require_unconditional=True,
        protect_identifiers=True,
    )
    rs4xx_registration = require_one_match(
        dispatcher_body,
        r"radeon_rs480_re_debugfs_register\(minor\);",
        "RS4xx development debugfs dispatcher",
    )
    palm_registration = require_one_match(
        dispatcher_body,
        r"radeon_evergreen_dev_debugfs_register\(minor\);",
        "Palm development debugfs dispatcher",
    )
    require(
        conditional_stack_at(
            dispatcher_body,
            rs4xx_registration.start(),
            "RS4xx development debugfs dispatcher",
        )
        == [("if", "RADEON_OBSERVE_DEV", "initial")],
        "RS4xx development debugfs callback branch differs",
    )
    require(
        conditional_stack_at(
            dispatcher_body,
            palm_registration.start(),
            "Palm development debugfs dispatcher",
        )
        == [("if", "RADEON_OBSERVE_DEV", "initial")],
        "Palm development debugfs callback branch differs",
    )
    kms_driver_body = initializer_body(driver_source, "kms_driver")
    kms_debugfs_match = require_one_match(
        kms_driver_body,
        r"\.debugfs_init = radeon_dev_debugfs_register",
        "DRM debugfs callback",
    )
    require(
        conditional_stack_at(
            kms_driver_body,
            kms_debugfs_match.start(),
            "DRM debugfs callback",
        )
        == [],
        "DRM debugfs callback branch differs",
    )
    require_no_local_macro_overrides(
        driver_source,
        (
            "RADEON_OBSERVE_DEV",
            "radeon_dev_debugfs_register",
            "radeon_evergreen_dev_debugfs_register",
            "radeon_rs480_re_debugfs_register",
        ),
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
    serialized = "".join(f"{path}\t{marker}\n" for path, marker in identities).encode(
        "ascii"
    )
    require(
        hashlib.sha256(serialized).hexdigest() == RETIRED_RESET_PROBE_MARKER_SHA256,
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
    mutation_marker = 'radeon_dev_mark_mutation(rdev, "RS4xx reset hang probe");'
    hardware_lock = "hardware_result = radeon_device_lock_hardware(rdev);"
    pre_status = "pre_reset_status = RREG32(R_000E40_RBBM_STATUS);"
    pre_signature = (
        "if (require_backend_idle ? !rs480_frontend_wedged(pre_reset_status)"
    )
    pre_unlock = "radeon_device_unlock_hardware(rdev);"
    parked_sentinel = "post_reset_status = 0x5041524B;"
    unavailable_sentinel = "post_reset_status = 0x554E4156;"
    status_read = "post_reset_status = RREG32(R_000E40_RBBM_STATUS);"
    for marker in (
        reset_call,
        mutation_marker,
        pre_status,
        pre_signature,
        parked_sentinel,
        unavailable_sentinel,
        status_read,
    ):
        require(
            wedged_body.count(marker) == 1,
            f"wedged reset-probe carries an invalid marker count: {marker}",
        )

    lock_positions = [
        match.start() for match in re.finditer(re.escape(hardware_lock), wedged_body)
    ]
    unlock_positions = [
        match.start() for match in re.finditer(re.escape(pre_unlock), wedged_body)
    ]
    require(
        len(lock_positions) == 2 and len(unlock_positions) == 3,
        "wedged reset-probe transaction lock denominator differs",
    )
    first_lock_at, second_lock_at = lock_positions
    first_unlock_at, second_unlock_at, third_unlock_at = unlock_positions
    pre_status_at = wedged_body.find(pre_status)
    pre_signature_at = wedged_body.find(pre_signature)
    mutation_marker_at = wedged_body.find(mutation_marker)
    reset_call_at = wedged_body.find(reset_call)
    parked_sentinel_at = wedged_body.find(parked_sentinel)
    unavailable_sentinel_at = wedged_body.find(unavailable_sentinel)
    status_read_at = wedged_body.find(status_read)
    require(
        first_lock_at
        < pre_status_at
        < pre_signature_at
        < first_unlock_at
        < mutation_marker_at
        < reset_call_at
        < second_lock_at
        < parked_sentinel_at
        < unavailable_sentinel_at
        < status_read_at
        < third_unlock_at,
        "wedged reset-probe transaction order differs",
    )
    require(
        brace_depth_at(wedged_body, first_lock_at) == 1
        and brace_depth_at(wedged_body, second_lock_at) == 1
        and brace_depth_at(wedged_body, reset_call_at) == 1
        and brace_depth_at(wedged_body, parked_sentinel_at) == 2
        and brace_depth_at(wedged_body, unavailable_sentinel_at) == 2
        and brace_depth_at(wedged_body, status_read_at) == 2,
        "wedged reset-probe transaction markers are not at their expected depth",
    )
    require(
        "RREG" not in wedged_body[:first_lock_at]
        and "radeon_gpu_reset_forced" not in wedged_body[:first_lock_at],
        "wedged reset-probe reaches hardware before its transaction root",
    )
    require(
        not strip_comments_and_literals(
            wedged_body[reset_call_at + len(reset_call) : second_lock_at]
        ).strip(),
        "wedged reset-probe executes code before post-reset transaction admission",
    )
    require(
        not strip_comments_and_literals(
            wedged_body[mutation_marker_at + len(mutation_marker) : reset_call_at]
        ).strip(),
        "wedged reset-probe mutates outside its reset call boundary",
    )
    first_failure = require_one_match(
        wedged_body,
        r"(?m)^\tif \(hardware_result\)\s*\{.*?return 0;\s*\}",
        "wedged reset-probe pre-reset lock refusal",
    )
    require_outer_function_match(
        wedged_body,
        first_failure,
        "wedged reset-probe pre-reset lock refusal",
    )
    post_parked = require_one_match(
        wedged_body,
        r"if \(hardware_result == -EIO\)\s*\{.*?"
        r"post_reset_status = 0x5041524B;\s*\}",
        "wedged reset-probe parked post-state",
    )
    post_unavailable = require_one_match(
        wedged_body,
        r"\} else if \(hardware_result\)\s*\{.*?"
        r"post_reset_status = 0x554E4156;\s*\}",
        "wedged reset-probe unavailable post-state",
    )
    post_success = require_one_match(
        wedged_body,
        r"\} else \{\s*"
        r"post_reset_status = RREG32\(R_000E40_RBBM_STATUS\);\s*"
        r"radeon_device_unlock_hardware\(rdev\);\s*\}",
        "wedged reset-probe successful post-state",
    )
    require_outer_function_match(
        wedged_body, post_parked, "wedged reset-probe parked post-state"
    )
    require_outer_function_match(
        wedged_body,
        post_unavailable,
        "wedged reset-probe unavailable post-state",
        expected_depth=2,
    )
    require_outer_function_match(
        wedged_body,
        post_success,
        "wedged reset-probe successful post-state",
        expected_depth=2,
    )
    require(
        "RREG" not in post_parked.group(0)
        and "RREG" not in post_unavailable.group(0)
        and post_success.group(0).count("RREG") == 1,
        "wedged reset-probe post-state branches reach the wrong hardware path",
    )
    require_control_flow_census(
        wedged_body,
        (6, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3),
        (("return 0;", 2), ("return 0;", 2), ("return 0;", 1)),
        "wedged reset-probe function",
    )
    require_no_opaque_control(wedged_body, "wedged reset-probe function")


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
        r"rs4xx_reset\s*=\s*radeon_rs4xx_hardware_target\(rdev\);\s*"
        r"if \(rs4xx_reset\)\s*\{\s*"
        r"r\s*=\s*radeon_rs4xx_hardware_transition_begin\(\s*"
        r"rdev,\s*RADEON_RS4XX_HARDWARE_RUNNING,\s*"
        r"RADEON_RS4XX_HARDWARE_RESETTING\);\s*"
        r"if \(r\)\s*return r;\s*\}\s*"
        r"down_write\(&rdev->exclusive_lock\);\s*"
        r"if \(READ_ONCE\(rdev->gpu_parked\)\) \{\s*"
        r"WRITE_ONCE\(rdev->needs_reset, false\);\s*"
        r"up_write\(&rdev->exclusive_lock\);\s*"
        r"dev_err_once\(rdev->dev,\s*"
        r'"RS4xx reset re-entry refused after terminal park\\n"\);\s*'
        r"if \(rs4xx_reset\)\s*"
        r"radeon_rs4xx_hardware_transition_end\(\s*rdev,\s*"
        r"RADEON_RS4XX_HARDWARE_PARKED\);\s*return -EIO;\s*\}\s*"
        r"if \(!force_reset && !READ_ONCE\(rdev->needs_reset\)\) \{\s*"
        r"if \(READ_ONCE\(rdev->gpu_parked\)\) \{\s*"
        r"WRITE_ONCE\(rdev->needs_reset, false\);\s*"
        r"up_write\(&rdev->exclusive_lock\);\s*"
        r"if \(rs4xx_reset\)\s*"
        r"radeon_rs4xx_hardware_transition_end\(\s*rdev,\s*"
        r"RADEON_RS4XX_HARDWARE_PARKED\);\s*return -EIO;\s*\}\s*"
        r"up_write\(&rdev->exclusive_lock\);\s*"
        r"if \(rs4xx_reset\)\s*"
        r"radeon_rs4xx_hardware_transition_end\(\s*rdev,\s*"
        r"RADEON_RS4XX_HARDWARE_RUNNING\);\s*return 0;\s*\}\s*"
        r"if \(force_reset\)\s*"
        r"WRITE_ONCE\(rdev->needs_reset, true\);\s*"
        r".*?atomic_inc\(&rdev->gpu_reset_counter\)"
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
    require(
        reset_function_body.find("radeon_rs4xx_hardware_transition_begin(")
        < reset_function_body.find("down_write(&rdev->exclusive_lock);")
        < reset_function_body.find("if (READ_ONCE(rdev->gpu_parked))")
        < reset_function_body.find("if (!force_reset && !READ_ONCE(rdev->needs_reset))")
        < reset_function_body.find("WRITE_ONCE(rdev->needs_reset, true);")
        < reset_counter_at,
        "forced GPU-reset transaction prefix differs",
    )
    require_control_flow_census(
        reset_function_body,
        (57, 6, 2, 0, 0, 0, 0, 0, 0, 0, 5, 12),
        (
            ("return r;", 2),
            ("return -EIO;", 2),
            ("return -EIO;", 3),
            ("return 0;", 2),
            ("return -EIO;", 3),
            ("return -EIO;", 2),
            ("return r;", 2),
            ("return -EIO;", 2),
            ("return -EIO;", 2),
            ("return -EIO;", 3),
            ("return r;", 1),
            ("return r;", 1),
        ),
        "forced GPU-reset implementation",
        (
            "rs4xx_reset_release_ring_copies:",
            "rs4xx_reset_parked_after_downgrade:",
        ),
    )
    require_no_opaque_control(
        reset_function_body,
        "forced GPU-reset implementation",
    )
    require(
        brace_depth_at(reset_function_body, reset_counter_at) == 1,
        "forced GPU-reset counter transition is not an outer function statement",
    )
    reset_body = reset_function_body[reset_counter_at + len(reset_counter) :]
    terminal_writer_exit_pattern = re.compile(
        r"if \(rs4xx_reset && READ_ONCE\(rdev->gpu_parked\)\) \{\s*"
        r"radeon_rs4xx_publish_parked_state\(rdev\);\s*"
        r"WRITE_ONCE\(rdev->in_reset, false\);\s*"
        r"up_write\(&rdev->exclusive_lock\);\s*"
        r"radeon_rs4xx_hardware_transition_end\(\s*rdev,\s*"
        r"RADEON_RS4XX_HARDWARE_PARKED\);\s*"
        r"return -EIO;\s*\}"
    )
    terminal_writer_exits = list(
        terminal_writer_exit_pattern.finditer(reset_function_body)
    )
    require(
        len(terminal_writer_exits) == 3,
        "forced GPU-reset terminal writer-exit denominator differs",
    )
    for exit_index, terminal_writer_exit in enumerate(terminal_writer_exits):
        require_outer_function_match(
            reset_function_body,
            terminal_writer_exit,
            f"forced GPU-reset terminal writer exit {exit_index}",
        )
    require(
        reset_body.count("up_write(&rdev->exclusive_lock);")
        == len(terminal_writer_exits),
        "forced GPU-reset writer lock has an unclassified post-counter exit",
    )
    require(
        reset_body.count("downgrade_write(&rdev->exclusive_lock);") == 2,
        "forced GPU-reset writer-to-reader downgrade paths differ",
    )
    require(
        reset_body.count("up_read(&rdev->exclusive_lock);") == 3,
        "forced GPU-reset read-lock release paths differ",
    )
    parked_exit = require_one_match(
        reset_function_body,
        r"if \(gpu_parked\)\s*\{\s*"
        r"radeon_rs4xx_publish_parked_state\(rdev\);\s*"
        r"downgrade_write\(&rdev->exclusive_lock\);\s*"
        r"WRITE_ONCE\(rdev->in_reset, false\);\s*"
        r"up_read\(&rdev->exclusive_lock\);\s*"
        r"radeon_rs4xx_hardware_transition_end\(\s*rdev,\s*"
        r"RADEON_RS4XX_HARDWARE_PARKED\);.*?return r;",
        "forced GPU-reset parked exit",
    )
    require_outer_function_match(
        reset_function_body,
        parked_exit,
        "forced GPU-reset parked exit",
        expected_depth=1,
    )
    ordinary_exit = require_one_match(
        reset_function_body,
        r"radeon_hpd_init\(rdev\);.*?"
        r"downgrade_write\(&rdev->exclusive_lock\);.*?"
        r"drm_helper_resume_force_mode\(rdev_to_drm\(rdev\)\);.*?"
        r"WRITE_ONCE\(rdev->in_reset, false\);\s*"
        r"up_read\(&rdev->exclusive_lock\);\s*"
        r"if \(rs4xx_reset\)\s*\{\s*"
        r"radeon_rs4xx_hardware_transition_end\(\s*rdev,\s*"
        r"RADEON_RS4XX_HARDWARE_RUNNING\);\s*"
        r"if \(READ_ONCE\(rdev->gpu_parked\)\) \{\s*"
        r"radeon_rs4xx_publish_parked_state\(rdev\);\s*"
        r"return -EIO;\s*\}\s*"
        r"drm_kms_helper_poll_enable\(rdev_to_drm\(rdev\)\);\s*\}\s*return r;",
        "forced GPU-reset ordinary exit",
    )
    require_outer_function_match(
        reset_function_body,
        ordinary_exit,
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
        validate_rs4xx_output_schema_paths(
            rows,
            source_texts["drivers/gpu/drm/radeon/radeon_rs4xx_dev.c"],
        )
        validate_rs4xx_hardware_transaction_paths(source_texts)
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
        "probe-dev": (11, 9, 25),
        "mutate-dev": (20, 18, 33),
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
        ("probe-dev", "probe-dev"): (11, 9, 25),
        ("mutate-dev", "off"): (0, 0, 0),
        ("mutate-dev", "observe-dev"): (4, 2, 18),
        ("mutate-dev", "probe-dev"): (11, 9, 25),
        ("mutate-dev", "mutate-dev"): (20, 18, 33),
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
    rs4xx_source_path = "drivers/gpu/drm/radeon/radeon_rs4xx_dev.c"
    validate_rs4xx_output_schema_paths(rows, source_texts[rs4xx_source_path])
    validate_rs4xx_hardware_transaction_paths(source_texts)
    rs4xx_source = source_texts[rs4xx_source_path]
    transaction_rejection_count = 0

    def reject_transaction_mutant(label: str, candidate_texts: dict[str, str]) -> None:
        nonlocal transaction_rejection_count
        try:
            validate_rs4xx_hardware_transaction_paths(candidate_texts)
        except InterfaceError:
            transaction_rejection_count += 1
            return
        raise InterfaceError(f"self-test accepted {label}")

    header_path = "drivers/gpu/drm/radeon/radeon.h"
    wrong_transaction_root = copy.deepcopy(source_texts)
    wrong_transaction_root[header_path] = wrong_transaction_root[header_path].replace(
        "r = radeon_rs4xx_hardware_transaction_begin(rdev);",
        "r = radeon_rs4xx_hardware_transaction_try_begin(rdev);",
        1,
    )
    require(
        wrong_transaction_root[header_path] != source_texts[header_path],
        "self-test transaction-root fixture differs from the source",
    )
    reject_transaction_mutant(
        "a debugfs transaction root that uses try-begin",
        wrong_transaction_root,
    )

    missing_transaction_release = copy.deepcopy(source_texts)
    missing_transaction_release[header_path] = missing_transaction_release[
        header_path
    ].replace(
        "\tradeon_rs4xx_hardware_transaction_end(rdev);\n}\n\nstatic inline int "
        "radeon_device_trylock_hardware",
        "}\n\nstatic inline int radeon_device_trylock_hardware",
        1,
    )
    require(
        missing_transaction_release[header_path] != source_texts[header_path],
        "self-test transaction-release fixture differs from the source",
    )
    reject_transaction_mutant(
        "a device unlock without transaction release",
        missing_transaction_release,
    )

    missing_debugfs_root = copy.deepcopy(source_texts)
    missing_debugfs_root[rs4xx_source_path] = missing_debugfs_root[
        rs4xx_source_path
    ].replace(
        "\tr = radeon_device_lock_hardware(rdev);",
        "\tr = 0;",
        1,
    )
    require(
        missing_debugfs_root[rs4xx_source_path] != source_texts[rs4xx_source_path],
        "self-test debugfs transaction-root fixture differs from the source",
    )
    reject_transaction_mutant(
        "a debugfs lock without the centralized transaction root",
        missing_debugfs_root,
    )

    missing_safe_register_unlock = copy.deepcopy(source_texts)
    missing_safe_register_unlock[rs4xx_source_path] = missing_safe_register_unlock[
        rs4xx_source_path
    ].replace(
        "\t}\n\tradeon_device_unlock_hardware(rdev);\n\treturn 0;\n}"
        "\n\nDEFINE_SHOW_ATTRIBUTE(rs480_safe_regs);",
        "\t}\n\treturn 0;\n}\n\nDEFINE_SHOW_ATTRIBUTE(rs480_safe_regs);",
        1,
    )
    require(
        missing_safe_register_unlock[rs4xx_source_path]
        != source_texts[rs4xx_source_path],
        "self-test safe-register unlock fixture differs from the source",
    )
    reject_transaction_mutant(
        "a safe-register reader without successful transaction release",
        missing_safe_register_unlock,
    )

    missing_post_increment_parked_check = copy.deepcopy(source_texts)
    device_path = "drivers/gpu/drm/radeon/radeon_device.c"
    missing_post_increment_parked_check[device_path] = (
        missing_post_increment_parked_check[device_path].replace(
            "\t    (state == RADEON_RS4XX_HARDWARE_RUNNING &&\n"
            "\t     !READ_ONCE(rdev->gpu_parked) &&\n"
            "\t     !atomic_read(&rdev->rs4xx_hardware_closing)))",
            "\t    (state == RADEON_RS4XX_HARDWARE_RUNNING &&\n"
            "\t     !atomic_read(&rdev->rs4xx_hardware_closing)))",
            1,
        )
    )
    require(
        missing_post_increment_parked_check[device_path] != source_texts[device_path],
        "self-test post-increment parked fixture differs from the source",
    )
    reject_transaction_mutant(
        "transaction admission without post-increment parked revalidation",
        missing_post_increment_parked_check,
    )

    missing_rollback_publisher = copy.deepcopy(source_texts)
    missing_rollback_publisher[device_path] = missing_rollback_publisher[
        device_path
    ].replace(
        "\t\twake_up_all(&rdev->rs4xx_hardware_wait);\n"
        "\t\tradeon_rs4xx_queue_parked_publish(rdev);\n"
        "\t}\n"
        "\tif (state == RADEON_RS4XX_HARDWARE_RUNNING)\n",
        "\t\twake_up_all(&rdev->rs4xx_hardware_wait);\n"
        "\t}\n"
        "\tif (state == RADEON_RS4XX_HARDWARE_RUNNING)\n",
        1,
    )
    require(
        missing_rollback_publisher[device_path] != source_texts[device_path],
        "self-test rollback-publisher fixture differs from the source",
    )
    reject_transaction_mutant(
        "transaction rollback without pending parked publication",
        missing_rollback_publisher,
    )

    missing_debugfs_route = copy.deepcopy(source_texts)
    missing_debugfs_route[rs4xx_source_path] = missing_debugfs_route[
        rs4xx_source_path
    ].replace(
        "\tif (rs480_debugfs_lock_hardware(m, rdev))\n\t\treturn 0;\n",
        "",
        1,
    )
    require(
        missing_debugfs_route[rs4xx_source_path] != source_texts[rs4xx_source_path],
        "self-test debugfs route fixture differs from the source",
    )
    try:
        validate_rs4xx_output_schema_paths(
            rows, missing_debugfs_route[rs4xx_source_path]
        )
    except InterfaceError:
        transaction_rejection_count += 1
    else:
        raise InterfaceError(
            "self-test accepted a readable RS4xx node without transaction admission"
        )
    schema_rejection_count = 0

    def reject_schema_mutant(
        label: str,
        candidate: str,
        expected_show_functions: frozenset[str] = RS4XX_OUTPUT_SCHEMA_SHOW_FUNCTIONS,
    ) -> None:
        nonlocal schema_rejection_count
        try:
            validate_rs4xx_output_schema_paths(
                rows,
                candidate,
                expected_show_functions,
            )
        except InterfaceError:
            schema_rejection_count += 1
            return
        raise InterfaceError(f"self-test accepted {label}")

    missing_common_schema = rs4xx_source.replace(
        "\t\tseq_puts(m, RADEON_DEV_OUTPUT_SCHEMA_LINE);",
        "\t\tremoved_schema_line;",
        1,
    )
    require(
        missing_common_schema != rs4xx_source,
        "self-test common schema fixture differs from the source",
    )
    reject_schema_mutant("a missing common schema line", missing_common_schema)

    early_disarmed_functions = (
        "rs480_candidate_vap_regs_show",
        "rs480_candidate_firmware_read_regs_show",
        "rs480_candidate_vip_straggler_regs_show",
    )
    for function_name in early_disarmed_functions:
        missing_early_schema, replacement_count = re.subn(
            rf"(static int {re.escape(function_name)}\(.*?\n\{{\n)"
            r"\trs480_debugfs_emit_schema\(m\);\n",
            r"\1",
            rs4xx_source,
            count=1,
            flags=re.DOTALL,
        )
        require(
            replacement_count == 1,
            f"self-test early schema fixture differs for {function_name}",
        )
        reject_schema_mutant(
            f"an early schema bypass in {function_name}",
            missing_early_schema,
        )

    early_emitter_return = rs4xx_source.replace(
        "static void rs480_debugfs_emit_schema(struct seq_file *m)\n"
        "{\n"
        "\tif (m->count == 0)",
        "static void rs480_debugfs_emit_schema(struct seq_file *m)\n"
        "{\n"
        "\tif (m->count != 0)\n"
        "\t\treturn;\n"
        "\tif (m->count == 0)",
        1,
    )
    require(
        early_emitter_return != rs4xx_source,
        "self-test schema-emitter return fixture differs from the source",
    )
    reject_schema_mutant("an early schema-emitter return", early_emitter_return)

    hardware_lock_output, replacement_count = re.subn(
        r"(static int rs480_debugfs_lock_hardware\(.*?\n\{\n)"
        r"(\trs480_debugfs_emit_schema\(m\);)",
        r'\1\tseq_puts(m, "bad\\n");\n\2',
        rs4xx_source,
        count=1,
        flags=re.DOTALL,
    )
    require(
        replacement_count == 1,
        "self-test hardware-lock output fixture differs from the source",
    )
    reject_schema_mutant(
        "hardware-lock output before its schema route",
        hardware_lock_output,
    )

    alternate_seq_output = rs4xx_source.replace(
        "static int rs480_safe_regs_show(struct seq_file *m, void *unused)\n{\n",
        "static int rs480_safe_regs_show(struct seq_file *m, void *unused)\n"
        "{\n"
        '\tseq_put_decimal_ull(m, "", 7);\n',
        1,
    )
    require(
        alternate_seq_output != rs4xx_source,
        "self-test alternate seq output fixture differs from the source",
    )
    reject_schema_mutant("output through an alternate seq API", alternate_seq_output)

    candidate_helper_output, replacement_count = re.subn(
        r"(static int rs480_candidate_regs_emit\(.*?\n\{\n)"
        r"(\tif \(rs480_debugfs_lock_hardware\(m, rdev\)\))",
        r'\1\tseq_puts(m, "bad\\n");\n\2',
        rs4xx_source,
        count=1,
        flags=re.DOTALL,
    )
    require(
        replacement_count == 1,
        "self-test candidate-helper output fixture differs from the source",
    )
    reject_schema_mutant(
        "candidate-helper output before its schema route",
        candidate_helper_output,
    )

    write_only_fops = rs4xx_source.replace(
        'debugfs_create_file("radeon_rs480_safe_regs", 0400, root, rdev,\n'
        "\t\t\t    &rs480_safe_regs_fops);",
        'debugfs_create_file("radeon_rs480_safe_regs", 0400, root, rdev,\n'
        "\t\t\t    &rs480_mc_flush_fops);",
        1,
    )
    require(
        write_only_fops != rs4xx_source,
        "self-test node-to-fops fixture differs from the source",
    )
    reject_schema_mutant("a readable node with write-only fops", write_only_fops)

    unreadable_mode = rs4xx_source.replace(
        'debugfs_create_file("radeon_rs480_safe_regs", 0400, root, rdev,',
        'debugfs_create_file("radeon_rs480_safe_regs", 0200, root, rdev,',
        1,
    )
    require(
        unreadable_mode != rs4xx_source,
        "self-test readable-node mode fixture differs from the source",
    )
    reject_schema_mutant("a schema-bearing node without read mode", unreadable_mode)

    missing_dump_header = rs4xx_source.replace(
        "if (*pos == 0)\n\t\treturn SEQ_START_TOKEN;",
        "if (*pos == 0)\n\t\treturn NULL;",
        1,
    )
    require(
        missing_dump_header != rs4xx_source,
        "self-test CP-ME dump header fixture differs from the source",
    )
    reject_schema_mutant("a CP-ME dump without its header record", missing_dump_header)

    early_dump_header_output = rs4xx_source.replace(
        "\tif (v == SEQ_START_TOKEN) {\n\t\trs480_debugfs_emit_schema(m);",
        "\tif (v == SEQ_START_TOKEN) {\n"
        '\t\tseq_puts(m, "bad\\n");\n'
        "\t\trs480_debugfs_emit_schema(m);",
        1,
    )
    require(
        early_dump_header_output != rs4xx_source,
        "self-test CP-ME header output fixture differs from the source",
    )
    reject_schema_mutant(
        "CP-ME header output before its schema",
        early_dump_header_output,
    )

    early_dump_return = rs4xx_source.replace(
        "\tif (*pos > RS480_CP_ME_RAM_DUMP_LIMIT)\n"
        "\t\treturn NULL;\n"
        "\tterminal_position = rs480_cp_me_ram_seq_terminal_position(rdev);",
        "\treturn pos;\n"
        "\tif (*pos > RS480_CP_ME_RAM_DUMP_LIMIT)\n"
        "\t\treturn NULL;\n"
        "\tterminal_position = rs480_cp_me_ram_seq_terminal_position(rdev);",
        1,
    )
    require(
        early_dump_return != rs4xx_source,
        "self-test CP-ME dump ordering fixture differs from the source",
    )
    reject_schema_mutant("an early CP-ME dump iterator return", early_dump_return)

    paginated_dump_schema = rs4xx_source.replace(
        "\tterminal_position = rs480_cp_me_ram_seq_terminal_position(rdev);\n"
        "\tif (terminal_position) {",
        "\trs480_debugfs_emit_schema(m);\n"
        "\tterminal_position = rs480_cp_me_ram_seq_terminal_position(rdev);\n"
        "\tif (terminal_position) {",
        1,
    )
    require(
        paginated_dump_schema != rs4xx_source,
        "self-test CP-ME dump pagination fixture differs from the source",
    )
    reject_schema_mutant(
        "a schema emitter in CP-ME data records", paginated_dump_schema
    )

    direct_paginated_schema = rs4xx_source.replace(
        "\t}\n\tterminal_position = rs480_cp_me_ram_seq_terminal_position(rdev);",
        "\t}\n"
        "\trs480_debugfs_emit_schema(m);\n"
        "\tterminal_position = rs480_cp_me_ram_seq_terminal_position(rdev);",
        1,
    )
    require(
        direct_paginated_schema != rs4xx_source,
        "self-test direct paginated schema fixture differs from the source",
    )
    reject_schema_mutant(
        "a direct schema emitter in CP-ME data records",
        direct_paginated_schema,
    )

    early_dump_data_output = rs4xx_source.replace(
        "\t}\n\tterminal_position = rs480_cp_me_ram_seq_terminal_position(rdev);",
        "\t}\n"
        '\tseq_puts(m, "bad\\n");\n'
        "\tterminal_position = rs480_cp_me_ram_seq_terminal_position(rdev);",
        1,
    )
    require(
        early_dump_data_output != rs4xx_source,
        "self-test CP-ME data output fixture differs from the source",
    )
    reject_schema_mutant(
        "CP-ME data output before its hardware-refusal route",
        early_dump_data_output,
    )

    wrong_dump_start_binding = rs4xx_source.replace(
        "\t.start = rs480_cp_me_ram_seq_start,",
        "\t.start = rs480_cp_me_ram_seq_next,",
        1,
    )
    require(
        wrong_dump_start_binding != rs4xx_source,
        "self-test CP-ME sequence binding fixture differs from the source",
    )
    reject_schema_mutant(
        "a CP-ME sequence with the wrong start binding",
        wrong_dump_start_binding,
    )

    unbounded_dump_next = rs4xx_source.replace(
        "\tif (*pos > RS480_CP_ME_RAM_DUMP_LIMIT)\n"
        "\t\treturn NULL;\n"
        "\tterminal_position = rs480_cp_me_ram_seq_terminal_position(rdev);",
        "\tterminal_position = rs480_cp_me_ram_seq_terminal_position(rdev);",
        1,
    )
    require(
        unbounded_dump_next != rs4xx_source,
        "self-test CP-ME dump termination fixture differs from the source",
    )
    reject_schema_mutant("an unbounded CP-ME dump iterator", unbounded_dump_next)

    early_dump_next_return = rs4xx_source.replace(
        "\t++*pos;\n\tif (was_terminal)\n\t\treturn NULL;",
        "\t++*pos;\n\treturn pos;\n\tif (was_terminal)\n\t\treturn NULL;",
        1,
    )
    require(
        early_dump_next_return != rs4xx_source,
        "self-test CP-ME next-return fixture differs from the source",
    )
    reject_schema_mutant(
        "an early CP-ME dump next return",
        early_dump_next_return,
    )

    dump_start_schema = rs4xx_source.replace(
        "static void *rs480_cp_me_ram_seq_start(struct seq_file *m, loff_t *pos)\n{\n",
        "static void *rs480_cp_me_ram_seq_start(struct seq_file *m, loff_t *pos)\n"
        "{\n"
        "\trs480_debugfs_emit_schema(m);\n",
        1,
    )
    require(
        dump_start_schema != rs4xx_source,
        "self-test CP-ME start-schema fixture differs from the source",
    )
    reject_schema_mutant("schema output from CP-ME dump start", dump_start_schema)

    extra_dump_start_return = rs4xx_source.replace(
        "\tif (*pos == 0)\n"
        "\t\treturn SEQ_START_TOKEN;\n"
        "\tif (rs480_cp_me_ram_seq_is_terminal(*pos))",
        "\tif (*pos == 0)\n"
        "\t\treturn SEQ_START_TOKEN;\n"
        "\treturn NULL;\n"
        "\tif (rs480_cp_me_ram_seq_is_terminal(*pos))",
        1,
    )
    require(
        extra_dump_start_return != rs4xx_source,
        "self-test CP-ME start-return fixture differs from the source",
    )
    reject_schema_mutant(
        "an extra CP-ME dump start return",
        extra_dump_start_return,
    )

    dump_next_schema = rs4xx_source.replace(
        "\t++*pos;\n\tif (was_terminal)\n\t\treturn NULL;",
        "\t++*pos;\n"
        "\trs480_debugfs_emit_schema(m);\n"
        "\tif (was_terminal)\n"
        "\t\treturn NULL;",
        1,
    )
    require(
        dump_next_schema != rs4xx_source,
        "self-test CP-ME next-schema fixture differs from the source",
    )
    reject_schema_mutant("schema output from CP-ME dump next", dump_next_schema)

    dump_next_refusal = rs4xx_source.replace(
        "\t++*pos;\n\tif (was_terminal)\n\t\treturn NULL;",
        "\t++*pos;\n"
        "\trs480_debugfs_lock_hardware(m, rdev);\n"
        "\tif (was_terminal)\n"
        "\t\treturn NULL;",
        1,
    )
    require(
        dump_next_refusal != rs4xx_source,
        "self-test CP-ME next-refusal fixture differs from the source",
    )
    reject_schema_mutant(
        "hardware-lock output from CP-ME dump next",
        dump_next_refusal,
    )

    dump_stop_schema = rs4xx_source.replace(
        "static void rs480_cp_me_ram_seq_stop(struct seq_file *m, void *v)\n{\n}",
        "static void rs480_cp_me_ram_seq_stop(struct seq_file *m, void *v)\n"
        "{\n"
        "\trs480_debugfs_emit_schema(m);\n"
        "}",
        1,
    )
    require(
        dump_stop_schema != rs4xx_source,
        "self-test CP-ME stop-schema fixture differs from the source",
    )
    reject_schema_mutant("schema output from CP-ME dump stop", dump_stop_schema)

    early_dump_open_return = rs4xx_source.replace(
        "static int rs480_cp_me_ram_dump_open(struct inode *inode, struct file *file)\n"
        "{\n",
        "static int rs480_cp_me_ram_dump_open(struct inode *inode, struct file *file)\n"
        "{\n"
        "\tif (radeon_rs480_cp_me_ram_dump != 1)\n"
        "\t\treturn -ENODEV;\n",
        1,
    )
    require(
        early_dump_open_return != rs4xx_source,
        "self-test CP-ME dump-open fixture differs from the source",
    )
    reject_schema_mutant(
        "an early CP-ME dump open return",
        early_dump_open_return,
    )

    early_inject_open_return = rs4xx_source.replace(
        "static int rs480_cp_me_ram_inject_open(struct inode *inode, "
        "struct file *file)\n"
        "{\n",
        "static int rs480_cp_me_ram_inject_open(struct inode *inode, "
        "struct file *file)\n"
        "{\n"
        "\tif (radeon_rs480_cp_me_ram_inject == 0)\n"
        "\t\treturn -ENODEV;\n",
        1,
    )
    require(
        early_inject_open_return != rs4xx_source,
        "self-test CP-ME injection-open fixture differs from the source",
    )
    reject_schema_mutant(
        "an early CP-ME injection open return",
        early_inject_open_return,
    )

    readable_mc_flush = rs4xx_source.replace(
        'debugfs_create_file("radeon_rs480_mc_flush", 0200,',
        'debugfs_create_file("radeon_rs480_mc_flush", 0400,',
        1,
    )
    require(
        readable_mc_flush != rs4xx_source,
        "self-test MC-flush mode fixture differs from the source",
    )
    reject_schema_mutant("a readable MC-flush node", readable_mc_flush)

    wrong_mc_flush_fops = rs4xx_source.replace(
        "\t\t\t    &rs480_mc_flush_fops);",
        "\t\t\t    &rs480_safe_regs_fops);",
        1,
    )
    require(
        wrong_mc_flush_fops != rs4xx_source,
        "self-test MC-flush fops fixture differs from the source",
    )
    reject_schema_mutant("an MC-flush node with read fops", wrong_mc_flush_fops)

    missing_mc_flush_node = rs4xx_source.replace(
        '\tdebugfs_create_file("radeon_rs480_mc_flush", 0200,\n'
        "\t\t\t    rdev_to_drm(rdev)->primary->debugfs_root, rdev,\n"
        "\t\t\t    &rs480_mc_flush_fops);\n",
        "",
        1,
    )
    require(
        missing_mc_flush_node != rs4xx_source,
        "self-test MC-flush registration fixture differs from the source",
    )
    reject_schema_mutant("a missing MC-flush node", missing_mc_flush_node)

    conditional_vap_schema = rs4xx_source.replace(
        "static int rs480_candidate_vap_regs_show(struct seq_file *m, void *unused)\n"
        "{\n"
        "\trs480_debugfs_emit_schema(m);\n",
        "static int rs480_candidate_vap_regs_show(struct seq_file *m, void *unused)\n"
        "{\n"
        "\tif (radeon_rs480_hazard_readers_armed == 1)\n"
        "\t\trs480_debugfs_emit_schema(m);\n",
        1,
    )
    require(
        conditional_vap_schema != rs4xx_source,
        "self-test conditional VAP schema fixture differs from the source",
    )
    reject_schema_mutant("a conditional VAP schema route", conditional_vap_schema)

    gart_schema_route = (
        '\trs480_debugfs_emit_schema(m);\n\tseq_puts(m,\n\t\t "row_type\\tstart_index'
    )
    literal_gart_schema = rs4xx_source.replace(
        gart_schema_route,
        '\t(void)"rs480_debugfs_emit_schema(m);";\n'
        "\tseq_puts(m,\n"
        '\t\t "row_type\\tstart_index',
        1,
    )
    require(
        literal_gart_schema != rs4xx_source,
        "self-test literal GART schema fixture differs from the source",
    )
    reject_schema_mutant("a literal GART schema route", literal_gart_schema)

    disabled_gart_schema = rs4xx_source.replace(
        gart_schema_route,
        "#if 0\n"
        "\trs480_debugfs_emit_schema(m);\n"
        "#endif\n"
        "\tseq_puts(m,\n"
        '\t\t "row_type\\tstart_index',
        1,
    )
    require(
        disabled_gart_schema != rs4xx_source,
        "self-test disabled GART schema fixture differs from the source",
    )
    reject_schema_mutant("a disabled GART schema route", disabled_gart_schema)

    early_dump_header_refusal = rs4xx_source.replace(
        "\tif (v == SEQ_START_TOKEN) {\n\t\trs480_debugfs_emit_schema(m);\n",
        "\tif (v == SEQ_START_TOKEN) {\n"
        "\t\tterminal_position = rs480_cp_me_ram_seq_terminal_position(rdev);\n"
        "\t\trs480_debugfs_emit_schema(m);\n",
        1,
    )
    require(
        early_dump_header_refusal != rs4xx_source,
        "self-test early CP-ME header-refusal fixture differs from the source",
    )
    reject_schema_mutant(
        "CP-ME header refusal before its schema",
        early_dump_header_refusal,
    )

    missing_dump_data_arm = rs4xx_source.replace(
        "\tterminal_position = rs480_cp_me_ram_seq_terminal_position(rdev);\n"
        "\tif (terminal_position) {",
        "\tif (terminal_position) {",
        1,
    )
    require(
        missing_dump_data_arm != rs4xx_source,
        "self-test CP-ME data-arm fixture differs from the source",
    )
    reject_schema_mutant("a missing CP-ME data arm gate", missing_dump_data_arm)

    missing_start_terminal_route = rs4xx_source.replace(
        "\tterminal_position = rs480_cp_me_ram_seq_terminal_position(rdev);\n"
        "\tif (terminal_position) {\n"
        "\t\t*pos = terminal_position;\n"
        "\t\treturn pos;\n"
        "\t}\n",
        "",
        1,
    )
    require(
        missing_start_terminal_route != rs4xx_source,
        "self-test CP-ME start terminal-route fixture differs from the source",
    )
    reject_schema_mutant(
        "a missing CP-ME start terminal route",
        missing_start_terminal_route,
    )

    start_mmio_before_gate = rs4xx_source.replace(
        "\tloff_t terminal_position;\n\n\tif (*pos == 0)",
        "\tloff_t terminal_position;\n\n"
        "\tterminal_position = RREG32(RADEON_CP_ME_RAM_DATAL);\n"
        "\tif (*pos == 0)",
        1,
    )
    require(
        start_mmio_before_gate != rs4xx_source,
        "self-test CP-ME start MMIO fixture differs from the source",
    )
    reject_schema_mutant(
        "CP-ME start MMIO before its terminal gate",
        start_mmio_before_gate,
    )

    start_helper_mmio = rs4xx_source.replace(
        "static void *rs480_cp_me_ram_seq_start(struct seq_file *m, loff_t *pos)",
        "static void rs480_cp_me_ram_unguarded_read(struct radeon_device *rdev)\n"
        "{\n"
        "\tu32 value = RREG32(RADEON_CP_ME_RAM_DATAL);\n\n"
        "\t(void)value;\n"
        "}\n\n"
        "static void *rs480_cp_me_ram_seq_start(struct seq_file *m, loff_t *pos)",
        1,
    )
    start_helper_mmio = start_helper_mmio.replace(
        "\tif (*pos > RS480_CP_ME_RAM_DUMP_LIMIT)\n"
        "\t\treturn NULL;\n"
        "\tterminal_position = rs480_cp_me_ram_seq_terminal_position(rdev);",
        "\tif (*pos > RS480_CP_ME_RAM_DUMP_LIMIT)\n"
        "\t\treturn NULL;\n"
        "\trs480_cp_me_ram_unguarded_read(rdev);\n"
        "\tterminal_position = rs480_cp_me_ram_seq_terminal_position(rdev);",
        1,
    )
    require(
        start_helper_mmio != rs4xx_source,
        "self-test CP-ME start helper-MMIO fixture differs from the source",
    )
    reject_schema_mutant(
        "CP-ME start MMIO through an unvalidated helper",
        start_helper_mmio,
    )

    early_terminal_gate_diversion = rs4xx_source.replace(
        "static loff_t rs480_cp_me_ram_seq_terminal_position("
        "struct radeon_device *rdev)\n"
        "{\n"
        "\tif (READ_ONCE(rdev->gpu_parked))",
        "static loff_t rs480_cp_me_ram_seq_terminal_position("
        "struct radeon_device *rdev)\n"
        "{\n"
        "\tif (READ_ONCE(rdev->gpu_parked))\n"
        "\t\tgoto no_terminal;\n"
        "\tif (READ_ONCE(rdev->gpu_parked))",
        1,
    )
    early_terminal_gate_diversion = early_terminal_gate_diversion.replace(
        "\tif (READ_ONCE(radeon_rs480_cp_me_ram_dump) != 1)\n"
        "\t\treturn RS480_CP_ME_RAM_DUMP_TERMINAL_DISARMED;\n"
        "\treturn 0;\n"
        "}",
        "\tif (READ_ONCE(radeon_rs480_cp_me_ram_dump) != 1)\n"
        "\t\treturn RS480_CP_ME_RAM_DUMP_TERMINAL_DISARMED;\n"
        "no_terminal:\n"
        "\treturn 0;\n"
        "}",
        1,
    )
    require(
        early_terminal_gate_diversion != rs4xx_source,
        "self-test CP-ME terminal diversion fixture differs from the source",
    )
    reject_schema_mutant(
        "an early CP-ME terminal gate diversion",
        early_terminal_gate_diversion,
    )

    missing_next_terminal_route = rs4xx_source.replace(
        "\tterminal_position = rs480_cp_me_ram_seq_terminal_position(rdev);\n"
        "\tif (terminal_position) {\n"
        "\t\t*pos = terminal_position;\n"
        "\t\treturn pos;\n"
        "\t}\n"
        "\treturn pos;",
        "\treturn pos;",
        1,
    )
    require(
        missing_next_terminal_route != rs4xx_source,
        "self-test CP-ME next terminal-route fixture differs from the source",
    )
    reject_schema_mutant(
        "a missing CP-ME next terminal route",
        missing_next_terminal_route,
    )

    late_bound_next = rs4xx_source.replace(
        "\tif (*pos > RS480_CP_ME_RAM_DUMP_LIMIT)\n"
        "\t\treturn NULL;\n"
        "\tterminal_position = rs480_cp_me_ram_seq_terminal_position(rdev);\n"
        "\tif (terminal_position) {\n"
        "\t\t*pos = terminal_position;\n"
        "\t\treturn pos;\n"
        "\t}\n",
        "\tterminal_position = rs480_cp_me_ram_seq_terminal_position(rdev);\n"
        "\tif (terminal_position) {\n"
        "\t\t*pos = terminal_position;\n"
        "\t\treturn pos;\n"
        "\t}\n"
        "\tif (*pos > RS480_CP_ME_RAM_DUMP_LIMIT)\n"
        "\t\treturn NULL;\n",
        1,
    )
    require(
        late_bound_next != rs4xx_source,
        "self-test CP-ME late-bound fixture differs from the source",
    )
    reject_schema_mutant(
        "a CP-ME terminal route after the completed-data bound",
        late_bound_next,
    )

    conditional_next_bound = rs4xx_source.replace(
        "\tif (*pos > RS480_CP_ME_RAM_DUMP_LIMIT)\n"
        "\t\treturn NULL;\n"
        "\tterminal_position = rs480_cp_me_ram_seq_terminal_position(rdev);",
        "\tif (rdev->gpu_parked && !rdev->gpu_parked) {\n"
        "\t\tif (*pos > RS480_CP_ME_RAM_DUMP_LIMIT)\n"
        "\t\t\treturn NULL;\n"
        "\t}\n"
        "\tterminal_position = rs480_cp_me_ram_seq_terminal_position(rdev);",
        1,
    )
    require(
        conditional_next_bound != rs4xx_source,
        "self-test CP-ME conditional-bound fixture differs from the source",
    )
    reject_schema_mutant(
        "a conditional CP-ME iterator bound",
        conditional_next_bound,
    )

    late_show_terminal_route = rs4xx_source.replace(
        "\tif (rs480_debugfs_lock_hardware(m, rdev))\n"
        "\t\treturn 0;\n"
        "\taddr = (unsigned int)m->index - 1;\n\n"
        "\tWREG32(RADEON_CP_ME_RAM_RADDR, addr);\n"
        "\tdatah = RREG32(RADEON_CP_ME_RAM_DATAH);\n"
        "\tdatal = RREG32(RADEON_CP_ME_RAM_DATAL);\n",
        "\taddr = (unsigned int)m->index - 1;\n\n"
        "\tWREG32(RADEON_CP_ME_RAM_RADDR, addr);\n"
        "\tdatah = RREG32(RADEON_CP_ME_RAM_DATAH);\n"
        "\tdatal = RREG32(RADEON_CP_ME_RAM_DATAL);\n"
        "\tif (rs480_debugfs_lock_hardware(m, rdev))\n"
        "\t\treturn 0;\n",
        1,
    )
    require(
        late_show_terminal_route != rs4xx_source,
        "self-test CP-ME late-show terminal fixture differs from the source",
    )
    reject_schema_mutant(
        "a CP-ME terminal route after MMIO",
        late_show_terminal_route,
    )

    interroute_show_mmio = rs4xx_source.replace(
        "\tif (rs480_cp_me_ram_seq_is_terminal(m->index)) {\n"
        "\t\trs480_cp_me_ram_seq_emit_terminal(m, m->index);\n"
        "\t\treturn 0;\n"
        "\t}\n"
        "\tterminal_position = rs480_cp_me_ram_seq_terminal_position(rdev);",
        "\tif (rs480_cp_me_ram_seq_is_terminal(m->index)) {\n"
        "\t\trs480_cp_me_ram_seq_emit_terminal(m, m->index);\n"
        "\t\treturn 0;\n"
        "\t}\n"
        "\tm->index = RREG32(RADEON_CP_ME_RAM_DATAL);\n"
        "\tterminal_position = rs480_cp_me_ram_seq_terminal_position(rdev);",
        1,
    )
    require(
        interroute_show_mmio != rs4xx_source,
        "self-test CP-ME interroute MMIO fixture differs from the source",
    )
    reject_schema_mutant(
        "CP-ME show MMIO between terminal routes",
        interroute_show_mmio,
    )

    offset_dump_address = rs4xx_source.replace(
        "\taddr = (unsigned int)m->index - 1;",
        "\taddr = (unsigned int)m->index - 1 + 0x100;",
        1,
    )
    require(
        offset_dump_address != rs4xx_source,
        "self-test CP-ME address-offset fixture differs from the source",
    )
    reject_schema_mutant(
        "an offset CP-ME dump address expression",
        offset_dump_address,
    )

    missing_show_terminal_route = rs4xx_source.replace(
        "\t\tm->index = terminal_position;\n"
        "\t\trs480_cp_me_ram_seq_emit_terminal(m, terminal_position);\n"
        "\t\treturn 0;\n",
        "\t\tm->index = terminal_position;\n\t\treturn 0;\n",
        1,
    )
    require(
        missing_show_terminal_route != rs4xx_source,
        "self-test CP-ME show terminal-route fixture differs from the source",
    )
    reject_schema_mutant(
        "a missing CP-ME show terminal record",
        missing_show_terminal_route,
    )

    duplicate_show_terminal_route = rs4xx_source.replace(
        "\t\trs480_cp_me_ram_seq_emit_terminal(m, terminal_position);\n\t\treturn 0;\n",
        "\t\trs480_cp_me_ram_seq_emit_terminal(m, terminal_position);\n"
        "\t\trs480_cp_me_ram_seq_emit_terminal(m, terminal_position);\n"
        "\t\treturn 0;\n",
        1,
    )
    require(
        duplicate_show_terminal_route != rs4xx_source,
        "self-test CP-ME duplicate terminal-route fixture differs from the source",
    )
    reject_schema_mutant(
        "a duplicated CP-ME show terminal record",
        duplicate_show_terminal_route,
    )

    silent_show_terminal_route = rs4xx_source.replace(
        "\t\trs480_cp_me_ram_seq_emit_terminal(m, terminal_position);\n\t\treturn 0;\n",
        "\t\treturn 0;\n",
        1,
    )
    require(
        silent_show_terminal_route != rs4xx_source,
        "self-test CP-ME silent terminal-route fixture differs from the source",
    )
    reject_schema_mutant(
        "a silent CP-ME show terminal route",
        silent_show_terminal_route,
    )

    duplicate_terminal_status = rs4xx_source.replace(
        '\t\tseq_puts(m, "terminal_status\\tstatus=gpu-parked\\n");\n',
        '\t\tseq_puts(m, "terminal_status\\tstatus=gpu-parked\\n");\n'
        '\t\tseq_puts(m, "terminal_status\\tstatus=gpu-parked\\n");\n',
        1,
    )
    require(
        duplicate_terminal_status != rs4xx_source,
        "self-test CP-ME duplicate status fixture differs from the source",
    )
    reject_schema_mutant(
        "a duplicated CP-ME terminal status mapping",
        duplicate_terminal_status,
    )

    missing_terminal_status = rs4xx_source.replace(
        '\t\tseq_puts(m, "terminal_status\\tstatus=asic-suspended\\n");\n',
        "",
        1,
    )
    require(
        missing_terminal_status != rs4xx_source,
        "self-test CP-ME missing status fixture differs from the source",
    )
    reject_schema_mutant(
        "a missing CP-ME terminal status mapping",
        missing_terminal_status,
    )

    all_statuses_in_default = rs4xx_source.replace(
        "\tswitch (position) {\n"
        "\tcase RS480_CP_ME_RAM_DUMP_TERMINAL_DISARMED:\n"
        '\t\tseq_puts(m, "terminal_status\\tstatus=disarmed\\n");\n'
        "\t\tbreak;\n"
        "\tcase RS480_CP_ME_RAM_DUMP_TERMINAL_PARKED:\n"
        '\t\tseq_puts(m, "terminal_status\\tstatus=gpu-parked\\n");\n'
        "\t\tbreak;\n"
        "\tcase RS480_CP_ME_RAM_DUMP_TERMINAL_SUSPENDED:\n"
        '\t\tseq_puts(m, "terminal_status\\tstatus=asic-suspended\\n");\n'
        "\t\tbreak;\n"
        "\tdefault:\n"
        '\t\tseq_puts(m, "terminal_status\\tstatus=invalid\\n");\n'
        "\t\tbreak;\n"
        "\t}\n",
        "\tswitch (position) {\n"
        "\tdefault:\n"
        '\t\tseq_puts(m, "terminal_status\\tstatus=disarmed\\n");\n'
        '\t\tseq_puts(m, "terminal_status\\tstatus=gpu-parked\\n");\n'
        '\t\tseq_puts(m, "terminal_status\\tstatus=asic-suspended\\n");\n'
        '\t\tseq_puts(m, "terminal_status\\tstatus=invalid\\n");\n'
        "\t\tbreak;\n"
        "\t}\n",
        1,
    )
    require(
        all_statuses_in_default != rs4xx_source,
        "self-test CP-ME default mapping fixture differs from the source",
    )
    reject_schema_mutant(
        "all CP-ME terminal statuses in one default arm",
        all_statuses_in_default,
    )

    overwritten_terminal_position = rs4xx_source.replace(
        "\tswitch (position) {",
        "\tposition = RS480_CP_ME_RAM_DUMP_TERMINAL_DISARMED;\n\tswitch (position) {",
        1,
    )
    require(
        overwritten_terminal_position != rs4xx_source,
        "self-test CP-ME overwritten-position fixture differs from the source",
    )
    reject_schema_mutant(
        "an overwritten CP-ME terminal position",
        overwritten_terminal_position,
    )

    redefined_terminal_selector = rs4xx_source.replace(
        "static bool rs480_cp_me_ram_seq_is_terminal(loff_t position)",
        "#define rs480_cp_me_ram_seq_terminal_position(rdev) (0)\n\n"
        "static bool rs480_cp_me_ram_seq_is_terminal(loff_t position)",
        1,
    )
    require(
        redefined_terminal_selector != rs4xx_source,
        "self-test CP-ME selector-redefinition fixture differs from the source",
    )
    reject_schema_mutant(
        "a preprocessor-redefined CP-ME terminal selector",
        redefined_terminal_selector,
    )

    registration_arms_dump = rs4xx_source.replace(
        "\tif (rdev->family != CHIP_RS400 && rdev->family != CHIP_RS480)\n"
        "\t\treturn;\n\n"
        "\t/* Compatibility alias for the first config-aperture candidate cohort. */",
        "\tif (rdev->family != CHIP_RS400 && rdev->family != CHIP_RS480)\n"
        "\t\treturn;\n\n"
        "\tradeon_rs480_cp_me_ram_dump = 1;\n\n"
        "\t/* Compatibility alias for the first config-aperture candidate cohort. */",
        1,
    )
    require(
        registration_arms_dump != rs4xx_source,
        "self-test CP-ME registration-arm fixture differs from the source",
    )
    reject_schema_mutant(
        "candidate registration that arms the CP-ME dump",
        registration_arms_dump,
    )

    nested_terminal_mapping = rs4xx_source.replace(
        "\tswitch (position) {\n"
        "\tcase RS480_CP_ME_RAM_DUMP_TERMINAL_DISARMED:\n"
        '\t\tseq_puts(m, "terminal_status\\tstatus=disarmed\\n");\n'
        "\t\tbreak;\n"
        "\tcase RS480_CP_ME_RAM_DUMP_TERMINAL_PARKED:\n"
        '\t\tseq_puts(m, "terminal_status\\tstatus=gpu-parked\\n");\n'
        "\t\tbreak;\n"
        "\tcase RS480_CP_ME_RAM_DUMP_TERMINAL_SUSPENDED:\n"
        '\t\tseq_puts(m, "terminal_status\\tstatus=asic-suspended\\n");\n'
        "\t\tbreak;\n"
        "\tdefault:\n"
        '\t\tseq_puts(m, "terminal_status\\tstatus=invalid\\n");\n'
        "\t\tbreak;\n"
        "\t}\n",
        "\tif (position == -1) {\n"
        "\tswitch (position) {\n"
        "\tcase RS480_CP_ME_RAM_DUMP_TERMINAL_DISARMED:\n"
        '\t\tseq_puts(m, "terminal_status\\tstatus=disarmed\\n");\n'
        "\t\tbreak;\n"
        "\tcase RS480_CP_ME_RAM_DUMP_TERMINAL_PARKED:\n"
        '\t\tseq_puts(m, "terminal_status\\tstatus=gpu-parked\\n");\n'
        "\t\tbreak;\n"
        "\tcase RS480_CP_ME_RAM_DUMP_TERMINAL_SUSPENDED:\n"
        '\t\tseq_puts(m, "terminal_status\\tstatus=asic-suspended\\n");\n'
        "\t\tbreak;\n"
        "\tdefault:\n"
        '\t\tseq_puts(m, "terminal_status\\tstatus=invalid\\n");\n'
        "\t\tbreak;\n"
        "\t}\n"
        "\t}\n"
        "\treturn;\n",
        1,
    )
    require(
        nested_terminal_mapping != rs4xx_source,
        "self-test CP-ME nested mapping fixture differs from the source",
    )
    reject_schema_mutant(
        "a conditionally nested CP-ME terminal mapping",
        nested_terminal_mapping,
    )

    header_second_state_read = rs4xx_source.replace(
        "\t\trs480_debugfs_emit_schema(m);\n\t\treturn 0;",
        "\t\trs480_debugfs_emit_schema(m);\n"
        "\t\tif (rs480_debugfs_lock_hardware(m, rdev))\n"
        "\t\t\treturn 0;\n"
        "\t\treturn 0;",
        1,
    )
    require(
        header_second_state_read != rs4xx_source,
        "self-test CP-ME header state-read fixture differs from the source",
    )
    reject_schema_mutant(
        "a second CP-ME header state read",
        header_second_state_read,
    )

    header_index_mutation = rs4xx_source.replace(
        "\t\trs480_debugfs_emit_schema(m);\n\t\treturn 0;",
        "\t\trs480_debugfs_emit_schema(m);\n"
        "\t\tm->index = RS480_CP_ME_RAM_DUMP_TERMINAL_DISARMED;\n"
        "\t\treturn 0;",
        1,
    )
    require(
        header_index_mutation != rs4xx_source,
        "self-test CP-ME header index-mutation fixture differs from the source",
    )
    reject_schema_mutant(
        "a CP-ME header index mutation",
        header_index_mutation,
    )

    extra_header_terminal_record = rs4xx_source.replace(
        "\t\trs480_debugfs_emit_schema(m);\n\t\treturn 0;",
        "\t\trs480_debugfs_emit_schema(m);\n"
        '\t\tseq_puts(m, "terminal_status\\tstatus=invalid\\n");\n'
        "\t\treturn 0;",
        1,
    )
    require(
        extra_header_terminal_record != rs4xx_source,
        "self-test CP-ME extra header record fixture differs from the source",
    )
    reject_schema_mutant(
        "an extra CP-ME header terminal record",
        extra_header_terminal_record,
    )

    first_show_function = min(RS4XX_OUTPUT_SCHEMA_SHOW_FUNCTIONS)
    shrunk_show_denominator = RS4XX_OUTPUT_SCHEMA_SHOW_FUNCTIONS - {first_show_function}
    reject_schema_mutant(
        "a shrunk schema denominator",
        rs4xx_source,
        frozenset(shrunk_show_denominator),
    )

    validate_runtime_sources(source_texts)
    validate_palm_reset_registration(registration_rows, source_texts)
    validate_mutation_audit(source_texts, features)
    registration_source_mutations = (
        (
            "development dispatcher selects an inactive branch",
            "drivers/gpu/drm/radeon/radeon_drv.c",
            "#if RADEON_OBSERVE_DEV\n\tradeon_rs480_re_debugfs_register(minor);",
            "#if 0\n\tradeon_rs480_re_debugfs_register(minor);",
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
            "if (false)\n\t\tlockdep_assert_held_write(&rdev->exclusive_lock);",
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
            "if (false)\n\t\tif (!radeon_palm_dev_pci_reset_unsafe(rdev)) {",
        ),
        (
            "conditional mutation marker without braces",
            "drivers/gpu/drm/radeon/evergreen.c",
            'radeon_dev_mark_mutation(rdev, "Palm PCI config reset");',
            'if (false)\n\t\tradeon_dev_mark_mutation(rdev, "Palm PCI config reset");',
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
    family_refusal = "if (!rdev || rdev->family != CHIP_PALM)\n\t\treturn -ENODEV;"
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
    shrunk_retired_denominator[first_retired_path] = shrunk_retired_denominator[
        first_retired_path
    ][1:]
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
    wedged_function_start = reset_source.find("static int rs480_wedged_3d_reset(")
    wedged_function_end = reset_source.find(
        "\nstatic int rs480_reset_hang_probe_show(",
        wedged_function_start,
    )
    require(
        wedged_function_start >= 0 and wedged_function_end > wedged_function_start,
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
        raise InterfaceError("self-test accepted an unbraced conditional wedged reset")

    goto_wedged_body = (
        reset_source[wedged_function_start:wedged_function_end]
        .replace(
            "\treset_result = radeon_gpu_reset_forced(rdev);",
            "\tgoto bypass_wd3;\n\treset_result = radeon_gpu_reset_forced(rdev);",
            1,
        )
        .replace(
            "\tradeon_device_unlock_hardware(rdev);",
            "\tradeon_device_unlock_hardware(rdev);\nbypass_wd3:\n\t;",
            1,
        )
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
        raise InterfaceError("self-test accepted an overridden WD3 debugfs condition")

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
        raise InterfaceError("self-test accepted an overridden WD3 mutation condition")

    unreachable_wedged_body = reset_source[
        wedged_function_start:wedged_function_end
    ].replace(
        "\tradeon_device_unlock_hardware(rdev);",
        "\tunreachable();\n\tradeon_device_unlock_hardware(rdev);",
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
        raise InterfaceError("self-test accepted unreachable before the wedged unlock")

    wrong_post_state = copy.deepcopy(source_texts)
    wrong_post_state[reset_source_path] = wrong_post_state[reset_source_path].replace(
        "\tif (hardware_result == -EIO)",
        "\tif (hardware_result == -EHOSTDOWN)",
        1,
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
        "\tradeon_device_unlock_hardware(rdev);",
        unreachable_start,
    )
    unreachable_end = unreachable_unlock + len("\tradeon_device_unlock_hardware(rdev);")
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
    missing_lock_source = missing_post_reset_read_lock[reset_source_path]
    post_lock_marker = "\thardware_result = radeon_device_lock_hardware(rdev);"
    first_post_lock = missing_lock_source.find(
        post_lock_marker,
        wedged_function_start,
        wedged_function_end,
    )
    second_post_lock = missing_lock_source.find(
        post_lock_marker,
        first_post_lock + len(post_lock_marker),
        wedged_function_end,
    )
    require(
        first_post_lock >= 0 and second_post_lock > first_post_lock,
        "self-test post-reset lock fixture differs from the source",
    )
    missing_post_reset_read_lock[reset_source_path] = (
        missing_lock_source[:second_post_lock]
        + missing_lock_source[second_post_lock + len(post_lock_marker) :]
    )
    try:
        validate_wedged_reset_probe_post_state(missing_post_reset_read_lock)
    except InterfaceError:
        pass
    else:
        raise InterfaceError("self-test accepted an unlocked parked-state check")

    missing_post_reset_read_unlock = copy.deepcopy(source_texts)
    missing_unlock_source = missing_post_reset_read_unlock[reset_source_path]
    post_unlock_marker = "\tradeon_device_unlock_hardware(rdev);"
    third_post_unlock = missing_unlock_source.rfind(
        post_unlock_marker,
        wedged_function_start,
        wedged_function_end,
    )
    require(
        third_post_unlock >= 0
        and missing_unlock_source[wedged_function_start:wedged_function_end].count(
            post_unlock_marker
        )
        == 3,
        "self-test post-reset unlock fixture differs from the source",
    )
    missing_post_reset_read_unlock[reset_source_path] = (
        missing_unlock_source[:third_post_unlock]
        + missing_unlock_source[third_post_unlock + len(post_unlock_marker) :]
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
        + reset_implementation_source[wrapper_function_start:wrapper_function_end]
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
        raise InterfaceError("self-test accepted an inactive forced-reset wrapper")

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
            '\tatomic_inc(&rdev->gpu_reset_counter);\n\t__asm__ __volatile__("ud2");',
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

    parked_transition = (
        "\t\tdowngrade_write(&rdev->exclusive_lock);\n"
        "\t\tWRITE_ONCE(rdev->in_reset, false);"
    )
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
        raise InterfaceError("self-test accepted a conditional parked reset transition")

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
        "\tWRITE_ONCE(rdev->needs_reset, false);\n"
        "\tif (rs4xx_reset) {\n"
        "\t\tspin_lock_irqsave(&rdev->irq.lock, irqflags);"
    )
    early_ordinary_return = copy.deepcopy(source_texts)
    early_ordinary_return[reset_implementation_path] = (
        reset_implementation_source.replace(
            ordinary_transition,
            "\treturn r;\n" + ordinary_transition,
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
            "\tif (false)\n"
            "\t\tWRITE_ONCE(rdev->needs_reset, false);\n"
            "\tif (rs4xx_reset) {\n"
            "\t\tspin_lock_irqsave(&rdev->irq.lock, irqflags);",
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
        "\tif (gpu_parked) {\n"
        "\t\tradeon_rs4xx_publish_parked_state(rdev);\n"
        "\t\tdowngrade_write(&rdev->exclusive_lock);"
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
    forced_function_start = forced_source.find("static int radeon_gpu_reset_internal(")
    forced_function_end = forced_source.find(
        "\n/**\n * radeon_gpu_reset -",
        forced_function_start,
    )
    require(
        forced_function_start >= 0 and forced_function_end > forced_function_start,
        "self-test forced reset function boundary differs from the source",
    )
    forced_body = forced_source[forced_function_start:forced_function_end]
    forced_transaction_start = forced_body.find("\tdown_write(&rdev->exclusive_lock);")
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
    post_counter_forced_unlock[reset_implementation_path] = post_counter_forced_unlock[
        reset_implementation_path
    ].replace(
        "\tatomic_inc(&rdev->gpu_reset_counter);\n",
        "\tatomic_inc(&rdev->gpu_reset_counter);\n\tup_write(&rdev->exclusive_lock);\n",
        1,
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
        "\tWRITE_ONCE(rdev->needs_reset, false);\n"
        "\tif (rs4xx_reset) {\n"
        "\t\tspin_lock_irqsave(&rdev->irq.lock, irqflags);\n"
        "\t\tif (READ_ONCE(rdev->irq.installed) &&\n"
        "\t\t    !READ_ONCE(rdev->gpu_parked))\n"
        "\t\t\tradeon_irq_set(rdev);\n"
        "\t\tspin_unlock_irqrestore(&rdev->irq.lock, irqflags);\n"
        "\t} else {\n"
        "\t\trdev->in_reset = true;\n"
        "\t}\n\n"
        "\tdowngrade_write(&rdev->exclusive_lock);"
    )
    ordinary_without_downgrade = (
        "\tWRITE_ONCE(rdev->needs_reset, false);\n"
        "\tif (rs4xx_reset) {\n"
        "\t\tspin_lock_irqsave(&rdev->irq.lock, irqflags);\n"
        "\t\tif (READ_ONCE(rdev->irq.installed) &&\n"
        "\t\t    !READ_ONCE(rdev->gpu_parked))\n"
        "\t\t\tradeon_irq_set(rdev);\n"
        "\t\tspin_unlock_irqrestore(&rdev->irq.lock, irqflags);\n"
        "\t} else {\n"
        "\t\trdev->in_reset = true;\n"
        "\t}"
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
        "\tif (gpu_parked) {\n"
        "\t\tradeon_rs4xx_publish_parked_state(rdev);\n"
        "\t\tdowngrade_write(&rdev->exclusive_lock);\n"
        "\t\tWRITE_ONCE(rdev->in_reset, false);"
    )
    parked_without_downgrade = (
        "\tif (gpu_parked) {\n"
        "\t\tradeon_rs4xx_publish_parked_state(rdev);\n"
        "\t\tWRITE_ONCE(rdev->in_reset, false);"
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
        f"{schema_rejection_count} output-schema, "
        f"{transaction_rejection_count} transaction-root, "
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
