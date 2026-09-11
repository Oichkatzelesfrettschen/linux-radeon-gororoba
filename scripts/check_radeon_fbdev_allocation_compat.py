#!/usr/bin/env python3
"""Verify Radeon fbdev allocation against the target DRM helper API."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import tempfile
from pathlib import Path


DRIVER_ROOT = Path("drivers/gpu/drm/radeon")
COMPAT_PATH = DRIVER_ROOT / "radeon_fbdev_compat.mk"
MAKEFILE_PATH = DRIVER_ROOT / "Makefile"
SOURCE_PATH = DRIVER_ROOT / "radeon_fbdev.c"
CAPABILITY = "RADEON_DRM_FB_HELPER_ALLOC_INFO_PRESENT"
DECLARATION = "drm_fb_helper_alloc_info(struct drm_fb_helper *fb_helper)"


class CompatibilityError(Exception):
    """The Radeon fbdev allocation compatibility contract differs."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CompatibilityError(message)


def probe_make_fragment(fragment: Path, header_text: str | None) -> str:
    with tempfile.TemporaryDirectory(prefix="radeon-fbdev-compat.") as temp_name:
        temp_root = Path(temp_name)
        header = temp_root / "include/drm/drm_fb_helper.h"
        if header_text is not None:
            header.parent.mkdir(parents=True)
            header.write_text(header_text, encoding="utf-8")
        result = subprocess.run(
            [
                "make",
                "--no-print-directory",
                "-s",
                "-f",
                str(fragment),
                f"srctree={temp_root}",
                "RADEON_FBDEV_COMPAT_QUERY=1",
                "radeon-fbdev-compat-query",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
        )
        if header_text is None:
            require(result.returncode != 0, "missing DRM helper header is accepted")
            require(
                "missing DRM fb helper API header" in result.stderr,
                "missing-header failure omits its mechanism",
            )
            return "missing"
        require(
            result.returncode == 0,
            "compatibility make fragment failed: " + result.stderr.strip(),
        )
        return result.stdout


def validate(root: Path) -> None:
    compat_path = root / COMPAT_PATH
    makefile = (root / MAKEFILE_PATH).read_text(encoding="utf-8")
    source = (root / SOURCE_PATH).read_text(encoding="utf-8")
    compat = compat_path.read_text(encoding="utf-8")

    require(
        "include $(src)/radeon_fbdev_compat.mk" in makefile,
        "Radeon Makefile omits the fbdev compatibility fragment",
    )
    require(
        "$(srctree)/include/drm/drm_fb_helper.h" in compat,
        "compatibility probe does not read the target kernel header",
    )
    require(
        f"radeon_fb_helper_alloc_info_declaration := {DECLARATION}" in compat,
        "compatibility probe does not name the allocator declaration",
    )
    require(
        "$(findstring $(radeon_fb_helper_alloc_info_declaration),"
        "$(file <$(radeon_fb_helper_api_header)))" in compat,
        "compatibility probe does not resolve the allocator declaration",
    )
    require(
        f"-D{CAPABILITY}=$(radeon_drm_fb_helper_alloc_info_present)" in compat,
        "compatibility result does not reach the compiler",
    )

    function_start = source.index("int radeon_fbdev_driver_fbdev_probe(")
    function_end = source.index("\nbool radeon_fbdev_robj_is_fb(", function_start)
    function = source[function_start:function_end]
    require(
        f"#ifndef {CAPABILITY}" in function,
        "fbdev probe accepts an unresolved compatibility capability",
    )
    require(
        function.count(f"#if {CAPABILITY}") == 3,
        "fbdev probe does not bind declaration, allocation, and cleanup to the capability",
    )
    require(
        "KERNEL_VERSION(7, 0, 0)" not in function,
        "fbdev allocation still guesses the API from a major kernel version",
    )

    old_output = probe_make_fragment(
        compat_path,
        "struct fb_info *drm_fb_helper_alloc_info(struct drm_fb_helper *fb_helper);\n",
    )
    require(
        f"{CAPABILITY}=1" in old_output,
        "exported allocator declaration does not select driver allocation",
    )
    new_output = probe_make_fragment(
        compat_path,
        "struct drm_fb_helper { struct fb_info *info; };\n",
    )
    require(
        f"{CAPABILITY}=0" in new_output,
        "allocator absence does not select helper-owned allocation",
    )
    probe_make_fragment(compat_path, None)


def selftest(root: Path) -> None:
    validate(root)
    with tempfile.TemporaryDirectory(prefix="radeon-fbdev-mutants.") as temp_name:
        fixture = Path(temp_name)
        shutil.copytree(root / DRIVER_ROOT, fixture / DRIVER_ROOT)
        source_path = fixture / SOURCE_PATH
        canonical = source_path.read_text(encoding="utf-8")
        mutants = {
            "unresolved-capability": canonical.replace(
                f"#ifndef {CAPABILITY}", f"#if {CAPABILITY}", 1
            ),
            "version-guess": canonical.replace(
                f"#if {CAPABILITY}",
                "#if LINUX_VERSION_CODE < KERNEL_VERSION(7, 0, 0)",
                1,
            ),
            "cleanup-mismatch": canonical.replace(
                f"#if {CAPABILITY}\nerr_drm_framebuffer_unregister_private:",
                "#if 0\nerr_drm_framebuffer_unregister_private:",
                1,
            ),
        }
        for mutant_name, mutant in mutants.items():
            source_path.write_text(mutant, encoding="utf-8")
            try:
                validate(fixture)
            except CompatibilityError:
                pass
            else:
                raise CompatibilityError(f"{mutant_name} mutant is accepted")
        source_path.write_text(canonical, encoding="utf-8")
    print("Radeon fbdev allocation compatibility calibration: PASS (3 mutants)")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--selftest", action="store_true")
    arguments = parser.parse_args()
    try:
        if arguments.selftest:
            selftest(arguments.root)
        else:
            validate(arguments.root)
            print("Radeon fbdev allocation compatibility: PASS")
    except (CompatibilityError, OSError, ValueError) as error:
        print(f"Radeon fbdev allocation compatibility: FAIL: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
