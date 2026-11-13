#!/usr/bin/env python3
"""Verify Radeon DRM client suspend and resume calls against the target header."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


DRIVER_ROOT = Path("drivers/gpu/drm/radeon")
COMPAT_PATH = DRIVER_ROOT / "radeon_drm_client_compat.mk"
MAKEFILE_PATH = DRIVER_ROOT / "Makefile"
SOURCE_PATH = DRIVER_ROOT / "radeon_device.c"
CAPABILITY = "RADEON_DRM_CLIENT_CONSOLE_LOCK_ARG_PRESENT"
HEADER_RELATIVE = Path("include/drm/drm_client_event.h")
OLD_HEADER = (
    "void drm_client_dev_suspend(struct drm_device *dev, bool holds_console_lock);\n"
    "void drm_client_dev_resume(struct drm_device *dev, bool holds_console_lock);\n"
)
NEW_HEADER = (
    "void drm_client_dev_suspend(struct drm_device *dev);\n"
    "void drm_client_dev_resume(struct drm_device *dev);\n"
)
MIXED_HEADER = (
    "void drm_client_dev_suspend(struct drm_device *dev, bool holds_console_lock);\n"
    "void drm_client_dev_resume(struct drm_device *dev);\n"
)
# The capability branch of each call: the two-argument form sits under the
# #elif that tests the capability and the one-argument form under the #else.
CALL_BRANCH = (
    r"#ifndef {cap}\n#error \"[^\"\n]*\"\n#elif {cap}\n"
    r"\t\tdrm_client_dev_{name}\(dev, false\);\n#else\n"
    r"\t\tdrm_client_dev_{name}\(dev\);\n#endif\n"
)


class CompatibilityError(Exception):
    """The Radeon DRM client compatibility contract differs."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CompatibilityError(message)


def probe_make_fragment(fragment: Path, header_text: str | None) -> tuple[int, str, str]:
    with tempfile.TemporaryDirectory(prefix="radeon-drm-client-compat.") as temp_name:
        temp_root = Path(temp_name)
        if header_text is not None:
            header = temp_root / HEADER_RELATIVE
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
                "RADEON_DRM_CLIENT_COMPAT_QUERY=1",
                "radeon-drm-client-compat-query",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
        )
        return result.returncode, result.stdout, result.stderr


def validate(root: Path) -> None:
    compat_path = root / COMPAT_PATH
    makefile = (root / MAKEFILE_PATH).read_text(encoding="utf-8")
    source = (root / SOURCE_PATH).read_text(encoding="utf-8")
    compat = compat_path.read_text(encoding="utf-8")

    require(
        "include $(src)/radeon_drm_client_compat.mk" in makefile,
        "Radeon Makefile omits the DRM client compatibility fragment",
    )
    require(
        "$(srctree)/include/drm/drm_client_event.h" in compat,
        "compatibility probe does not read the target kernel header",
    )
    require(
        f"-D{CAPABILITY}=$(radeon_drm_client_suspend_console_lock_arg_present)"
        in compat,
        "compatibility result does not reach the compiler",
    )

    suspend_start = source.index("int radeon_suspend_kms(")
    resume_start = source.index("int radeon_resume_kms(")
    require(suspend_start < resume_start, "suspend and resume definitions are reordered")
    for name, function in (
        ("suspend", source[suspend_start:resume_start]),
        ("resume", source[resume_start:]),
    ):
        pattern = CALL_BRANCH.format(cap=CAPABILITY, name=name)
        require(
            len(re.findall(pattern, function)) == 1,
            f"drm_client_dev_{name} call is not bound to the console lock capability",
        )

    code, out, err = probe_make_fragment(compat_path, OLD_HEADER)
    require(code == 0, "compatibility make fragment failed: " + err.strip())
    require(
        f"{CAPABILITY}=1" in out,
        "declaration with holds_console_lock does not select the two-argument call",
    )
    require(
        f"-D{CAPABILITY}=1" in out,
        "two-argument selection does not reach the compiler flags",
    )
    code, out, err = probe_make_fragment(compat_path, NEW_HEADER)
    require(code == 0, "compatibility make fragment failed: " + err.strip())
    require(
        f"{CAPABILITY}=0" in out,
        "declaration without holds_console_lock does not select the one-argument call",
    )
    code, _, err = probe_make_fragment(compat_path, MIXED_HEADER)
    require(code != 0, "suspend and resume declarations that disagree are accepted")
    require(
        "disagree on the console lock argument" in err,
        "mismatched declarations fail without naming the mechanism",
    )
    code, _, err = probe_make_fragment(compat_path, None)
    require(code != 0, "missing DRM client event header is accepted")
    require(
        "missing DRM client event API header" in err,
        "missing-header failure omits its mechanism",
    )


def selftest(root: Path) -> None:
    validate(root)
    with tempfile.TemporaryDirectory(prefix="radeon-drm-client-mutants.") as temp_name:
        fixture = Path(temp_name)
        shutil.copytree(root / DRIVER_ROOT, fixture / DRIVER_ROOT)
        source_path = fixture / SOURCE_PATH
        compat_path = fixture / COMPAT_PATH
        canonical_source = source_path.read_text(encoding="utf-8")
        canonical_compat = compat_path.read_text(encoding="utf-8")
        source_mutants = {
            "unresolved-capability": canonical_source.replace(
                f"#ifndef {CAPABILITY}", f"#if 0 /* {CAPABILITY} */", 1
            ),
            "version-guess": canonical_source.replace(
                f"#elif {CAPABILITY}",
                "#elif LINUX_VERSION_CODE < KERNEL_VERSION(7, 0, 0)",
                1,
            ),
            "swapped-arguments": canonical_source.replace(
                "drm_client_dev_resume(dev, false);",
                "drm_client_dev_resume(dev);",
                1,
            ).replace(
                "\t\tdrm_client_dev_resume(dev);\n#endif",
                "\t\tdrm_client_dev_resume(dev, false);\n#endif",
                1,
            ),
            "resume-unbound": canonical_source.replace(
                f"#elif {CAPABILITY}\n\t\tdrm_client_dev_resume",
                "#elif 1\n\t\tdrm_client_dev_resume",
                1,
            ),
        }
        for mutant_name, mutant in source_mutants.items():
            require(mutant != canonical_source, f"{mutant_name} mutant did not apply")
            source_path.write_text(mutant, encoding="utf-8")
            try:
                validate(fixture)
            except CompatibilityError:
                pass
            else:
                raise CompatibilityError(f"{mutant_name} mutant is accepted")
        source_path.write_text(canonical_source, encoding="utf-8")
        compat_mutants = {
            "inverted-probe": canonical_compat.replace(
                "$(if $(findstring $(radeon_drm_client_suspend_console_lock_declaration),"
                "$(radeon_drm_client_event_api_text)),1,0)",
                "$(if $(findstring $(radeon_drm_client_suspend_console_lock_declaration),"
                "$(radeon_drm_client_event_api_text)),0,1)",
                1,
            ),
            "resume-ignored": canonical_compat.replace(
                "ifneq ($(radeon_drm_client_suspend_console_lock_arg_present),"
                "$(radeon_drm_client_resume_console_lock_arg_present))",
                "ifneq (0,0)",
                1,
            ),
        }
        for mutant_name, mutant in compat_mutants.items():
            require(mutant != canonical_compat, f"{mutant_name} mutant did not apply")
            compat_path.write_text(mutant, encoding="utf-8")
            try:
                validate(fixture)
            except CompatibilityError:
                pass
            else:
                raise CompatibilityError(f"{mutant_name} mutant is accepted")
    print("Radeon DRM client compatibility calibration: PASS (6 mutants)")


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
            print("Radeon DRM client compatibility: PASS")
    except (CompatibilityError, OSError, ValueError) as error:
        print(f"Radeon DRM client compatibility: FAIL: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
