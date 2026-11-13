#!/usr/bin/env python3
"""Install the compiler and pahole that a kernel build root records.

Kbuild compares the first line of `$(CC) --version` with CONFIG_CC_VERSION_TEXT
and `pahole --version` with CONFIG_PAHOLE_VERSION, and warns when either
differs. scripts/build_radeon_module.sh fails the build on every warning, so a
distribution that ships a newer compiler than the one a kernel package was built
with turns the lane red for a toolchain skew rather than a source defect.

The kernel build root's .config records the compiler family, its version text
and the pahole version. This tool probes the installed toolchain against those
records. A mismatch installs the exact build from the Arch Linux Archive: every
installed package that shares the compiler package's version moves together
(the compiler, its libraries and its companions), each file's detached
signature passes `pacman-key --verify`, and `pacman -U` installs the set. The
probe then repeats, because the first line of `--version` is the value Kbuild
compares.

Exit: 0 the installed toolchain matches the kernel records, 1 self-test
calibration failure, 2 unusable kernel records, 3 toolchain skew (no archive
build reproduces the recorded version text), 4 the archive, a signature or
pacman failed. Exit 3 names a toolchain condition and exit 4 an infrastructure
condition; neither says anything about the driver source.
"""

from __future__ import annotations

import argparse
import dataclasses
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import TextIO

ARCHIVE_URL = "https://archive.archlinux.org/packages"
FETCH_ATTEMPTS = 3
FETCH_TIMEOUT_SECONDS = 120
# One upstream version can have several archive snapshots and rebuilds, and a
# gcc snapshot date is visible only after installation, so the newest few are probed.
MAX_CANDIDATES = 8

EXIT_MATCH = 0
EXIT_SELF_TEST = 1
EXIT_BAD_RECORD = 2
EXIT_SKEW = 3
EXIT_INFRASTRUCTURE = 4


class RecordError(Exception):
    """The kernel build root does not record a usable toolchain."""


class ArchiveError(Exception):
    """The archive, a signature, or pacman failed."""


@dataclasses.dataclass(frozen=True)
class KernelRecord:
    family: str  # "clang" or "gcc"
    cc_text: str  # CONFIG_CC_VERSION_TEXT, the string Kbuild compares
    cc_version: str  # dotted compiler version inside cc_text
    pahole_code: int  # CONFIG_PAHOLE_VERSION; 0 when BTF generation is off
    linker: str  # human-readable linker record, informational


@dataclasses.dataclass(frozen=True)
class Requirement:
    label: str
    package: str  # the package whose version names the family
    recorded: str  # first line of the version probe that satisfies the kernel
    probe: tuple[str, ...]
    wanted_version: Callable[[str], bool]  # accepts an archive pkgver
    shares_version: bool  # the packages installed at the same version move together


@dataclasses.dataclass(frozen=True)
class Build:
    version: str  # pkgver including any epoch, as written in the file name
    release: str
    filename: str


@dataclasses.dataclass(frozen=True)
class Outcome:
    label: str
    recorded: str
    installed: str
    source: str


# --- kernel records ---------------------------------------------------------

CONFIG_LINE = re.compile(r"^(CONFIG_[A-Za-z0-9_]+)=(.*)$")
CLANG_TEXT = re.compile(r"^clang version (\d+\.\d+\.\d+)$")
GCC_TEXT = re.compile(r"^gcc \([^)]*\) (\d+\.\d+\.\d+)(?: \d{8})?$")


def parse_config(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        match = CONFIG_LINE.match(line)
        if match:
            values[match.group(1)] = match.group(2).strip('"')
    return values


def dotted(code: int) -> str:
    """Decode Kbuild's major*10000 + minor*100 + patch version code."""
    return f"{code // 10000}.{code % 10000 // 100}.{code % 100}"


def read_kernel_record(config_text: str) -> KernelRecord:
    config = parse_config(config_text)
    is_clang = config.get("CONFIG_CC_IS_CLANG") == "y"
    is_gcc = config.get("CONFIG_CC_IS_GCC") == "y"
    if is_clang == is_gcc:
        raise RecordError(
            "exactly one of CONFIG_CC_IS_CLANG and CONFIG_CC_IS_GCC must be y"
        )
    family = "clang" if is_clang else "gcc"
    text = config.get("CONFIG_CC_VERSION_TEXT", "")
    match = (CLANG_TEXT if is_clang else GCC_TEXT).match(text)
    if match is None:
        raise RecordError(
            f"CONFIG_CC_VERSION_TEXT {text!r} is not a {family} version line"
        )
    try:
        pahole_code = int(config.get("CONFIG_PAHOLE_VERSION", ""))
    except ValueError:
        raise RecordError("CONFIG_PAHOLE_VERSION is absent or not a number") from None
    if config.get("CONFIG_LD_IS_LLD") == "y":
        linker = f"LLD {dotted(int(config.get('CONFIG_LLD_VERSION', '0')))}"
    elif config.get("CONFIG_LD_IS_BFD") == "y":
        linker = f"GNU ld {dotted(int(config.get('CONFIG_LD_VERSION', '0')))}"
    else:
        linker = "unrecorded"
    return KernelRecord(family, text, match.group(1), pahole_code, linker)


def pahole_text(code: int) -> str:
    """Spell the pahole version Kbuild decodes from its major*100 + minor code."""
    return f"v{code // 100}.{code % 100:02d}"


def requirements(record: KernelRecord) -> list[Requirement]:
    cc_package = record.family
    probe = ("clang" if record.family == "clang" else "gcc", "--version")

    def compiler_version(pkgver: str) -> bool:
        if record.family == "clang":
            return pkgver == record.cc_version
        # GCC snapshots carry the upstream version plus a git suffix, and the
        # date inside the version text is not visible in the package name, so
        # the version probe after installation decides.
        return pkgver == record.cc_version or pkgver.startswith(record.cc_version + "+")

    needs = [
        Requirement(
            "compiler", cc_package, record.cc_text, probe, compiler_version, True
        )
    ]
    if record.pahole_code:
        want = pahole_text(record.pahole_code)[1:]
        needs.append(
            Requirement(
                "pahole",
                "pahole",
                pahole_text(record.pahole_code),
                ("pahole", "--version"),
                lambda pkgver: re.sub(r"^\d+:", "", pkgver) == want,
                False,
            )
        )
    return needs


# --- archive index ----------------------------------------------------------

HREF = re.compile(r'href="([^"]+\.pkg\.tar\.zst)"')


def parse_archive_index(index_html: str, name: str) -> list[Build]:
    """List the x86_64 and any builds of one package, newest first."""
    pattern = re.compile(
        rf"^{re.escape(name)}-((?:\d+:)?[0-9][^-]*)-([0-9]+(?:\.[0-9]+)?)-(?:x86_64|any)\.pkg\.tar\.zst$"
    )
    builds = []
    for href in HREF.findall(index_html):
        filename = urllib.parse.unquote(href)
        match = pattern.match(filename)
        if match:
            builds.append(Build(match.group(1), match.group(2), href))
    return sorted(builds, key=build_order, reverse=True)


def build_order(build: Build) -> tuple[tuple[int, ...], tuple[int, ...]]:
    """Order builds by version and pkgrel; the git hash of a snapshot is not an order."""
    numeric = re.sub(r"\+g[0-9a-f]+", "", build.version)
    version = tuple(int(part) for part in re.findall(r"\d+", numeric))
    release = tuple(int(part) for part in re.findall(r"\d+", build.release))
    return version, release


@dataclasses.dataclass(frozen=True)
class Candidate:
    members: dict[str, Build]  # one archive build per package to install
    dropped: tuple[str, ...]  # installed members the target version never had


def candidate_sets(
    requirement: Requirement, builds_by_package: Mapping[str, Sequence[Build]]
) -> list[Candidate]:
    """Return the version and pkgrel pairs that the family can install as one.

    The family members depend on each other at an exact version, so a candidate
    holds the compiler package's build and, for every other member, the build at
    the same version and pkgrel. A member that has no build at that version
    (LLVM 23.1.3 split clang-libs and llvm-lit out of earlier packages) is
    dropped, because the older packages own the files the split-out package
    would otherwise conflict on.
    """
    candidates = []
    for build in builds_by_package.get(requirement.package, []):
        if not requirement.wanted_version(build.version):
            continue
        members = {requirement.package: build}
        dropped = []
        for name, builds in builds_by_package.items():
            if name == requirement.package:
                continue
            at_version = [b for b in builds if b.version == build.version]
            same = [b for b in at_version if b.release == build.release]
            if same:
                members[name] = same[0]
            elif not at_version:
                dropped.append(name)
            else:
                break
        else:
            candidates.append(Candidate(members, tuple(dropped)))
    return candidates[:MAX_CANDIDATES]


# --- system access ----------------------------------------------------------


class System:
    """The host operations the matcher needs; the self-test replaces them."""

    def installed_packages(self) -> dict[str, str]:
        result = subprocess.run(
            ["pacman", "-Q"], capture_output=True, text=True, check=False
        )
        if result.returncode != 0:
            raise ArchiveError(f"pacman -Q failed: {result.stderr.strip()}")
        return dict(
            line.split(None, 1) for line in result.stdout.splitlines() if line.strip()
        )

    def first_line(self, command: Sequence[str]) -> str:
        env = dict(os.environ, LC_ALL="C")
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, check=False, env=env
            )
        except FileNotFoundError:
            return ""
        lines = result.stdout.splitlines()
        return lines[0].strip() if result.returncode == 0 and lines else ""

    def archive_builds(self, name: str) -> list[Build]:
        url = f"{ARCHIVE_URL}/{name[0]}/{name}/"
        return parse_archive_index(self._fetch(url).decode("utf-8", "replace"), name)

    def install(self, candidate: Candidate) -> None:
        with tempfile.TemporaryDirectory(prefix="toolchain-") as work:
            files = []
            for name, build in candidate.members.items():
                url = f"{ARCHIVE_URL}/{name[0]}/{name}/{build.filename}"
                package = Path(work) / urllib.parse.unquote(build.filename)
                signature = Path(f"{package}.sig")
                package.write_bytes(self._fetch(url))
                signature.write_bytes(self._fetch(url + ".sig"))
                verify = subprocess.run(
                    ["pacman-key", "--verify", str(signature)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if verify.returncode != 0:
                    raise ArchiveError(
                        f"signature of {package.name} did not verify:\n{verify.stderr.strip()}"
                    )
                files.append(str(package))
            if candidate.dropped:
                removal = subprocess.run(
                    ["pacman", "-Rdd", "--noconfirm", *candidate.dropped], check=False
                )
                if removal.returncode != 0:
                    raise ArchiveError(
                        f"pacman -Rdd could not remove {', '.join(candidate.dropped)}"
                    )
            result = subprocess.run(
                ["pacman", "-U", "--noconfirm", *files], check=False
            )
            if result.returncode != 0:
                raise ArchiveError("pacman -U rejected the archive set")

    @staticmethod
    def _fetch(url: str) -> bytes:
        failure = "no attempt"
        for _ in range(FETCH_ATTEMPTS):
            try:
                with urllib.request.urlopen(
                    url, timeout=FETCH_TIMEOUT_SECONDS
                ) as reply:
                    return bytes(reply.read())
            except (urllib.error.URLError, TimeoutError) as error:
                failure = f"{error}"
        raise ArchiveError(f"fetch of {url} failed: {failure}")


# --- matching ---------------------------------------------------------------


def family_members(installed: Mapping[str, str], package: str) -> list[str]:
    """Every installed package built at the family package's exact version."""
    version = installed.get(package)
    if version is None:
        return [package]
    return sorted(name for name, found in installed.items() if found == version)


def skew_verdict(
    release: str, requirement: Requirement, have: str, offered: str
) -> str:
    return (
        f"TOOLCHAIN SKEW: kernel {release} records {requirement.label} "
        f"{requirement.recorded!r}; installed {have!r}; {offered}"
    )


def ensure(
    system: System, release: str, requirement: Requirement
) -> tuple[Outcome | None, str | None, int]:
    """Return the outcome, a verdict line on failure, and an exit code."""
    have = system.first_line(requirement.probe)
    initial = have
    if have == requirement.recorded:
        version = system.installed_packages().get(requirement.package, "unknown")
        return (
            Outcome(
                requirement.label,
                requirement.recorded,
                have,
                f"image or repository {requirement.package} {version}",
            ),
            None,
            EXIT_MATCH,
        )
    try:
        names = (
            family_members(system.installed_packages(), requirement.package)
            if requirement.shares_version
            else [requirement.package]
        )
        builds = {name: system.archive_builds(name) for name in names}
    except ArchiveError as error:
        return (
            None,
            f"TOOLCHAIN UNAVAILABLE: archive listing failed: {error}",
            EXIT_INFRASTRUCTURE,
        )
    sets = candidate_sets(requirement, builds)
    primary = builds.get(requirement.package, [])
    if not sets:
        seen = sorted(
            {b.version for b in primary if requirement.wanted_version(b.version)}
        )
        offered = (
            f"the Arch Linux Archive carries {requirement.package} {', '.join(seen)} "
            f"but not every family member ({', '.join(names)}) at one version"
            if seen
            else f"the Arch Linux Archive carries no {requirement.package} build for this version"
        )
        return None, skew_verdict(release, requirement, initial, offered), EXIT_SKEW
    tried = []
    for candidate in sets:
        label = candidate.members[requirement.package]
        try:
            system.install(candidate)
        except ArchiveError as error:
            return None, f"TOOLCHAIN UNAVAILABLE: {error}", EXIT_INFRASTRUCTURE
        have = system.first_line(requirement.probe)
        if have == requirement.recorded:
            return (
                Outcome(
                    requirement.label,
                    requirement.recorded,
                    have,
                    f"Arch Linux Archive {requirement.package} {label.version}-{label.release}",
                ),
                None,
                EXIT_MATCH,
            )
        tried.append(
            f"{requirement.package} {label.version}-{label.release} reports {have!r}"
        )
    offered = "no archive build reproduces the recorded version text: " + "; ".join(
        tried
    )
    return None, skew_verdict(release, requirement, initial, offered), EXIT_SKEW


def summary_block(
    title: str,
    release: str,
    record: KernelRecord,
    outcomes: list[Outcome],
    system: System,
) -> str:
    rows = [("kernel release", release)]
    for outcome in outcomes:
        rows.append((f"{outcome.label} the kernel records", outcome.recorded))
        rows.append((f"{outcome.label} installed", outcome.installed))
        rows.append((f"{outcome.label} installed from", outcome.source))
    if not record.pahole_code:
        rows.append(("pahole", "the kernel records none (no BTF generation)"))
    linker_probe = "ld.lld" if record.family == "clang" else "ld"
    rows.append(("linker the kernel records (informational)", record.linker))
    rows.append(
        (
            "linker installed (informational)",
            system.first_line((linker_probe, "--version")) or "absent",
        )
    )
    lines = [f"### {title}", "", "| field | value |", "| --- | --- |"]
    lines.extend(f"| {field} | `{value}` |" for field, value in rows)
    return "\n".join(lines) + "\n"


def emit(message: str, file: TextIO | None = None) -> None:
    """Print and flush, so stdout and stderr keep their order in the job log."""
    print(message, file=file or sys.stdout, flush=True)


def match(system: System, root: Path, title: str, summary_path: str | None) -> int:
    release = root.parent.name
    try:
        record = read_kernel_record((root / ".config").read_text(encoding="utf-8"))
    except (OSError, RecordError) as error:
        emit(f"KERNEL RECORD UNUSABLE: {root}: {error}", file=sys.stderr)
        return EXIT_BAD_RECORD
    emit(
        f"kernel {release} records {record.cc_text!r}, pahole {pahole_text(record.pahole_code)}"
    )
    outcomes: list[Outcome] = []
    status = EXIT_MATCH
    for requirement in requirements(record):
        outcome, verdict, code = ensure(system, release, requirement)
        if outcome is not None:
            outcomes.append(outcome)
            emit(f"{requirement.label}: {outcome.installed!r} ({outcome.source})")
            continue
        verdict = verdict or "toolchain verdict missing"
        emit(verdict, file=sys.stderr)
        if summary_path:
            with open(summary_path, "a", encoding="utf-8") as summary:
                summary.write(f"### {title}\n\n`{verdict}`\n")
        if os.environ.get("GITHUB_ACTIONS"):
            emit(f"::error title=toolchain::{verdict}")
        status = code
        break
    if status == EXIT_MATCH and summary_path:
        with open(summary_path, "a", encoding="utf-8") as summary:
            summary.write(summary_block(title, release, record, outcomes, system))
    return status


# --- calibration ------------------------------------------------------------

CLANG_CONFIG = """CONFIG_CC_VERSION_TEXT="clang version 23.1.4"
CONFIG_CC_IS_CLANG=y
CONFIG_CLANG_VERSION=230104
CONFIG_LD_IS_LLD=y
CONFIG_LLD_VERSION=230104
CONFIG_PAHOLE_VERSION=132
"""
GCC_CONFIG = """CONFIG_CC_VERSION_TEXT="gcc (GCC) 16.2.1 20260810"
CONFIG_CC_IS_GCC=y
CONFIG_GCC_VERSION=160201
CONFIG_LD_IS_BFD=y
CONFIG_LD_VERSION=24700
CONFIG_PAHOLE_VERSION=132
"""
INDEX_FIXTURE = """<a href="../">../</a>
<a href="clang-22.1.8-1-x86_64.pkg.tar.zst">x</a>
<a href="clang-22.1.8-1-x86_64.pkg.tar.zst.sig">x</a>
<a href="clang-23.1.4-1-x86_64.pkg.tar.zst">x</a>
<a href="clang-23.1.4-2-x86_64.pkg.tar.zst">x</a>
<a href="clang-libs-23.1.4-1-x86_64.pkg.tar.zst">x</a>
<a href="pahole-1%3A1.31-2-x86_64.pkg.tar.zst">x</a>
<a href="gcc-16.2.1%2Br23%2Bgd564253eb6c8-1-x86_64.pkg.tar.zst">x</a>
<a href="gcc-16.2.1%2Br9%2Bgaaaaaaaaaaaa-1-x86_64.pkg.tar.zst">x</a>
<a href="gcc-libs-16.2.1%2Br23%2Bgd564253eb6c8-1-x86_64.pkg.tar.zst">x</a>
"""


class FakeSystem(System):
    """A host that serves a fixed package set and a scripted probe per install."""

    def __init__(
        self,
        installed: dict[str, str],
        archive: dict[str, list[Build]],
        probes: dict[tuple[str, ...], list[str]],
        archive_down: bool = False,
    ) -> None:
        self.installed = dict(installed)
        self.archive = archive
        self.probes = probes
        self.archive_down = archive_down
        self.installs: list[list[str]] = []

    def installed_packages(self) -> dict[str, str]:
        return dict(self.installed)

    def first_line(self, command: Sequence[str]) -> str:
        script = self.probes[tuple(command)]
        return script[min(len(self.installs), len(script) - 1)]

    def archive_builds(self, name: str) -> list[Build]:
        if self.archive_down:
            raise ArchiveError("archive unreachable")
        return self.archive.get(name, [])

    def install(self, candidate: Candidate) -> None:
        self.installs.append(
            sorted(f"{n} {b.version}-{b.release}" for n, b in candidate.members.items())
            + [f"drop {n}" for n in candidate.dropped]
        )


def replace_wanted(requirement: Requirement, version: str) -> Requirement:
    return dataclasses.replace(
        requirement, wanted_version=lambda pkgver: pkgver == version
    )


def build(name: str, version: str, release: str = "1") -> Build:
    return Build(version, release, f"{name}-{version}-{release}-x86_64.pkg.tar.zst")


def self_test() -> int:
    failures: list[str] = []

    def expect(label: str, condition: bool) -> None:
        print(f"  {'ok' if condition else 'CALIBRATION FAIL'}: {label}")
        if not condition:
            failures.append(label)

    def raises(config: str) -> bool:
        try:
            read_kernel_record(config)
        except RecordError:
            return True
        return False

    print("kernel toolchain matcher calibration:")
    clang = read_kernel_record(CLANG_CONFIG)
    gcc = read_kernel_record(GCC_CONFIG)
    expect(
        "clang record carries family, version text, pahole code and linker",
        (clang.family, clang.cc_version, clang.pahole_code, clang.linker)
        == ("clang", "23.1.4", 132, "LLD 23.1.4"),
    )
    expect(
        "gcc record keeps the dated version text Kbuild compares",
        (gcc.family, gcc.cc_text, gcc.cc_version, gcc.linker)
        == ("gcc", "gcc (GCC) 16.2.1 20260810", "16.2.1", "GNU ld 2.47.0"),
    )
    expect(
        "pahole code 127 spells v1.27 and code 130 spells v1.30",
        (pahole_text(127), pahole_text(130)) == ("v1.27", "v1.30"),
    )
    expect(
        "a record with both compiler families is rejected",
        raises(CLANG_CONFIG + "CONFIG_CC_IS_GCC=y\n"),
    )
    expect(
        "a record with no compiler family is rejected",
        raises(CLANG_CONFIG.replace("CONFIG_CC_IS_CLANG=y\n", "")),
    )
    expect(
        "a clang family with a gcc version text is rejected",
        raises(
            CLANG_CONFIG.replace("clang version 23.1.4", "gcc (GCC) 16.2.1 20260810")
        ),
    )
    expect(
        "a record without CONFIG_PAHOLE_VERSION is rejected",
        raises(CLANG_CONFIG.replace("CONFIG_PAHOLE_VERSION=132\n", "")),
    )

    clang_builds = parse_archive_index(INDEX_FIXTURE, "clang")
    expect(
        "the index parser keeps clang builds, orders newest first, and skips signatures and clang-libs",
        [(b.version, b.release) for b in clang_builds]
        == [("23.1.4", "2"), ("23.1.4", "1"), ("22.1.8", "1")],
    )
    expect(
        "the index parser decodes the epoch and snapshot suffix of gcc and pahole",
        [b.version for b in parse_archive_index(INDEX_FIXTURE, "gcc")]
        == ["16.2.1+r23+gd564253eb6c8", "16.2.1+r9+gaaaaaaaaaaaa"]
        and parse_archive_index(INDEX_FIXTURE, "pahole")[0].version == "1:1.31",
    )

    clang_need = requirements(clang)[0]
    pahole_need = requirements(clang)[1]
    expect(
        "the pahole requirement takes the epoch-stripped version it decodes",
        pahole_need.wanted_version("1:1.32")
        and not pahole_need.wanted_version("1:1.31"),
    )
    members = {
        "clang": clang_builds,
        "clang-libs": parse_archive_index(INDEX_FIXTURE, "clang-libs"),
    }
    selected = candidate_sets(clang_need, members)
    expect(
        "a candidate set needs one build of every family member at the same version and pkgrel",
        len(selected) == 1 and selected[0].members["clang"].release == "1",
    )

    split = candidate_sets(
        clang_need,
        {
            "clang": [build("clang", "23.1.4"), build("clang", "23.1.1")],
            "clang-libs": [build("clang-libs", "23.1.4")],
        },
    )
    expect(
        "only builds of the recorded version are candidates, and a complete family drops nothing",
        len(split) == 1
        and split[0].members["clang"].version == "23.1.4"
        and not split[0].dropped,
    )
    old_layout = replace_wanted(clang_need, "23.1.1")
    old = candidate_sets(
        old_layout,
        {
            "clang": [build("clang", "23.1.1")],
            "clang-libs": [build("clang-libs", "23.1.4")],
        },
    )
    expect(
        "a package split before the target version drops the split-out member",
        len(old) == 1 and old[0].dropped == ("clang-libs",),
    )
    expect(
        "a member present at the version under another pkgrel yields no candidate",
        not candidate_sets(
            old_layout,
            {
                "clang": [build("clang", "23.1.1", "2")],
                "llvm": [build("llvm", "23.1.1", "1")],
            },
        ),
    )

    def fake(
        installed_text: list[str], archive_clang: list[Build], down: bool = False
    ) -> FakeSystem:
        return FakeSystem(
            {"clang": "23.1.5-1", "clang-libs": "23.1.5-1", "pahole": "1:1.32-2"},
            {
                "clang": archive_clang,
                "clang-libs": [
                    build("clang-libs", b.version, b.release) for b in archive_clang
                ],
                "pahole": [],
            },
            {
                ("clang", "--version"): installed_text,
                ("pahole", "--version"): ["v1.32"],
                ("ld.lld", "--version"): ["LLD 23.1.5"],
            },
            down,
        )

    with tempfile.TemporaryDirectory(prefix="toolchain-selftest-") as work:
        root = Path(work) / "7.3.3-1-cachyos" / "build"
        root.mkdir(parents=True)
        (root / ".config").write_text(CLANG_CONFIG, encoding="utf-8")
        summary = Path(work) / "summary.md"

        known_good = fake(["clang version 23.1.4"], [])
        code = match(known_good, root, "calibration", str(summary))
        expect(
            "an installed toolchain that already matches installs nothing and exits 0",
            code == EXIT_MATCH and not known_good.installs,
        )

        skewed = fake(
            ["clang version 23.1.5", "clang version 23.1.4"],
            [build("clang", "23.1.4", "1")],
        )
        code = match(skewed, root, "calibration", str(summary))
        expect(
            "a newer repo compiler is replaced by the archive build that reproduces the record",
            code == EXIT_MATCH
            and skewed.installs == [["clang 23.1.4-1", "clang-libs 23.1.4-1"]],
        )
        expect(
            "the summary records the kernel's compiler, the installed compiler and its archive source",
            "clang version 23.1.4" in summary.read_text(encoding="utf-8")
            and "Arch Linux Archive clang 23.1.4-1"
            in summary.read_text(encoding="utf-8"),
        )

        wrong_text = fake(["clang version 23.1.5"], [build("clang", "23.1.4", "1")])
        expect(
            "an archive build whose version text still differs exits 3",
            match(wrong_text, root, "calibration", None) == EXIT_SKEW,
        )

        _, verdict, _ = ensure(
            fake(["clang version 23.1.5"], [build("clang", "23.1.4", "1")]),
            "7.3.3-1-cachyos",
            clang_need,
        )
        expect(
            "the skew verdict names the kernel-recorded and the repo-served compiler",
            verdict is not None
            and verdict.startswith("TOOLCHAIN SKEW")
            and "'clang version 23.1.4'" in verdict
            and "installed 'clang version 23.1.5'" in verdict,
        )

        absent = fake(["clang version 23.1.5"], [build("clang", "22.1.8", "1")])
        expect(
            "a version the archive does not carry exits 3",
            match(absent, root, "calibration", None) == EXIT_SKEW,
        )

        down = fake(["clang version 23.1.5"], [], down=True)
        expect(
            "an unreachable archive exits 4 rather than blaming the toolchain",
            match(down, root, "calibration", None) == EXIT_INFRASTRUCTURE,
        )

        (root / ".config").write_text("CONFIG_CC_IS_CLANG=y\n", encoding="utf-8")
        expect(
            "an unusable record exits 2",
            match(fake(["x"], []), root, "calibration", None) == EXIT_BAD_RECORD,
        )
        expect(
            "a missing .config exits 2",
            match(fake(["x"], []), Path(work) / "absent" / "build", "calibration", None)
            == EXIT_BAD_RECORD,
        )

        (root / ".config").write_text(GCC_CONFIG, encoding="utf-8")
        gcc_system = FakeSystem(
            {
                "gcc": "16.2.1+r30+gbbbbbbbbbbbb-1",
                "gcc-libs": "16.2.1+r30+gbbbbbbbbbbbb-1",
                "pahole": "1:1.32-2",
            },
            {
                "gcc": [
                    build("gcc", "16.2.1+r30+gbbbbbbbbbbbb"),
                    build("gcc", "16.2.1+r23+gd564253eb6c8"),
                ],
                "gcc-libs": [
                    build("gcc-libs", "16.2.1+r30+gbbbbbbbbbbbb"),
                    build("gcc-libs", "16.2.1+r23+gd564253eb6c8"),
                ],
                "pahole": [],
            },
            {
                ("gcc", "--version"): [
                    "gcc (GCC) 16.2.1 20260901",
                    "gcc (GCC) 16.2.1 20260901",
                    "gcc (GCC) 16.2.1 20260810",
                ],
                ("pahole", "--version"): ["v1.32"],
                ("ld", "--version"): ["GNU ld (GNU Binutils) 2.47"],
            },
        )
        code = match(gcc_system, root, "calibration", None)
        expect(
            "the gcc lane probes snapshot candidates newest first and stops at the one whose dated text matches",
            code == EXIT_MATCH
            and len(gcc_system.installs) == 2
            and "r23" in gcc_system.installs[1][0],
        )

    if failures:
        print(
            f"kernel toolchain matcher calibration: FAIL ({len(failures)})",
            file=sys.stderr,
        )
        return EXIT_SELF_TEST
    print(
        "kernel toolchain matcher calibration: record, archive index, candidate, install, and verdict cases"
    )
    return EXIT_MATCH


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--root", type=Path, help="kernel build root holding .config")
    parser.add_argument(
        "--title", default="module-build toolchain", help="job summary heading"
    )
    parser.add_argument(
        "--summary",
        default=os.environ.get("GITHUB_STEP_SUMMARY"),
        help="file receiving the markdown summary (default: GITHUB_STEP_SUMMARY)",
    )
    parser.add_argument(
        "--self-test", action="store_true", help="run the calibration cases"
    )
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if args.root is None:
        parser.error("--root is required")
    return match(System(), args.root, args.title, args.summary)


if __name__ == "__main__":
    sys.exit(main())
