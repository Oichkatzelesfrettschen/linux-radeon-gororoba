#!/usr/bin/env python3
"""Prove parked entry policy is an exact projection of source guard facts.

check_parked_admission_guards.py owns the source oracle for parked latch,
exclusive read lock, operation order, unlock, and errno invariants. This
checker delegates those facts to that oracle and verifies that the PRIME
import, WAIT_IDLE, and command submission TSV rows describe them exactly.
Its selftest mutates both the policy projection and the canonical source
fixtures. The result is source-static and makes no hardware verdict.
"""

from __future__ import annotations

import argparse
import copy
import csv
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import check_parked_admission_guards as admission

POLICY_PATH = Path("policy/parked-device-entry-contract.tsv")
POLICY_FIELDS = (
    "entry",
    "file",
    "operation_class",
    "takes_exclusive_lock",
    "hardware_touch",
    "new_resource",
    "existing_resource",
    "current_park_behavior",
    "required_park_behavior",
    "error",
    "evidence",
    "test",
)


class ContractError(Exception):
    """A parked entry policy row contradicts the canonical source oracle."""


@dataclass(frozen=True)
class Contract:
    entry: str
    guard_id: str
    expected_file: str
    error: str
    policy_fragments: tuple[tuple[str, str], ...]


CONTRACTS = (
    Contract(
        entry="PRIME_import",
        guard_id="prime-import",
        expected_file=(
            "drivers/gpu/drm/radeon/radeon_prime.c:radeon_gem_prime_import_sg_table"
        ),
        error="-EIO",
        policy_fragments=(
            ("current_park_behavior", "under the exclusive_lock reader"),
            (
                "current_park_behavior",
                "before dma_resv_lock and radeon_bo_create",
            ),
            ("test", "before dma_resv_lock and radeon_bo_create"),
        ),
    ),
    Contract(
        entry="GEM_WAIT_IDLE",
        guard_id="wait-idle-flush",
        expected_file=(
            "drivers/gpu/drm/radeon/radeon_gem.c:radeon_gem_wait_idle_ioctl"
        ),
        error="-EIO",
        policy_fragments=(
            (
                "current_park_behavior",
                "dma_resv_wait_timeout runs before the exclusive_lock reader",
            ),
            (
                "current_park_behavior",
                "before placement inspection and the HDP flush",
            ),
            (
                "required_park_behavior",
                "after the bounded reservation wait",
            ),
            ("test", "follows dma_resv_wait_timeout"),
            ("test", "precedes mmio_hdp_flush"),
        ),
    ),
    Contract(
        entry="DRM_RADEON_CS",
        guard_id="command-submission",
        expected_file="drivers/gpu/drm/radeon/radeon_cs.c:radeon_cs_ioctl",
        error="-EIO",
        policy_fragments=(
            (
                "current_park_behavior",
                "tests gpu_parked under the exclusive_lock reader",
            ),
            (
                "current_park_behavior",
                "returns -EIO before accel_working",
            ),
            ("current_park_behavior", "reset admission"),
            ("current_park_behavior", "relocation validation"),
            ("test", "gpu_parked -EIO refusal"),
            ("test", "reset admission"),
            ("test", "IB scheduling order"),
        ),
    ),
)

GUARDS = {guard["id"]: guard for guard in admission.GUARDS}


def read_policy(root: Path) -> dict[str, dict[str, str]]:
    path = root / POLICY_PATH
    try:
        with path.open(encoding="ascii", newline="") as source:
            reader = csv.DictReader(source, delimiter="\t")
            if tuple(reader.fieldnames or ()) != POLICY_FIELDS:
                raise ContractError(f"{POLICY_PATH}: columns differ from schema")
            rows: dict[str, dict[str, str]] = {}
            for row in reader:
                entry = row["entry"]
                if entry in rows:
                    raise ContractError(f"{POLICY_PATH}: duplicate entry {entry}")
                rows[entry] = row
    except FileNotFoundError as exc:
        raise ContractError(f"missing policy {path}") from exc
    return rows


def check_policy_row(row: dict[str, str], contract: Contract) -> None:
    expected = next(item for item in GOOD_POLICY if item["entry"] == contract.entry)
    for field in POLICY_FIELDS:
        if row[field] != expected[field]:
            raise ContractError(
                f"{contract.entry}: policy {field} is {row[field]!r}, "
                f"expected {expected[field]!r}"
            )


def check_tree(root: Path) -> None:
    rows = read_policy(root)
    for contract in CONTRACTS:
        try:
            row = rows[contract.entry]
        except KeyError as exc:
            raise ContractError(
                f"{POLICY_PATH}: missing entry {contract.entry}"
            ) from exc
        try:
            admission.check_guard(root, GUARDS[contract.guard_id])
        except admission.GuardError as exc:
            raise ContractError(
                f"{contract.entry}: source guard disagrees: {exc}"
            ) from exc
        check_policy_row(row, contract)


GOOD_POLICY = (
    {
        "entry": "PRIME_import",
        "file": (
            "drivers/gpu/drm/radeon/radeon_prime.c:radeon_gem_prime_import_sg_table"
        ),
        "operation_class": "buffer-object-allocation",
        "takes_exclusive_lock": "read",
        "hardware_touch": "none",
        "new_resource": "yes",
        "existing_resource": "no",
        "current_park_behavior": (
            "refused under the exclusive_lock reader before dma_resv_lock "
            "and radeon_bo_create; the import entry point returns ERR_PTR(-EIO) "
            "with radeon_bo_create counting zero"
        ),
        "required_park_behavior": "refused",
        "error": "-EIO",
        "evidence": (
            "hardware-pass on 0.6-1; source-order verified on 0.7-1; "
            "steinmarder-r300 "
            "cachyos_vostro1000_rs482_parked_entry_contract_matrix_20260805T055406Z"
        ),
        "test": "parked import returns before dma_resv_lock and radeon_bo_create",
    },
    {
        "entry": "GEM_WAIT_IDLE",
        "file": ("drivers/gpu/drm/radeon/radeon_gem.c:radeon_gem_wait_idle_ioctl"),
        "operation_class": "existing-buffer-register-access",
        "takes_exclusive_lock": "read",
        "hardware_touch": "mmio_hdp_flush",
        "new_resource": "no",
        "existing_resource": "yes",
        "current_park_behavior": (
            "dma_resv_wait_timeout runs before the exclusive_lock reader; "
            "the parked test then returns -EIO before placement inspection and the "
            "HDP flush; mmio_hdp_flush is additionally NULL on rs400_asic"
        ),
        "required_park_behavior": (
            "refused before MMIO, after the bounded reservation wait"
        ),
        "error": "-EIO",
        "evidence": (
            "hardware-pass on 0.6-1; source-order verified on 0.7-1; "
            "steinmarder-r300 "
            "cachyos_vostro1000_rs482_parked_entry_contract_matrix_20260805T055406Z"
        ),
        "test": (
            "parked refusal follows dma_resv_wait_timeout and precedes mmio_hdp_flush"
        ),
    },
    {
        "entry": "DRM_RADEON_CS",
        "file": "drivers/gpu/drm/radeon/radeon_cs.c:radeon_cs_ioctl",
        "operation_class": "command-submission",
        "takes_exclusive_lock": "read",
        "hardware_touch": "none reached",
        "new_resource": "no",
        "existing_resource": "yes",
        "current_park_behavior": (
            "tests gpu_parked under the exclusive_lock reader and returns -EIO "
            "before accel_working, reset admission, parser initialization, "
            "relocation validation, and IB scheduling"
        ),
        "required_park_behavior": "bounded refusal",
        "error": "-EIO",
        "evidence": (
            "pre-fix hardware-pass; steinmarder-r300 "
            "cachyos_vostro1000_rs482_parked_entry_contract_matrix_20260805T055406Z "
            "measured -EBUSY in 16us before parser entry; corrected -EIO ordering "
            "is compile-verified and silicon acceptance remains pending"
        ),
        "test": (
            "check_parked_admission_guards.py proves read lock, unconditional "
            "gpu_parked refusal, acceleration and reset admission, parser "
            "initialization, relocation validation, and IB scheduling order"
        ),
    },
)

POLICY_MUTATIONS = (
    (
        "PRIME required behavior inverted",
        "PRIME_import",
        "required_park_behavior",
        "permitted",
    ),
    (
        "PRIME hardware touch contradicted",
        "PRIME_import",
        "hardware_touch",
        "unbounded MMIO",
    ),
    ("PRIME new-resource fact contradicted", "PRIME_import", "new_resource", "no"),
    (
        "PRIME existing-resource fact contradicted",
        "PRIME_import",
        "existing_resource",
        "yes",
    ),
    ("PRIME evidence removed", "PRIME_import", "evidence", ""),
    ("PRIME stale lock column", "PRIME_import", "takes_exclusive_lock", "none"),
    (
        "PRIME stale order prose",
        "PRIME_import",
        "current_park_behavior",
        "refused before radeon_bo_create",
    ),
    (
        "WAIT stale lock column",
        "GEM_WAIT_IDLE",
        "takes_exclusive_lock",
        "none",
    ),
    (
        "WAIT stale pre-wait claim",
        "GEM_WAIT_IDLE",
        "current_park_behavior",
        "refused with -EIO before the dma_resv wait and the HDP flush",
    ),
    (
        "CS stale acceleration refusal",
        "DRM_RADEON_CS",
        "current_park_behavior",
        "returns -EBUSY on accel_working false before parser init",
    ),
    ("CS stale errno", "DRM_RADEON_CS", "error", "-EBUSY"),
)


def write_policy(root: Path, rows: tuple[dict[str, str], ...]) -> None:
    path = root / POLICY_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="ascii", newline="") as output:
        writer = csv.DictWriter(
            output,
            fieldnames=POLICY_FIELDS,
            delimiter="\t",
            lineterminator="\n",
        )
        writer.writeheader()
        for sparse in rows:
            row = dict.fromkeys(POLICY_FIELDS, "")
            row.update(sparse)
            writer.writerow(row)


def write_sources(root: Path) -> None:
    fixtures = {
        "prime-import": admission.PRIME_FIXTURE_GOOD,
        "wait-idle-flush": admission.WAIT_FIXTURE_GOOD,
        "command-submission": admission.CS_FIXTURE_GOOD,
    }
    for guard_id, source in fixtures.items():
        path = root / GUARDS[guard_id]["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="ascii")


def expect_rejection(root: Path, label: str) -> bool:
    try:
        check_tree(root)
    except ContractError:
        print(f"selftest known-bad rejected: {label}")
        return True
    print(f"selftest known-bad ACCEPTED: {label}", file=sys.stderr)
    return False


def selftest(root: Path) -> int:
    write_policy(root, GOOD_POLICY)
    write_sources(root)
    try:
        check_tree(root)
    except ContractError as exc:
        print(f"selftest known-good REJECTED: {exc}", file=sys.stderr)
        return 1
    print("selftest known-good accepted: policy projects source oracle")

    failures = 0
    for label, entry, field, replacement in POLICY_MUTATIONS:
        rows = copy.deepcopy(GOOD_POLICY)
        row = next(item for item in rows if item["entry"] == entry)
        row[field] = replacement
        write_policy(root, rows)
        write_sources(root)
        failures += 0 if expect_rejection(root, label) else 1

    source_mutations = (
        (
            "prime-import",
            admission.PRIME_FIXTURE_GOOD,
            admission.PRIME_FIXTURE_MUTATIONS,
        ),
        (
            "wait-idle-flush",
            admission.WAIT_FIXTURE_GOOD,
            admission.WAIT_FIXTURE_MUTATIONS,
        ),
    )
    for guard_id, source, mutations in source_mutations:
        for label, (old, new) in mutations.items():
            write_policy(root, GOOD_POLICY)
            write_sources(root)
            path = root / GUARDS[guard_id]["path"]
            if source.count(old) != 1:
                print(
                    f"selftest fixture error: {guard_id} {label}",
                    file=sys.stderr,
                )
                failures += 1
                continue
            path.write_text(source.replace(old, new, 1), encoding="ascii")
            failures += 0 if expect_rejection(root, f"{guard_id} {label}") else 1

    for label, source in admission.CS_FIXTURES_BAD.items():
        write_policy(root, GOOD_POLICY)
        write_sources(root)
        path = root / GUARDS["command-submission"]["path"]
        path.write_text(source, encoding="ascii")
        failures += 0 if expect_rejection(root, f"command-submission {label}") else 1

    if failures:
        print(f"selftest: {failures} fixture(s) misclassified", file=sys.stderr)
        return 1
    source_count = sum(len(mutations) for _, _, mutations in source_mutations) + len(
        admission.CS_FIXTURES_BAD
    )
    count = len(POLICY_MUTATIONS) + source_count
    print(f"selftest: 1 good and {count} bad fixtures classified")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="classify built-in known-good and known-bad fixtures",
    )
    args = parser.parse_args()

    if args.selftest:
        with tempfile.TemporaryDirectory() as directory:
            return selftest(Path(directory))

    try:
        check_tree(args.root)
    except ContractError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1
    print("parked entry policy: 3 TSV projections match the source oracle")
    return 0


if __name__ == "__main__":
    sys.exit(main())
