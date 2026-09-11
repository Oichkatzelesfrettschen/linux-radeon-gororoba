# SPDX-License-Identifier: MIT
"""Check requirement source references at their pinned Git revisions offline.

Discovery strings encode literal searches, never shell programs. This check
establishes source traceability, not specification completeness or behavior.
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import shlex
import subprocess
from functools import lru_cache
from pathlib import Path, PurePosixPath


SOURCE_IDENTITY = {
    "vulkan_commit": "ab08f0951ef1ad9b84db93f971e113c1d9d55609",
    "vulkan_repository": "https://github.com/KhronosGroup/Vulkan-Docs",
    "vulkan_chapter_root": "doc/specs/vulkan/chapters/",
    "mesa_commit": "0b66d14e758c80808e7cc661c008b2a834d12fba",
    "kernel_commit": "07e65682a835bb807420e079b56387cbf1c0b172",
}
OWNERS = {"mesa-26-gororoba", "linux-radeon-gororoba", "steinmarder-r300"}
CLASSIFICATIONS = {
    "existing_support", "missing_validation", "confirmed_mesa_defect",
    "confirmed_drm_defect", "hardware_uncertainty",
}
LEDGERS = (
    "policy/radeon-cs-reservation-fence-contract.tsv",
    "policy/rs4xx-gart-memory-path.tsv",
)
CHAPTER_BLOBS = {
    "memory.txt": "0f1b8e360a7c65a695e6e67081d797bc46eeae4c",
    "resources.txt": "4068853b843b48eb1b9c76c972cff9b3e5d1aaf9",
    "synchronization.txt": "3d285f3c19f65e23d5e45ed946ab7d9e52207e8f",
    "devsandqueues.txt": "ea67767e54469bbd18aaf0776f7e28ee0184fdd1",
}
ANCHOR_DECLARATION = re.compile(
    r"^[ \t]*(?:\*[ \t]+)?\[\[([A-Za-z0-9_-]+)\]\][ \t]*$", re.MULTILINE
)
SUPPORTING_CLAIMS = {
    "device-memory-allocation": {"allocation-alignment", "allocation-size-failure"},
    "image-memory-binding": {"allowed-memory-type", "aligned-offset"},
    "host-coherent-memory-type": {"cache-maintenance"},
    "buffer-memory-binding": {"allowed-memory-type", "aligned-offset"},
    "resource-access-dependencies": {"access-scopes"},
    "memory-availability-visibility": {"availability-operations", "visibility-operations"},
    "queue-fence-completion": {"memory-access-scopes"},
    "device-loss-finite-waits": {"terminal-logical-device", "object-lifetime"},
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


@lru_cache(maxsize=None)
def source_text(root: Path, revision: str, path: str) -> str:
    relative = PurePosixPath(path)
    require(not relative.is_absolute() and ".." not in relative.parts,
            f"uncontained source path: {path}")
    result = subprocess.run(
        ["git", "-C", str(root), "show", f"{revision}:{path}"],
        check=True, capture_output=True, text=True,
    )
    return result.stdout


def check_discovery(root: Path, revision: str, discovery: str) -> None:
    arguments = shlex.split(discovery)
    require(len(arguments) == 4 and arguments[:2] == ["rg", "--fixed-strings"],
            f"expected one literal search and one source file: {discovery}")
    needle, path = arguments[2:]
    require(bool(needle.strip()), "empty discovery query")
    require(needle in source_text(root, revision, path),
            f"query absent at {revision}:{path}: {needle}")


def check_specification(specification: dict, vulkan: Path) -> None:
    chapter = specification["chapter"]
    require(chapter in CHAPTER_BLOBS, "unknown specification chapter")
    anchor = specification["anchor"]
    require(bool(re.fullmatch(r"[A-Za-z0-9-]+", anchor)),
            "invalid specification anchor")
    revision = SOURCE_IDENTITY["vulkan_commit"]
    path = SOURCE_IDENTITY["vulkan_chapter_root"] + chapter
    result = subprocess.run(
        ["git", "-C", str(vulkan), "rev-parse", f"{revision}:{path}"],
        check=True, capture_output=True, text=True,
    )
    require(result.stdout.strip() == CHAPTER_BLOBS[chapter],
            "specification chapter identity drift")
    chapter_text = source_text(vulkan, revision, path)
    declarations = [match for match in ANCHOR_DECLARATION.finditer(chapter_text)
                    if match.group(1) == anchor]
    require(len(declarations) == 1,
            f"expected one anchor declaration in {chapter}: {anchor}")
    section_start = declarations[0].end()
    next_anchor = ANCHOR_DECLARATION.search(chapter_text, section_start)
    section_end = next_anchor.start() if next_anchor else len(chapter_text)
    section = chapter_text[section_start:section_end]
    excerpt = specification["excerpt"]
    require(isinstance(excerpt, str) and len(excerpt.strip()) >= 40,
            "missing or vacuous specification excerpt")
    require(excerpt in section,
            f"exact excerpt absent from anchor interval: {chapter}:{anchor}")


def check(document: dict, kernel: Path, mesa: Path, vulkan: Path) -> None:
    require(document["schema_version"] == 2, "unsupported schema")
    require(document["sources"] == SOURCE_IDENTITY, "source identity drift")
    require(bool(document["coverage"].strip()), "missing coverage boundary")
    rows = document["requirements"]
    require(isinstance(rows, list) and bool(rows), "empty requirement list")
    identifiers = [row["id"] for row in rows]
    require(len(set(identifiers)) == len(identifiers), "duplicate requirement id")
    require(set(identifiers) == set(SUPPORTING_CLAIMS), "requirement coverage drift")
    policy_ids = set()
    for ledger in LEDGERS:
        text = source_text(kernel, SOURCE_IDENTITY["kernel_commit"], ledger)
        policy_ids.update(line.split("\t")[0] for line in text.splitlines()[1:])
    for row in rows:
        require(bool(re.fullmatch(r"[a-z][a-z0-9-]+", row["id"])), "invalid id")
        require(row["owner"] in OWNERS, f"unknown owner: {row['id']}")
        require(row["classification"] in CLASSIFICATIONS, "unknown classification")
        require(row["kernel_policy_row"] in policy_ids, "unknown kernel policy row")
        for field in ("requirement", "interface", "test", "boundary"):
            require(bool(row[field].strip()), f"empty {field}: {row['id']}")
        check_specification(row["specification"], vulkan)
        supporting = row["supporting_specifications"]
        require(isinstance(supporting, list), "supporting specifications must be a list")
        claims = [clause["claim"] for clause in supporting]
        require(len(set(claims)) == len(claims), "duplicate supporting claim")
        require(set(claims) == SUPPORTING_CLAIMS[row["id"]], "supporting coverage drift")
        for clause in supporting:
            check_specification(clause, vulkan)
        require(row["test_status"] == "not_run",
                "execution results require a retained-evidence schema extension")
        check_discovery(mesa, SOURCE_IDENTITY["mesa_commit"], row["mesa_discovery"])
        require(isinstance(row["kernel_discovery"], list)
                and bool(row["kernel_discovery"]), "empty kernel discoveries")
        for discovery in row["kernel_discovery"]:
            check_discovery(kernel, SOURCE_IDENTITY["kernel_commit"], discovery)


def selftest(document: dict, kernel: Path, mesa: Path, vulkan: Path) -> int:
    check(document, kernel, mesa, vulkan)
    mutations = [
        ("owner", "unowned"), ("classification", "conformant"),
        ("kernel_policy_row", "ABSENT_POLICY_ROW"), ("requirement", ""),
        ("test", ""), ("boundary", ""), ("test_status", "passed"),
        ("kernel_discovery", []),
        ("supporting_specifications", []),
        ("mesa_discovery", "rg --fixed-strings absent_symbol missing.c"),
        ("mesa_discovery", "rg --fixed-strings absent_symbol ../outside.c"),
        ("mesa_discovery", "rg --fixed-strings '' file.c"),
        ("mesa_discovery", "sh -c 'exit 0'"),
        ("mesa_discovery", "rg --fixed-strings absent_symbol "
         "src/amd/r300/vulkan/r3v_native_memory.c"),
    ]
    bad_documents = []
    for field, value in (
        ("anchor", "absent-specification-anchor"),
        ("anchor", "memory-device-bitmask-list.*"),
        ("chapter", "resources.txt"),
        ("chapter", "../memory.txt"),
        ("chapter", "absent.txt"),
        ("excerpt", ""),
        ("excerpt", " "),
        ("excerpt", "There must:"),
        ("excerpt", "An invented normative statement with enough characters to pass length."),
        ("excerpt", document["requirements"][1]["specification"]["excerpt"]),
        ("anchor", "memory-device"),
    ):
        mutated = copy.deepcopy(document)
        mutated["requirements"][0]["specification"][field] = value
        bad_documents.append(mutated)
    for field, value in mutations:
        mutated = copy.deepcopy(document)
        mutated["requirements"][0][field] = value
        bad_documents.append(mutated)
    conditional = copy.deepcopy(document)
    lost_specification = next(row["specification"] for row in conditional["requirements"]
                              if row["id"] == "device-loss-finite-waits")
    lost_specification["excerpt"] = lost_specification["excerpt"].replace(
        "ifdef::VK_KHR_swapchain[]\n", ""
    ).replace("endif::VK_KHR_swapchain[]\n", "")
    bad_documents.append(conditional)
    for row_index, row in enumerate(document["requirements"]):
        for clause_index, clause in enumerate(row["supporting_specifications"]):
            for field, value in (("excerpt", clause["excerpt"] + " altered"),
                                 ("claim", "unknown-claim")):
                mutated = copy.deepcopy(document)
                mutated["requirements"][row_index]["supporting_specifications"][
                    clause_index][field] = value
                bad_documents.append(mutated)
    missing_row = copy.deepcopy(document)
    missing_row["requirements"].pop()
    bad_documents.append(missing_row)
    duplicate_clause = copy.deepcopy(document)
    supporting = duplicate_clause["requirements"][0]["supporting_specifications"]
    supporting.append(copy.deepcopy(supporting[0]))
    bad_documents.append(duplicate_clause)
    duplicated = copy.deepcopy(document)
    duplicated["requirements"].append(copy.deepcopy(duplicated["requirements"][0]))
    bad_documents.append(duplicated)
    for field in SOURCE_IDENTITY:
        mutated = copy.deepcopy(document)
        mutated["sources"][field] += "-drift"
        bad_documents.append(mutated)
    for mutated in bad_documents:
        try:
            check(mutated, kernel, mesa, vulkan)
        except (ValueError, subprocess.CalledProcessError):
            continue
        raise ValueError("known-bad source reference accepted")
    return len(bad_documents)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel-tree", type=Path,
                        default=Path(__file__).resolve().parents[1])
    parser.add_argument("--mesa-tree", type=Path, required=True)
    parser.add_argument("--vulkan-tree", type=Path, required=True,
                        help="offline Vulkan-Docs Git checkout or bare repository")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    try:
        document = json.loads((args.kernel_tree /
            "policy/r3v-vulkan-drm-requirements.json").read_text(encoding="utf-8"))
        check(document, args.kernel_tree, args.mesa_tree, args.vulkan_tree)
        if args.selftest:
            count = selftest(document, args.kernel_tree, args.mesa_tree, args.vulkan_tree)
            print(f"selftest: one good document and {count} bad mutations classified")
        print(f"source references: {len(document['requirements'])} requirements pass")
        excerpt_count = sum(1 + len(row["supporting_specifications"])
                            for row in document["requirements"])
        print(f"normative source excerpts: {excerpt_count} pass")
        print("Pinned chapter identities, anchor declarations, and exact excerpts pass.")
        print("Semantic completeness and behavior remain unverified.")
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(f"source reference check failed: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
