#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile the production RS480 index-selector show functions against host
fixtures and prove each path stays closed unless the exact arm token is set.

Each selector path reads a module parameter that holds an index, where -1
means no selection and zero selects the first table entry. The functions are
extracted from drivers/gpu/drm/radeon/radeon_rs4xx_dev.c together with their
tables, structures, and constants, then compiled with stub register accessors
that count every MMIO read, PLL write, and mutation mark. The harness sweeps
the arm token (unset, 0, 1, 2, -1) against the selector (-1, 0, last entry,
one past the end) and requires zero register traffic for every arm value other
than exactly 1, one transaction for an in-range selector with the arm at 1,
and zero traffic for an out-of-range selector with the arm at 1.

The self-test mutates the production source into known-bad gates (token check
removed, token compared as nonzero, token compared as nonnegative) and
requires the sweep to reject every mutant on every path, so a verdict of PASS
means the sweep discriminates.
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

SOURCE = Path("drivers/gpu/drm/radeon/radeon_rs4xx_dev.c")
ARM = "radeon_rs480_index_selectors_armed"
ARM_VALUES = (0, 1, 2, -1, 0x7FFFFFFF)

# function, selector global, table symbol, table element struct
PATHS = (
    ("rs480_force_clock_read_show", "radeon_rs480_force_clock_index",
     "rs480_force_clock_list", "rs480_force_clock_reg"),
    ("rs480_force_clock_3d_read_show", "radeon_rs480_force_clock_3d_index",
     "rs480_force_clock_3d_list", "rs480_force_clock_3d_reg"),
    ("rs480_gated_read_show", "radeon_rs480_gated_read_index",
     "rs480_gated_read_list", "rs480_gated_read_reg"),
    ("rs480_pll_write_probe_show", "radeon_rs480_pll_write_probe_index",
     "rs480_pll_write_probe_list", "rs480_pll_write_probe_entry"),
    ("rs480_frontier_probe_show", "radeon_rs480_frontier_index",
     "rs480_frontier_probe_reg_list", "rs480_candidate_reg"),
    ("rs480_vertex_probe_show", "radeon_rs480_vertex_index",
     "rs480_vertex_engine_reg_list", "rs480_candidate_reg"),
    ("rs480_hazard_read_show", "radeon_rs480_hazard_index",
     "rs480_hazard_read_reg_list", "rs480_candidate_reg"),
)

# The production frontier table is empty, so no selection can reach a
# register. The harness substitutes one entry so the sweep can show the
# armed path reaching its access; the closed verdicts hold either way.
FRONTIER_FIXTURE_ENTRY = '{ 0x1234, "FIXTURE_FRONTIER_ENTRY", 0 }'


class ArmingError(Exception):
    """A selector path performs register access without the exact token."""


def brace_block(source, start):
    opening = source.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return end


def function_source(source, name):
    match = re.search(r"^static int %s\(" % re.escape(name), source, re.M)
    if not match:
        raise ArmingError("missing production function " + name)
    return source[match.start():brace_block(source, match.start())]


def struct_source(source, name):
    match = re.search(r"^struct %s \{" % re.escape(name), source, re.M)
    if not match:
        raise ArmingError("missing production structure " + name)
    return source[match.start():brace_block(source, match.start()) + 1]


def table_source(source, table, struct):
    match = re.search(
        r"^static const struct %s\s+%s\[\] = \{" % (struct, re.escape(table)),
        source, re.M)
    if not match:
        raise ArmingError("missing production table " + table)
    end = source.index("\n};", match.start()) + 3
    return source[match.start():end]


def define_chain(source, name, ordered):
    """Append the definition of name, preceded by the constants it names."""
    if name in ordered:
        return
    match = re.search(r"^#define %s\b.*$" % re.escape(name), source, re.M)
    if not match:
        raise ArmingError("missing production constant " + name)
    end = match.end()
    while source[end - 1] == "\\":
        newline = source.find("\n", end + 1)
        end = len(source) if newline < 0 else newline
    text = source[match.start():end]
    for ref in re.findall(r"\bRS480_[A-Z0-9_]+\b", text.split(None, 2)[2]):
        define_chain(source, ref, ordered)
    ordered[name] = text


def build_c(source):
    structs = {}
    tables = []
    for function, _, table, struct in PATHS:
        if struct not in structs:
            structs[struct] = struct_source(source, struct)
        text = table_source(source, table, struct)
        if table == "rs480_frontier_probe_reg_list":
            text = re.sub(r"= \{\s*\};", "= { %s };" % FRONTIER_FIXTURE_ENTRY,
                          text)
        tables.append(text)
    functions = [function_source(source, f) for f, *_ in PATHS]
    body = "\n".join(list(structs.values()) + tables + functions)
    ordered = {}
    for name in sorted(set(re.findall(r"\bRS480_[A-Z0-9_]+\b", body))):
        define_chain(source, name, ordered)
    cases = "\n".join(
        '  { "%s", &%s, (int)ARRAY_SIZE(%s), %s },'
        % (function, selector, table, function)
        for function, selector, table, _ in PATHS)
    return "\n".join([
        PREAMBLE, "\n".join(ordered.values()), "\n".join(structs.values()),
        "\n".join(tables), "\n".join(functions),
        DRIVER.replace("@CASES@", cases)])


PREAMBLE = r"""
#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
typedef unsigned int u32;
typedef unsigned char u8;
typedef unsigned long long u64;
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
struct seq_file { void *private; char buffer[4096]; size_t count; };
struct radeon_device { int unused; };
static int mmio_reads, mmio_writes, mutation_marks, locks, unlocks;
static void seq_puts(struct seq_file *m, const char *text)
{
	m->count += (size_t)snprintf(m->buffer + m->count,
				     sizeof(m->buffer) - m->count, "%s", text);
}
static void seq_printf(struct seq_file *m, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	m->count += (size_t)vsnprintf(m->buffer + m->count,
				      sizeof(m->buffer) - m->count, format, args);
	va_end(args);
}
static int rs480_debugfs_lock_hardware(struct seq_file *m,
				       struct radeon_device *rdev)
{
	(void)m; (void)rdev; locks++; return 0;
}
static void radeon_device_unlock_hardware(struct radeon_device *rdev)
{
	(void)rdev; unlocks++;
}
static void radeon_dev_mark_mutation(struct radeon_device *rdev,
				     const char *operation)
{
	(void)rdev; (void)operation; mutation_marks++;
}
struct rs480_candidate_reg;
static u32 rs480_candidate_reg_read(struct radeon_device *rdev,
				    const struct rs480_candidate_reg *reg)
{
	(void)rdev; (void)reg; mmio_reads++; return 0;
}
static u32 pll_value;
#define RREG32(offset) (mmio_reads++, (u32)(offset))
#define RREG32_PLL(index) (mmio_reads++, pll_value)
#define WREG32_PLL(index, value) do { mmio_writes++; pll_value = (value); } while (0)
#define udelay(us) do { } while (0)
#define mdelay(ms) do { } while (0)
static int radeon_rs480_index_selectors_armed;
static int radeon_rs480_force_clock_index = -1;
static int radeon_rs480_force_clock_3d_index = -1;
static int radeon_rs480_gated_read_index = -1;
static int radeon_rs480_pll_write_probe_index = -1;
static int radeon_rs480_frontier_index = -1;
static int radeon_rs480_vertex_index = -1;
static int radeon_rs480_hazard_index = -1;
"""

DRIVER = r"""
struct path_case {
	const char *name;
	int *selector;
	int entries;
	int (*show)(struct seq_file *, void *);
};
static const struct path_case cases[] = {
@CASES@
};
static const int arm_values[] = { 0, 1, 2, -1, 0x7FFFFFFF };

static void run(const struct path_case *path, int arm, int selector)
{
	static struct radeon_device rdev;
	static struct seq_file m;

	memset(&m, 0, sizeof(m));
	m.private = &rdev;
	mmio_reads = mmio_writes = mutation_marks = locks = unlocks = 0;
	radeon_rs480_index_selectors_armed = arm;
	*path->selector = selector;
	path->show(&m, NULL);
	printf("RESULT %s arm=%d selector=%d reads=%d writes=%d marks=%d "
	       "locks=%d unlocks=%d\n", path->name, arm, selector, mmio_reads,
	       mmio_writes, mutation_marks, locks, unlocks);
}

int main(void)
{
	size_t path_index, arm_index, sel_index;

	/* A fresh module load leaves the arm token at its default. */
	for (path_index = 0; path_index < sizeof(cases) / sizeof(cases[0]);
	     path_index++) {
		const struct path_case *path = &cases[path_index];
		int selectors[4];

		selectors[0] = -1;
		selectors[1] = 0;
		selectors[2] = path->entries - 1;
		selectors[3] = path->entries;
		printf("ENTRIES %s %d\n", path->name, path->entries);
		radeon_rs480_index_selectors_armed = 0;
		for (arm_index = 0;
		     arm_index < sizeof(arm_values) / sizeof(arm_values[0]);
		     arm_index++)
			for (sel_index = 0; sel_index < 4; sel_index++)
				run(path, arm_values[arm_index],
				    selectors[sel_index]);
	}
	return 0;
}
"""


def compile_and_sweep(source_text, workdir):
    c_path = workdir / "sweep.c"
    binary = workdir / "sweep"
    c_path.write_text(build_c(source_text), encoding="utf-8")
    compiler = os.environ.get("CC", "cc")
    subprocess.run(
        [compiler, "-O1", "-Wall", "-Wextra", "-Werror",
         "-Wno-unused-function", "-Wno-unused-variable",
         "-Wno-unused-but-set-variable", "-Wno-unused-parameter",
         "-Wno-pointer-arith", "-o", str(binary), str(c_path)],
        check=True)
    result = subprocess.run([str(binary)], check=True, capture_output=True,
                            text=True)
    return result.stdout


def judge(output):
    """Return (violations, summary lines) for a sweep transcript."""
    entries = {}
    results = []
    for line in output.splitlines():
        parts = line.split()
        if parts[0] == "ENTRIES":
            entries[parts[1]] = int(parts[2])
        elif parts[0] == "RESULT":
            fields = dict(item.split("=") for item in parts[2:])
            results.append((parts[1], {k: int(v) for k, v in fields.items()}))
    violations = []
    summary = []
    for function, _, _, _ in PATHS:
        rows = [row for name, row in results if name == function]
        if not rows:
            violations.append("%s produced no sweep rows" % function)
            continue
        unarmed = closed = in_range_armed = reached = 0
        out_of_range = refused = 0
        for row in rows:
            traffic = row["reads"] + row["writes"] + row["marks"]
            in_range = 0 <= row["selector"] < entries[function]
            if row["arm"] != 1:
                unarmed += 1
                closed += not traffic
                if traffic:
                    violations.append(
                        "%s arm=%d selector=%d performed register access"
                        % (function, row["arm"], row["selector"])
                    )
            elif in_range:
                in_range_armed += 1
                reached += bool(traffic)
                if not traffic:
                    violations.append(
                        "%s arm=1 selector=%d stayed closed"
                        % (function, row["selector"])
                    )
            else:
                out_of_range += 1
                refused += not traffic
                if traffic:
                    violations.append(
                        "%s arm=1 out-of-range selector=%d performed access"
                        % (function, row["selector"])
                    )
            if row["locks"] != row["unlocks"]:
                violations.append(
                    "%s arm=%d selector=%d leaves the hardware lock held"
                    % (function, row["arm"], row["selector"])
                )
        summary.append(
            "%-32s closed without token: %2d/%2d  reachable with token: "
            "%d/%d  out-of-range closed with token: %d/%d"
            % (function, closed, unarmed, reached, in_range_armed, refused,
               out_of_range)
        )
    return violations, summary


def mutate(source, function, kind):
    text = function_source(source, function)
    gate = ("\tif (%s != 1) {" % ARM)
    if gate not in text:
        raise ArmingError("%s carries no arm gate" % function)
    if kind == "gate-removed":
        replacement = "\tif (0) {"
    elif kind == "token-compared-as-nonzero":
        replacement = "\tif (%s == 0) {" % ARM
    elif kind == "token-compared-as-nonnegative":
        replacement = "\tif (%s < 0) {" % ARM
    else:
        raise ArmingError("unknown mutation " + kind)
    return source.replace(text, text.replace(gate, replacement, 1), 1)


def run_sweep(source_text):
    with tempfile.TemporaryDirectory(prefix="rs480-selector-arming.") as name:
        return judge(compile_and_sweep(source_text, Path(name)))


def selftest(root):
    source = (root / SOURCE).read_text(encoding="utf-8")
    violations, summary = run_sweep(source)
    if violations:
        raise ArmingError("known-good production source fails the sweep: "
                          + violations[0])
    rejected = 0
    for function, _, _, _ in PATHS:
        for kind in ("gate-removed", "token-compared-as-nonzero",
                     "token-compared-as-nonnegative"):
            bad, _ = run_sweep(mutate(source, function, kind))
            if not bad:
                raise ArmingError(
                    "known-bad %s on %s is accepted" % (kind, function))
            rejected += 1
    print("RS480 index-selector arming calibration: PASS (production source "
          "accepted; %d known-bad gates rejected)" % rejected)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path,
                        default=Path(__file__).resolve().parents[1])
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    try:
        if args.selftest:
            selftest(args.root)
            return 0
        source = (args.root / SOURCE).read_text(encoding="utf-8")
        violations, summary = run_sweep(source)
    except (ArmingError, OSError, subprocess.CalledProcessError) as error:
        print("RS480 index-selector arming: FAIL: %s" % error)
        return 1
    for line in summary:
        print(line)
    if violations:
        for violation in violations:
            print("VIOLATION " + violation)
        print("RS480 index-selector arming: FAIL")
        return 1
    print("RS480 index-selector arming: PASS (%d paths, arm values %s)"
          % (len(PATHS), list(ARM_VALUES)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
