#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile production flip cleanup helpers against reservation and ownership fixtures."""

import argparse
from pathlib import Path
import subprocess
import tempfile


FUNCTIONS = (
    "radeon_flip_work_add_retained_locked",
    "radeon_flip_work_add_retained",
    "radeon_flip_work_release_references",
    "radeon_flip_work_release_old",
    "radeon_unpin_work_func",
)


def function_source(source, name):
    start = source.rfind("static ", 0, source.index(name + "("))
    opening = source.index("{", source.index(name + "("))
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


PREAMBLE = r"""
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <errno.h>
#include <stdio.h>
struct list_head { bool linked; };
struct work_struct { int unused; };
struct ttm_buffer_object { struct { int refs; } base; };
struct radeon_bo { struct ttm_buffer_object tbo; int pins; };
struct drm_device { int event_lock; };
struct radeon_device {
 struct drm_device drm; bool target;
 struct list_head rs4xx_retained_flips;
 long long rs4xx_flip_reserve_busy, rs4xx_flip_admission_refused;
 long long rs4xx_flip_retained_total, rs4xx_flip_retained_released;
 int rs4xx_flip_retained_pending;
 struct work_struct rs4xx_flip_cleanup_work;
};
struct radeon_flip_work {
 struct work_struct unpin_work; struct list_head retained;
 struct radeon_device *rdev; struct radeon_bo *old_rbo, *new_rbo;
 bool retained_accounted;
};
static int reserve_result, admission_result, errors, queued, reference_puts, frees;
static bool reserved, admitted;
#define container_of(pointer, type, member) ((type *)((char *)(pointer) - offsetof(type, member)))
#define rdev_to_drm(device) (&(device)->drm)
#define lockdep_assert_held(lock) assert(*(lock))
#define spin_lock_irqsave(lock, flags) do { (flags) = 0; *(lock) = 1; } while (0)
#define spin_unlock_irqrestore(lock, flags) do { (void)(flags); *(lock) = 0; } while (0)
#define atomic64_inc(value) (++*(value))
#define atomic_inc(value) (++*(value))
#define atomic_dec(value) (--*(value))
#define DRM_ERROR(...) (++errors)
#define DRM_DEBUG_KMS(...) ((void)0)
#define RADEON_FLIP_CLEANUP_RETRY_DELAY 100
#define system_unbound_wq NULL
static bool list_empty(struct list_head *head) { return !head->linked; }
static void list_add_tail(struct list_head *entry, struct list_head *head) {
 (void)head; entry->linked = true;
}
static bool radeon_rs4xx_hardware_target(struct radeon_device *device) { return device->target; }
static int ttm_bo_reserve(struct ttm_buffer_object *bo, bool interruptible, bool no_wait, void *ticket) {
 (void)bo; assert(!interruptible && no_wait && ticket == NULL);
 reserved = reserve_result == 0; return reserve_result;
}
static int radeon_bo_reserve(struct radeon_bo *bo, bool interruptible) {
 (void)bo; (void)interruptible; reserved = reserve_result == 0; return reserve_result;
}
static int radeon_device_lock_hardware(struct radeon_device *device) {
 (void)device; admitted = admission_result == 0; return admission_result;
}
static void radeon_device_unlock_hardware(struct radeon_device *device) {
 (void)device; assert(admitted); admitted = false;
}
static void radeon_bo_unreserve(struct radeon_bo *bo) { (void)bo; assert(reserved); reserved = false; }
static void radeon_bo_unpin(struct radeon_bo *bo) { assert(reserved && admitted); assert(bo->pins == 1); --bo->pins; }
#define drm_gem_object_put(object) do { assert((object)->refs == 1); --(object)->refs; ++reference_puts; } while (0)
#define kfree(object) do { (void)(object); ++frees; } while (0)
static void queue_delayed_work(void *queue, struct work_struct *work, int delay) {
 (void)queue; (void)work; assert(delay == 100); ++queued;
}
"""

TEST = r"""
int main(void) {
 struct radeon_device device = {.target = true};
 struct radeon_bo old = {.tbo.base.refs = 1, .pins = 1};
 struct radeon_bo new = {.tbo.base.refs = 1};
 struct radeon_flip_work work = {.rdev = &device, .old_rbo = &old, .new_rbo = &new};
 reserve_result = -EBUSY;
 radeon_unpin_work_func(&work.unpin_work);
 assert(errors == 0 && queued == 1 && reference_puts == 0 && frees == 0);
 assert(device.rs4xx_flip_reserve_busy == 1 && device.rs4xx_flip_retained_pending == 1);
 assert(device.rs4xx_flip_retained_total == 1 && old.pins == 1);
 work.retained.linked = false;
 radeon_flip_work_add_retained(&work);
 assert(device.rs4xx_flip_retained_pending == 1 && device.rs4xx_flip_retained_total == 1);
 reserve_result = -EIO;
 assert(radeon_flip_work_release_old(&work) == -EIO);
 assert(errors == 1 && reference_puts == 0 && old.pins == 1);
 reserve_result = 0; admission_result = -EBUSY;
 assert(radeon_flip_work_release_old(&work) == -EBUSY);
 assert(errors == 2 && !reserved && !admitted && reference_puts == 0);
 assert(device.rs4xx_flip_admission_refused == 1 && device.rs4xx_flip_reserve_busy == 1);
 admission_result = -EIO;
 assert(radeon_flip_work_release_old(&work) == -EIO);
 assert(errors == 3 && old.pins == 1 && !reserved);
 admission_result = 0;
 assert(radeon_flip_work_release_old(&work) == 0);
 assert(reference_puts == 2 && frees == 1 && old.pins == 0 && !reserved && !admitted);
 assert(device.rs4xx_flip_retained_released == 1 && device.rs4xx_flip_retained_pending == 0);
 printf("PASS: reservation retry, error separation, and exact retained release");
 return 0;
}
"""


def run_fixture(source):
    helpers = "\n\n".join(function_source(source, name) for name in FUNCTIONS)
    with tempfile.TemporaryDirectory(prefix="radeon-flip-cleanup-") as temporary:
        root = Path(temporary)
        code = root / "test.c"
        code.write_text(PREAMBLE + helpers + TEST)
        compile_result = subprocess.run(
            [
                "cc",
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                str(code),
                "-o",
                str(root / "test"),
            ],
            capture_output=True,
            text=True,
        )
        if compile_result.returncode:
            raise RuntimeError(compile_result.stderr)
        return subprocess.run([str(root / "test")], capture_output=True, text=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    source = (root / "drivers/gpu/drm/radeon/radeon_display.c").read_text()
    result = run_fixture(source)
    if result.returncode:
        raise RuntimeError(result.stderr)
    print(result.stdout)
    if args.selftest:
        mutations = [
            ("busy classification", "r == -EBUSY", "r != -EBUSY"),
            ("retained accounting", "if (!work->retained_accounted)", "if (true)"),
            (
                "pending release",
                "atomic_dec(&work->rdev->rs4xx_flip_retained_pending);",
                ";",
            ),
        ]
        for name, before, after in mutations:
            assert before in source
            result = run_fixture(source.replace(before, after, 1))
            if result.returncode == 0:
                raise RuntimeError("mutation survived: " + name)
            print("PASS: rejected " + name)


if __name__ == "__main__":
    main()
