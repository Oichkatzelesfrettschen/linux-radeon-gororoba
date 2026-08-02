#!/bin/sh
# Classify a pull request's changed paths as build-relevant or
# documentation-only, so the kernel-build and packaging CI jobs run only when a
# change can alter a compiled object, a packaged input, or a reproduction
# oracle. Those jobs recompile radeon.ko and reproduce the tracked source and
# patch-effect manifests, and a Markdown file is neither compiled nor read by
# any reproduction gate, so a change touching only *.md files is
# documentation-only and the build jobs skip. Every other path, and an empty or
# unreadable change set, resolves to build so an unclassified input never
# silences the build gate. Reads paths on stdin, one per line; prints
# "build=true" or "build=false".

set -eu

classify() {
    saw_path=0
    saw_nondoc=0
    while IFS= read -r path || [ -n "$path" ]; do
        [ -n "$path" ] || continue
        saw_path=1
        case "$path" in
            *.md) ;;
            *) saw_nondoc=1 ;;
        esac
    done
    if [ "$saw_path" -eq 0 ] || [ "$saw_nondoc" -eq 1 ]; then
        echo "build=true"
    else
        echo "build=false"
    fi
}

self_test() {
    check() {
        want=$1
        got=$(printf '%s' "$2" | classify)
        if [ "$got" != "$want" ]; then
            echo "self-test: input <<$2>> expected $want, got $got" >&2
            exit 1
        fi
    }
    # Documentation-only: every changed path is Markdown.
    check build=false 'README.md'
    check build=false 'README.md
docs/dev-interface-surface-audit.md'
    # Build-relevant: a compiled source, a packaged input, a reproduction
    # oracle, a workflow, and a non-Markdown attestation each force the build.
    check build=true 'drivers/gpu/drm/radeon/r300.c'
    check build=true 'packaging/arch/radeon-unified-dkms/PKGBUILD'
    check build=true 'docs/base-delta-map.tsv'
    check build=true '.github/workflows/gates.yml'
    check build=true 'docs/profiled-source-attestations/radeon-unified-0.5-profiled-source.toml'
    check build=true 'README.md
drivers/gpu/drm/radeon/r300.c'
    # An empty change set resolves to build rather than silencing the gate.
    check build=true ''
    echo "classify_build_relevance self-test: PASS"
}

if [ "${1:-}" = "--self-test" ]; then
    self_test
    exit 0
fi
classify
