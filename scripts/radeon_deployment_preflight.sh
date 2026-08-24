#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Read only deployment identity and ring health preflight for an RS480 family
# Radeon host.
#
# A clear verdict binds a clean source commit and its driver tree to the exact
# installed module metadata, then binds that installed module to the running
# module through srcversion. It also requires the target device, current boot
# journal, process wait channels, fresh evidence directory, and off host log
# path. Every probe reads. No probe writes hardware state, loads a module,
# resets a device, or opens a graphics context.
#
# gpu_parked has no operator readable sysfs or debugfs node. The reset path
# latches it when RS400 or RS480 reset recovery fails. The preflight therefore
# reads the current boot journal for the unique parking message.
#
# Usage: radeon_deployment_preflight.sh SOURCE_TREE EVIDENCE_DIR
#        radeon_deployment_preflight.sh --self-test
#
# Output contains one key=value line per fact and a final verdict. Exit 0 means
# that every required observation is present and clear. Exit 1 means that at
# least one condition blocks qualification. Exit 2 reports invocation failure.

set -u

blocking=0
report_file=
journal_file=

emit() {
    printf '%s=%s\n' "$1" "$2"
    if [ -n "${report_file}" ]; then
        printf '%s=%s\n' "$1" "$2" >>"${report_file}"
    fi
}

unavailable() {
    emit "$1" "unavailable($2)"
}

block() {
    printf 'BLOCKING %s\n' "$1"
    blocking=$((blocking + 1))
}

fact_value() {
    fact_key=$1
    awk -v fact_key="${fact_key}" '
        index($0, "=") > 0 && substr($0, 1, index($0, "=") - 1) == fact_key {
            count++
            value = substr($0, index($0, "=") + 1)
        }
        END {
            if (count != 1)
                exit 1
            print value
        }
    ' "${report_file}"
}

require_fact() {
    required_key=$1
    required_description=$2
    required_value=$(fact_value "${required_key}" 2>/dev/null) || required_value=
    case "${required_value}" in
        ''|unavailable\(*\))
            block "${required_description} is unavailable"
            return 1
            ;;
    esac
    return 0
}

require_value() {
    required_key=$1
    expected_value=$2
    required_description=$3
    actual_value=$(fact_value "${required_key}" 2>/dev/null) || actual_value=
    if [ "${actual_value}" != "${expected_value}" ]; then
        block "${required_description} is ${actual_value:-unavailable}, expected ${expected_value}"
        return 1
    fi
    return 0
}

require_match() {
    left_key=$1
    right_key=$2
    match_description=$3
    left_value=$(fact_value "${left_key}" 2>/dev/null) || left_value=
    right_value=$(fact_value "${right_key}" 2>/dev/null) || right_value=
    if [ -z "${left_value}" ] || [ "${left_value}" != "${right_value}" ]; then
        block "${match_description} does not match"
        return 1
    fi
    return 0
}

require_zero() {
    required_key=$1
    required_description=$2
    require_value "${required_key}" 0 "${required_description}"
}

is_lower_hex() {
    expected_length=$1
    candidate=$2
    printf '%s\n' "${candidate}" | grep -Eq "^[0-9a-f]{${expected_length}}$"
}

validate_report() {
    blocking=0

    require_fact kernel_release "kernel release" || :
    require_fact uname_version "kernel build identity" || :
    require_fact boot_id "boot identity" || :
    boot_id=$(fact_value boot_id 2>/dev/null) || boot_id=
    if ! printf '%s\n' "${boot_id}" | grep -Eq \
        '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'; then
        block "boot identity is not a UUID"
    fi
    require_fact hostname_class "host architecture" || :

    require_fact source_commit "source commit" || :
    source_commit=$(fact_value source_commit 2>/dev/null) || source_commit=
    if ! is_lower_hex 40 "${source_commit}"; then
        block "source commit is not a full object identity"
    fi
    require_fact source_branch "source branch" || :
    require_value source_worktree clean "source worktree" || :
    require_fact source_driver_tree "source driver tree" || :
    require_fact source_feature_policy_sha256 "source feature policy digest" || :
    require_fact source_upstream_base "source upstream base" || :
    source_driver_tree=$(fact_value source_driver_tree 2>/dev/null) || source_driver_tree=
    source_feature_policy_sha256=$(fact_value source_feature_policy_sha256 2>/dev/null) || \
        source_feature_policy_sha256=
    source_upstream_base=$(fact_value source_upstream_base 2>/dev/null) || source_upstream_base=
    if ! is_lower_hex 40 "${source_driver_tree}"; then
        block "source driver tree is not a full object identity"
    fi
    if ! is_lower_hex 64 "${source_feature_policy_sha256}"; then
        block "source feature policy digest is not a SHA256 identity"
    fi
    if ! is_lower_hex 40 "${source_upstream_base}"; then
        block "source upstream base is not a full object identity"
    fi
    require_fact source_has_gpu_parked "source parked path count" || :
    source_parked_count=$(fact_value source_has_gpu_parked 2>/dev/null) || source_parked_count=0
    case "${source_parked_count}" in
        *[!0-9]*|'') block "source parked path count is invalid" ;;
        0) block "source contains no parked path" ;;
    esac
    require_value source_cs_ioctl_checks_parked yes "command submission parked guard" || :

    require_value module_loaded yes "running Radeon module" || :
    require_fact module_srcversion "running module srcversion" || :
    for module_parameter in lockup_timeout dpm audio runpm; do
        require_fact "module_param_${module_parameter}" \
            "running module parameter ${module_parameter}" || :
    done
    require_value module_param_lockup_timeout 0 "automatic lockup reset policy" || :

    require_fact installed_module_path "installed module path" || :
    require_fact installed_module_srcversion "installed module srcversion" || :
    require_fact installed_module_vermagic "installed module vermagic" || :
    require_fact installed_module_build_profile "installed module build profile" || :
    require_fact installed_module_source_commit "installed module source commit" || :
    require_fact installed_module_driver_tree "installed module driver tree" || :
    require_fact installed_module_feature_policy_sha256 \
        "installed module feature policy digest" || :
    require_fact installed_module_upstream_base "installed module upstream base" || :
    require_value installed_module_has_parked yes "installed module parked path" || :
    require_value module_text_scan calibrated "installed module text scan" || :

    require_match module_srcversion installed_module_srcversion \
        "running and installed module srcversion" || :
    require_match source_commit installed_module_source_commit \
        "source and installed module commit" || :
    require_match source_driver_tree installed_module_driver_tree \
        "source and installed module driver tree" || :
    require_match source_feature_policy_sha256 installed_module_feature_policy_sha256 \
        "source and installed module feature policy" || :
    require_match source_upstream_base installed_module_upstream_base \
        "source and installed module upstream base" || :

    kernel_release=$(fact_value kernel_release 2>/dev/null) || kernel_release=
    installed_vermagic=$(fact_value installed_module_vermagic 2>/dev/null) || installed_vermagic=
    case "${installed_vermagic}" in
        "${kernel_release}"|"${kernel_release}"_*) ;;
        *) block "installed module vermagic does not name the running kernel" ;;
    esac
    installed_profile=$(fact_value installed_module_build_profile 2>/dev/null) || installed_profile=
    case "${installed_profile}" in
        prod|observe-dev|probe-dev|mutate-dev) ;;
        *) block "installed module build profile is invalid" ;;
    esac

    require_value target_device rs482_present "RS482 target device" || :
    require_fact pci_display_ids "PCI display identity" || :
    require_value process_wait_scan readable "process wait channel scan" || :
    require_zero process_wait_unreadable "unreadable process wait channels" || :
    require_zero radeon_fence_waiters "Radeon fence waiters" || :
    require_value process_state_scan readable "process state scan" || :
    require_fact uninterruptible_tasks "uninterruptible task count" || :

    require_value journal_readable yes "current boot kernel journal" || :
    require_zero journal_parked_signature "current boot parked signatures" || :
    require_zero journal_lockup_signature "current boot lockup signatures" || :
    require_zero journal_reset_signature "current boot reset signatures" || :

    require_value evidence_dir fresh "evidence directory" || :
    require_fact evidence_dir_path "evidence directory path" || :
    require_fact offbox_logging "off host logging" || :
    offbox_logging=$(fact_value offbox_logging 2>/dev/null) || offbox_logging=
    case "${offbox_logging}" in
        netconsole|serial_console) ;;
        *) block "off host logging is unavailable" ;;
    esac

    [ "${blocking}" -eq 0 ]
}

netconsole_console_active() {
    consoles_path=$1

    [ -r "${consoles_path}" ] || return 1
    awk '
        $1 ~ /^netcon[0-9]+$/ && $0 ~ /\(E[[:space:]]/ {
            active = 1
        }
        END {
            exit active ? 0 : 1
        }
    ' "${consoles_path}"
}

write_good_report() {
    good_commit=1111111111111111111111111111111111111111
    good_tree=2222222222222222222222222222222222222222
    good_policy=3333333333333333333333333333333333333333333333333333333333333333
    good_upstream=4444444444444444444444444444444444444444
    cat >"$1" <<EOF
kernel_release=7.1.4-1-cachyos
uname_version=fixture
boot_id=55555555-5555-5555-5555-555555555555
hostname_class=x86_64
source_commit=${good_commit}
source_branch=main
source_worktree=clean
source_driver_tree=${good_tree}
source_feature_policy_sha256=${good_policy}
source_upstream_base=${good_upstream}
source_has_gpu_parked=16
source_cs_ioctl_checks_parked=yes
module_loaded=yes
module_srcversion=ABC123
module_param_lockup_timeout=0
module_param_dpm=0
module_param_audio=-1
module_param_runpm=0
module_parked_sysfs_node=absent
installed_module_path=/lib/modules/fixture/radeon.ko
installed_module_srcversion=ABC123
installed_module_vermagic=7.1.4-1-cachyos_SMP_preempt_mod_unload_
installed_module_build_profile=probe-dev
installed_module_source_commit=${good_commit}
installed_module_driver_tree=${good_tree}
installed_module_feature_policy_sha256=${good_policy}
installed_module_upstream_base=${good_upstream}
installed_module_has_parked=yes
module_text_scan=calibrated
pci_display_ids=1002:5974,
target_device=rs482_present
process_wait_scan=readable
process_wait_unreadable=0
radeon_fence_waiters=0
process_state_scan=readable
uninterruptible_tasks=0
journal_readable=yes
journal_parked_signature=0
journal_lockup_signature=0
journal_reset_signature=0
journal_cs_reject_signature=0
evidence_dir_path=/tmp/evidence
evidence_dir=fresh
offbox_logging=netconsole
EOF
}

self_test() {
    self_test_root=$(mktemp -d "${TMPDIR:-/tmp}/radeon-preflight-selftest.XXXXXX") || exit 1
    trap 'rm -rf -- "${self_test_root}"' EXIT HUP INT TERM
    good_report="${self_test_root}/good.report"
    mutant_report="${self_test_root}/mutant.report"
    active_consoles="${self_test_root}/active-consoles"
    inactive_consoles="${self_test_root}/inactive-consoles"
    missing_consoles="${self_test_root}/missing-consoles"
    printf '%s\n' 'netcon0              -W- (E  Np  ) 0:0' >"${active_consoles}"
    printf '%s\n' 'netcon0              -W- (   Np  ) 0:0' >"${inactive_consoles}"

    if ! netconsole_console_active "${active_consoles}"; then
        echo "deployment preflight self test: active netconsole console rejected" >&2
        exit 1
    fi
    if netconsole_console_active "${inactive_consoles}"; then
        echo "deployment preflight self test: inactive netconsole console accepted" >&2
        exit 1
    fi
    if netconsole_console_active "${missing_consoles}"; then
        echo "deployment preflight self test: missing netconsole console accepted" >&2
        exit 1
    fi

    write_good_report "${good_report}"

    report_file=${good_report}
    if ! validate_report >/dev/null; then
        echo "deployment preflight self test: known good report failed" >&2
        exit 1
    fi

    expect_block() {
        mutant_key=$1
        mutant_value=$2
        awk -v key="${mutant_key}" -v value="${mutant_value}" '
            index($0, "=") > 0 && substr($0, 1, index($0, "=") - 1) == key {
                print key "=" value
                next
            }
            { print }
        ' "${good_report}" >"${mutant_report}"
        report_file=${mutant_report}
        if validate_report >/dev/null; then
            echo "deployment preflight self test: ${mutant_key} mutant cleared" >&2
            exit 1
        fi
    }

    expect_block boot_id 'unavailable(fixture)'
    expect_block source_commit invalid
    expect_block source_worktree dirty
    expect_block source_driver_tree aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    expect_block source_feature_policy_sha256 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    expect_block source_upstream_base cccccccccccccccccccccccccccccccccccccccc
    expect_block source_has_gpu_parked 0
    expect_block source_cs_ioctl_checks_parked no
    expect_block module_loaded no
    expect_block module_srcversion 'unavailable(fixture)'
    expect_block module_param_lockup_timeout 10
    expect_block module_param_dpm 'unavailable(fixture)'
    expect_block installed_module_path 'unavailable(fixture)'
    expect_block installed_module_srcversion DEF456
    expect_block installed_module_vermagic 6.18.38-2-cachyos_SMP_
    expect_block installed_module_build_profile unknown
    expect_block installed_module_source_commit aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    expect_block installed_module_has_parked no
    expect_block module_text_scan uncalibrated
    expect_block target_device rs482_absent
    expect_block process_wait_scan 'unavailable(fixture)'
    expect_block process_wait_unreadable 1
    expect_block radeon_fence_waiters 1
    expect_block process_state_scan 'unavailable(fixture)'
    expect_block journal_readable no
    expect_block journal_parked_signature 1
    expect_block journal_lockup_signature 1
    expect_block journal_reset_signature 1
    expect_block evidence_dir not_fresh
    expect_block offbox_logging none

    echo "radeon deployment preflight self test: PASS"
}

if [ "${1:-}" = "--self-test" ]; then
    [ "$#" -eq 1 ] || {
        echo "usage: $0 --self-test" >&2
        exit 2
    }
    self_test
    exit 0
fi

if [ "$#" -ne 2 ]; then
    echo "usage: $0 SOURCE_TREE EVIDENCE_DIR" >&2
    exit 2
fi

source_tree=$1
evidence_dir=$2
report_file=$(mktemp "${TMPDIR:-/tmp}/radeon-deployment-preflight.XXXXXX") || exit 2
journal_file="${report_file}.journal"
trap 'rm -f -- "${report_file}" "${journal_file}"' EXIT HUP INT TERM

echo "# host and boot identity"
emit kernel_release "$(uname -r)"
emit uname_version "$(uname -v | tr ' ' '_')"
if [ -r /proc/sys/kernel/random/boot_id ]; then
    emit boot_id "$(cat /proc/sys/kernel/random/boot_id)"
else
    unavailable boot_id "/proc/sys/kernel/random/boot_id unreadable"
fi
emit hostname_class "$(uname -m)"

echo "# source tree"
if [ -e "${source_tree}/.git" ] &&
    [ "$(git -C "${source_tree}" rev-parse --is-inside-work-tree 2>/dev/null)" = true ]; then
    source_commit=$(git -C "${source_tree}" rev-parse HEAD 2>/dev/null) || source_commit=
    source_branch=$(git -C "${source_tree}" rev-parse --abbrev-ref HEAD 2>/dev/null) || source_branch=
    source_status=$(git -C "${source_tree}" status --porcelain 2>/dev/null) || source_status=unreadable
    source_driver_tree=$(git -C "${source_tree}" \
        rev-parse HEAD:drivers/gpu/drm/radeon 2>/dev/null) || source_driver_tree=
    source_feature_policy_sha256=$(sha256sum \
        "${source_tree}/policy/build-features.toml" 2>/dev/null | awk '{print $1}')
    source_upstream_base=$(awk -F '"' \
        '/^commit[[:space:]]*=/ { print $2; exit }' \
        "${source_tree}/UPSTREAM_BASE.toml" 2>/dev/null)

    [ -n "${source_commit}" ] && emit source_commit "${source_commit}" || \
        unavailable source_commit "HEAD could not be resolved"
    [ -n "${source_branch}" ] && emit source_branch "${source_branch}" || \
        unavailable source_branch "branch could not be resolved"
    if [ -z "${source_status}" ]; then
        emit source_worktree clean
    else
        emit source_worktree dirty
    fi
    [ -n "${source_driver_tree}" ] && emit source_driver_tree "${source_driver_tree}" || \
        unavailable source_driver_tree "driver tree could not be resolved"
    [ -n "${source_feature_policy_sha256}" ] && \
        emit source_feature_policy_sha256 "${source_feature_policy_sha256}" || \
        unavailable source_feature_policy_sha256 "build feature policy unreadable"
    [ -n "${source_upstream_base}" ] && emit source_upstream_base "${source_upstream_base}" || \
        unavailable source_upstream_base "upstream base unreadable"
    emit source_has_gpu_parked \
        "$(grep -rl 'gpu_parked' "${source_tree}/drivers/gpu/drm/radeon/" \
            2>/dev/null | wc -l)"
    if grep -q 'gpu_parked' \
        "${source_tree}/drivers/gpu/drm/radeon/radeon_cs.c" 2>/dev/null; then
        emit source_cs_ioctl_checks_parked yes
    else
        emit source_cs_ioctl_checks_parked no
    fi
else
    unavailable source_commit "source tree is not a Git worktree"
fi

echo "# Radeon module"
if [ -d /sys/module/radeon ]; then
    emit module_loaded yes
    if [ -r /sys/module/radeon/srcversion ]; then
        emit module_srcversion "$(cat /sys/module/radeon/srcversion)"
    else
        unavailable module_srcversion "/sys/module/radeon/srcversion absent"
    fi
    for module_parameter in lockup_timeout dpm audio runpm; do
        if [ -r "/sys/module/radeon/parameters/${module_parameter}" ]; then
            emit "module_param_${module_parameter}" \
                "$(cat "/sys/module/radeon/parameters/${module_parameter}")"
        else
            unavailable "module_param_${module_parameter}" "parameter not exposed"
        fi
    done
    emit module_parked_sysfs_node absent
else
    emit module_loaded no
    unavailable module_srcversion "Radeon module not loaded"
fi

installed_module_path=$(modinfo -n radeon 2>/dev/null) || installed_module_path=
if [ -n "${installed_module_path}" ] && [ -r "${installed_module_path}" ]; then
    emit installed_module_path "${installed_module_path}"
    for module_field in srcversion vermagic gororoba_build_profile \
        gororoba_source_commit gororoba_driver_tree \
        gororoba_feature_policy_sha256 gororoba_upstream_base; do
        module_value=$(modinfo -F "${module_field}" "${installed_module_path}" 2>/dev/null) || module_value=
        output_field=$(printf '%s\n' "${module_field}" | sed 's/^gororoba_//')
        output_field="installed_module_${output_field}"
        [ -n "${module_value}" ] && emit "${output_field}" "$(printf '%s' "${module_value}" | tr ' ' '_')" || \
            unavailable "${output_field}" "module metadata absent"
    done

    module_text=
    case "${installed_module_path}" in
        *.zst)
            if command -v zstdcat >/dev/null 2>&1; then
                module_text=$(zstdcat "${installed_module_path}" 2>/dev/null | strings 2>/dev/null)
            fi
            ;;
        *.xz)
            if command -v xzcat >/dev/null 2>&1; then
                module_text=$(xzcat "${installed_module_path}" 2>/dev/null | strings 2>/dev/null)
            fi
            ;;
        *.gz)
            if command -v zcat >/dev/null 2>&1; then
                module_text=$(zcat "${installed_module_path}" 2>/dev/null | strings 2>/dev/null)
            fi
            ;;
        *) module_text=$(strings "${installed_module_path}" 2>/dev/null) ;;
    esac
    if [ -z "${module_text}" ]; then
        unavailable installed_module_has_parked "module text unreadable"
        emit module_text_scan uncalibrated
    else
        if printf '%s\n' "${module_text}" | \
            grep -q 'parking GPU, skipping resume-side access'; then
            emit installed_module_has_parked yes
        else
            emit installed_module_has_parked no
        fi
        if printf '%s\n' "${module_text}" | grep -q 'radeon_gem_object_create'; then
            emit module_text_scan calibrated
        else
            emit module_text_scan uncalibrated
        fi
    fi
else
    unavailable installed_module_path "modinfo found no readable Radeon module"
fi

echo "# device"
if command -v lspci >/dev/null 2>&1 && lspci_output=$(lspci -n 2>/dev/null); then
    pci_display_ids=$(printf '%s\n' "${lspci_output}" | \
        awk '$2 ~ /^0300:/ {print $3}' | tr '\n' ',')
    emit pci_display_ids "${pci_display_ids:-none}"
    case "${pci_display_ids}" in
        *1002:5974*) emit target_device rs482_present ;;
        *) emit target_device rs482_absent ;;
    esac
else
    unavailable pci_display_ids "lspci unavailable or failed"
    emit target_device rs482_unavailable
fi

echo "# ring health"
radeon_fence_waiters=0
process_wait_unreadable=0
if [ -r /proc/self/wchan ]; then
    emit process_wait_scan readable
    for process_path in /proc/[0-9]*; do
        if process_wait_channel=$(cat "${process_path}/wchan" 2>/dev/null); then
            :
        elif [ -d "${process_path}" ]; then
            process_wait_unreadable=$((process_wait_unreadable + 1))
            continue
        else
            continue
        fi
        case "${process_wait_channel}" in
            *radeon_fence*) radeon_fence_waiters=$((radeon_fence_waiters + 1)) ;;
        esac
    done
    emit process_wait_unreadable "${process_wait_unreadable}"
    emit radeon_fence_waiters "${radeon_fence_waiters}"
else
    unavailable process_wait_scan "/proc wait channels unreadable"
    unavailable process_wait_unreadable "/proc wait channels unreadable"
    unavailable radeon_fence_waiters "/proc wait channels unreadable"
fi

if process_states=$(ps -eo stat= 2>/dev/null); then
    emit process_state_scan readable
    uninterruptible_tasks=$(printf '%s\n' "${process_states}" | grep -c '^D' || true)
    emit uninterruptible_tasks "${uninterruptible_tasks:-0}"
else
    unavailable process_state_scan "ps failed"
    unavailable uninterruptible_tasks "ps failed"
fi

echo "# journal signatures for this boot"
if command -v journalctl >/dev/null 2>&1 &&
    journalctl -k -b >"${journal_file}" 2>/dev/null; then
    emit journal_readable yes
    journal_parked=$(grep -c 'parking GPU, skipping resume-side access' \
        "${journal_file}" || true)
    journal_lockup=$(grep -cE 'ring [0-9]+ stalled for more than|GPU lockup' \
        "${journal_file}" || true)
    journal_reset=$(grep -cE 'GPU reset (succeeded|failed)' \
        "${journal_file}" || true)
    journal_cs_reject=$(grep -cE 'Forbidden register|Buffer too small|No reloc for' \
        "${journal_file}" || true)
    emit journal_parked_signature "${journal_parked:-0}"
    emit journal_lockup_signature "${journal_lockup:-0}"
    emit journal_reset_signature "${journal_reset:-0}"
    emit journal_cs_reject_signature "${journal_cs_reject:-0}"
else
    emit journal_readable no
    unavailable journal_parked_signature "current boot kernel journal unreadable"
    unavailable journal_lockup_signature "current boot kernel journal unreadable"
    unavailable journal_reset_signature "current boot kernel journal unreadable"
    unavailable journal_cs_reject_signature "current boot kernel journal unreadable"
fi

echo "# evidence and logging"
emit evidence_dir_path "${evidence_dir}"
if [ ! -d "${evidence_dir}" ]; then
    emit evidence_dir absent
elif [ ! -r "${evidence_dir}" ] || [ ! -x "${evidence_dir}" ]; then
    emit evidence_dir unreadable
elif [ -e "${evidence_dir}/attempt.token" ]; then
    emit evidence_dir already_attempted
elif evidence_entry=$(find "${evidence_dir}" -mindepth 1 -maxdepth 1 \
    -print -quit 2>/dev/null); then
    if [ -n "${evidence_entry}" ]; then
        emit evidence_dir not_fresh
    else
        emit evidence_dir fresh
    fi
else
    emit evidence_dir unreadable
fi

if netconsole_console_active /proc/consoles && [ -r "${journal_file}" ] &&
    grep -q 'netconsole: network logging started' "${journal_file}"; then
    emit offbox_logging netconsole
elif [ -r /proc/cmdline ] &&
    grep -Eq '(^|[[:space:]])console=ttyS[0-9]+([,[:space:]]|$)' /proc/cmdline; then
    emit offbox_logging serial_console
else
    emit offbox_logging none
fi

echo "# containment rules in force"
emit rule_no_3d_positive_control_on_this_boot required
emit rule_direct_write_control_on_sacrificial_boot required
emit rule_cold_boot_before_successor required
emit rule_no_userspace_unwinder_on_fence_waiter required
emit rule_recovery_is_physical_power_cycle required

if validate_report; then
    echo "verdict=CLEAR conditions=0"
    exit 0
fi
echo "verdict=BLOCKED conditions=${blocking}"
exit 1
