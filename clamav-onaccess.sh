#!/usr/bin/env bash
#
# ClamAV Real-Time Protection Deployment
# Target: Debian / Ubuntu / Kali Linux (and derivatives via ID_LIKE)
# Components: clamd + clamonacc + freshclam + systemd
#
# Review WATCH_PATHS, EXCLUDE_GLOBS, PREVENTION, QUARANTINE, ENABLE_RELOAD and
# SOCKET_MODE before deployment.
# Test on a pilot machine before production rollout.
#
# Transaction note: on failure this script restores files and service state that it
# changes. APT package installation/upgrades and downloaded signature databases are
# not rolled back.

set -Eeuo pipefail
umask 027

readonly CONFIG="/etc/clamav/clamd.conf"
readonly FRESHCLAM_CONFIG="/etc/clamav/freshclam.conf"
readonly LOG_DIR="/var/log/clamav"
readonly ONACCESS_LOG="${LOG_DIR}/clamonacc.log"
readonly SERVICE="/etc/systemd/system/clamonacc.service"
readonly TEMP_DIR="/var/lib/clamav/clamd-tmp"
readonly BEGIN_MARK="# BEGIN MANAGED CLAMAV ON-ACCESS CONFIGURATION"
readonly END_MARK="# END MANAGED CLAMAV ON-ACCESS CONFIGURATION"
readonly AA_PROFILE="/etc/apparmor.d/usr.sbin.clamd"
readonly AA_LOCAL="/etc/apparmor.d/local/usr.sbin.clamd"
readonly SOCKET_DROPIN_DIR="/etc/systemd/system/clamav-daemon.socket.d"
readonly SOCKET_DROPIN_FILE="${SOCKET_DROPIN_DIR}/10-onaccess-hardening.conf"
readonly DAEMON_DROPIN_DIR="/etc/systemd/system/clamav-daemon.service.d"
readonly DAEMON_DROPIN_FILE="${DAEMON_DROPIN_DIR}/10-onaccess-resilience.conf"
readonly ALERT_UNIT="/etc/systemd/system/clamav-alert@.service"
readonly LOGROTATE_FILE="/etc/logrotate.d/clamonacc"
readonly BACKUP="${CONFIG}.pre-onaccess.$(date +%Y%m%d%H%M%S)"
readonly ROLLBACK_DIR="$(mktemp -d /var/tmp/clamav-onaccess-rollback.XXXXXX)"

# Customize these for your environment.
# /root, /dev/shm, /tmp and /var/tmp are the usual malware staging areas.
# Not covered by default: /run/user/* (per-login tmpfs containing FUSE mounts that
# root cannot traverse) and removable media (mount points appear and disappear, which
# leaves stale directory watches). Cover those with OnAccessMountPath or udev-triggered
# scans rather than OnAccessIncludePath.
WATCH_PATHS=(
    "/home"
    "/root"
    "/tmp"
    "/var/tmp"
    "/dev/shm"
)

# Noisy locations to exclude from on-access scanning. An exclusion only has an effect
# inside a watched path (WATCH_PATHS above); entries outside every watched path are
# ignored with a log message. Glob patterns are expanded once at deployment time, and
# directories that do not exist yet are skipped, so re-run the script after creating them.
# Every exclusion is a blind spot, so none are enabled by default. ~/.cache is a common
# malware staging location; enable it only if it causes measurable load. VM and
# container storage is not watched by default; if you add such a path to WATCH_PATHS,
# exclude its noisy subdirectories here.
EXCLUDE_GLOBS=(
    # "/home/*/.cache"
    # "/root/.cache"
)

# "yes" blocks access to files detected as malicious; "no" only reports, and cannot be
# combined with QUARANTINE="yes" (quarantine moves files, which is not report-only).
PREVENTION="yes"

# "yes" (requires PREVENTION="yes") makes clamonacc move detected files into
# QUARANTINE_DIR so that indexers,
# backup tools and users stop re-triggering denials on the same file. The directory
# must be outside every watched path, an absolute path without whitespace, and is
# created root:root 0700. "no" leaves detected files where they are.
QUARANTINE="yes"
QUARANTINE_DIR="/var/lib/clamav-quarantine"

# Optional extra command run as ROOT when clamd or clamonacc enters the failed state, in
# addition to the critical syslog entry (tag "clamav-alert"). It is placed in a systemd
# ExecStart line, not a shell: give an absolute path to an executable file only (no
# arguments, quotes or % / $ characters). It receives one argument, the failed unit's
# name (for example "clamonacc.service"). The file and its directory must be owned by
# root and not group/world-writable. For anything more elaborate, use a wrapper script.
# A failure of this command is ignored. Example:
#   ALERT_COMMAND="/usr/local/sbin/notify-secops"
ALERT_COMMAND=""

# Weekly rotations of the clamonacc log kept locally (26 is about 180 days). clamonacc
# writes this file itself (--log); unless you forward it to central logging with its own
# retention, treat it as the only copy. Check disk capacity before raising this.
LOG_RETENTION_WEEKS="26"

# Enables freshclam -> clamd signature reload notifications.
ENABLE_RELOAD="yes"

# With systemd socket activation, these permissions are applied by the socket unit.
# 0660 with SocketUser/SocketGroup clamav allows root and the clamav account/group.
SOCKET_MODE="0660"

CONFIG_CHANGED=0
TRANSACTION_STARTED=0
TMP_CONFIG=""
SELFTEST_DIR=""
ONACCESS_TEST_DIR=""
ONACC_LOG_OFFSET=0
ONACC_LOG_INODE=""
CLAMD_START_TS=""
CLAMONACC_START_TS=""
TEMP_DIR_CREATED=0
LOG_DIR_CREATED=0
ONACCESS_LOG_CREATED=0
SOCKET_DROPIN_DIR_CREATED=0
QUARANTINE_DIR_CREATED=0
ONACC_ACTION_ARGS=""
SELFTEST_QNAME=""
LOGGER_BIN=""
BACKUP_DIR_KEEP=0

declare -a VALID_PATHS=()
declare -a EXCLUDE_PATHS=()
declare -A SNAPSHOT_EXISTS=()
declare -A UNIT_WAS_ACTIVE=()
declare -A UNIT_WAS_ENABLED=()

log() { echo "[$(date '+%F %T')] $*"; }

die() {
    log "ERROR: $*"
    exit 1
}

snapshot_path() {
    local key="$1" path="$2"
    if [[ -e "$path" || -L "$path" ]]; then
        SNAPSHOT_EXISTS["$key"]=1
        cp -a -- "$path" "${ROLLBACK_DIR}/${key}"
    else
        SNAPSHOT_EXISTS["$key"]=0
    fi
}

restore_path() {
    local key="$1" path="$2"
    if [[ "${SNAPSHOT_EXISTS[$key]:-0}" == "1" ]]; then
        rm -rf -- "$path"
        cp -a -- "${ROLLBACK_DIR}/${key}" "$path"
    else
        rm -rf -- "$path"
    fi
}

capture_unit_state() {
    local unit="$1" active enabled
    active="no"
    enabled="unknown"
    systemctl is-active --quiet "$unit" && active="yes" || true
    if systemctl cat "$unit" >/dev/null 2>&1; then
        enabled="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
        [[ -n "$enabled" ]] || enabled="unknown"
    else
        enabled="absent"    # unit did not exist before this deployment
    fi
    UNIT_WAS_ACTIVE["$unit"]="$active"
    UNIT_WAS_ENABLED["$unit"]="$enabled"
}

restore_unit_enable_state() {
    local unit="$1" state="${UNIT_WAS_ENABLED[$1]:-unknown}"
    case "$state" in
        enabled) systemctl enable "$unit" >/dev/null 2>&1 || true ;;
        enabled-runtime) systemctl enable --runtime "$unit" >/dev/null 2>&1 || true ;;
        disabled) systemctl disable "$unit" >/dev/null 2>&1 || true ;;
        masked) systemctl mask "$unit" >/dev/null 2>&1 || true ;;
        masked-runtime) systemctl mask --runtime "$unit" >/dev/null 2>&1 || true ;;
        absent) : ;;    # handled by disable_new_units / remove_stale_enablement_links
        *) : ;;
    esac
}

restore_unit_active_state() {
    local unit="$1" state="${UNIT_WAS_ACTIVE[$1]:-no}"
    if [[ "$state" == "yes" ]]; then
        systemctl start "$unit" >/dev/null 2>&1 || true
    else
        systemctl stop "$unit" >/dev/null 2>&1 || true
    fi
}

# A unit that did not exist before the deployment must not keep an enablement symlink
# once its unit file is removed. Disable it while its unit file still exists...
disable_new_units() {
    local unit
    for unit in clamav-daemon.socket clamav-daemon.service clamav-freshclam.service clamonacc.service; do
        if [[ "${UNIT_WAS_ENABLED[$unit]:-unknown}" == "absent" ]]; then
            systemctl disable "$unit" >/dev/null 2>&1 || true
        fi
    done
}

# ...and remove any dangling *.wants symlink that survived (e.g. a partial "enable").
remove_stale_enablement_links() {
    local unit
    for unit in clamav-daemon.socket clamav-daemon.service clamav-freshclam.service clamonacc.service; do
        if [[ "${UNIT_WAS_ENABLED[$unit]:-unknown}" == "absent" ]]; then
            find /etc/systemd/system -maxdepth 2 -type l -name "$unit" -path '*.wants/*' -delete 2>/dev/null || true
        fi
    done
}

rollback() {
    local rc="$1"
    log "Deployment failed; attempting transactional rollback."
    # Stop every affected service before touching files. Otherwise a daemon started with
    # the new configuration keeps running after its config file is restored (starting an
    # already-running unit is a no-op). The socket goes before the daemon so it cannot
    # re-activate it.
    systemctl stop clamonacc.service 2>/dev/null || true
    systemctl stop clamav-freshclam.service 2>/dev/null || true
    systemctl stop clamav-daemon.socket 2>/dev/null || true
    systemctl stop clamav-daemon.service 2>/dev/null || true

    disable_new_units

    restore_path config "$CONFIG" || log "WARNING: could not restore $CONFIG"
    restore_path service "$SERVICE" || log "WARNING: could not restore $SERVICE"
    restore_path socket_dropin "$SOCKET_DROPIN_FILE" || log "WARNING: could not restore $SOCKET_DROPIN_FILE"
    restore_path daemon_dropin "$DAEMON_DROPIN_FILE" || log "WARNING: could not restore $DAEMON_DROPIN_FILE"
    restore_path alert_unit "$ALERT_UNIT" || log "WARNING: could not restore $ALERT_UNIT"
    restore_path logrotate "$LOGROTATE_FILE" || log "WARNING: could not restore $LOGROTATE_FILE"

    if [[ "${SOCKET_DROPIN_DIR_WAS_PRESENT:-no}" == "no" ]]; then
        rmdir "$SOCKET_DROPIN_DIR" 2>/dev/null || true
    fi
    if [[ "${DAEMON_DROPIN_DIR_WAS_PRESENT:-no}" == "no" ]]; then
        rmdir "$DAEMON_DROPIN_DIR" 2>/dev/null || true
    fi

    remove_stale_enablement_links
    systemctl daemon-reload 2>/dev/null || true

    # Restore enablement before active state. Socket activation must be restored first.
    restore_unit_enable_state clamav-daemon.socket
    restore_unit_enable_state clamav-daemon.service
    restore_unit_enable_state clamav-freshclam.service
    restore_unit_enable_state clamonacc.service

    restore_unit_active_state clamav-daemon.socket
    restore_unit_active_state clamav-daemon.service
    restore_unit_active_state clamav-freshclam.service
    restore_unit_active_state clamonacc.service

    if (( TEMP_DIR_CREATED )); then rmdir "$TEMP_DIR" 2>/dev/null || true; fi
    # rmdir leaves the directory in place if real detections were quarantined.
    if (( QUARANTINE_DIR_CREATED )); then rmdir "$QUARANTINE_DIR" 2>/dev/null || true; fi
    if (( ONACCESS_LOG_CREATED )); then rm -f "$ONACCESS_LOG"; fi
    if (( LOG_DIR_CREATED )); then rmdir "$LOG_DIR" 2>/dev/null || true; fi

    log "Rollback attempted. APT package changes and signature downloads were not reverted."
    log "Rollback snapshots: $ROLLBACK_DIR"
    BACKUP_DIR_KEEP=1
    return "$rc"
}

# Remove only this run's self-test artifact. SELFTEST_QNAME is unique per run (random
# suffix), so an unrelated quarantined file can never match.
remove_selftest_quarantine() {
    [[ "$QUARANTINE" == "yes" && -n "$SELFTEST_QNAME" && -d "$QUARANTINE_DIR" ]] || return 0
    find "$QUARANTINE_DIR" -maxdepth 1 -name "${SELFTEST_QNAME}*" -delete 2>/dev/null || true
}

cleanup() {
    local rc=$?
    [[ -z "$TMP_CONFIG" ]] || rm -f "$TMP_CONFIG"
    [[ -z "$SELFTEST_DIR" ]] || rm -rf "$SELFTEST_DIR"
    [[ -z "$ONACCESS_TEST_DIR" ]] || rm -rf "$ONACCESS_TEST_DIR"

    remove_selftest_quarantine

    if (( rc != 0 && TRANSACTION_STARTED )); then
        rollback "$rc" || true
    else
        rm -rf "$ROLLBACK_DIR"
    fi

    if (( BACKUP_DIR_KEEP )); then
        log "Preserving rollback snapshots at $ROLLBACK_DIR"
    fi
    return "$rc"
}
trap cleanup EXIT

is_within() {
    local child="${1%/}" parent="${2%/}"
    [[ "$child" == "$parent" || "$child" == "$parent/"* ]]
}

normalize_watch_paths() {
    local raw canonical existing skip
    VALID_PATHS=()

    for raw in "${WATCH_PATHS[@]}"; do
        [[ -d "$raw" ]] || { log "Skipping nonexistent path: $raw"; continue; }
        canonical="$(realpath -e -- "$raw")" ||
            die "Cannot canonicalize monitoring path: $raw"
        [[ "$canonical" != "/" ]] ||
            die "Monitoring the filesystem root is not supported (WATCH_PATHS entry: $raw)."

        skip=0
        for existing in "${VALID_PATHS[@]}"; do
            if [[ "$canonical" == "$existing" ]]; then
                log "Skipping duplicate monitoring path: $raw -> $canonical"
                skip=1
                break
            elif is_within "$canonical" "$existing"; then
                log "Skipping nested path $canonical; parent $existing is already monitored recursively."
                skip=1
                break
            elif is_within "$existing" "$canonical"; then
                log "Removing previously selected nested path $existing; parent $canonical covers it."
                local -a kept=()
                local item
                for item in "${VALID_PATHS[@]}"; do
                    [[ "$item" == "$existing" ]] || kept+=("$item")
                done
                VALID_PATHS=("${kept[@]}")
            fi
        done
        (( skip == 1 )) || VALID_PATHS+=("$canonical")
    done

    ((${#VALID_PATHS[@]} > 0)) || die "No valid monitoring directories."
}

validate_temp_path() {
    local temp_canonical watch
    temp_canonical="$(realpath -m -- "$TEMP_DIR")" ||
        die "Cannot canonicalize TEMP_DIR: $TEMP_DIR"

    for watch in "${VALID_PATHS[@]}"; do
        if is_within "$temp_canonical" "$watch" || is_within "$watch" "$temp_canonical"; then
            die "TEMP_DIR ($temp_canonical) overlaps watched path ($watch). Move one of them."
        fi
    done
}

# The quarantine directory must never be watched: a file moved into a watched
# directory would be scanned again and re-trigger the same detection.
validate_quarantine_path() {
    local q watch
    [[ "$QUARANTINE" == "yes" ]] || return 0

    [[ "$QUARANTINE_DIR" == /* ]] ||
        die "QUARANTINE_DIR must be an absolute path: $QUARANTINE_DIR"
    [[ "$QUARANTINE_DIR" != *[[:space:]]* ]] ||
        die "QUARANTINE_DIR must not contain whitespace: $QUARANTINE_DIR"

    q="$(realpath -m -- "$QUARANTINE_DIR")" ||
        die "Cannot canonicalize QUARANTINE_DIR: $QUARANTINE_DIR"
    [[ "$q" != "/" ]] || die "QUARANTINE_DIR must not be the filesystem root."

    for watch in "${VALID_PATHS[@]}"; do
        if is_within "$q" "$watch" || is_within "$watch" "$q"; then
            die "QUARANTINE_DIR ($q) overlaps watched path ($watch). Move one of them."
        fi
    done
}

# Expand EXCLUDE_GLOBS into canonical directories that live inside a watched path.
resolve_exclude_paths() {
    local pattern match canonical watch existing covered dup had_nullglob=0
    local IFS=
    EXCLUDE_PATHS=()

    shopt -q nullglob && had_nullglob=1
    shopt -s nullglob

    for pattern in "${EXCLUDE_GLOBS[@]}"; do
        # Unquoted on purpose: IFS is empty, so only globbing applies (no word splitting).
        # shellcheck disable=SC2206
        local -a matches=( $pattern )
        for match in "${matches[@]}"; do
            [[ -d "$match" ]] || continue
            canonical="$(realpath -e -- "$match")" || continue

            covered=0
            for watch in "${VALID_PATHS[@]}"; do
                if [[ "$canonical" == "${watch%/}" ]]; then
                    log "Ignoring exclusion $canonical: it would disable a whole watched path."
                    continue 2
                elif is_within "$canonical" "$watch"; then
                    covered=1
                    break
                fi
            done
            if (( covered == 0 )); then
                log "Ignoring exclusion $canonical: not inside any watched path."
                continue
            fi

            dup=0
            for existing in "${EXCLUDE_PATHS[@]}"; do
                if [[ "$existing" == "$canonical" ]]; then dup=1; break; fi
            done
            if (( dup == 0 )); then
                EXCLUDE_PATHS+=("$canonical")
                log "On-access exclusion: $canonical"
            fi
        done
    done

    (( had_nullglob )) || shopt -u nullglob
    return 0
}

# Count unique directories across non-overlapping canonical watch paths. A failed or
# timed-out traversal is reported as incomplete rather than silently undercounted.
check_inotify_capacity() {
    local list err path rc watches instances queued marks dirs=0 item
    list="$(mktemp /run/clamav-watchdirs.XXXXXX)"
    err="$(mktemp /run/clamav-find-errors.XXXXXX)"
    : > "$list"
    : > "$err"

    watches="$(cat /proc/sys/fs/inotify/max_user_watches 2>/dev/null || echo 0)"
    instances="$(cat /proc/sys/fs/inotify/max_user_instances 2>/dev/null || echo unknown)"
    queued="$(cat /proc/sys/fs/inotify/max_queued_events 2>/dev/null || echo unknown)"
    marks="$(cat /proc/sys/fs/fanotify/max_user_marks 2>/dev/null || echo unknown)"

    log "Counting directories under watched paths (120-second limit per path)..."
    for path in "${VALID_PATHS[@]}"; do
        rc=0
        timeout 120 find "$path" -type d -print0 >> "$list" 2>> "$err" || rc=$?
        if (( rc != 0 )); then
            cat "$err" >&2
            rm -f "$list" "$err"
            die "Directory traversal failed or timed out under $path; refusing an unreliable capacity estimate."
        fi
    done

    while IFS= read -r -d '' item; do
        dirs=$((dirs + 1))
    done < <(sort -zu "$list")

    rm -f "$list" "$err"
    log "inotify: unique_directories=${dirs} max_user_watches=${watches} max_user_instances=${instances} max_queued_events=${queued}"
    log "fanotify: max_user_marks=${marks} (reported for telemetry; not compared to directory count)."

    if [[ "$watches" =~ ^[0-9]+$ ]] && (( watches > 0 && dirs * 100 > watches * 80 )); then
        log "WARNING: ${dirs} directories exceed 80% of max_user_watches=${watches}."
        log "  Suggested temporary value: sysctl -w fs.inotify.max_user_watches=$((dirs * 2))"
        log "  Persist only after reviewing workload in /etc/sysctl.d/."
    fi
}

filter_managed_config() {
    local input="$1" output="$2"
    awk -v begin="$BEGIN_MARK" -v end="$END_MARK" '
        $0 == begin {
            if (inside || seen_begin) { print "duplicate/nested BEGIN marker" > "/dev/stderr"; bad=1; exit 2 }
            inside=1; seen_begin=1; next
        }
        $0 == end {
            if (!inside) { print "END marker without BEGIN marker" > "/dev/stderr"; bad=1; exit 2 }
            inside=0; seen_end=1; next
        }
        !inside { print }
        END {
            if (inside) { print "unterminated managed block" > "/dev/stderr"; bad=1 }
            if (bad) exit 2
        }
    ' "$input" > "$output" || die "Malformed managed block markers in $CONFIG."
}

reconcile_managed_directives() {
    local file="$1"
    local tmp

    tmp="$(mktemp "${file}.XXXXXX")" ||
        die "Cannot create temporary configuration file."

    # Remove only the active directives this installer emits. Preserve comments, blank
    # lines and all other directives, including administrator-managed OnAccessExcludePath,
    # OnAccessExcludeUID and unrelated OnAccessExcludeUname lines. Installer-owned
    # watch scope (OnAccessIncludePath) is always regenerated from WATCH_PATHS.
    if ! awk '
        /^[[:space:]]*#/ || /^[[:space:]]*$/ {
            print
            next
        }

        {
            key=$1

            # Only the exact line this installer emits is replaced.
            if (key == "OnAccessExcludeUname") {
                if ($2 == "clamav") next
                print
                next
            }

            if (key ~ /^(OnAccessMaxFileSize|OnAccessPrevention|OnAccessExtraScanning|OnAccessIncludePath|TemporaryDirectory|EnableReloadCommand|LocalSocketMode|LogSyslog|LogTime)$/)
                next

            print
        }
    ' "$file" > "$tmp"; then
        rm -f "$tmp"
        die "Failed to reconcile existing ClamAV configuration."
    fi

    if ! cat "$tmp" > "$file"; then
        rm -f "$tmp"
        die "Failed to update ClamAV configuration."
    fi

    rm -f "$tmp"
    log "Existing managed directives reconciled successfully."
}

# Administrator-managed OnAccess* directives outside the managed block are preserved.
# List them, and refuse combinations that cannot work with the generated settings.
report_preserved_onaccess() {
    local file="$1" kept
    kept="$(grep -E '^[[:space:]]*OnAccess[A-Za-z0-9]*[[:space:]]' "$file" || true)"
    [[ -n "$kept" ]] || return 0

    log "Preserving administrator-managed on-access directives:"
    sed 's/^/    /' <<<"$kept"

    if grep -Eq '^[[:space:]]*OnAccessMountPath[[:space:]]' <<<"$kept"; then
        die "OnAccessMountPath cannot be combined with the OnAccessIncludePath directives this script generates. Remove it from $CONFIG or change the deployment."
    fi
    if grep -Eiq '^[[:space:]]*OnAccessDisableDDD[[:space:]]+(yes|true|1)' <<<"$kept"; then
        log "WARNING: OnAccessDisableDDD is enabled; new subdirectories will not be watched and the nested-directory self-test is expected to fail."
    fi
}

apparmor_active() {
    [[ -r /sys/module/apparmor/parameters/enabled ]] &&
        grep -qx 'Y' /sys/module/apparmor/parameters/enabled &&
        [[ -f "$AA_PROFILE" ]]
}

check_apparmor_static() {
    local rules
    command -v apparmor_parser >/dev/null ||
        die "AppArmor is active but apparmor_parser is unavailable; install apparmor-utils and retry."

    rules="$(apparmor_parser -p "$AA_PROFILE" 2>/dev/null)" ||
        die "Could not parse expanded AppArmor profile: $AA_PROFILE"

    if ! grep -Eq '^[[:space:]]*/var/lib/clamav/\*\*[[:space:]]+[a-z]*w[a-z]*,' <<<"$rules"; then
        die "Expanded AppArmor profile does not show write permission under /var/lib/clamav/**.
Inspect $AA_PROFILE and $AA_LOCAL; do not blindly add duplicate rules."
    fi
}

report_apparmor_confinement() {
    local pid attr loaded
    pid="$(systemctl show -p MainPID --value clamav-daemon.service 2>/dev/null || true)"
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || { log "WARNING: could not identify clamd PID for AppArmor check."; return 0; }
    attr="$(tr -d '\0' < "/proc/${pid}/attr/current" 2>/dev/null || true)"
    loaded="$(grep -E '^/usr/sbin/clamd ' /sys/kernel/security/apparmor/profiles 2>/dev/null || true)"
    log "AppArmor: clamd process state='${attr:-unknown}'; loaded profile='${loaded:-none}'"
    case "$attr" in
        *"(enforce)"*) ;;
        *"(complain)"*) log "WARNING: clamd profile is in complain mode; denials are logged, not enforced." ;;
        *) log "WARNING: clamd is not visibly confined by an AppArmor profile." ;;
    esac
}

check_apparmor_denials() {
    local mode="$1" hits
    hits="$(journalctl -k --since "$CLAMD_START_TS" --no-pager 2>/dev/null |
        grep -E 'apparmor="DENIED"' | grep -E 'comm="clamd"|profile="[^"]*clamd' || true)"
    [[ -n "$hits" ]] || return 0
    echo "$hits" | tail -n 20
    if [[ "$mode" == "strict" ]] && grep -q 'clamd-tmp' <<<"$hits"; then
        die "AppArmor denied clamd access to $TEMP_DIR."
    fi
    log "WARNING: AppArmor denied clamd operations since $CLAMD_START_TS."
}

selftest_clamd() {
    local out rc=0
    SELFTEST_DIR="$(mktemp -d /run/clamav-selftest.XXXXXX)"
    printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' |
        gzip -c > "${SELFTEST_DIR}/eicar.txt.gz"

    out="$("$CLAMDSCAN_BIN" --fdpass --no-summary "${SELFTEST_DIR}/eicar.txt.gz" 2>&1)" || rc=$?
    rm -rf "$SELFTEST_DIR"
    SELFTEST_DIR=""
    if (( rc != 1 )) || ! grep -q 'FOUND' <<<"$out"; then
        echo "$out"
        die "clamd self-test failed (expected EICAR detection inside gzip; rc=$rc)."
    fi
    log "clamd self-test passed: $out"
}

verify_socket() {
    local sock mode expected
    sock="$(awk '$1 == "LocalSocket" { print $2; exit }' "$CONFIG")"
    [[ -n "$sock" && -S "$sock" ]] ||
        die "clamd Unix socket not found (LocalSocket: ${sock:-unset})."

    mode="$(stat -c %a "$sock")"
    expected="${SOCKET_MODE#0}"
    log "clamd socket: $(stat -c '%A %U:%G %n' "$sock")"
    [[ "$mode" == "$expected" ]] ||
        die "Socket mode is $mode, expected $expected. Inspect systemctl cat clamav-daemon.socket."

    runuser -u clamav -- "$CLAMDSCAN_BIN" --ping 1 >/dev/null 2>&1 ||
        die "User clamav cannot reach clamd; freshclam notifications would fail."

    if [[ "$ENABLE_RELOAD" == "yes" ]]; then
        runuser -u clamav -- "$CLAMDSCAN_BIN" --reload >/dev/null 2>&1 ||
            die "Reload command failed as clamav; freshclam signature notifications will not work."
    fi

    if (( (8#$mode & 8#007) == 0 )); then
        if runuser -u nobody -- "$CLAMDSCAN_BIN" --ping 1 >/dev/null 2>&1; then
            die "An unprivileged user can still reach the clamd socket despite mode $mode."
        fi
        log "Verified: nobody cannot reach the clamd socket."
    elif [[ "$ENABLE_RELOAD" == "yes" ]]; then
        log "WARNING: socket is world-accessible while RELOAD is enabled."
    fi
}

onacc_log_since_start() {
    local inode size offset="$ONACC_LOG_OFFSET"
    inode="$(stat -c %i "$ONACCESS_LOG" 2>/dev/null || true)"
    size="$(stat -c %s "$ONACCESS_LOG" 2>/dev/null || echo 0)"
    if [[ "$inode" != "$ONACC_LOG_INODE" ]] || (( size < offset )); then
        offset=0
    fi
    tail -c "+$((offset + 1))" "$ONACCESS_LOG" 2>/dev/null || true
}


check_onaccess_errors() {
    local inv out known_race fatal

    inv="$(systemctl show -p InvocationID --value clamonacc.service 2>/dev/null || true)"

    out="$({
        if [[ -n "$inv" ]]; then
            journalctl --no-pager "_SYSTEMD_INVOCATION_ID=${inv}" 2>/dev/null || true
        else
            journalctl -u clamonacc.service --since "$CLAMONACC_START_TS" --no-pager 2>/dev/null || true
        fi
        onacc_log_since_start
    } | grep -E 'ERROR:' | sort -u || true)"

    [[ -n "$out" ]] || return 0

    # Known ClamAV DDD race: its directory-discovery thread attempts
    # to register its own short-lived quarantine staging directory.
    # Allow ONLY this exact error and path pattern.

    # Known ClamAV DDD race during quarantine moves:
    # a short-lived .clamav-unlink-* staging directory disappears
    # while the DDD thread attempts to register an inotify watch.
    known_race_re='ERROR: ClamInotif: (could not add element to hash table for .*/\.clamav-unlink-[^/[:space:]]+([[:space:]]|$)|watch descriptor issue when adding watch for .*/\.clamav-unlink-[^/[:space:]]+/\.rename-noreplace-(src|dst)([[:space:]]|$)|issue when adding watch for .*/\.clamav-unlink-[^/[:space:]]+/\.rename-noreplace-(src|dst)([[:space:]]|$))'

    known_race="$(
        printf '%s\n' "$out" |
        grep -E "$known_race_re" || true
    )"

    # Anything outside those narrowly identified transient paths remains fatal.
    fatal="$(
        printf '%s\n' "$out" |
        grep -Ev "$known_race_re" || true
    )"

    if [[ -n "$known_race" ]]; then
        log "WARNING: Known ClamAV DDD race involving .clamav-unlink-*; treating as non-fatal."
        printf '%s\n' "$known_race"
    fi

    if [[ -n "$fatal" ]]; then
        printf '%s\n' "$fatal"
        die "clamonacc reported unexpected errors; on-access coverage may be incomplete."
    fi

    return 0
}


selftest_onaccess() {
    local watch_dir="${VALID_PATHS[0]}" test_file read_rc=0 quarantined=0 i
    ONACCESS_TEST_DIR="$(mktemp -d "${watch_dir%/}/.clamav-onaccess-test.XXXXXX")"

    # Give DDD time to attach a watch to the newly-created nested directory.
    SELFTEST_QNAME="clamav-onaccess-selftest-$(date +%s)-$$-${RANDOM}${RANDOM}.txt"
    sleep 2
    test_file="${ONACCESS_TEST_DIR}/${SELFTEST_QNAME}"
    printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$test_file"

    if cat "$test_file" >/dev/null 2>&1; then
        read_rc=0
    else
        read_rc=$?
    fi

    if [[ "$PREVENTION" == "yes" && "$read_rc" -eq 0 ]]; then
        die "On-access EICAR read was NOT blocked in prevention mode."
    fi

    # With quarantine enabled, the infected file must end up in QUARANTINE_DIR. The move
    # can also win the race against the read above (the read then fails with ENOENT).
    if [[ "$QUARANTINE" == "yes" ]]; then
        for (( i = 0; i < 15; i++ )); do
            if compgen -G "${QUARANTINE_DIR}/${SELFTEST_QNAME}*" >/dev/null; then
                quarantined=1
                break
            fi
            sleep 1
        done
        (( quarantined )) ||
            die "Detected EICAR test file was not moved to ${QUARANTINE_DIR}; quarantine is not working."
        # Detect the known ClamAV #1883 duplicate-quarantine behaviour
        # before cleanup removes this run's test artifacts.
        local qfiles qcount

        qfiles="$(
            find "$QUARANTINE_DIR" \
                -maxdepth 1 -type f \
                -name "${SELFTEST_QNAME}*" \
                -printf '%f\n' 2>/dev/null || true
        )"

        qcount="$(printf '%s\n' "$qfiles" | awk 'NF { n++ } END { print n+0 }')"

        if (( qcount > 1 )); then
            log "WARNING: ${qcount} quarantine artifacts created for one EICAR test. Possible ClamAV #1883 duplicate-move race."
            printf '%s\n' "$qfiles" | sed 's/^/  /'
        fi

	remove_selftest_quarantine
        log "Quarantine test passed: infected file was moved to ${QUARANTINE_DIR} (test artifact removed)."
    fi

    if [[ "$PREVENTION" == "no" && "$read_rc" -ne 0 ]]; then
        die "On-access EICAR read unexpectedly failed in detection-only mode (rc=$read_rc)."
    fi

    if [[ "$PREVENTION" == "yes" ]]; then
        log "On-access prevention test passed: EICAR read was blocked in a newly-created nested directory."
    else
        log "On-access access-semantics test passed (detection-only); confirm the EICAR detection entry in clamonacc/clamd logs."
    fi
    rm -rf "$ONACCESS_TEST_DIR"
    ONACCESS_TEST_DIR=""
}

unit_prop() { systemctl show -p "$2" --value "$1" 2>/dev/null || true; }

expect_unit_prop() {
    local unit="$1" prop="$2" actual alt
    shift 2
    actual="$(unit_prop "$unit" "$prop")"
    for alt in "$@"; do
        if [[ "$actual" == "$alt" ]]; then return 0; fi
    done
    die "${unit}: ${prop} is '${actual:-unset}', expected one of: $*"
}

# Confirm systemd actually loaded the restart policy, start limits and failure-alert
# wiring of both units. Timespans are accepted in systemd's human or raw form because
# the format of "systemctl show" varies between versions.
verify_resilience() {
    local unit expected token found
    for unit in clamav-daemon clamonacc; do
        expect_unit_prop "${unit}.service" Restart on-failure
        expect_unit_prop "${unit}.service" StartLimitBurst 5
        expect_unit_prop "${unit}.service" StartLimitIntervalUSec 5min 300s 300000000

        # Exact match against each listed OnFailure unit (not a substring match).
        expected="clamav-alert@${unit}.service"
        found=0
        # shellcheck disable=SC2046
        for token in $(unit_prop "${unit}.service" OnFailure); do
            if [[ "$token" == "$expected" ]]; then found=1; fi
        done
        (( found )) ||
            die "${unit}.service OnFailure='$(unit_prop "${unit}.service" OnFailure)', expected ${expected}."
        [[ "$(unit_prop "$expected" LoadState)" == "loaded" ]] ||
            die "Failure alert instance ${expected} did not load; check $ALERT_UNIT."
    done
    expect_unit_prop clamav-daemon.service RestartUSec 5s 5000000
    expect_unit_prop clamonacc.service RestartUSec 10s 10000000
    log "Resilience verified: restart policy, start limits and failure alerts are loaded for clamd and clamonacc."
}

capture_original_states() {
    local unit
    for unit in clamav-daemon.socket clamav-daemon.service clamav-freshclam.service clamonacc.service; do
        capture_unit_state "$unit"
    done
    if [[ -d "$SOCKET_DROPIN_DIR" ]]; then
        SOCKET_DROPIN_DIR_WAS_PRESENT="yes"
    else
        SOCKET_DROPIN_DIR_WAS_PRESENT="no"
    fi
    if [[ -d "$DAEMON_DROPIN_DIR" ]]; then
        DAEMON_DROPIN_DIR_WAS_PRESENT="yes"
    else
        DAEMON_DROPIN_DIR_WAS_PRESENT="no"
    fi
}

# ------------------------------ Preflight ------------------------------------

[[ $EUID -eq 0 ]] || die "Run as root (sudo)."
command -v systemctl >/dev/null || die "systemd is required."
command -v realpath >/dev/null || die "realpath is required."
command -v timeout >/dev/null || die "timeout is required."
command -v sort >/dev/null || die "sort is required."
LOGGER_BIN="$(command -v logger)" || die "logger (util-linux/bsdutils) is required for failure alerts."
[[ "$PREVENTION" == "yes" || "$PREVENTION" == "no" ]] || die "PREVENTION must be yes or no."
[[ "$QUARANTINE" == "yes" || "$QUARANTINE" == "no" ]] || die "QUARANTINE must be yes or no."
[[ "$QUARANTINE" == "no" || "$PREVENTION" == "yes" ]] ||
    die "QUARANTINE=yes requires PREVENTION=yes (quarantine moves detected files; PREVENTION=no is report-only)."
[[ "$LOG_RETENTION_WEEKS" =~ ^[1-9][0-9]*$ ]] || die "LOG_RETENTION_WEEKS must be a positive integer."

if [[ -n "$ALERT_COMMAND" ]]; then
    alert_re='^/[A-Za-z0-9._+/-]+$'
    [[ "$ALERT_COMMAND" =~ $alert_re ]] ||
        die "ALERT_COMMAND must be an absolute path using only [A-Za-z0-9._+/-]: no arguments, quoting or systemd specifiers. Use a wrapper script instead."
    ALERT_COMMAND="$(realpath -e -- "$ALERT_COMMAND")" ||
        die "ALERT_COMMAND does not exist: $ALERT_COMMAND"
    [[ "$ALERT_COMMAND" =~ $alert_re ]] ||
        die "ALERT_COMMAND resolves to a path with unsupported characters: $ALERT_COMMAND"
    [[ -f "$ALERT_COMMAND" && -x "$ALERT_COMMAND" ]] ||
        die "ALERT_COMMAND must be an executable regular file: $ALERT_COMMAND"
    for alert_path in "$ALERT_COMMAND" "$(dirname -- "$ALERT_COMMAND")"; do
        [[ "$(stat -c %u "$alert_path")" == "0" ]] &&
            (( (8#$(stat -c %a "$alert_path") & 8#022) == 0 )) ||
            die "ALERT_COMMAND runs as root: $alert_path must be owned by root and not group/world-writable."
    done
fi
[[ "$ENABLE_RELOAD" == "yes" || "$ENABLE_RELOAD" == "no" ]] || die "ENABLE_RELOAD must be yes or no."
[[ "$SOCKET_MODE" =~ ^0?[0-7]{3}$ ]] || die "SOCKET_MODE must be an octal mode such as 0660."
SOCKET_MODE="0${SOCKET_MODE#0}"

# shellcheck disable=SC1091
. /etc/os-release
case " ${ID:-} ${ID_LIKE:-} " in
    *" debian "*|*" ubuntu "*|*" kali "*) ;;
    *) die "Unsupported distribution: ${ID:-unknown}" ;;
esac

log "Installing ClamAV packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y clamav clamav-daemon clamav-freshclam logrotate

CLAMD_BIN="$(command -v clamd)" || die "clamd not found."
CLAMONACC_BIN="$(command -v clamonacc)" || die "clamonacc not found."
CLAMDSCAN_BIN="$(command -v clamdscan)" || die "clamdscan not found."
[[ -f "$CONFIG" ]] || die "Missing $CONFIG"
[[ -f "$FRESHCLAM_CONFIG" ]] || die "Missing $FRESHCLAM_CONFIG"
command -v logrotate >/dev/null || die "logrotate is required: the clamonacc log must be rotated and retained."

if [[ "$ENABLE_RELOAD" == "yes" ]]; then
    grep -Eq '^[[:space:]]*NotifyClamd[[:space:]]+' "$FRESHCLAM_CONFIG" ||
        die "ENABLE_RELOAD=yes but NotifyClamd is not active in $FRESHCLAM_CONFIG."
fi

normalize_watch_paths
validate_temp_path
validate_quarantine_path
resolve_exclude_paths
check_inotify_capacity

# Preserve the package-provided config before any deployment edits.
cp -a "$CONFIG" "$BACKUP"
log "Configuration backup: $BACKUP"

capture_original_states
snapshot_path config "$CONFIG"
snapshot_path service "$SERVICE"
snapshot_path socket_dropin "$SOCKET_DROPIN_FILE"
snapshot_path daemon_dropin "$DAEMON_DROPIN_FILE"
snapshot_path alert_unit "$ALERT_UNIT"
snapshot_path logrotate "$LOGROTATE_FILE"

if [[ -d "$TEMP_DIR" ]]; then
    TEMP_DIR_CREATED=0
else
    TEMP_DIR_CREATED=1
fi
if [[ -d "$LOG_DIR" ]]; then LOG_DIR_CREATED=0; else LOG_DIR_CREATED=1; fi
if [[ -e "$ONACCESS_LOG" ]]; then ONACCESS_LOG_CREATED=0; else ONACCESS_LOG_CREATED=1; fi
if [[ "$QUARANTINE" == "yes" && ! -e "$QUARANTINE_DIR" ]]; then QUARANTINE_DIR_CREATED=1; fi

# Build the non-managed part of the config now: malformed markers or conflicting
# administrator directives abort here, before any service or file is touched.
log "Preparing clamd configuration..."
TMP_CONFIG="$(mktemp)"
filter_managed_config "$CONFIG" "$TMP_CONFIG"
reconcile_managed_directives "$TMP_CONFIG"
report_preserved_onaccess "$TMP_CONFIG"

# --------------------------- Deployment transaction -------------------------

TRANSACTION_STARTED=1

if [[ -e "$TEMP_DIR" ]]; then
    [[ -d "$TEMP_DIR" && ! -L "$TEMP_DIR" ]] ||
        die "TEMP_DIR exists but is not a real directory: $TEMP_DIR"
    temp_owner="$(stat -c %U "$TEMP_DIR")"
    temp_mode="$(stat -c %a "$TEMP_DIR")"
    [[ "$temp_owner" == "clamav" && "$temp_mode" == "700" ]] ||
        die "Existing TEMP_DIR must be owned by clamav with mode 0700 (found ${temp_owner}:${temp_mode}). Correct it manually or move it aside."
else
    install -d -o clamav -g clamav -m 0700 "$TEMP_DIR"
fi

if [[ "$QUARANTINE" == "yes" ]]; then
    if [[ -e "$QUARANTINE_DIR" ]]; then
        [[ -d "$QUARANTINE_DIR" && ! -L "$QUARANTINE_DIR" ]] ||
            die "QUARANTINE_DIR exists but is not a real directory: $QUARANTINE_DIR"
        quarantine_owner="$(stat -c %U "$QUARANTINE_DIR")"
        quarantine_mode="$(stat -c %a "$QUARANTINE_DIR")"
        [[ "$quarantine_owner" == "root" && "$quarantine_mode" == "700" ]] ||
            die "Existing QUARANTINE_DIR must be owned by root with mode 0700 (found ${quarantine_owner}:${quarantine_mode}). Correct it manually or move it aside."
    else
        install -d -o root -g root -m 0700 "$QUARANTINE_DIR"
    fi
    ONACC_ACTION_ARGS=" --move=${QUARANTINE_DIR}"
fi

if apparmor_active; then
    log "Checking expanded AppArmor profile for clamd..."
    check_apparmor_static
else
    log "AppArmor profile not active/present; skipping static profile check."
fi

if [[ -s "$TMP_CONFIG" ]] && [[ "$(tail -c 1 "$TMP_CONFIG" | wc -l)" -eq 0 ]]; then
    printf '\n' >> "$TMP_CONFIG"
fi
{
    printf '%s\n' "$BEGIN_MARK"
    echo "LogSyslog yes"
    echo "LogTime yes"
    echo "TemporaryDirectory ${TEMP_DIR}"
    echo "OnAccessMaxFileSize 5M"
    echo "OnAccessPrevention ${PREVENTION}"
    # Keep DDD enabled for recursive directory coverage.
    # Disable ExtraScanning to reduce duplicate create/move quarantine scans.
    echo "OnAccessExtraScanning no"

    echo "EnableReloadCommand ${ENABLE_RELOAD}"
    echo "LocalSocketMode ${SOCKET_MODE#0}"
    echo "OnAccessExcludeUname clamav"

    # Internal ClamAV quarantine staging directories are transient.
    # Exclude the exact directory; its descendants are excluded automatically.
    echo 'OnAccessExcludePath ^.*/\.clamav-unlink-[^/]+(/.*)?$'

    for path in "${VALID_PATHS[@]}"; do
        printf 'OnAccessIncludePath %s\n' "$path"
    done
    printf '%s\n' "$END_MARK"
} >> "$TMP_CONFIG"

install -o root -g root -m 0644 "$TMP_CONFIG" "$CONFIG"
rm -f "$TMP_CONFIG"
TMP_CONFIG=""

log "Preparing log directory..."
if [[ ! -d "$LOG_DIR" ]]; then
    install -d -o clamav -g adm -m 0750 "$LOG_DIR"
fi
if [[ ! -e "$ONACCESS_LOG" ]]; then
    install -o root -g adm -m 0640 /dev/null "$ONACCESS_LOG"
fi

log "Installing log rotation for ${ONACCESS_LOG}..."
# copytruncate: clamonacc does not reopen its log file on SIGHUP.
cat > "$LOGROTATE_FILE" <<EOF
${ONACCESS_LOG} {
    su root adm
    weekly
    rotate ${LOG_RETENTION_WEEKS}
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF
chmod 0644 "$LOGROTATE_FILE"
if ! logrotate_out="$(logrotate -d "$LOGROTATE_FILE" 2>&1)"; then
    echo "$logrotate_out"
    die "logrotate rejected $LOGROTATE_FILE; the clamonacc log would not be rotated or retained."
fi

log "Creating clamonacc systemd service..."
cat > "$SERVICE" <<EOF
[Unit]
Description=ClamAV On-Access Real-Time Scanner
Documentation=https://docs.clamav.net/manual/OnAccess.html
Requires=clamav-daemon.service
After=clamav-daemon.service
PartOf=clamav-daemon.service
StartLimitIntervalSec=300
StartLimitBurst=5
OnFailure=clamav-alert@%p.service

[Service]
Type=simple
ExecStartPre=${CLAMDSCAN_BIN} --ping 60:5
ExecStart=${CLAMONACC_BIN} --foreground --fdpass --config-file=${CONFIG} --log=${ONACCESS_LOG}${ONACC_ACTION_ARGS}
Restart=on-failure
RestartSec=10
TimeoutStartSec=360

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$SERVICE"

log "Installing clamd restart policy and failure-alert unit..."
# On-access scanning fails open: if clamd is down, file access is allowed unscanned.
# Restart clamd quickly, and raise an alert if it cannot be kept running
# (start rate limiting counts every start, including the first one and manual starts:
# a sixth start within 300 seconds is refused and the unit enters the failed state).
[[ -d "$DAEMON_DROPIN_DIR" ]] || install -d -m 0755 "$DAEMON_DROPIN_DIR"
cat > "$DAEMON_DROPIN_FILE" <<'EOF'
[Unit]
StartLimitIntervalSec=300
StartLimitBurst=5
OnFailure=clamav-alert@%p.service

[Service]
Restart=on-failure
RestartSec=5
EOF
chmod 0644 "$DAEMON_DROPIN_FILE"

{
    echo "[Unit]"
    echo "Description=ClamAV failure alert for %i"
    echo
    echo "[Service]"
    echo "Type=oneshot"
    echo "ExecStart=${LOGGER_BIN} -t clamav-alert -p auth.crit \"%i.service entered failed state - on-access scanning is NOT protecting this host (fail-open)\""
    if [[ -n "$ALERT_COMMAND" ]]; then
        echo "ExecStart=-${ALERT_COMMAND} %i.service"
    fi
} > "$ALERT_UNIT"
chmod 0644 "$ALERT_UNIT"

if systemctl cat clamav-daemon.socket >/dev/null 2>&1; then
    log "Configuring socket activation permissions: ${SOCKET_MODE}"
    [[ -d "$SOCKET_DROPIN_DIR" ]] || SOCKET_DROPIN_DIR_CREATED=1
    install -d -m 0755 "$SOCKET_DROPIN_DIR"
    cat > "$SOCKET_DROPIN_FILE" <<EOF
[Socket]
SocketUser=clamav
SocketGroup=clamav
SocketMode=${SOCKET_MODE}
EOF
fi

systemctl daemon-reload

log "Stopping services for a clean daemon restart..."
systemctl stop clamonacc.service 2>/dev/null || true
systemctl stop clamav-freshclam.service 2>/dev/null || true
systemctl stop clamav-daemon.service 2>/dev/null || true
systemctl stop clamav-daemon.socket 2>/dev/null || true

log "Updating signature database..."
freshclam || log "WARNING: freshclam failed; checking whether a usable existing database remains."
compgen -G "/var/lib/clamav/*.c[lv]d" >/dev/null ||
    die "No signature database found in /var/lib/clamav."

if systemctl cat clamav-daemon.socket >/dev/null 2>&1; then
    systemctl start clamav-daemon.socket
fi

CLAMD_START_TS="$(date '+%F %T')"
systemctl start clamav-daemon.service

log "Waiting for clamd to answer..."
"$CLAMDSCAN_BIN" --ping 60:5 ||
    die "clamd did not become ready."

verify_socket

if apparmor_active; then
    report_apparmor_confinement
fi

selftest_clamd
if apparmor_active; then
    check_apparmor_denials strict
fi

# Record log identity immediately before starting the new clamonacc invocation.
ONACC_LOG_OFFSET="$(stat -c %s "$ONACCESS_LOG")"
ONACC_LOG_INODE="$(stat -c %i "$ONACCESS_LOG")"
CLAMONACC_START_TS="$(date '+%F %T')"

systemctl start clamonacc.service
sleep 3
systemctl is-active --quiet clamonacc.service ||
    die "clamonacc failed to start. See journalctl -u clamonacc -n 50."

check_onaccess_errors
selftest_onaccess
check_onaccess_errors
verify_resilience

if apparmor_active; then
    check_apparmor_denials warn
fi

# Start the updater only after clamd is available; verify it remains active.
systemctl start clamav-freshclam.service
systemctl is-active --quiet clamav-freshclam.service ||
    die "clamav-freshclam.service is not active."

# Enable services only after functional checks have passed.
systemctl enable clamav-daemon.service clamav-freshclam.service clamonacc.service

log "Checking service health..."
for unit in clamav-daemon clamav-freshclam clamonacc; do
    systemctl --no-pager --full status "${unit}.service" || true
done

log "Deployment completed. Daemon detection and on-access ${PREVENTION} test passed."
echo
echo "Configuration backup: $BACKUP"
echo "On-access log: $ONACCESS_LOG (rotated weekly, ${LOG_RETENTION_WEEKS} archives kept, via $LOGROTATE_FILE)"
if [[ "$QUARANTINE" == "yes" ]]; then
    echo "Quarantine directory: $QUARANTINE_DIR"
else
    echo "Quarantine: disabled (detected files stay in place)"
fi
echo "Failure alerts: syslog tag 'clamav-alert' (journalctl -t clamav-alert)"
echo "Monitored paths:"
printf '  %s\n' "${VALID_PATHS[@]}"
if ((${#EXCLUDE_PATHS[@]} > 0)); then
    echo "Excluded paths:"
    printf '  %s\n' "${EXCLUDE_PATHS[@]}"
fi
echo
echo "Inspect logs with:"
echo "  tail -f $ONACCESS_LOG"
echo "  journalctl -u clamonacc -f"
echo "  journalctl -u clamav-daemon -f"
