#!/bin/bash
set -euo pipefail
ROOT="${SS_TEST_ROOT:?}"
RUN="$ROOT/runs/$1"
source "$ROOT/actual-functions.sh"
TMP_DIR="$RUN/tmp"; INSTALL_DIR="$RUN/config"; BINARY_PATH="$RUN/bin/ss-rust"; CONFIG_PATH="$INSTALL_DIR/config.json"; VERSION_FILE="$INSTALL_DIR/ver.txt"; SYSTEMD_SERVICE_FILE="$RUN/system/ss-rust.service"
BACKUP_ACTIVE=false; INSTALL_COMMITTED=false
DEFAULT_ENCRYPTION_METHOD=2022-blake3-aes-128-gcm
AES_KEY_BYTES=16; CHACHA_KEY_BYTES=32; MIN_PORT=1; MAX_PORT=65535
SERVICE_START_ATTEMPTS=5; SERVICE_START_WAIT=0
C_RESET=''; C_RED=''; C_GREEN=''; C_YELLOW=''; C_BLUE=''; C_CYAN=''; C_MAGENTA=''
# Every mutable filesystem operand is constrained to this scratch case.
guard_paths() { local a; for a in "$@"; do [[ "$a" != /* || "$a" == "$RUN/"* ]] || { printf 'UNSAFE PATH: %s\n' "$a" >&2; exit 99; }; done; }
rm() { guard_paths "$@"; command rm "$@"; }
cp() { guard_paths "$@"; if [[ ( "$CASE" == backup_failure && "$*" == *old-config* ) || ( "$CASE" == restore_failure && "$1" == -p && "$2" == "$TMP_DIR/old-config" ) ]]; then return 1; fi; command cp "$@"; }
install() { guard_paths "$@"; if [[ "$CASE" == restore_failure && "$*" == *old-config* ]]; then return 1; fi; command install "$@"; }
mv() { guard_paths "$@"; command mv "$@"; }
chmod() { guard_paths "$@"; command chmod "$@"; }
chown() { guard_paths "$@"; command chown "$@"; }
mkdir() { guard_paths "$@"; command mkdir "$@"; }
find() { guard_paths "$@"; command find "$@"; }
mktemp() { guard_paths "$@"; command mktemp "$@"; }
# No host services, processes, packages or network may be contacted.
systemctl() {
 printf '%s\n' "$*" >> "$RUN/systemctl.log"
 case "$1" in
 is-active)
   if [[ "$CASE" == transient_active ]]; then
     local n=0; [[ ! -f "$RUN/probes" ]] || n=$(<"$RUN/probes")
     n=$((n+1)); printf '%s\n' "$n" > "$RUN/probes"
     [[ $n -le 2 ]]
   elif [[ "$CASE" == inactive_after_restart ]]; then return 3
   else [[ -f "$RUN/active" ]]; fi ;;
 show) printf "4242\n" ;;
 is-enabled) [[ -f "$RUN/enabled" ]] ;;
 stop) [[ "$CASE" != fresh_stop_failure ]] || return 1; command rm -f "$RUN/active" ;;
 disable) command rm -f "$RUN/enabled" ;;
 enable) : > "$RUN/enabled" ;;
 start|restart)
   if [[ "$CASE" == restart_failure || "$CASE" == restore_failure || "$CASE" == modify_restart_failure || "$CASE" == mode_rollback ]]; then
     if [[ ! -f "$RUN/restart-failed" ]]; then : > "$RUN/restart-failed"; command rm -f "$RUN/active"; return 1; fi
   fi
   : > "$RUN/active" ;;
 daemon-reload|reset-failed|status) return 0 ;;
 *) printf 'unhandled systemctl %s\n' "$*" >&2; return 99 ;;
 esac
}
pgrep() { printf '%s\n' "$*" >> "$RUN/pgrep.log"; if [[ "$CASE" == pgrep_failure ]]; then return 2; else [[ -f "$RUN/orphan" ]] || return 1; printf '4243\n'; fi; }
pkill() { printf '%s\n' "$*" >> "$RUN/pkill.log"; command rm -f "$RUN/orphan"; }
readlink() { if [[ "$CASE" == foreign_process || "$CASE" == wrong_main ]]; then printf "/other/program\n"; else printf "%s\n" "$BINARY_PATH"; fi; }
kill() { printf "%s\n" "$*" >> "$RUN/kill.log"; [[ "$CASE" != kill_failure ]] || return 1; [[ "$CASE" != stubborn_process ]] || return 0; command rm -f "$RUN/orphan"; }
journalctl() { printf 'mock journal\n'; }
sleep() { printf 'sleep %s\n' "$*" >> "$RUN/actions.log"; :; }
apt-get() { printf 'FORBIDDEN apt\n' >&2; exit 99; }
yum() { exit 99; }; curl() { exit 99; }; wget() { exit 99; }
detect_os() { printf debian; }; detect_arch() { printf aarch64; }
check_dependencies() { :; }; get_latest_version() { printf 2.0.0; }
validate_version() { :; }; check_port_available() { :; }; view_config() { :; }
download_and_install() {
 printf 'download\n' >> "$RUN/actions.log"
 [[ "$CASE" != download_failure ]] || return 1
 mkdir -p "$INSTALL_DIR"
 printf 'NEW_BINARY\n' > "$BINARY_PATH.new"
 mv "$BINARY_PATH.new" "$BINARY_PATH"
 printf '%s\n' "$1" > "$VERSION_FILE"
}
generate_config() { write_config 8388 AAAAAAAAAAAAAAAAAAAAAA== "$DEFAULT_ENCRYPTION_METHOD"; }
# Redirect only prompt reads; real TSV parsing still uses builtin read.
read() { if [[ "$*" == *' -p '* || "$*" == '-p '* ]]; then local dest="${!#}"; case "$dest" in method_choice|new_password_input) printf -v "$dest" '';; new_port) printf -v "$dest" '8390';; choice) printf -v "$dest" 'y';; *) return 99;; esac; else builtin read "$@"; fi; }
CASE="$1"
case "$CASE" in
 stale_unit_dropin)
 command rm -f "$BINARY_PATH"
 ( trap 'on_exit' EXIT; install_flow true 8388 AAAAAAAAAAAAAAAAAAAAAA== "$DEFAULT_ENCRYPTION_METHOD" 2.0.0 ) || true ;;
 retained_dropin)
 ( trap 'on_exit' EXIT; install_flow false '' '' "$DEFAULT_ENCRYPTION_METHOD" 2.0.0 ) || true ;;
 foreign_install)
 CASE=foreign_process
 ( trap 'on_exit' EXIT; install_flow true 8388 AAAAAAAAAAAAAAAAAAAAAA== "$DEFAULT_ENCRYPTION_METHOD" 2.0.0 ) || true ;;
 fresh_rollback)
 ( trap 'on_exit' EXIT; backup_install_state; create_systemd_service; : > "$RUN/active"; error injected ) || true ;;
 transient_active|inactive_after_restart|wrong_main)
 ( trap 'on_exit' EXIT; manage_service restart ) || true
 if systemctl is-active --quiet ss-rust; then printf 'POSTCHECK_ACTIVE\n'; else printf 'POSTCHECK_INACTIVE\n'; fi ;;
 stopped_update)
 ( trap 'on_exit' EXIT; do_update ) || true ;;
 backup_failure|download_failure|restart_failure|restore_failure|mode_rollback)
 ( trap 'on_exit' EXIT; install_flow false '' '' "$DEFAULT_ENCRYPTION_METHOD" 2.0.0 ) || true ;;
 fresh_success|stale_dropin_success)
 ( trap 'on_exit' EXIT; install_flow true 8388 AAAAAAAAAAAAAAAAAAAAAA== "$DEFAULT_ENCRYPTION_METHOD" 2.0.0 ) || true ;;
 fresh_stop_failure)
 ( trap 'on_exit' EXIT; backup_install_state; create_systemd_service; : > "$RUN/active"; error injected ) || true ;;
 modify_success|modify_restart_failure)
 ( trap 'on_exit' EXIT; do_modify_config ) || true ;;
 orphan_uninstall|dropin_uninstall|normal_uninstall|pgrep_failure|kill_failure|stubborn_process|foreign_process)
 ( trap 'on_exit' EXIT; do_uninstall ) || true ;;
 orphan_cli_uninstall)
 ( trap 'on_exit' EXIT; run_uninstall_logic ) || true ;;
 repeated)
 ( trap 'on_exit' EXIT; install_flow false '' '' "$DEFAULT_ENCRYPTION_METHOD" 2.0.0 ) || true
 command rm -f "$CONFIG_PATH" "$RUN/active" "$RUN/enabled"
 CASE=download_failure
 ( trap 'on_exit' EXIT; install_flow false '' '' "$DEFAULT_ENCRYPTION_METHOD" 3.0.0 ) || true ;;
 keep_blocks_next)
 CASE=restore_failure
 ( trap 'on_exit' EXIT; install_flow false '' '' "$DEFAULT_ENCRYPTION_METHOD" 2.0.0 ) || true
 cp "$TMP_DIR/old-config" "$RUN/saved-snapshot"
 CASE=download_failure
 ( trap 'on_exit' EXIT; install_flow false '' '' "$DEFAULT_ENCRYPTION_METHOD" 3.0.0 ) || true ;;
 uninstall_install)
 ( trap 'on_exit' EXIT; do_uninstall ) || true
 ( trap 'on_exit' EXIT; install_flow true 8388 AAAAAAAAAAAAAAAAAAAAAA== "$DEFAULT_ENCRYPTION_METHOD" 2.0.0 ) || true ;;
 *) exit 99;;
esac
printf 'MENU_RETURNED\n'
