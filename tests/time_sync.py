"""Extracted installer functions; all clock/service/package calls are mocked."""
from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest

SOURCE = (Path(__file__).resolve().parents[1] / 'install.sh').read_text()


def function(name):
    match = re.search(r'^' + name + r'\(\).*?\n}', SOURCE, re.M | re.S)
    if not match:
        raise AssertionError(f'missing installer function: {name}')
    return match.group()


class TimeSync(unittest.TestCase):
    def run_sync(self, loaded='', active='', enabled='', fail='', os_type='debian'):
        with tempfile.TemporaryDirectory(prefix='ss2022-time-') as tmp:
            script = 'set -euo pipefail\n' + function('enable_time_sync') + '\n'
            script += r'''
info() { printf 'INFO %s\n' "$*"; }
success() { printf 'SUCCESS %s\n' "$*"; }
error() { printf 'ERROR %s\n' "$*"; exit 1; }
check_systemd() { :; }
detect_os() { printf '%s' "$OS_TYPE"; }
install_dependencies() {
 printf 'PACKAGE %s\n' "$*"
 [[ "$FAIL" != package ]] || return 1
 LOADED='chrony chronyd'
}
systemctl() {
 printf 'SYSTEMCTL %s\n' "$*" >&2
 local unit="$2"
 case "$1" in
 show) if [[ " $LOADED " == *" $unit "* ]]; then
   [[ "$unit" != chronyd || "$OS_TYPE" == centos ]] || unit=chrony
   [[ "$unit" != ntpsec ]] || unit=ntp
   printf 'LoadState=loaded\nId=%s.service\n' "$unit"
 else printf 'LoadState=not-found\nId=%s.service\n' "$unit"; fi ;;
 is-active) unit="${!#}"; [[ "$FAIL" != active-query ]] || return 1
   [[ "$FAIL" != inactive && " $ACTIVE " == *" $unit "* ]] || return 3 ;;
 is-enabled) unit="${!#}"; [[ " $ENABLED " == *" $unit "* ]] ;;
 enable) unit="${!#}"; [[ "$FAIL" != enable ]] || return 1; [[ "$*" != *--now* || "$OS_TYPE" != centos ]] ;;
 start) unit="${!#}"; [[ "$FAIL" != start ]] || return 1; ACTIVE="$ACTIVE $unit" ;;
 *) printf 'UNEXPECTED SERVICE CALL\n'; exit 99 ;;
 esac
}
chronyc() { printf 'CHRONYC %s\n' "$*"; [[ "$FAIL" != sync ]]; }
timedatectl() {
 printf 'TIMEDATECTL %s\n' "$*" >&2
 [[ "$FAIL" != query ]] || return 1
 if [[ "$OS_TYPE" == centos && "$1" == show ]]; then return 1; fi
 if [[ "$OS_TYPE" == centos ]]; then printf 'NTP synchronized: yes\n'
 elif [[ "$FAIL" == sync ]]; then printf 'NTPSynchronized=no\n'
 else printf 'NTPSynchronized=yes\n'; fi
}
sleep() { :; }
( enable_time_sync ) || exit $?
'''
            env = dict(os.environ, LOADED=loaded, ACTIVE=active, ENABLED=enabled,
                       FAIL=fail, OS_TYPE=os_type, TMPDIR=tmp)
            return subprocess.run(['bash', '-c', script], env=env, text=True,
                                  capture_output=True, timeout=10)

    def test_chrony_alias_is_not_a_conflict(self):
        p = self.run_sync(loaded='chrony chronyd', active='chrony chronyd')
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertNotIn('PACKAGE', p.stdout)

    def test_install_syncs_before_download_and_snapshot(self):
        with tempfile.TemporaryDirectory(prefix='ss2022-time-flow-') as tmp:
            script = 'set -euo pipefail\n' + function('install_flow') + r'''
SYSTEMD_SERVICE_FILE="$TMPDIR/absent.service"; BINARY_PATH="$TMPDIR/absent-bin"
DEFAULT_ENCRYPTION_METHOD=2022-blake3-aes-128-gcm
check_systemd() { :; }; detect_os() { echo debian; }; check_dependencies() { :; }
detect_arch() { echo aarch64; }
error() { echo "ERROR $*"; exit 1; }
enable_time_sync() { echo SYNC; return "${SYNC_FAILURE:-0}"; }
prepare_download() { echo DOWNLOAD; exit 42; }
backup_install_state() { echo SNAPSHOT; exit 99; }
( install_flow true 8388 key "$DEFAULT_ENCRYPTION_METHOD" 1.0.0 ) || exit $?
'''
            for failed in ('0', '1'):
                p = subprocess.run(['bash', '-c', script], text=True, capture_output=True,
                                   env=dict(os.environ, TMPDIR=tmp, SYNC_FAILURE=failed), timeout=10)
                self.assertIn('SYNC', p.stdout)
                self.assertNotIn('SNAPSHOT', p.stdout)
                if failed == '1':
                    self.assertNotIn('DOWNLOAD', p.stdout)
                    self.assertIn('ERROR', p.stdout)
                else:
                    self.assertLess(p.stdout.index('SYNC'), p.stdout.index('DOWNLOAD'))

    def test_menu_time_sync_returns_after_failure(self):
        with tempfile.TemporaryDirectory(prefix='ss2022-time-menu-') as tmp:
            script = 'set -euo pipefail\n' + function('main_menu').replace('< /dev/tty', '< /dev/null') + r'''
VERSION_FILE="$TMPDIR/absent-version"; SCRIPT_VERSION=test
C_CYAN=''; C_RESET=''; C_YELLOW=''; C_GREEN=''; C_RED=''; C_MAGENTA=''
cprintf() { printf "$@"; }; draw_divider() { :; }
menu_item() { printf '%s %s\n' "$2" "$3"; }
clear() { :; }; info() { echo "$*"; }; warn() { echo "$*"; }
on_exit() { :; }
enable_time_sync() { echo SYNC_CALLED; exit 1; }
n=0
read() {
 n=$((n+1))
 case "$n" in 1) choice=10 ;; 2) : ;; 3) choice=0 ;; *) exit 99 ;; esac
}
main_menu
'''
            p = subprocess.run(['bash', '-c', script], text=True, capture_output=True,
                               env=dict(os.environ, TMPDIR=tmp), timeout=10)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            self.assertIn('10. 时间同步', p.stdout)
            self.assertIn('SYNC_CALLED', p.stdout)
            self.assertEqual(p.stdout.count('管理脚本'), 2)

    def test_reuses_existing_daemons(self):
        for loaded, active, enabled, expected, os_type in [
            ('chrony systemd-timesyncd', 'systemd-timesyncd', '', 'systemd-timesyncd', 'debian'),
            ('chrony systemd-timesyncd', '', 'systemd-timesyncd', 'systemd-timesyncd', 'ubuntu'),
            ('systemd-timesyncd', '', '', 'systemd-timesyncd', 'debian'),
            ('chronyd', 'chronyd', '', 'chronyd', 'centos'),
            ('ntpd', 'ntpd', '', 'ntpd', 'centos'),
            ('ntp ntpsec', 'ntp', '', 'ntp', 'debian'),
        ]:
            with self.subTest(unit=expected, active=active):
                p = self.run_sync(loaded, active, enabled, os_type=os_type)
                self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
                self.assertNotIn('PACKAGE', p.stdout)
                self.assertIn('enable ' + expected, p.stderr)
                self.assertIn('SUCCESS', p.stdout)

    def test_centos_installs_chronyd(self):
        p = self.run_sync(os_type='centos')
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn('PACKAGE centos chrony', p.stdout)
        self.assertIn('enable chronyd', p.stderr)

    def test_conflicting_services_are_not_changed(self):
        p = self.run_sync('chrony systemd-timesyncd', 'chrony systemd-timesyncd')
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('多个时间同步服务', p.stdout)
        self.assertNotIn('enable', p.stderr)
        self.assertNotIn('PACKAGE', p.stdout)

    def test_active_probe_error_cannot_select_another_daemon(self):
        p = self.run_sync('chrony systemd-timesyncd', 'systemd-timesyncd', fail='active-query')
        self.assertNotEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn('读取时间同步服务运行状态失败', p.stdout)
        self.assertNotIn('SYSTEMCTL enable ', p.stderr)
        self.assertNotIn('SYSTEMCTL start ', p.stderr)

    def test_failures_never_claim_success(self):
        for loaded, active, failure in [
            ('', '', 'package'), ('chrony', '', 'enable'),
            ('chrony', '', 'start'), ('chrony', '', 'inactive'), ('chrony', 'chrony', 'sync'),
            ('systemd-timesyncd', '', 'sync'), ('systemd-timesyncd', '', 'query'),
        ]:
            with self.subTest(unit=loaded, failure=failure):
                p = self.run_sync(loaded, active, fail=failure)
                self.assertNotEqual(p.returncode, 0, p.stdout + p.stderr)
                self.assertIn('ERROR', p.stdout)
                self.assertNotIn('SUCCESS', p.stdout)

    def test_noninteractive_dispatch_reaches_default_sync(self):
        with tempfile.TemporaryDirectory(prefix='ss2022-time-cli-') as tmp:
            script = ('set -euo pipefail\n' + function('main') + '\n' + function('install_flow') + r'''
DEFAULT_ENCRYPTION_METHOD=2022-blake3-aes-128-gcm
SYSTEMD_SERVICE_FILE="$TMPDIR/absent.service"; BINARY_PATH="$TMPDIR/absent-bin"
check_root() { :; }; init_temp_dir() { :; }
validate_port() { :; }; validate_password() { :; }; get_key_bytes() { echo 16; }
has_installation_residue() { return 1; }
info() { :; }; error() { echo "ERROR $*"; exit 1; }
check_systemd() { :; }; detect_os() { echo debian; }; check_dependencies() { :; }
enable_time_sync() { echo NONINTERACTIVE_DEFAULT_SYNC; exit 42; }
prepare_download() { echo UNEXPECTED_DOWNLOAD; exit 99; }
main --port 8388 --password AAAAAAAAAAAAAAAAAAAAAA==
''')
            p = subprocess.run(['bash', '-c', script], text=True, capture_output=True,
                               env=dict(os.environ, TMPDIR=tmp), timeout=10)
            self.assertEqual(p.returncode, 42, p.stdout + p.stderr)
            self.assertIn('NONINTERACTIVE_DEFAULT_SYNC', p.stdout)
            self.assertNotIn('UNEXPECTED_DOWNLOAD', p.stdout)

    def test_default_installs_chrony(self):
        p = self.run_sync()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn('PACKAGE debian chrony', p.stdout)
        self.assertIn('enable chrony', p.stderr)
        self.assertIn('CHRONYC waitsync 60 1 0 1', p.stdout)
        self.assertIn('SUCCESS', p.stdout)


if __name__ == '__main__':
    unittest.main()
