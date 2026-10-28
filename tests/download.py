"""Download and staging checks extract real functions; never run the installer."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from protocol import extract, SETUP


class DownloadTests(unittest.TestCase):
    def run_shell(self, names, body):
        with tempfile.TemporaryDirectory(prefix='ss2022-download-') as directory:
            fixture = Path(directory) / 'fixture.sh'
            fixture.write_text(SETUP + '\n' + '\n'.join(extract(name) for name in names) + '\n' + body)
            result = subprocess.run(['bash', str(fixture)], cwd=directory, text=True,
                                    capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def test_failed_preparation_never_stops_or_snapshots_service(self):
        self.run_shell(['install_flow'], r'''
check_systemd() { :; }
detect_os() { printf debian; }
check_dependencies() { :; }
detect_arch() { printf aarch64; }
get_latest_version() { printf 1.25.0; }
prepare_download() { printf 'prepare\n' >> calls; return 1; }
backup_install_state() { touch snapshotted; }
systemctl() { touch service-touched; }
stop_residual_processes() { touch processes-touched; }
download_and_install() { touch installed; }
create_systemd_service() { :; }
manage_service() { :; }
if (install_flow false '' '' "$DEFAULT_ENCRYPTION_METHOD" 1.25.0); then exit 80; fi
[[ $(cat calls) = prepare && ! -e snapshotted && ! -e service-touched && ! -e processes-touched && ! -e installed ]]
''')
    def test_download_before_snapshot_before_stop(self):
        self.run_shell(['install_flow'], r'''
check_systemd() { :; }
detect_os() { printf debian; }
check_dependencies() { :; }
detect_arch() { printf aarch64; }
prepare_download() { printf 'prepare\n' >> calls; }
backup_install_state() { printf 'snapshot\n' >> calls; }
systemctl() { [[ "$1" != stop ]] || printf 'stop\n' >> calls; }
stop_residual_processes() { printf 'processes\n' >> calls; }
download_and_install() { printf 'install\n' >> calls; }
manage_service() { :; }
touch "$SYSTEMD_SERVICE_FILE" "$BINARY_PATH"
(install_flow false '' '' "$DEFAULT_ENCRYPTION_METHOD" 1.25.0) || exit 80
[[ $(cat calls) = $'prepare\nsnapshot\nstop\nprocesses\ninstall' ]]
''')

    def test_config_failure_cleans_secret_staging(self):
        for fault in ('invalid-original', 'jq-write', 'chmod', 'rename'):
            with self.subTest(fault=fault):
                self.run_shell(['write_config'], 'FAULT=' + fault + r'''
mkdir -p "$INSTALL_DIR"
printf '{"server_port":8388,"password":"old","method":"old"}\n' > "$CONFIG_PATH"
[[ "$FAULT" != invalid-original ]] || printf invalid > "$CONFIG_PATH"
cp "$CONFIG_PATH" expected
jq() { if [[ "$FAULT" = jq-write && "$1" = -e ]]; then printf partial; return 1; fi; command jq "$@"; }
chmod() { [[ "$FAULT" != chmod ]] || return 1; command chmod "$@"; }
chown() { :; }
mv() { [[ "$FAULT" != rename ]] || return 1; command mv "$@"; }
if (write_config 8389 AAAAAAAAAAAAAAAAAAAAAA== 2022-blake3-aes-128-gcm); then exit 80; fi
cmp expected "$CONFIG_PATH"
[[ -z $(compgen -G "$CONFIG_PATH.tmp.*") ]]
''')

    def test_atomic_install_failure_cleans_owned_staging(self):
        for fault in ('install', 'binary-rename', 'version-write', 'version-rename'):
            with self.subTest(fault=fault):
                self.run_shell(['download_and_install'], 'FAULT=' + fault + r'''
mkdir -p config
printf old-program > "$BINARY_PATH"
printf '1.0.0\n' > "$VERSION_FILE"
printf new-program > verified
PREPARED_BINARY="$PWD/verified"
install() { [[ "$FAULT" != install ]] || return 1; command install "$@"; }
chmod() { [[ "$FAULT" != version-write ]] || return 1; command chmod "$@"; }
chown() { :; }
mv() {
    if [[ "$FAULT" = binary-rename && "${@: -1}" = "$BINARY_PATH" ]] ||
       [[ "$FAULT" = version-rename && "${@: -1}" = "$VERSION_FILE" ]]; then return 1; fi
    command mv "$@"
}
if (download_and_install 1.25.0); then exit 80; fi
[[ -z $(compgen -G "$BINARY_PATH.new.*") && -z $(compgen -G "$VERSION_FILE.new.*") ]]
''')

    def test_prepared_archive_is_verified_before_use(self):
        for fault in ('none', 'download', 'checksum', 'missing', 'unrunnable', 'wrong-version'):
            with self.subTest(fault=fault):
                self.run_shell(['prepare_download'], 'FAULT=' + fault + r'''
mkdir payload
printf '#!/bin/sh\nprintf "shadowsocks 1.25.0\\n"\n' > payload/ssserver
case "$FAULT" in
    unrunnable) printf '#!/bin/sh\nexit 7\n' > payload/ssserver;;
    wrong-version) printf '#!/bin/sh\nprintf "shadowsocks 1.0.0\\n"\n' > payload/ssserver;;
    missing) mv payload/ssserver payload/other;;
esac
tar -cJf payload.tar.xz -C payload .
# Production assets have top-level names, not ./ prefixes.
if [[ "$FAULT" != missing ]]; then tar -cJf payload.tar.xz -C payload ssserver; fi
sha256sum payload.tar.xz > payload.sha256
[[ "$FAULT" != checksum ]] || printf '%064d  payload.tar.xz\n' 0 > payload.sha256
download_file() {
    [[ "$FAULT" != download ]] || return 1
    if [[ "$2" = *.sha256 ]]; then cp payload.sha256 "$1"; else cp payload.tar.xz "$1"; fi
}
PREPARED_BINARY=stale
if [[ "$FAULT" = none ]]; then
    prepare_download 1.25.0 aarch64-unknown-linux-musl
    [[ -x "$PREPARED_BINARY" && $("$PREPARED_BINARY" --version) = 'shadowsocks 1.25.0' ]]
else
    if (prepare_download 1.25.0 aarch64-unknown-linux-musl); then exit 80; fi
fi
[[ ! -e "$BINARY_PATH" && ! -e "$VERSION_FILE" && ! -e "$CONFIG_PATH" ]]
''')

    def test_old_extraction_cannot_satisfy_missing_member(self):
        self.run_shell(['prepare_download'], r'''
printf '#!/bin/sh\nprintf "shadowsocks 1.25.0\\n"\n' > "$TMP_DIR/ssserver"
chmod 755 "$TMP_DIR/ssserver"
printf unrelated > other
tar -cJf payload.tar.xz other
sha256sum payload.tar.xz > payload.sha256
download_file() { if [[ "$2" = *.sha256 ]]; then cp payload.sha256 "$1"; else cp payload.tar.xz "$1"; fi; }
if (prepare_download 1.25.0 aarch64-unknown-linux-musl); then exit 80; fi
[[ ! -e "$BINARY_PATH" && ! -e "$VERSION_FILE" ]]
''')


if __name__ == '__main__':
    unittest.main(verbosity=2)
