import pathlib,re,subprocess,tempfile,unittest,os
SRC=(pathlib.Path(__file__).resolve().parents[1]/'install.sh').read_text()
ROOT=None
def extract(n):
 m=re.search(r'^'+n+r'\(\) \{[^\n]*\n.*?^\}',SRC,re.M|re.S)
 assert m,n
 return m[0].replace('/proc/', '${RUN}/proc/')
class Review(unittest.TestCase):
 def run_case(self,names,body):
  with tempfile.TemporaryDirectory(prefix='ss2022-independent-',dir=ROOT) as d:
   setup='''set -euo pipefail
RUN="$PWD"; BINARY_PATH="$RUN/bin"; INSTALL_DIR="$RUN/config"; CONFIG_PATH="$RUN/config/cfg"; VERSION_FILE="$RUN/config/ver"; SYSTEMD_SERVICE_FILE="$RUN/unit"; TMP_DIR="$RUN/snap"
SERVICE_START_ATTEMPTS=3; SERVICE_START_WAIT=0
error() { exit "${2:-1}"; }; warn() { :; }; success() { :; }; info() { :; }
systemctl() { return 99; }; pgrep() { return 99; }; kill() { exit 99; }; pkill() { exit 99; }; apt-get() { exit 99; }; sleep() { :; }; journalctl() { :; }
readlink() { return 99; }
'''
   p=pathlib.Path(d)/'test.sh';p.write_text(setup+'\n'+'\n'.join(extract(n) for n in names)+'\n'+body)
   r=subprocess.run(['bash',str(p)],cwd=d,capture_output=True,text=True,timeout=10)
   self.assertEqual(r.returncode,0,r.stdout+r.stderr)
 def test_mainpid_identity(self):
  self.run_case(['service_main_pid'],'''systemctl() { printf '12\\n'; }; readlink() { printf '%s\\n' "$BINARY_PATH"; }; [[ $(service_main_pid) == 12 ]]
readlink() { printf '%s (deleted)\\n' "$BINARY_PATH"; }; [[ $(service_main_pid) == 12 ]]
readlink() { printf '/foreign\\n'; }; if service_main_pid; then exit 80; fi
systemctl() { printf '0\\n'; }; if service_main_pid; then exit 80; fi
systemctl() { return 1; }; if service_main_pid; then exit 80; fi
''')
 def test_process_scan_status(self):
  self.run_case(['ss_rust_pids'],'''pgrep() { return 1; }; [[ -z $(ss_rust_pids) ]]
pgrep() { return 2; }; if ss_rust_pids; then exit 80; else [[ $? == 2 ]]; fi
pgrep() { printf '12 BAD\\n'; }; readlink() { printf /foreign; }; if ss_rust_pids; then exit 80; else [[ $? == 2 ]]; fi
''')
 def test_process_scan_mixed_identity(self):
  self.run_case(['ss_rust_pids'],'''pgrep() { printf '12\\n13\\n14\\n'; }
readlink() { case "$1" in */12/*) printf '%s' "$BINARY_PATH";; */13/*) printf /foreign;; */14/*) printf '%s (deleted)' "$BINARY_PATH";; esac; }
[[ $(ss_rust_pids) == $'12\\n14' ]]
''')
 def test_readlink_failure_live_vs_gone(self):
  self.run_case(['ss_rust_pids'],'''pgrep() { printf '12\\n'; }; readlink() { return 1; }
[[ -z $(ss_rust_pids) ]]
mkdir -p "$RUN/proc/12"
if ss_rust_pids; then exit 80; else [[ $? == 2 ]]; fi
''')
 def test_identity_recheck_before_term(self):
  self.run_case(['ss_rust_pids','stop_residual_processes'],'''pgrep() { printf '12\\n'; }
readlink() { if [[ -e "$RUN/seen" ]]; then printf /foreign; else : > "$RUN/seen"; printf '%s' "$BINARY_PATH"; fi; }
kill() { exit 80; }
stop_residual_processes
''')
 def test_term_and_recheck(self):
  self.run_case(['ss_rust_pids','stop_residual_processes'],'''pgrep() { [[ ! -e "$RUN/stopped" ]] || return 1; printf '12\\n'; }
readlink() { printf '%s' "$BINARY_PATH"; }
kill() { [[ "$*" == '-TERM 12' ]]; : > "$RUN/stopped"; }
stop_residual_processes; [[ -e "$RUN/stopped" ]]
''')
 def test_termination_fail_closed(self):
  for mode in ('killfail','stubborn'):
   self.run_case(['ss_rust_pids','stop_residual_processes'],'''mkdir -p "$RUN/proc/12"
pgrep() { printf '12\\n'; }; readlink() { printf '%s' "$BINARY_PATH"; }
kill() { return '''+('1' if mode=='killfail' else '0')+'''; }
if stop_residual_processes; then exit 80; fi
''')
 def test_pid_change_rejects_start(self):
  self.run_case(['service_main_pid','manage_service'],'''touch "$SYSTEMD_SERVICE_FILE"
systemctl() { if [[ "$1" == show ]]; then if [[ -e "$RUN/seen" ]]; then printf '13\\n'; else : > "$RUN/seen"; printf '12\\n'; fi; else return 0; fi; }
readlink() { printf '%s' "$BINARY_PATH"; }
if (manage_service restart); then exit 80; else [[ $? == 1 ]]; fi
[[ -f "$RUN/seen" ]]
''')
 def test_restore_metadata_and_atomic_inode(self):
  self.run_case(['restore_install_state'],'''mkdir -p "$TMP_DIR" "$INSTALL_DIR"
BACKUP_ACTIVE=true
for n in binary version config service; do printf 'old-%s' "$n" > "$TMP_DIR/old-$n"; chmod 600 "$TMP_DIR/old-$n"; touch -t 202001020304 "$TMP_DIR/old-$n"; done
for p in "$BINARY_PATH" "$VERSION_FILE" "$CONFIG_PATH" "$SYSTEMD_SERVICE_FILE"; do printf new > "$p"; done
old_inode=$(stat -c %i "$BINARY_PATH")
systemctl() { return 0; }
restore_install_state
[[ $(stat -c %i "$BINARY_PATH") != "$old_inode" ]]
for pair in "binary:$BINARY_PATH" "version:$VERSION_FILE" "config:$CONFIG_PATH" "service:$SYSTEMD_SERVICE_FILE"; do n=${pair%%:*}; p=${pair#*:}; cmp "$TMP_DIR/old-$n" "$p"; [[ $(stat -c '%a %u %g %Y' "$TMP_DIR/old-$n") == $(stat -c '%a %u %g %Y' "$p") ]]; done
''')
if __name__=='__main__':unittest.main(verbosity=2)
