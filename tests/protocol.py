import unittest,pathlib,re,subprocess,tempfile,base64,urllib.parse
SRC=(pathlib.Path(__file__).resolve().parents[1]/'install.sh').read_text()
def extract(n):
 m=re.search(r'^'+n+r'\(\) \{[^\n]*\n.*?^\}',SRC,re.M|re.S);assert m,n;return m.group(0).replace(' < /dev/tty','')
SETUP=r'''set -euo pipefail
TMP_DIR="$PWD" INSTALL_DIR="$PWD/config" CONFIG_PATH="$PWD/config/config.json"
BINARY_PATH="$PWD/bin" SYSTEMD_SERVICE_FILE="$PWD/unit" VERSION_FILE="$PWD/version"
AES_KEY_BYTES=16 CHACHA_KEY_BYTES=32 MIN_PORT=1 MAX_PORT=65535 DEFAULT_PORT=8388
DEFAULT_ENCRYPTION_METHOD=2022-blake3-aes-128-gcm SCRIPT_VERSION=test
error() { printf 'ERROR %s\n' "$1" >&2; exit "${2:-1}"; }
info() { :; }; success() { :; }; warn() { :; }
'''
class Tests(unittest.TestCase):
 def run_shell(self,names,body):
  with tempfile.TemporaryDirectory(prefix='ss2022-fix-') as d:
   p=pathlib.Path(d)/'fixture.sh';p.write_text(SETUP+'\n'+'\n'.join(extract(n) for n in names)+'\n'+body)
   o=subprocess.run(['bash',str(p)],cwd=d,text=True,capture_output=True,timeout=15)
  self.assertEqual(o.returncode,0,o.stdout+o.stderr);return o
 def test_cli_residue_guard(self):
  key=base64.b64encode(bytes(16)).decode()
  self.run_shell(['main','get_key_bytes','has_installation_residue'],f'''
check_root() {{ :; }}
init_temp_dir() {{ :; }}
validate_port() {{ :; }}
validate_password() {{ :; }}
ss_rust_pids() {{ return 0; }}
mkdir -p "${{SYSTEMD_SERVICE_FILE}}.d"
install_flow() {{ exit 81; }}
if (main --port 8388 --password '{key}'); then exit 80; else [[ $? = 1 ]]; fi
''')
 def test_uninstall_cleans_before_reload(self):
  self.run_shell(['run_uninstall_logic'],r'''
systemctl() {
 case "$1" in is-active|is-enabled) return 1;; daemon-reload) [[ -f cleaned ]] || exit 81;; esac
}
stop_residual_processes() { :; }
cleanup_uninstall_residue() { touch cleaned; }
run_uninstall_logic
''')
 def test_fresh_cli_without_pgrep(self):
  self.run_shell(['has_installation_residue'],r'''
command() { if [[ "$*" = '-v pgrep' ]]; then return 1; fi; builtin command "$@"; }
ss_rust_pids() { return 2; }
if has_installation_residue install; then exit 80; fi
has_installation_residue || exit 80
''')
 def test_pgrep_dependency_mapping(self):
  for os_type,package in [('debian','procps'),('centos','procps-ng')]:
   o=self.run_shell(['install_dependencies'],f'''apt-get() {{ printf '%s\\n' "$*"; }}
yum() {{ printf '%s\\n' "$*"; }}
install_dependencies {os_type} pgrep
''')
   self.assertIn(package,o.stdout)
 def test_modify_port_probe_failure_aborts(self):
  self.run_shell(['do_modify_config'],r'''
load_config() { printf '8388\tAAAAAAAAAAAAAAAAAAAAAA==\t2022-blake3-aes-128-gcm\n'; }
validate_existing_config_values() { :; }
get_key_bytes() { printf 16; }
read() {
 if [[ "$*" = *current_method ]]; then builtin read "$@"; return; fi
 if [[ "$*" = *method_choice ]]; then method_choice='';
 elif [[ ! -e read-once ]]; then touch read-once; new_port=9000;
 else exit 81; fi
}
check_port_available() { exit 3; }
if (do_modify_config); then exit 80; else [[ $? = 3 ]]; fi
''')
 def test_generate_port_probe_failure_is_not_occupied(self):
  self.run_shell(['generate_config'],r'''
read() { if [[ -e read-once ]]; then exit 81; fi; touch read-once; port=8388; }
get_key_bytes() { printf 16; }
check_port_available() { exit 3; }
if (generate_config '' '' 2022-blake3-aes-128-gcm); then exit 80; else [[ $? = 3 ]]; fi
''')
 def test_invalid_method_exit_two(self):
  self.run_shell(['main','get_key_bytes'],r'''
check_root() { :; }
if (main --method invalid); then exit 80; else [[ $? = 2 ]]; fi
''')
 def test_port_queries_fail_closed(self):
  for tcp,udp,net,good in [(0,0,1,True),(1,0,1,False),(0,1,1,False),(1,1,0,True),(1,1,1,False)]:
   self.run_shell(['check_port_available'],f'''ss() {{ [[ "$*" = *-ltn* ]] && return {tcp}; return {udp}; }}
netstat() {{ return {net}; }}
if (check_port_available 8388); then {'true' if good else 'exit 80'}; else {'exit 80' if good else 'true'}; fi''')
 def test_port_occupied_rejected(self):
  for which in ['ss','netstat']:
   stub='ss() { printf "LISTEN 0 128 *:8388 *:*\\n"; }; netstat() { return 0; }' if which=='ss' else 'ss() { return 1; }; netstat() { printf "tcp 0 0 :::8388 :::* LISTEN\\n"; }'
   self.run_shell(['check_port_available'],stub+'\nif (check_port_available 8388); then exit 80; fi')
 def test_ipv6_boundaries(self):
  for ip,good in [('1::2:',False),(':1::2',False),('2001:db8::1:',False),('::',True),('::1',True),('2001:db8::',True),('::ffff:192.0.2.1',True),('1:2:3:4:5:6:7:8',True)]:
   self.run_shell(['validate_ipv4','validate_ipv6'],f"if validate_ipv6 '{ip}'; then {'true' if good else 'exit 80'}; else {'exit 80' if good else 'true'}; fi")
 def test_load_requires_single_object(self):
  import json
  cfg=json.dumps({'server_port':8388,'password':base64.b64encode(bytes(16)).decode(),'method':'2022-blake3-aes-128-gcm'})
  for value in [cfg+'\n'+cfg,'', '[]',cfg+'\nnull']:
   self.run_shell(['load_config'],f"mkdir -p \"$INSTALL_DIR\"; printf '%s' '{value}' > \"$CONFIG_PATH\"; if (load_config); then exit 80; fi")
  self.run_shell(['load_config'],f"mkdir -p \"$INSTALL_DIR\"; printf '%s' '{cfg}' > \"$CONFIG_PATH\"; load_config")
 def test_url_is_aead2022_sip002(self):
  for method,size in [('2022-blake3-aes-128-gcm',16),('2022-blake3-chacha20-poly1305',32)]:
   k=base64.b64encode(bytes([251])*size).decode()
   o=self.run_shell(['generate_ss_url'],f"generate_ss_url '[2001:db8::1]' 65535 '{k}' '{method}' '测试 + node'")
   u=urllib.parse.urlsplit(o.stdout.strip())
   self.assertEqual(urllib.parse.unquote(u.username or ''),method)
   self.assertEqual(urllib.parse.unquote(u.password or ''),k)
   self.assertEqual(u.hostname,'2001:db8::1');self.assertEqual(u.port,65535)
   self.assertEqual(urllib.parse.unquote(u.fragment),'测试 + node')
 def test_existing_key_rejects_bad_bits(self):
  for size in (16,32):
   k=base64.b64encode(bytes(size)).decode();bad=k.rstrip('=')[:-1]+'B'+k[len(k.rstrip('=')):]
   self.run_shell(['decode_base64','validate_password','validate_existing_password'],f"if (validate_existing_password '{bad}' {size}); then exit 80; fi")
 def test_existing_key_accepts_padding_variants(self):
  for size in (16,32):
   key=base64.b64encode(bytes(size)).decode()
   for k in {key,key.rstrip('='),key.rstrip('=')+'='}:
    self.run_shell(['decode_base64','validate_password','validate_existing_password'],f"(validate_existing_password '{k}' {size}) || exit 80")
 def test_existing_key_decoder_failure_rejected(self):
  self.run_shell(['validate_password','validate_existing_password'],r'''
decode_base64() { printf '1234567890123456'; return 1; }
if (validate_existing_password AAAAAAAAAAAAAAAAAAAAAA== 16); then exit 80; fi
''')
if __name__=='__main__':unittest.main(verbosity=2)
