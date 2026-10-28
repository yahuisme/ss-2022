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
 def test_help_and_argument_errors_never_reach_mutators(self):
  for args,code in [('--help',0),('-h',0),('--help extra',2),('--uninstall extra',2),('--unknown',2),('--port',2),('--password',2),('--method',2),('--port 8388',2)]:
   with self.subTest(args=args):
    self.run_shell(['main','get_key_bytes'],r'''
check_root() { :; }
init_temp_dir() { :; }
install_flow() { touch mutation; exit 81; }
run_uninstall_logic() { touch mutation; exit 81; }
main_menu() { touch mutation; exit 81; }
''' + f'if (main {args}); then rc=0; else rc=$?; fi\n[[ $rc = {code} && ! -e mutation ]]\n')
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
 def test_pgrep_and_ss_dependency_mapping(self):
  for os_type,package in [('debian','procps'),('centos','procps-ng'),('debian','iproute2'),('centos','iproute')]:
   o=self.run_shell(['install_dependencies'],f'''apt-get() {{ printf '%s\\n' "$*"; }}
yum() {{ printf '%s\\n' "$*"; }}
install_dependencies {os_type} {'pgrep' if package.startswith('procps') else 'ss'}
''')
   self.assertIn(package,o.stdout)
 def test_socket_dependency_added_only_when_both_tools_missing(self):
  self.run_shell(['check_dependencies','install_dependencies'],r'''
command() {
 if [[ "$1" = -v && ( "$2" = ss || "$2" = netstat ) ]]; then return 1; fi
 if [[ "$1" = -v ]]; then return 0; fi
 builtin command "$@"
}
apt-get() { printf '%s\\n' "$*"; }
non_interactive=true
check_dependencies debian | grep -F -- 'iproute2'
''')
 def test_socket_dependency_not_added_when_netstat_exists(self):
  self.run_shell(['check_dependencies','install_dependencies'],r'''
command() {
 if [[ "$1" = -v && "$2" = ss ]]; then return 1; fi
 if [[ "$1" = -v && "$2" = netstat ]]; then return 0; fi
 if [[ "$1" = -v ]]; then return 0; fi
 builtin command "$@"
}
apt-get() { printf '%s\\n' "$*"; }
non_interactive=true
check_dependencies debian
! grep -F -- 'iproute2' <<< "$(check_dependencies debian)"
''')
 def test_ipv4_lookup_uses_shared_validator(self):
  start=SRC.index('get_public_ip() {')
  end=SRC.index('\ndetect_os() {',start)
  body=SRC[start:end]
  self.assertIn('https://api6.ipify.org',body)
  self.assertNotIn('https://api64.ipify.org',body)
  self.assertIn('validate_ipv4 "$ip"',body)
  self.assertNotIn('local valid=true',body)
  self.assertNotIn('IFS=. read -ra octets',body)
 def test_public_ip_ipv6_endpoint_and_fallback(self):
  o=self.run_shell(['validate_ipv4','validate_ipv6','get_public_ip'],r'''
mkdir -p "$INSTALL_DIR"
safe_curl() {
 case "$1" in
  https://api.ipify.org|https://ip.sb) return 1;;
  https://api6.ipify.org) printf '2001:db8::1\n';;
  *) return 1;;
 esac
}
result=$(get_public_ip)
[[ "$result" = '[2001:db8::1]' ]]
''')
  self.assertNotIn('api64.ipify.org',o.stdout)
 def test_public_ip_cache_ttl_and_write_failures_are_nonfatal(self):
  self.run_shell(['validate_ipv4','validate_ipv6','get_public_ip'],r'''
mkdir -p "$INSTALL_DIR"
printf '203.0.113.10\n' > "$INSTALL_DIR/.public-ip"
result=$(get_public_ip)
[[ "$result" = 203.0.113.10 ]]
touch -d '2 days ago' "$INSTALL_DIR/.public-ip"
safe_curl() { [[ "$1" = https://api.ipify.org ]] && printf '198.51.100.7\n' || return 1; }
result=$(get_public_ip)
[[ "$result" = 198.51.100.7 ]]
rm -f "$INSTALL_DIR/.public-ip"
mkdir "$INSTALL_DIR/.public-ip"
result=$(get_public_ip)
[[ "$result" = 198.51.100.7 ]]
''')
 def test_public_ip_missing_cache_directory_and_total_failure(self):
  self.run_shell(['validate_ipv4','validate_ipv6','get_public_ip'],r'''
safe_curl() { [[ "$1" = https://api.ipify.org ]] && printf '198.51.100.8\n' || return 1; }
result=$(get_public_ip)
[[ "$result" = 198.51.100.8 ]]
rm -rf "$INSTALL_DIR"
safe_curl() { return 1; }
if get_public_ip; then exit 80; fi
''')
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
