from pathlib import Path
import re, json, subprocess, os
root=Path(os.environ['SS_TEST_ROOT'])
src=(Path(__file__).resolve().parents[1]/'install.sh').read_text()
names='cleanup cleanup_uninstall_residue restore_install_state on_exit backup_install_state cprintf info success warn error check_systemd manage_service run_uninstall_logic install_flow do_update do_uninstall load_config do_modify_config write_config create_systemd_service get_key_bytes validate_port validate_existing_password validate_existing_config_values validate_config_values validate_password decode_base64'.split()
names += [n for n in ['has_installation_residue', 'ss_rust_pids', 'stop_residual_processes', 'service_main_pid'] if re.search(r'^'+n+r'\(\)',src,re.M)]
blocks=[]
for name in names:
    m=re.search(r'^'+name+r'\(\).*?\n}',src,re.M|re.S) if name not in ['info','success','warn'] else re.search(r'^'+name+r'\(\).*$',src,re.M)
    assert m,name
    blocks.append(m.group())
text='\n\n'.join(blocks)
text=text.replace('/usr/local/bin', '${RUN}/bin').replace('/etc/systemd/system/ss-rust.service.d','${RUN}/system/ss-rust.service.d').replace('/run/ss-rust','${RUN}/runtime').replace('< /dev/tty','< "${RUN}/tty"')
(root/'actual-functions.sh').write_text(text+'\n')
print(json.dumps({'functions':names,'source':str(root/'actual-functions.sh')},indent=2))
