from pathlib import Path
import subprocess, json, shutil, sys, tempfile, os
HERE=Path(__file__).resolve().parent
TEMP=tempfile.TemporaryDirectory(prefix='ss2022-transaction-')
ROOT=Path(TEMP.name)
os.environ['SS_TEST_ROOT']=str(ROOT)
shutil.copyfile(HERE/'harness.sh',ROOT/'harness.sh')
config={'server_port':8388,'password':'AAAAAAAAAAAAAAAAAAAAAA==','method':'2022-blake3-aes-128-gcm','custom':{'keep':True}}
CASES=[]
def run(case, fresh=False, active=True, dropin=False, orphan=False):
 CASES.append(case)
 subprocess.run(['python3',str(HERE/'build_harness.py')],check=True,stdout=subprocess.DEVNULL)
 r=ROOT/'runs'/case
 if r.exists(): shutil.rmtree(r)
 for d in ['tmp','bin','system']: (r/d).mkdir(parents=True,exist_ok=True)
 (r/'tty').touch()
 if not fresh:
  (r/'config').mkdir(); (r/'bin/ss-rust').write_text('OLD_BINARY\n'); (r/'config/ver.txt').write_text('1.0.0\n')
  c=r/'config/config.json'; c.write_text(json.dumps(config)); c.chmod(0o600)
  (r/'system/ss-rust.service').write_text('[Service]\nUser=root\nExecStart='+str(r/'bin/ss-rust')+'\n')
  if active: (r/'active').touch(); (r/'enabled').touch()
 if dropin:
  d=r/'system/ss-rust.service.d'; d.mkdir(); (d/'override.conf').write_text('[Service]\nExecStart=/bin/true\n')
 if orphan: (r/'orphan').touch()
 p=subprocess.run(['bash',str(ROOT/'harness.sh'),case],text=True,capture_output=True,timeout=10)
 (r/'stdout.log').write_text(p.stdout); (r/'stderr.log').write_text(p.stderr)
 assert p.returncode==0,(case,p.returncode,p.stderr)
 assert 'MENU_RETURNED' in p.stdout,(case,p.stdout,p.stderr)
 return r,p

def metadata():
 r,p=run('mode_rollback')
 assert (r/'config/config.json').stat().st_mode&0o777==0o600,'rollback widened config mode to '+oct((r/'config/config.json').stat().st_mode&0o777)
 for name,path in [('binary','bin/ss-rust'),('version','config/ver.txt'),('config','config/config.json'),('service','system/ss-rust.service')]:
  a=(r/path).stat(); b=(r/('tmp/old-'+name)).stat()
  assert (a.st_mode,a.st_uid,a.st_gid,a.st_mtime_ns)==(b.st_mode,b.st_uid,b.st_gid,b.st_mtime_ns),(name,'metadata changed')
 assert not (r/'tmp/KEEP').exists()
 assert (r/'active').exists()

def orphan():
 r,p=run('orphan_cli_uninstall',fresh=True,orphan=True)
 assert not (r/'orphan').exists(),'uninstall left external ss-rust process running'
 assert '卸载完成' in p.stderr

def dropin():
 r,p=run('dropin_uninstall',fresh=True,dropin=True)
 assert not (r/'system/ss-rust.service.d').exists(),'menu ignored drop-in-only residue'
 r,p=run('stale_dropin_success',fresh=True,dropin=True)
 assert not (r/'bin/ss-rust').exists(),'fresh install accepted unsnapshotted old override'
 assert (r/'system/ss-rust.service.d/override.conf').read_text()=='[Service]\nExecStart=/bin/true\n'

def retained_units():
 r,p=run('stale_unit_dropin',dropin=True)
 assert not (r/'bin/ss-rust').exists()
 assert (r/'system/ss-rust.service.d/override.conf').read_text()=='[Service]\nExecStart=/bin/true\n'
 assert not (r/'tmp/old-service').exists(),'must refuse before snapshot/mutation'
 r,p=run('retained_dropin',dropin=True)
 assert (r/'system/ss-rust.service.d/override.conf').read_text()=='[Service]\nExecStart=/bin/true\n'
 assert (r/'system/ss-rust.service').read_bytes()==(r/'tmp/old-service').read_bytes()
 assert (r/'active').exists()

def stability():
 r,p=run('transient_active')
 assert '服务运行正常' not in p.stderr,'transient active was reported healthy'
 assert '服务启动失败' in p.stderr

def install_process_safety():
 r,p=run('foreign_install',fresh=True,orphan=True)
 assert (r/'orphan').exists(),'install killed unrelated same-name executable'
 assert not (r/'pkill.log').exists()

def regressions():
 for case in ['backup_failure','download_failure','restart_failure','restore_failure','fresh_success','fresh_stop_failure','fresh_rollback','modify_success','modify_restart_failure','normal_uninstall','repeated','keep_blocks_next','uninstall_install','stopped_update']:
  r,p=run(case,fresh=case.startswith('fresh_'),active=case!='stopped_update')
  if case in ['restore_failure','fresh_stop_failure','keep_blocks_next']:
   assert (r/'tmp/KEEP').exists(),(case,p.stderr)
  else: assert not (r/'tmp/KEEP').exists(),(case,p.stderr)
  if case in ['backup_failure','download_failure','restart_failure','modify_restart_failure']:
   assert (r/'config/config.json').read_text()==json.dumps(config),(case,p.stderr)
   assert (r/'active').exists(),case
  if case=='repeated':
   assert not (r/'config/config.json').exists()
   assert (r/'bin/ss-rust').read_text()=='NEW_BINARY\n'
   assert not (r/'active').exists()
  if case=='stopped_update': assert not (r/'active').exists()
  if case=='fresh_rollback':
   assert not (r/'active').exists() and not (r/'enabled').exists() and not (r/'system/ss-rust.service').exists()
  if case=='fresh_success': assert (r/'active').exists()
  if case=='normal_uninstall': assert not (r/'config').exists()
  if case=='uninstall_install': assert (r/'active').exists() and (r/'config/config.json').exists()
 for case in ['pgrep_failure','kill_failure','stubborn_process','foreign_process']:
  r,p=run(case,orphan=True)
  assert (r/'orphan').exists(),case
  if case=='foreign_process':
   assert not (r/'kill.log').exists(),case
   assert not (r/'config').exists(),case
  else:
   assert (r/'config/config.json').exists(),case
   assert '卸载完成' not in p.stderr,case
 r,p=run('wrong_main')
 assert '服务启动失败' in p.stderr
 r,p=run('orphan_uninstall',fresh=True,orphan=True)
 assert not (r/'orphan').exists()

if __name__=='__main__':
 for name in (sys.argv[1:] or ['metadata','orphan','dropin','retained_units','stability','install_process_safety','regressions']):
  globals()[name](); print('PASS',name)
 print('PASS',len(set(CASES)),'unique transaction scenarios')
