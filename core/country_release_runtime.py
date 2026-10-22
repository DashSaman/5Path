"""Only newly owned country services: admission, transaction rollback, tiny health, exact firewall."""
import asyncio,hashlib,ipaddress,json,math,os,pathlib,re,signal,subprocess,sys,time
from country_instance import from_rid,firewall_tuples

def digest(p):
 h=hashlib.sha256()
 with pathlib.Path(p).open('rb')as f:
  for b in iter(lambda:f.read(65536),b''):h.update(b)
 return h.hexdigest()
def validate_role(c):
 rid=c['run_id'];root=c['root']
 scope=from_rid(rid)
 if root!='/var/lib/'+rid or c['role']not in['gw','foreign']or c.get('country',scope['country'])!=scope['country']:raise ValueError('RELEASE_OWNER_ROLE')
 if not isinstance(c['commit_deadline'],(int,float))or not math.isfinite(c['commit_deadline']):raise ValueError('RELEASE_COMMIT_BOUND')
 names=[]
 for p in c['processes']:
  names.append(p['id']);a=p['argv']
  if not re.fullmatch(r'[a-z][a-z0-9_-]*',p['id'])or not a or any(not isinstance(x,str)or any(z in x for z in['\n','\r',chr(0),'://'])for x in a):raise ValueError('RELEASE_ARGV')
  if a[0]=='/usr/bin/python3':
   if len(a)<2 or a[1]not in[root+'/gw/mesh_gateway.py',root+'/foreign/mesh_gateway.py',root+'/country_release_runtime.py']:raise ValueError('RELEASE_PYTHON_SCOPE')
  elif a[0]not in[root+'/bin/'+x for x in['frps','frpc','gost','Waterwall']]:raise ValueError('RELEASE_BINARY_SCOPE')
 if len(names)!=len(set(names)):raise ValueError('RELEASE_DUPLICATE_PROCESS')
 for rel,sha in c['files'].items():
  if pathlib.PurePosixPath(rel).is_absolute()or'..'in pathlib.PurePosixPath(rel).parts or chr(92)in rel or not re.fullmatch(r'[a-f0-9]{64}',sha):raise ValueError('RELEASE_DEPENDENCY_SCOPE')
 return True
def lease_required(cfg,commit,sha):
 if commit is None:return True
 if commit.get('run_id')!=cfg['run_id']or commit.get('config_sha256')!=sha:raise ValueError('RELEASE_COMMIT_IDENTITY')
 return False
def read_cfg(path):
 path=pathlib.Path(path);root=path.parent;c=json.loads(path.read_text());validate_role(c)
 if str(root)!=c['root']or root.is_symlink()or path.is_symlink():raise ValueError('RELEASE_ROOT_PATH')
 owner=json.loads((root/'ownership.json').read_text());sha=digest(path)
 if owner['run_id']!=c['run_id']or owner['role']!=c['role']or owner['config_sha256']!=sha or owner['purpose']not in['NEW_COUNTRY_RELEASE','LOCAL_RELEASE_FIXTURE']:raise ValueError('RELEASE_OWNER_MANIFEST')
 return root,c,sha
def uncommitted(root,c,sha):
 p=root/'committed.json';return lease_required(c,json.loads(p.read_text())if p.exists()else None,sha)
def transaction_lease(root,c,sha):
 if c.get('local_fixture_deadline')and time.time()>=c['local_fixture_deadline']:raise RuntimeError('LOCAL_FIXTURE_ABSOLUTE_DEADLINE')
 if not uncommitted(root,c,sha):return
 if time.time()>=c['commit_deadline']:raise RuntimeError('NEW_RELEASE_TRANSACTION_DEADLINE')
 g=pathlib.Path(c['guard_root'])
 if(g/'guard-stop.json').exists():raise RuntimeError('NEW_RELEASE_GUARD_STOPPED')
 state=json.loads((g/'guard-state.json').read_text())
 if state.get('run_id')!=c['guard_run_id']or not state.get('ready')or not 0<=time.time()-state['epoch']<=15:raise RuntimeError('NEW_RELEASE_GUARD_STALE_OR_NOT_READY')
def admit(path,name):
 root,c,sha=read_cfg(path);transaction_lease(root,c,sha)
 if name not in[p['id']for p in c['processes']]:raise ValueError('NEW_RELEASE_PROCESS_NOT_REGISTERED')
 for rel,expected in c['files'].items():
  p=root/rel
  if p.is_symlink()or p.resolve()!=p or not p.is_file()or digest(p)!=expected:raise ValueError('NEW_RELEASE_DEPENDENCY_CHANGED:'+rel)
 print('NEW_RELEASE_PROCESS_ADMITTED',flush=True)
def own_properties(name,c):
 if not re.fullmatch(re.escape(c['run_id'])+r'-[a-z0-9-]+\.service',name):raise ValueError('NEW_RELEASE_FOREIGN_UNIT')
 r=subprocess.run(['systemctl','show',name,'-p','Description','-p','FragmentPath','-p','ActiveState','-p','MainPID'],capture_output=True,text=True,timeout=4)
 p=dict(x.split('=',1)for x in r.stdout.splitlines()if'='in x)
 if p.get('ActiveState')in['active','activating','deactivating']:
  if p.get('Description')!=c['run_id']or p.get('FragmentPath')not in['/run/systemd/transient/'+name,'/etc/systemd/system/'+name]:raise ValueError('NEW_RELEASE_UNIT_OWNER_CHANGED')
 return p
def abort(path):
 root,c,sha=read_cfg(path)
 if not uncommitted(root,c,sha):return
 active=[]
 for name in c['units']:
  p=own_properties(name,c)
  if p.get('ActiveState')in['active','activating','deactivating']:active.append(name)
 if active:subprocess.run(['systemctl','stop']+active,check=True,timeout=25)
 (root/'transaction-aborted.json').write_text(json.dumps(dict(run_id=c['run_id'],epoch=time.time(),only_owned_units=active)))
def guard(path):
 root,c,sha=read_cfg(path)
 def stopped(*_):raise SystemExit(0)
 def expired(*_):
  if uncommitted(root,c,sha):raise TimeoutError('NEW_RELEASE_TRANSACTION_EXPIRED')
 signal.signal(signal.SIGTERM,stopped);signal.signal(signal.SIGALRM,expired)
 signal.setitimer(signal.ITIMER_REAL,max(.01,c['commit_deadline']-time.time()))
 try:
  while uncommitted(root,c,sha):transaction_lease(root,c,sha);time.sleep(1)
 finally:
  signal.setitimer(signal.ITIMER_REAL,0)
  if uncommitted(root,c,sha):abort(path)
def firewall_rules(c):
 rid=c['run_id']
 allowed=firewall_tuples(from_rid(rid)['country'])
 result=[]
 for r in c['rules']:
  value=(r['source'],r['destination'],r['protocol'],r['port'])
  if value not in allowed:raise ValueError('RELEASE_FIREWALL_EXACT_SCOPE')
  result.append(['INPUT','-s',r['source']+'/32','-d',r['destination']+'/32','-p',r['protocol'],'--dport',str(r['port']),'-m','comment','--comment',rid,'-j','ACCEPT'])
 if len({tuple(x)for x in result})!=len(result):raise ValueError('RELEASE_FIREWALL_DUPLICATE')
 return result
def ipt(a):return subprocess.run(['iptables','-w','3']+a,capture_output=True,text=True,timeout=5)
def cleanup_firewall(path):
 root,c,sha=read_cfg(path)
 for r in firewall_rules(c):
  v=ipt(['-C']+r)
  if v.returncode==1:continue
  if v.returncode!=0 or ipt(['-D']+r).returncode!=0:raise RuntimeError('RELEASE_EXACT_RULE_CLEANUP_FAILED')
def firewall(path):
 root,c,sha=read_cfg(path);transaction_lease(root,c,sha)
 def stopped(*_):raise SystemExit(0)
 signal.signal(signal.SIGTERM,stopped)
 try:
  for r in firewall_rules(c):
   v=ipt(['-C']+r)
   if v.returncode==1:
    if ipt(['-I',r[0],'1']+r[1:]).returncode:raise RuntimeError('RELEASE_RULE_INSERT_FAILED')
   elif v.returncode:raise RuntimeError('RELEASE_RULE_CHECK_FAILED')
  while True:transaction_lease(root,c,sha);time.sleep(1)
 finally:cleanup_firewall(path)
async def health(path):
 c=json.loads(pathlib.Path(path).read_text());assert ipaddress.ip_address(c['host']).is_loopback and 0<c['port']<65536 and 1<=len(c['body'])<=128
 active=set();body=c['body'].encode()
 async def handle(reader,writer):
  task=asyncio.current_task()
  if len(active)>=20:writer.close();return
  active.add(task)
  try:
   raw=await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'),2)
   if len(raw)>2048 or not raw.startswith(b'GET / HTTP/1.'):return
   writer.write(b'HTTP/1.0 200 OK\r\nConnection: close\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body);await asyncio.wait_for(writer.drain(),2)
  except (OSError,ValueError,asyncio.TimeoutError,asyncio.IncompleteReadError,asyncio.LimitOverrunError):pass
  finally:active.discard(task);writer.close()
 server=await asyncio.start_server(handle,c['host'],c['port'],limit=2048)
 async with server:await server.serve_forever()
if __name__=='__main__':
 mode,path=sys.argv[1:3]
 if mode=='admit':admit(path,sys.argv[3])
 elif mode=='guard':guard(path)
 elif mode=='abort':abort(path)
 elif mode=='firewall':firewall(path)
 elif mode=='cleanup-firewall':cleanup_firewall(path)
 elif mode=='health':asyncio.run(health(path))
 else:raise ValueError('NEW_RELEASE_MODE')
