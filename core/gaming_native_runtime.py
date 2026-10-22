"""Own native gaming release only. Uncommitted workers fail closed independently.

An exact committed manifest disables preparation leases; production users are
never killed by a later CPU sample, controller loss or preparation deadline.
"""
import hashlib,json,math,os,pathlib,re,signal,socket,subprocess,sys,time

COUNTRIES={'DE':'198.51.100.10','FI':'198.51.100.20','TR':'198.51.100.30','US':'198.51.100.40'}
PORT_NAMES={'front','primary','backup','force_primary','force_backup','api','health'}

class PreparationStopped(ValueError):pass

def validate(c):
 cc=c.get('country');rid=c.get('run_id','');root=c.get('root','')
 if cc not in COUNTRIES or c.get('foreign')!=COUNTRIES[cc] or not re.fullmatch('tp-game-'+cc.lower()+'-[a-f0-9]{8}',rid) or root!='/var/lib/'+rid or c.get('role')not in['gw','foreign']:raise ValueError('GAMING_OWNER_COUNTRY')
 ports=c['ports']
 if set(ports)!=PORT_NAMES or len(set(ports.values()))!=7 or not all(type(x)is int and 1024<=x<10000 for x in ports.values()):raise ValueError('GAMING_PORT_SCOPE')
 if not isinstance(c['commit_deadline'],(int,float))or not math.isfinite(c['commit_deadline']):raise ValueError('GAMING_ABSOLUTE_DEADLINE')
 for name,sha in c['files'].items():
  if pathlib.PurePosixPath(name).is_absolute()or'..'in pathlib.PurePosixPath(name).parts or '\\'in name or not re.fullmatch('[a-f0-9]{64}',sha):raise ValueError('GAMING_FILE_SCOPE')
 for name,argv in c['processes'].items():
  if name not in['gateway','primary','backup','selector','echo']or not argv or any(not isinstance(x,str)or any(y in x for y in['\n','\r',chr(0)])for x in argv):raise ValueError('GAMING_PROCESS_SCOPE')
  if argv[0]==root+'/sing-box':
   if len(argv)!=4 or argv[1:3]!=['run','-c']or argv[3]not in[root+'/'+n+'.json'for n in['gateway','primary-server','backup-server']]:raise ValueError('GAMING_BINARY_ARGV')
  elif argv[0]=='/usr/bin/python3':
   if not(argv[1:]==[root+'/udp_health_selector.py',root+'/health.private.json']or argv[1:]==[root+'/gaming_native_runtime.py','echo',root+'/runtime.json']):raise ValueError('GAMING_PYTHON_ARGV')
  else:raise ValueError('GAMING_BINARY_SCOPE')
 return True

def requires_lease(c,commit,sha):
 if commit is None:return True
 if commit.get('run_id')!=c['run_id']or commit.get('config_sha256')!=sha:raise ValueError('GAMING_COMMIT_IDENTITY')
 return False

def check_prepare(c,lease,guard,now):
 if now>=c['commit_deadline']:raise ValueError('GAMING_PREPARATION_DEADLINE')
 if lease.get('run_id')!=c['run_id']or not 0<=now-lease['epoch']<=10:raise ValueError('GAMING_LEASE_EXPIRED')
 if guard.get('run_id')!=c.get('guard_run_id',c['run_id'])or not guard.get('ready')or not 0<=now-guard['epoch']<=12:raise ValueError('GAMING_GUARD_STALE')
 cpu=guard.get('cpu_mean')
 if not isinstance(cpu,(int,float))or not math.isfinite(cpu)or not 0<=cpu<=85 or guard.get('available_kB',0)<131072:raise ValueError('GAMING_RESOURCE_GUARD')

def rule_tuples(c):
 validate(c);p=c['ports']
 if c['role']=='gw':return{('192.0.2.10','192.0.2.30',proto,p['front'])for proto in['tcp','udp']}
 return{('203.0.113.30',c['foreign'],'udp',p[n])for n in['primary','backup']}

def digest(path):
 h=hashlib.sha256()
 with pathlib.Path(path).open('rb')as f:
  for b in iter(lambda:f.read(65536),b''):h.update(b)
 return h.hexdigest()

def atomic(root,name,value):
 p=root/name;t=p.with_name(p.name+'.tmp-'+str(os.getpid())+'-'+str(time.monotonic_ns()));t.write_text(json.dumps(value));os.replace(t,p)

def load(path):
 path=pathlib.Path(path);c=json.loads(path.read_text());validate(c);root=path.parent
 if str(root)!=c['root']or root.is_symlink()or path.is_symlink():raise ValueError('GAMING_ROOT')
 owner=json.loads((root/'ownership.json').read_text());sha=digest(path)
 if owner.get('run_id')!=c['run_id']or owner.get('role')!=c['role']or owner.get('config_sha256')!=sha:raise ValueError('GAMING_OWNER_MANIFEST')
 return root,c,sha

def pending(root,c,sha):
 p=root/'committed.json'
 return requires_lease(c,json.loads(p.read_text())if p.exists()else None,sha)

def reject_aborted(root,c,sha):
 p=root/'prepare-aborted.json'
 if p.exists():
  a=json.loads(p.read_text())
  if a.get('run_id')!=c['run_id']or a.get('config_sha256')!=sha:raise PreparationStopped('GAMING_ABORT_IDENTITY')
  raise PreparationStopped('GAMING_PREPARATION_ALREADY_ABORTED')

def stop_preparation(root,c,sha,reason,details=None):
 # Exact publication may race a last preparation check; committed users must
 # never be killed by a preparation controller or its old resource guard.
 if not pending(root,c,sha):return
 atomic(root,'prepare-aborted.json',dict(run_id=c['run_id'],config_sha256=sha,reason=reason,epoch=time.time(),details=details or{}))
 raise PreparationStopped(reason)

def transaction(root,c,sha):
 if not pending(root,c,sha):return
 guard={};lease={};now=time.time()
 try:
  reject_aborted(root,c,sha)
  g=pathlib.Path(c['guard_root'])
  if str(g)!='/var/lib/'+c['guard_run_id']or not re.fullmatch('tp-udp-[a-f0-9]{8}',c['guard_run_id'])or g.is_symlink():raise ValueError('GAMING_GUARD_OWNER')
  if json.loads((g/'ownership.json').read_text()).get('run_id')!=c['guard_run_id']or(g/'guard-stop.json').exists():raise ValueError('GAMING_GUARD_STOP')
  guard=json.loads((g/'guard-state.json').read_text());lease=json.loads((root/'lease.json').read_text());now=time.time()
  if guard.get('duration',0)<300:raise ValueError('GAMING_FULL300_REQUIRED')
  check_prepare(c,lease,guard,now)
 except (ValueError,OSError)as exc:
  if not pending(root,c,sha):return
  if isinstance(exc,PreparationStopped):raise
  details={k:now-v['epoch']for k,v in[('lease_age_s',lease),('guard_age_s',guard)]if isinstance(v.get('epoch'),(int,float))}
  stop_preparation(root,c,sha,str(exc)[:150],details)

def admit(root,c,sha):
 transaction(root,c,sha)
 for rel,expected in c['files'].items():
  p=root/rel
  if p.is_symlink()or p.resolve()!=p or not p.is_file()or digest(p)!=expected:raise ValueError('GAMING_DEPENDENCY_CHANGED')

def arm(root,c,sha):
 def terminate(*_):raise SystemExit(0)
 def expired(*_):
  if pending(root,c,sha):stop_preparation(root,c,sha,'GAMING_PREPARATION_ABSOLUTE_DEADLINE')
 signal.signal(signal.SIGTERM,terminate);signal.signal(signal.SIGALRM,expired)
 if pending(root,c,sha):signal.setitimer(signal.ITIMER_REAL,max(.01,c['commit_deadline']-time.time()))

def run_worker(path,name):
 root,c,sha=load(path);admit(root,c,sha);arm(root,c,sha)
 if name not in c['processes']:raise ValueError('GAMING_WORKER_NAME')
 child=None;log=None
 try:
  log=(root/(name+'.log')).open('ab');child=subprocess.Popen(c['processes'][name],cwd=root,stdout=log,stderr=log)
  def start(pid):return pathlib.Path('/proc',str(pid),'stat').read_text().split(') ',1)[1].split()[19]
  atomic(root,name+'-identity.json',dict(run_id=c['run_id'],worker_pid=os.getpid(),worker_start_ticks=start(os.getpid()),child_pid=child.pid,child_start_ticks=start(child.pid)))
  while True:
   transaction(root,c,sha)
   if child.poll()is not None:raise RuntimeError('GAMING_OWN_CHILD_EXIT')
   time.sleep(.5)
 finally:
  if child and child.poll()is None:
   child.terminate()
   try:child.wait(timeout=3)
   except subprocess.TimeoutExpired:child.kill();child.wait(timeout=3)
  if log:log.close()

def rules(c):
 return[['INPUT','-s',a+'/32','-d',b+'/32','-p',proto,'--dport',str(port),'-m','comment','--comment',c['run_id'],'-j','ACCEPT']for a,b,proto,port in sorted(rule_tuples(c))]

def ipt(args):return subprocess.run(['iptables','-w','3']+args,capture_output=True,text=True,timeout=6)

def cleanup(path):
 root,c,sha=load(path)
 for rule in rules(c):
  z=ipt(['-C']+rule)
  if z.returncode==0:
   if ipt(['-D']+rule).returncode:raise RuntimeError('GAMING_EXACT_RULE_DELETE')
  elif z.returncode!=1:raise RuntimeError('GAMING_RULE_CHECK')

def firewall(path):
 root,c,sha=load(path);admit(root,c,sha);arm(root,c,sha)
 try:
  for rule in rules(c):
   z=ipt(['-C']+rule)
   if z.returncode==1:
    if ipt(['-I','INPUT','1']+rule[1:]).returncode:raise RuntimeError('GAMING_EXACT_RULE_INSERT')
   elif z.returncode:raise RuntimeError('GAMING_RULE_CHECK')
  while True:transaction(root,c,sha);time.sleep(.5)
 finally:cleanup(path)

def echo(path):
 root,c,sha=load(path);admit(root,c,sha);arm(root,c,sha)
 if c['role']!='foreign':raise ValueError('GAMING_ECHO_LOOPBACK_ONLY')
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',c['ports']['health']));s.settimeout(.5)
 try:
  while True:
   transaction(root,c,sha)
   try:body,peer=s.recvfrom(2048)
   except socket.timeout:continue
   if peer[0]!='127.0.0.1':continue
   s.sendto(body,peer)
 finally:s.close()

if __name__=='__main__':
 mode,path=sys.argv[1:3]
 try:
  if mode=='worker':run_worker(path,sys.argv[3])
  elif mode=='firewall':firewall(path)
  elif mode=='cleanup':cleanup(path)
  elif mode=='echo':echo(path)
  else:raise ValueError('GAMING_EXACT_MODE')
 except PreparationStopped as exc:
  print(json.dumps(dict(event='GAMING_PREPARATION_TERMINAL',reason=str(exc))),file=sys.stderr);raise SystemExit(78)
