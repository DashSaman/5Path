"""Bounded, low-priority, read-only IR storage + all netns listeners/services audit."""
import os,pathlib,json,subprocess,time,signal,re,hashlib,stat
signal.alarm(140)
os.nice(15)
def run(a,t=15):
 z=subprocess.run(a,capture_output=True,text=True,timeout=t);return dict(code=z.returncode,stdout=z.stdout,stderr=z.stderr[-2000:])
def fields(unit):
 z=run(['systemctl','show',unit,'-p','Description','-p','ActiveState','-p','SubState','-p','MainPID','-p','NRestarts','-p','FragmentPath','-p','ControlGroup'],4)
 return dict(x.split('=',1)for x in z['stdout'].splitlines()if'='in x)
out=dict(epoch=time.time(),read_only=True,target='192.0.2.10')
out['df']=run(['df','-B1','-P','/','/var','/var/lib','/var/log','/tmp','/root','/home','/opt','/usr/local'])
out['inodes']=run(['df','-Pi','/']);out['mounts']=run(['findmnt','-J','-o','TARGET,SOURCE,FSTYPE,OPTIONS'],5)
listing=run(['systemctl','list-units','--all','--type=service','--no-legend','--plain','--no-pager']);assert listing['code']==0
out['services']={}
for line in listing['stdout'].splitlines():
 a=line.split();name=next((x for x in a if x.endswith('.service')),None)
 if not name:continue
 if any(x in a for x in ['active','activating','deactivating','failed']):out['services'][name]=fields(name)
namespaces={};processes=[];deleted={};refs={};configs=set()
rootpat=re.compile(r'/var/lib/(tp-[a-z0-9]+(?:-[a-z0-9]+)+)')
for p in pathlib.Path('/proc').iterdir():
 if not p.name.isdigit():continue
 try:
  pid=int(p.name);comm=(p/'comm').read_text().strip();namespaces.setdefault(os.stat(p/'ns/net').st_ino,pid)
  args=(p/'cmdline').read_bytes().decode(errors='replace').split(chr(0));paths=[]
  for kind in ['exe','cwd']:
   try:paths.append(str((p/kind).resolve()))
   except OSError:pass
  for arg in args:
   if arg.startswith(('/etc/','/var/lib/','/opt/','/usr/local/')):
    paths.append(arg)
    q=pathlib.Path(arg)
    if q.suffix.lower()in ['.json','.toml','.yaml','.yml','.conf']and q.is_file():configs.add(q)
  for fd in(p/'fd').iterdir():
   try:
    link=os.readlink(fd);paths.append(link)
    if link.endswith(' (deleted)'):
     st=fd.stat()
     if stat.S_ISREG(st.st_mode):deleted.setdefault((st.st_dev,st.st_ino),dict(pid=pid,comm=comm,bytes=st.st_size,allocated_bytes=st.st_blocks*512,path=link))
   except OSError:pass
  for value in paths:
   for rid in rootpat.findall(value):refs.setdefault(rid,[]).append(dict(pid=pid,comm=comm,kind='proc_path'))
  processes.append(dict(pid=pid,comm=comm))
 except OSError:pass
out['deleted_open_files']=sorted(deleted.values(),key=lambda x:x['allocated_bytes'],reverse=True)
out['process_count']=len(processes);out['package_manager_active']=[p for p in processes if p['comm']in ['apt','apt-get','dpkg','unattended-upgr','snapd']]
assert len(namespaces)<=20,'NETNS_AUDIT_BOUND';out['netns_listeners']=[]
for inode,pid in namespaces.items():
 z=run(['nsenter','-t',str(pid),'-n','ss','-H','-ltnup'],8);assert z['code']==0,'LISTENER_AUDIT_INCOMPLETE';out['netns_listeners'].append(dict(inode=inode,pid=pid,listeners=z['stdout']))
out['reference_roots']=refs;out['config_refs']={}
for p in configs:
 try:
  if p.stat().st_size<=4*1048576:
   found=sorted(set(rootpat.findall(p.read_text(errors='replace'))))
   if found:out['config_refs'][str(p)]=found
 except OSError:pass
out['systemd_root_refs']={}
for directory in ['/etc/systemd/system','/run/systemd/transient','/usr/lib/systemd/system']:
 for p in pathlib.Path(directory).rglob('*'):
  try:
   if p.is_file()and p.stat().st_size<=1048576:
    found=sorted(set(rootpat.findall(p.read_text(errors='replace'))))
    if found:out['systemd_root_refs'][str(p)]=found
  except OSError:pass
out['space_by_directory']={}
for directory in ['/var','/var/lib','/var/log','/var/cache','/tmp','/opt','/root','/home','/usr/local']:
 out['space_by_directory'][directory]=run(['ionice','-c','3','du','-x','-B1','--max-depth=1',directory],18)
out['journal_usage']=run(['journalctl','--disk-usage'],6)
out['owned_roots']=[]
for r in pathlib.Path('/var/lib').glob('tp-*'):
 if not r.is_dir()or r.is_symlink():continue
 row=dict(path=str(r),mtime=r.stat().st_mtime,committed=(r/'committed.json').exists(),accepted=(r/'accepted.json').exists())
 try:
  c=json.loads((r/'ownership.json').read_text());row['owner']={k:c.get(k)for k in ['run_id','root','purpose','role','status','deadline','commit_deadline']};row['owner_sha256']=hashlib.sha256((r/'ownership.json').read_bytes()).hexdigest()
 except (OSError,ValueError):row['owner_verified']=False
 out['owned_roots'].append(row)
print(json.dumps(out))
