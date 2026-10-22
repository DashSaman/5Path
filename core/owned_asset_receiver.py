"""Receive one owned software source through bounded stdin; never execute it.

EOF, lease, telemetry and absolute deadline are checked without controller RPC.
Only exclusively created files with unchanged inode identities are cleaned up.
"""
import pathlib,os,json,time,re,hashlib,signal,select,tarfile,math,argparse

def digest(path):
 h=hashlib.sha256()
 with path.open('rb')as f:
  for data in iter(lambda:f.read(65536),b''):h.update(data)
 return h.hexdigest()

def load(root):
 assert root.parent==pathlib.Path('/var/lib')and re.fullmatch('tp-lv19-[a-f0-9]{8}',root.name)and not root.is_symlink(),'EXACT_SOURCE_ROOT'
 owner=json.loads((root/'ownership.json').read_text());assert owner['run_id']==root.name and owner['root']==str(root)and owner['role']=='OFFICIAL_SOURCE_STAGE','SOURCE_OWNER'
 for name,sha in owner['files'].items():
  path=root/name;assert path.parent==root and not path.is_symlink()and digest(path)==sha,'SOURCE_DEPENDENCY_HASH'
 c=json.loads((root/'asset-receive.json').read_text());assert c['run_id']==root.name and c['root']==str(root),'SOURCE_CONFIG_OWNER'
 assert type(c['archive_bytes'])is int and 0<c['archive_bytes']<=40*1048576 and type(c['binary_bytes'])is int and 0<c['binary_bytes']<=90*1048576,'EXACT_SOURCE_LENGTH_LIMIT'
 assert type(c['rate_Bps'])is int and 0<c['rate_Bps']<=131072 and type(c['chunk_bytes'])is int and 0<c['chunk_bytes']<=16384,'SOURCE_RATE_LIMIT'
 assert all(re.fullmatch('[a-f0-9]{64}',c[k])for k in['archive_sha256','binary_sha256']),'SOURCE_HASH_FORMAT'
 g=pathlib.Path(c['guard_root']);assert g.parent==root.parent and g.name==c['guard_run_id']and re.fullmatch('tp-udp-[a-f0-9]{8}',g.name)and not g.is_symlink(),'EXACT_GUARD_ROOT'
 assert json.loads((g/'ownership.json').read_text())['run_id']==g.name,'GUARD_OWNER'
 assert not any((root/name).exists()for name in['receiver-claimed.json','asset-aborted.json','source-ready.json']),'TERMINAL_RUN'
 return c

def healthy(root,c):
 now=time.time();assert now<c['deadline'],'DEADLINE'
 lease=json.loads((root/'lease.json').read_text());lease_age=time.time()-lease['epoch'];assert lease['run_id']==c['run_id']and 0<=lease_age<=10,'LEASE_EXPIRED:age='+str(lease_age)
 g=pathlib.Path(c['guard_root']);assert not(g/'guard-stop.json').exists(),'GUARD_STOPPED'
 s=json.loads((g/'guard-state.json').read_text());guard_age=time.time()-s['epoch'];assert s['run_id']==c['guard_run_id']and s['ready']and s['duration']>=300 and 0<=guard_age<=12,'GUARD_NOT_FRESH_FULL300:age='+str(guard_age)
 assert isinstance(s['cpu_mean'],(int,float))and math.isfinite(s['cpu_mean'])and 0<=s['cpu_mean']<=85 and s['available_kB']>=131072,'CPU_OR_RAM_GUARD'

def atomic_new(root,name,value):
 tmp=root/(name+'.tmp-'+str(os.getpid()));target=root/name
 with tmp.open('x')as f:f.write(json.dumps(value));f.flush();os.fsync(f.fileno())
 try:os.link(tmp,target)
 finally:tmp.unlink()

def receive(root,fd=0):
 c=load(root);created=[];started=time.monotonic();ready=False;error=None
 def register(path):
  st=path.stat();created.append((path,st.st_dev,st.st_ino));return path
 def link_new(part,target):os.link(part,target);register(target);part.unlink()
 def check():healthy(root,c)
 def timeout(*_):raise TimeoutError('DEADLINE')
 signal.signal(signal.SIGALRM,timeout);signal.signal(signal.SIGTERM,lambda *_:(_ for _ in()).throw(InterruptedError('RECEIVER_TERMINATED')))
 signal.alarm(max(1,math.ceil(c['deadline']-time.time())))
 try:
  check();atomic_new(root,'receiver-claimed.json',dict(run_id=c['run_id'],pid=os.getpid(),start_ticks=pathlib.Path('/proc/self/stat').read_text().split(') ',1)[1].split()[19],deadline=c['deadline']))
  part=root/'archive.part';total=0;sha=hashlib.sha256()
  with part.open('xb')as out:
   register(part)
   while True:
    check()
    if not select.select([fd],[],[],.15)[0]:continue
    block=os.read(fd,c['chunk_bytes'])
    if not block:break
    total+=len(block);assert total<=c['archive_bytes'],'INPUT_LENGTH_EXCEEDED'
    sha.update(block);out.write(block)
    due=started+total/c['rate_Bps']
    while time.monotonic()<due:check();time.sleep(min(.1,max(0,due-time.monotonic())))
   out.flush();os.fsync(out.fileno())
  assert total==c['archive_bytes'],'INPUT_LENGTH_INCOMPLETE'
  assert sha.hexdigest()==c['archive_sha256'],'ARCHIVE_SHA_MISMATCH'
  check();directory=root/'bin';directory.mkdir(mode=0o700);binary=directory/'sing-box.part';bsha=hashlib.sha256();size=0
  with tarfile.open(part,'r:gz')as archive:
   members=archive.getmembers();assert len(members)<=64,'ARCHIVE_MEMBER_LIMIT'
   chosen=[m for m in members if pathlib.PurePosixPath(m.name).name=='sing-box']
   assert len(chosen)==1 and chosen[0].isfile()and chosen[0].size==c['binary_bytes'],'EXACT_REGULAR_BINARY_MEMBER'
   with archive.extractfile(chosen[0])as src,binary.open('xb')as dst:
    register(binary)
    while data:=src.read(65536):
     check();size+=len(data);assert size<=c['binary_bytes'],'BINARY_LENGTH_EXCEEDED';bsha.update(data);dst.write(data)
    dst.flush();os.fsync(dst.fileno())
  assert size==c['binary_bytes']and bsha.hexdigest()==c['binary_sha256'],'BINARY_SHA_OR_LENGTH_MISMATCH'
  check();binary.chmod(0o700);link_new(binary,directory/'sing-box');link_new(part,root/'sing-box.tar.gz');check()
  receipt=dict(run_id=c['run_id'],root=str(root),source_ready=True,software_source_only=True,archive_bytes=total,archive_sha256=sha.hexdigest(),binary_bytes=size,binary_sha256=bsha.hexdigest(),rate_cap_Bps=c['rate_Bps'],elapsed_seconds=time.monotonic()-started,deadline=c['deadline'],pid=os.getpid(),start_ticks=pathlib.Path('/proc/self/stat').read_text().split(') ',1)[1].split()[19])
  atomic_new(root,'source-ready.json',receipt);ready=True;return receipt
 except BaseException as exc:error=type(exc).__name__+':'+str(exc);raise
 finally:
  signal.alarm(0)
  if not ready:
   unknown=[]
   for path,dev,ino in reversed(created):
    if not path.exists():continue
    st=path.lstat()
    if(st.st_dev,st.st_ino)==(dev,ino)and not path.is_symlink():path.unlink()
    else:unknown.append(str(path))
   try:atomic_new(root,'asset-aborted.json',dict(run_id=c['run_id'],epoch=time.time(),reason=error,own_partial_files_removed=not unknown,unknown_files_untouched=unknown))
   except FileExistsError:pass

if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--root',required=True);args=parser.parse_args();print(json.dumps(receive(pathlib.Path(args.root))))
