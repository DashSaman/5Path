"""Choose only nonce-verified, fresh SAME-country paths; never closes a TCP session."""
import asyncio,contextlib,hashlib,http.client,json,math,os,pathlib,re,signal,statistics,subprocess,sys,time

def select(state, expected_pid, members, now, current, history):
 if state.get('worker_pid')!=expected_pid or not 0<=now-state.get('updated_at',-1e20)<=15:return None
 scores={}
 for key in members:
  probe=state.get('probes',{}).get(key,{})
  v=probe.get('latency_ms')
  if not state.get('healthy',{}).get(key) or not probe.get('ok') or type(v)not in (int,float) or not math.isfinite(v) or v<0:continue
  values=history.setdefault(key,[]);values.append(v);del values[:-4]
  scores[key]=statistics.median(values)
 if not scores:return None
 best=min(scores,key=scores.get)
 if current in scores and scores[current]<=scores[best]+max(30,.15*scores[best]):return current
 return best

def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for data in iter(lambda:f.read(65536),b''):h.update(data)
 return h.hexdigest()

def load(root):
 root=pathlib.Path(root)
 if not re.fullmatch('tp-opt-(de|fi|tr|us)-[a-f0-9]{8}',root.name) or root!=pathlib.Path('/var/lib')/root.name or root.is_symlink():raise ValueError('NATIVE_ROOT_SCOPE')
 c=json.loads((root/'ownership.json').read_text())
 assert c['run_id']==root.name and c['root']==str(root) and c['purpose']=='OWN_TCP_NATIVE_FRONT','NATIVE_OWNER'
 for name,digest in c['files'].items():
  p=root/name;assert p.parent==root and not p.is_symlink() and p.is_file() and sha(p)==digest,'NATIVE_DEPENDENCY'
 return root,c

def committed(root,c):
 p=root/'committed.json'
 if not p.exists():return False
 x=json.loads(p.read_text());assert x['run_id']==c['run_id'] and x['ownership_sha256']==sha(root/'ownership.json'),'NATIVE_COMMIT_IDENTITY'
 return True

def admission(root,c):
 if committed(root,c):return
 now=time.time();l=json.loads((root/'lease.json').read_text());assert l['run_id']==c['run_id'] and 0<=now-l['epoch']<=10 and now<c['deadline'],'NATIVE_LEASE_OR_DEADLINE'
 for item in c['guards']:
  p=pathlib.Path(item['root']);s=json.loads((p/'guard-state.json').read_text());assert not(p/'guard-stop.json').exists() and s['run_id']==item['run_id'] and s['ready'] and s['duration']>=300 and 0<=now-s['epoch']<=12 and 0<=s['cpu_mean']<=85,'NATIVE_FULL300_GUARD'

def redirect_args(c):
 assert c['source']=='192.0.2.10' and c['destination']=='192.0.2.30' and c['old_port'] in (32101,32102,32103,32104) and 1024<c['new_port']<65536 and c['new_port']!=c['old_port']
 return ['PREROUTING','-s',c['source']+'/32','-d',c['destination']+'/32','-p','tcp','--dport',str(c['old_port']),'--syn','-m','comment','--comment',c['run_id'],'-j','REDIRECT','--to-ports',str(c['new_port'])]

def ipt(args):return subprocess.run(['iptables','-w','3','-t','nat',*args],capture_output=True,text=True,timeout=5)

def parent_pid(c):
 root=pathlib.Path(c['parent_root']);assert sha(root/'gw/gateway.json')==c['parent_config_sha256'],'PARENT_CONFIG_CHANGED'
 state=json.loads(pathlib.Path(c['state_path']).read_text());pid=state.get('worker_pid')
 assert type(pid)is int and pid>1,'PARENT_PID_INVALID'
 args=pathlib.Path('/proc',str(pid),'cmdline').read_bytes().split(bytes([0]))
 assert str(root/'gw/mesh_gateway.py').encode() in args and str(root/'gw/gateway.json').encode() in args,'PARENT_PROCESS_SCOPE'
 assert c['parent_gateway_cgroup'] in pathlib.Path('/proc',str(pid),'cgroup').read_text(),'PARENT_CGROUP_SCOPE'
 return pid,state

def remove_redirect(c):
 args=redirect_args(c);z=ipt(['-C',*args])
 if z.returncode==0:assert ipt(['-D',*args]).returncode==0,'NATIVE_OWN_RULE_REMOVE'
 else:assert z.returncode==1,'NATIVE_RULE_CHECK_FAILED'

def redirect(root,c):
 assert committed(root,c),'NATIVE_PUBLICATION_REQUIRES_COMMIT'
 args=redirect_args(c);z=ipt(['-C',*args])
 if z.returncode==1:assert ipt(['-I',args[0],'1',*args[1:]]).returncode==0,'NATIVE_OWN_RULE_ADD'
 else:assert z.returncode==0,'NATIVE_RULE_CHECK_FAILED'

async def run_worker(root,c):
 secret=json.loads((root/'native.json').read_text())['experimental']['clash_api']['secret'];history={};current=None;last_write=None
 async def deny(r,w):w.close();await w.wait_closed()
 reject=await asyncio.start_server(deny,'127.0.0.1',c['reject_port'])
 log=(root/'native.private.log').open('ab');p=subprocess.Popen([str(root/'sing-box'),'run','-c',str(root/'native.json')],cwd=root,stdout=log,stderr=log)
 def switch(member):
  api=http.client.HTTPConnection('127.0.0.1',c['control_port'],timeout=1)
  try:
   api.request('PUT','/proxies/'+c['country']+'-latency',json.dumps({'name':member}),{'Authorization':'Bearer '+secret,'Content-Type':'application/json'});r=api.getresponse();body=r.read(1024);assert r.status==204,'NATIVE_SELECTOR_UPDATE'
  finally:api.close()
 try:
  for _ in range(30):
   admission(root,c);assert p.poll() is None,'NATIVE_CHILD_EARLY_EXIT'
   try:await asyncio.to_thread(switch,c['country']+'-reject');break
   except (OSError,AssertionError):await asyncio.sleep(.1)
  else:raise TimeoutError('NATIVE_CONTROL_NOT_READY')
  while True:
   admission(root,c);assert p.poll() is None,'NATIVE_CHILD_EXIT'
   try:
    pid,state=parent_pid(c);chosen=select(state,pid,c['members'],time.time(),current,history)
   except (OSError,ValueError,TypeError,KeyError,AssertionError):chosen=None
   member=chosen or c['country']+'-reject'
   if current!=chosen or last_write is None:
    await asyncio.to_thread(switch,member);current=chosen
    last_write=time.monotonic()
   status={'run_id':c['run_id'],'epoch':time.time(),'selected':member,'selection_changes_existing_connections':False,'native_pid':p.pid}
   tmp=root/'selected.json.tmp';tmp.write_text(json.dumps(status));os.replace(tmp,root/'selected.json')
   await asyncio.sleep(3)
 finally:
  reject.close();await reject.wait_closed()
  if not committed(root,c):remove_redirect(c)
  if p.poll() is None:p.terminate()
  try:p.wait(timeout=3)
  except subprocess.TimeoutExpired:p.kill();p.wait(timeout=2)
  log.close()

if __name__=='__main__':
 root,c=load(sys.argv[2]);mode=sys.argv[1]
 if mode=='admit':
  try:admission(root,c)
  except BaseException as exc:
   if not committed(root,c):
    (root/'prepare-aborted.json').write_text(json.dumps({'run_id':c['run_id'],'epoch':time.time(),'error_type':type(exc).__name__}));raise SystemExit(78)
   raise
 elif mode=='redirect':redirect(root,c)
 elif mode=='remove':remove_redirect(c)
 elif mode=='worker':
  try:asyncio.run(run_worker(root,c))
  except BaseException as exc:
   if not committed(root,c):
    (root/'prepare-aborted.json').write_text(json.dumps({'run_id':c['run_id'],'epoch':time.time(),'error_type':type(exc).__name__}));raise SystemExit(78)
   raise
 else:raise ValueError('NATIVE_MODE')
