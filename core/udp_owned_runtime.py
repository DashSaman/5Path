"""Bounded, independently leased NEW UDP tests. Never controls production units."""
import os,sys,pathlib,json,time,hashlib,subprocess,signal,socket,threading,statistics
ROOT=pathlib.Path(__file__).resolve().parent
def atomic(name,v):
 p=ROOT/name;t=p.with_name(p.name+'.tmp');t.write_text(json.dumps(v));os.replace(t,p)
def load(name):return json.loads((ROOT/name).read_text())
def digest(p):
 h=hashlib.sha256()
 with pathlib.Path(p).open('rb')as f:
  for x in iter(lambda:f.read(65536),b''):h.update(x)
 return h.hexdigest()
def owner():
 import re
 c=load('ownership.json');assert re.fullmatch('tp-udp-[a-f0-9]{8}',c['run_id'])and str(ROOT)=='/var/lib/'+c['run_id']and not ROOT.is_symlink()
 for n,h in c['files'].items():assert (ROOT/n).parent==ROOT and not(ROOT/n).is_symlink()and digest(ROOT/n)==h,'DEPENDENCY_CHANGED'
 return c
def lease(c):
 assert time.time()<c['deadline'],'DEADLINE'
 l=load('lease.json');assert l['run_id']==c['run_id']and 0<=time.time()-l['epoch']<=10,'LEASE_EXPIRED'
def snapshot():
 cpu=list(map(int,pathlib.Path('/proc/stat').read_text().splitlines()[0].split()[1:9]));m={l.split(':')[0]:int(l.split()[1])for l in pathlib.Path('/proc/meminfo').read_text().splitlines()};return dict(epoch=time.time(),monotonic=time.monotonic(),cpu=cpu,available=m['MemAvailable'],total=m['MemTotal'])
def guard(c):
 samples=[snapshot()];reason='DEADLINE'
 try:
  while True:
   lease(c);now=snapshot()
   if now['monotonic']-samples[-1]['monotonic']>15:raise ValueError('TELEMETRY_STALE')
   if now['monotonic']>samples[-1]['monotonic']:samples.append(now)
   while len(samples)>2 and samples[-1]['monotonic']-samples[1]['monotonic']>=300:samples.pop(0)
   d=[b-a for a,b in zip(samples[0]['cpu'],now['cpu'])];total=sum(d);duration=now['monotonic']-samples[0]['monotonic'];assert min(d)>=0,'CPU_COUNTER_RESET'
   mean=100*(total-d[3]-d[4])/total if total else 0
   assert now['available']>=max(131072,.12*now['total']),'RAM_LOW'
   assert duration<300 or mean<=85,'CPU_FULL300_GT85'
   s=dict(run_id=c['run_id'],epoch=now['epoch'],duration=duration,cpu_mean=mean,available_kB=now['available'],ready=duration>=300)
   atomic('guard-state.json',s)
   with(ROOT/'telemetry.jsonl').open('a')as f:f.write(json.dumps(s)+'\n')
   time.sleep(3)
 except BaseException as e:reason=type(e).__name__+':'+str(e);raise
 finally:atomic('guard-stop.json',dict(run_id=c['run_id'],epoch=time.time(),reason=reason))
def healthy(c):
 lease(c);assert not(ROOT/'guard-stop.json').exists(),'GUARD_STOP'
 g=load('guard-state.json');assert g['run_id']==c['run_id']and g['ready']and 0<=time.time()-g['epoch']<=12,'GUARD_NOT_READY'
def rule_args(c):
 result=[]
 for r in c['rules']:
  assert r['protocol']in['tcp','udp']and r['port']in c['allowed_ports'],'EXACT_TEST_PORT'
  import ipaddress
  a=['INPUT','-s',str(ipaddress.IPv4Address(r['source']))+'/32','-d',str(ipaddress.IPv4Address(r['destination']))+'/32','-p',r['protocol'],'--dport',str(r['port']),'-m','comment','--comment',c['run_id'],'-j','ACCEPT'];result.append(a)
 return result
def ipt(a):return subprocess.run(['iptables','-w','3']+a,capture_output=True,text=True,timeout=6)
def cleanup(c):
 for r in rule_args(c):
  z=ipt(['-C']+r)
  if z.returncode==0:assert ipt(['-D']+r).returncode==0,'EXACT_RULE_DELETE'
  else:assert z.returncode==1,'RULE_CHECK_FAILED'
def firewall(c):
 healthy(c)
 try:
  for r in rule_args(c):assert ipt(['-C']+r).returncode==1 and ipt(['-I',r[0],'1']+r[1:]).returncode==0,'NEW_RULE_INSERT'
  while True:healthy(c);time.sleep(.5)
 finally:cleanup(c)
def echo(c):
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((c['echo_bind'],c.get('echo_port',24439)));s.settimeout(.5)
 budget=0
 try:
  while True:
   healthy(c)
   try:data,peer=s.recvfrom(2048)
   except socket.timeout:continue
   if c['role']=='GW':
    if peer[0]!=c['foreign']or not data.startswith(c['witness_nonce'].encode()):continue
    reply=json.dumps(dict(source_ip=peer[0],sha256=hashlib.sha256(data).hexdigest())).encode()
   else:reply=data
   budget+=len(data);assert budget<=2*1048576,'ECHO_BUDGET'
   s.sendto(reply,peer)
 finally:s.close()
def worker(c):
 healthy(c);children=[]
 try:
  threading.Thread(target=echo,args=(c,),daemon=True).start()
  for name in c['configs']:
   log=(ROOT/(name+'.log')).open('ab');p=subprocess.Popen([str(ROOT/'sing-box'),'run','-c',str(ROOT/name)],cwd=ROOT,stdout=log,stderr=log);children.append(p)
  atomic('processes.json',dict(run_id=c['run_id'],epoch=time.time(),children=[dict(pid=p.pid,start_ticks=pathlib.Path('/proc',str(p.pid),'stat').read_text().split(') ',1)[1].split()[19])for p in children]))
  while True:
   healthy(c);assert all(p.poll()is None for p in children),'OWN_CHILD_EXIT';time.sleep(.5)
 finally:
  for p in children:
   if p.poll()is None:p.terminate()
  for p in children:
   try:p.wait(timeout=3)
   except subprocess.TimeoutExpired:p.kill();p.wait(timeout=3)
if __name__=='__main__':
 c=owner();mode=sys.argv[1];signal.signal(signal.SIGTERM,lambda *_:(_ for _ in()).throw(KeyboardInterrupt()))
 if mode=='cleanup':cleanup(c)
 elif mode=='guard':guard(c)
 elif mode=='firewall':firewall(c)
 elif mode=='worker':worker(c)
 else:raise ValueError('EXACT_MODE')
