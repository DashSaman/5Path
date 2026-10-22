"""Real old/native SOCKS admission characterization in an empty LOCAL netns."""
import asyncio,contextlib,hashlib,importlib.util,json,os,pathlib,secrets,signal,socket,subprocess,sys,tempfile,time
sys.path[:0]=[str(pathlib.Path(__file__).resolve().parents[1]/x)for x in ('core','experimental')]
from native_front_config import build
B=pathlib.Path(__file__).resolve().parents[1]
assert socket.if_nameindex()==[(1,'lo')],'ISOLATED_LOCAL_NETNS_REQUIRED'
subprocess.run(['ip','link','set','lo','up'],check=True,timeout=3)
asset=pathlib.Path(os.environ['SING_BOX_BINARY']).resolve()
assert hashlib.sha256(asset.read_bytes()).hexdigest()=='768d31fa7f68debc067bb4626539498a1e8751d36a7b99e1a54bee6a23815f93'
spec=importlib.util.spec_from_file_location('mesh',B/'core/mesh_gateway.py');mesh=importlib.util.module_from_spec(spec);spec.loader.exec_module(mesh)
directory=B/'local-results'/('native-admission-local-'+secrets.token_hex(4));directory.mkdir(mode=0o700,parents=True)
children=[];streams=[];report=dict(local_only=True,WAN_bytes=0,server_mutations=False,cap=3)
signal.alarm(55)
def freeport():
 with socket.socket()as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
ports=[]
while len(ports)<7:
 p=freeport()
 if p not in ports:ports.append(p)
def start(args,name):
 f=(directory/(name+'.log')).open('wb');p=subprocess.Popen(args,stdout=f,stderr=f);children.append(p);return p
def identity(p):return dict(pid=p.pid,start=pathlib.Path('/proc',str(p.pid),'stat').read_text().rsplit(') ',1)[1].split()[19])
async def wait(port,p):
 for _ in range(80):
  assert p.poll()is None,'LOCAL_PROCESS_EXIT'
  try:r,w=await asyncio.open_connection('127.0.0.1',port);w.close();await w.wait_closed();return
  except OSError:await asyncio.sleep(.025)
 raise TimeoutError('LOCAL_LISTENER_NOT_READY')
async def greeting(port):
 r,w=await asyncio.open_connection('127.0.0.1',port);streams.append(w);w.write(b'\x05\x01\x02');await w.drain()
 try:reply=await asyncio.wait_for(r.readexactly(2),1)
 except (ConnectionResetError,asyncio.IncompleteReadError):reply=b''
 return r,w,reply
async def close_all():
 for w in streams:w.close()
 for w in streams:
  with contextlib.suppress(OSError):await w.wait_closed()
 streams.clear();await asyncio.sleep(.1)
def cpu(p):
 a=pathlib.Path('/proc',str(p.pid),'stat').read_text().rsplit(') ',1)[1].split();return(int(a[11])+int(a[12]))/os.sysconf('SC_CLK_TCK')
async def choose(member):
 r,w=await asyncio.open_connection('127.0.0.1',ports[4]);body=json.dumps({'name':member}).encode();w.write(('PUT /proxies/DE-latency HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer local-control-secret-sufficient-length\r\nContent-Type: application/json\r\nContent-Length: '+str(len(body))+'\r\nConnection: close\r\n\r\n').encode()+body);await w.drain();reply=await r.read();w.close();await w.wait_closed();assert reply.startswith(b'HTTP/1.1 204')
async def auth_destination(r,w,old):
 u=old['username'].encode();pw=old['password'].encode();w.write(b'\x01'+bytes([len(u)])+u+bytes([len(pw)])+pw);await w.drain();assert await r.readexactly(2)==b'\x01\x00';w.write(b'\x05\x01\x00\x01\x7f\x00\x00\x01'+ports[0].to_bytes(2,'big'));await w.drain();assert(await r.readexactly(10))[:2]==b'\x05\x00'
async def payload(r,w,data):
 w.write(data);await w.drain();assert hashlib.sha256(await r.readexactly(len(data))).digest()==hashlib.sha256(data).digest()
async def gate_phase(old,op,np,data):
 await close_all();await choose('DE-one');cfg=directory/'gate.json';state=directory/'gate-state.json';cfg.write_text(json.dumps(dict(listen_port=ports[6],backend_port=ports[3],maximum=3,state_path=str(state))));cfg.chmod(0o600)
 gp=start([sys.executable,str(B/'experimental/native_tcp_admission.py'),str(cfg)],'gate');await wait(ports[6],gp)
 async def empty():
  for _ in range(80):
   if state.exists()and json.loads(state.read_text())['active']==0:return
   await asyncio.sleep(.025)
  raise TimeoutError('GATE_SLOTS_DID_NOT_DRAIN')
 await empty();pid=identity(gp)
 oldheld=[(await greeting(ports[2]))[:2]for _ in range(3)];newheld=[]
 for _ in range(3):
  r,w,reply=await greeting(ports[6]);assert reply==b'\x05\x02';newheld.append((r,w))
 def backend_count():return sum(x.split()[1].endswith(':'+format(ports[3],'04X'))and x.split()[3]=='01'for x in pathlib.Path('/proc/net/tcp').read_text().splitlines()[1:])
 assert backend_count()==3,'ONLY_THREE_PENDING_NATIVE_BACKENDS'
 for port in [ports[2],ports[6]]:
  r,w=await asyncio.open_connection('127.0.0.1',port);streams.append(w)
  with contextlib.suppress(ConnectionResetError):assert await asyncio.wait_for(r.read(1),1)==b''
 assert backend_count()==3,'OVER_CAP_MUST_NOT_OPEN_BACKEND'
 await auth_destination(*newheld[0],old);await payload(*newheld[0],data);await auth_destination(*oldheld[0],old);await payload(*oldheld[0],data)
 report.update(gate_rejects_N_plus_1_with_N_pending=True,gate_excess_opens_no_backend=True,old_native_overlap=dict(legacy_cap=3,native_gate_cap=3,simultaneously_held=6,strict_aggregate_legacy_cap_preserved=False),old_and_gated_held_payload_SHA_preserved=True)
 await choose('DE-reject');await payload(*newheld[0],data);await payload(*oldheld[0],data);report['held_payload_survives_native_selection_reject']=True
 await choose('DE-one');await close_all();await empty()
 metrics=[]
 for mode,port,ps in [('old',ports[2],[op]),('native',ports[3],[np]),('gated-native',ports[6],[np,gp])]:
  up=dict(host='127.0.0.1',port=port,username=old['username'],password=old['password']);held=[await mesh.socks_connect(up,'127.0.0.1',ports[0])for _ in range(2)]
  for _,w in held:streams.append(w)
  initial=[cpu(p)for p in ps];began=time.monotonic()
  async def transfer(stream):
   for _ in range(1024):await payload(*stream,data)
  await asyncio.gather(*(transfer(s)for s in held));elapsed=time.monotonic()-began;used=[cpu(p)-v for p,v in zip(ps,initial)]
  metrics.append(dict(mode=mode,bytes_each_direction=32*1048576,file_bytes=len(data),concurrency=2,seconds=elapsed,component_CPU_seconds=used,total_front_CPU_seconds=sum(used),CPU_seconds_per_MiB=sum(used)/32));await close_all()
  if mode=='gated-native':await empty()
 report['local_CPU_comparison_same_data_upstream_concurrency']=metrics;report['gated_CPU_better_than_old_in_this_sample']=metrics[2]['total_front_CPU_seconds']<metrics[0]['total_front_CPU_seconds'];report['gate_PID_start_ticks_preserved']=identity(gp)==pid;report['production_rollout_unlocked']=False
async def exercise():
 async def echo(r,w):
  try:
   while data:=await r.read(65536):w.write(data);await w.drain()
  finally:w.close()
 origin=await asyncio.start_server(echo,'127.0.0.1',ports[0])
 async def upstream(r,w):await mesh.serve_socks(r,w,mesh.direct_connect,'up','local-upstream-only')
 server=await asyncio.start_server(upstream,'127.0.0.1',ports[1])
 old=dict(listen_host='127.0.0.1',listen_port=ports[2],username='front',password='local-front-only-secret',max_connections=3,mode='failover',upstreams=[dict(id='DE-one',host='127.0.0.1',port=ports[1],username='up',password='local-upstream-only',probe=dict(host='127.0.0.1',port=ports[0],nonce='fixture'))])
 path=directory/'old.json';path.write_text(json.dumps(old));path.chmod(0o600)
 code='import asyncio,json,sys;sys.path.insert(0,'+repr(str(B/'core'))+');from mesh_gateway import Gateway;c=json.load(open(sys.argv[1]));g=Gateway(c,sys.argv[2]);g.policy.healthy={x["id"]:True for x in c["upstreams"]}\nasync def main():\n await g.start_listener()\n async with g.server:await g.server.serve_forever()\nasyncio.run(main())'
 op=start([sys.executable,'-c',code,str(path),str(directory/'old-state.json')],'old');await wait(ports[2],op)
 conf=build(old,'DE',ports[3],ports[4],'local-control-secret-sufficient-length',ports[5]);path=directory/'native.json';path.write_text(json.dumps(conf));path.chmod(0o600)
 z=subprocess.run([str(asset),'check','-c',str(path)],capture_output=True,text=True,timeout=5);assert z.returncode==0,z.stderr
 np=start([str(asset),'run','-c',str(path)],'native');await wait(ports[3],np);await wait(ports[4],np)
 before={p.pid:identity(p)for p in children};await asyncio.sleep(.1)
 try:
  accepted=[]
  for _ in range(3):
   r,w,reply=await greeting(ports[2]);assert reply==b'\x05\x02';accepted.append((r,w))
  r,w,reply=await greeting(ports[2]);assert reply==b'';report['legacy_rejects_N_plus_1_with_N_pending']=True
  r,w=accepted[0];u=old['username'].encode();pw=old['password'].encode();w.write(b'\x01'+bytes([len(u)])+u+bytes([len(pw)])+pw);await w.drain();assert await r.readexactly(2)==b'\x01\x00'
  w.write(b'\x05\x01\x00\x01\x7f\x00\x00\x01'+ports[0].to_bytes(2,'big'));await w.drain();assert(await r.readexactly(10))[:2]==b'\x05\x00'
  data=secrets.token_bytes(16384);w.write(data);await w.drain();assert hashlib.sha256(await r.readexactly(len(data))).digest()==hashlib.sha256(data).digest();report['legacy_held_payload_SHA_preserved_after_reject']=True
  await close_all()
  replies=[]
  for _ in range(4):
   _,_,reply=await greeting(ports[3]);replies.append(reply==b'\x05\x02')
  report['direct_native_pending_accepted']=sum(replies);report['direct_native_enforces_legacy_cap']=sum(replies)<=3
  assert all(replies),'CHARACTERIZATION_CHANGED_REVIEW_NATIVE_IMPLEMENTATION'
  report['missing_native_admission_reproduced']=True
  await gate_phase(old,op,np,data)
  report['existing_PIDs_start_ticks_preserved']=all(identity(p)==before[p.pid]for p in children if p.pid in before)
 finally:
  await close_all();origin.close();server.close();await origin.wait_closed();await server.wait_closed()
try:asyncio.run(asyncio.wait_for(exercise(),45))
finally:
 for p in reversed(children):
  p.terminate()
  try:p.wait(timeout=2)
  except subprocess.TimeoutExpired:p.kill();p.wait(timeout=2)
 report['all_owned_children_stopped']=all(p.poll()is not None for p in children)
 (directory/'result.json').write_text(json.dumps(report,indent=2));print(json.dumps(dict(directory=str(directory),**report)))
