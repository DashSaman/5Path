"""LOCAL loopback only: native auth, new-flow switching, existing flows and CPU/byte."""
import asyncio,contextlib,hashlib,importlib.util,json,os,pathlib,secrets,signal,socket,subprocess,sys,tempfile,time
sys.path[:0]=[str(pathlib.Path(__file__).resolve().parents[1]/x) for x in ('core','experimental')]
from native_front_config import build

B=pathlib.Path(__file__).resolve().parents[1]
ASSET=pathlib.Path(os.environ['SING_BOX_BINARY']).resolve()
assert hashlib.sha256(ASSET.read_bytes()).hexdigest()=='768d31fa7f68debc067bb4626539498a1e8751d36a7b99e1a54bee6a23815f93'
spec=importlib.util.spec_from_file_location('oldmesh',B/'core/mesh_gateway.py');mesh=importlib.util.module_from_spec(spec);spec.loader.exec_module(mesh)
children=[];report={'scope':'LOCAL_LOOPBACK_ONLY','WAN_payload_bytes':0};directory=pathlib.Path(tempfile.mkdtemp(prefix='native-front-fixture-'));signal.alarm(65)

def freeport():
 with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
ports=[]
while len(ports)<6:
 p=freeport()
 if p not in ports:ports.append(p)

def cpu(pid):
 a=pathlib.Path('/proc',str(pid),'stat').read_text().rsplit(') ',1)[1].split();return (int(a[11])+int(a[12]))/os.sysconf('SC_CLK_TCK')

async def api(port,secret,tag,member):
 r,w=await asyncio.open_connection('127.0.0.1',port);data=json.dumps({'name':member}).encode();w.write(('PUT /proxies/'+tag+' HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer '+secret+'\r\nContent-Type: application/json\r\nContent-Length: '+str(len(data))+'\r\nConnection: close\r\n\r\n').encode()+data);await w.drain();reply=await r.read();w.close();await w.wait_closed();assert reply.startswith(b'HTTP/1.1 204'),reply[:100]

async def exercise():
 servers=[];held=[];accepts=[0,0]
 async def echo(r,w):
  try:
   while data:=await r.read(65536):w.write(data);await w.drain()
  finally:w.close()
 origin=await asyncio.start_server(echo,'127.0.0.1',0);servers.append(origin);dest=origin.sockets[0].getsockname()[1]
 for i in range(2):
  async def upstream(r,w,i=i):
   accepts[i]+=1;await mesh.serve_socks(r,w,mesh.direct_connect,'up','fixture-upstream-secret')
  servers.append(await asyncio.start_server(upstream,'127.0.0.1',ports[i]))
 async def reject(r,w):w.close();await w.wait_closed()
 servers.append(await asyncio.start_server(reject,'127.0.0.1',ports[5]))
 old={'listen_host':'127.0.0.1','listen_port':ports[2],'username':'front','password':'fixture-front-secret','mode':'failover','upstreams':[{'id':'DE-'+str(i),'host':'127.0.0.1','port':ports[i],'username':'up','password':'fixture-upstream-secret','probe':{'host':'127.0.0.1','port':dest,'nonce':'fixture'}} for i in range(2)]}
 native=build(old,'DE',ports[3],ports[4],'fixture-control-secret-long-enough',ports[5]);cfg=directory/'native.json';cfg.write_text(json.dumps(native));cfg.chmod(0o600)
 check=subprocess.run([str(ASSET),'check','-c',str(cfg)],capture_output=True,text=True,timeout=6);assert check.returncode==0,check.stderr
 log=(directory/'native.log').open('wb');p=subprocess.Popen([str(ASSET),'run','-c',str(cfg)],stdout=log,stderr=log);children.append(p)
 async def wait(port):
  for _ in range(60):
   assert p.poll() is None,(directory/'native.log').read_text()
   try:r,w=await asyncio.open_connection('127.0.0.1',port);w.close();await w.wait_closed();return
   except OSError:await asyncio.sleep(.05)
  raise TimeoutError('LOCAL_NATIVE_LISTEN')
 await wait(ports[4]);await wait(ports[3])
 front={'host':'127.0.0.1','port':ports[3],'username':'front','password':'fixture-front-secret'}
 payload=secrets.token_bytes(16384);payload_sha=hashlib.sha256(payload).hexdigest()
 async def connect(upstream=front):return await mesh.socks_connect(upstream,'127.0.0.1',dest)
 async def exchange(r,w):w.write(payload);await w.drain();body=await r.readexactly(len(payload));assert hashlib.sha256(body).hexdigest()==payload_sha
 try:
  try:await connect();raise AssertionError('DEFAULT_MUST_FAIL_CLOSED')
  except (ConnectionError,asyncio.IncompleteReadError):pass
  await api(ports[4],'fixture-control-secret-long-enough','DE-latency','DE-0')
  a=await connect();held.append(a);await exchange(*a)
  await api(ports[4],'fixture-control-secret-long-enough','DE-latency','DE-1')
  b=await connect();held.append(b);await exchange(*b);await exchange(*a)
  assert accepts[0]>=1 and accepts[1]>=1
  report['selector_changes_only_new_flows']=True;report['existing_flow_survives_selection_change']=True
  await api(ports[4],'fixture-control-secret-long-enough','DE-latency','DE-reject')
  try:await connect();raise AssertionError('ALL_DOWN_MUST_FAIL_CLOSED')
  except (ConnectionError,asyncio.IncompleteReadError):pass
  await exchange(*a);report['all_down_rejects_new_and_preserves_existing']=True
  bad=dict(front,password='wrong-fixture-secret')
  try:await connect(bad);raise AssertionError('WRONG_AUTH_ACCEPTED')
  except ConnectionError:pass
  report['wrong_auth_rejected']=True
  await api(ports[4],'fixture-control-secret-long-enough','DE-latency','DE-0')
  # Same bounded local payload and same upstream, separate process CPU accounting.
  oldcfg=directory/'old.json';oldcfg.write_text(json.dumps(old));oldcfg.chmod(0o600)
  code='import asyncio,json,sys;sys.path.insert(0,'+repr(str(B/'core'))+');from mesh_gateway import Gateway; c=json.load(open(sys.argv[1]));g=Gateway(c,sys.argv[2]);g.policy.healthy={x["id"]:True for x in c["upstreams"]}\nasync def main():\n await g.start_listener()\n async with g.server:await g.server.serve_forever()\nasyncio.run(main())'
  oldlog=(directory/'old.log').open('wb');op=subprocess.Popen([sys.executable,'-c',code,str(oldcfg),str(directory/'old-state.json')],stdout=oldlog,stderr=oldlog);children.append(op);await wait(ports[2])
  oldfront=dict(front,port=ports[2]);metrics=[]
  for mode,up,process in [('old',oldfront,op),('native',front,p)]:
   streams=[await connect(up) for _ in range(8)];start=time.monotonic();c0=cpu(process.pid)
   async def traffic(stream):
    for _ in range(256):await exchange(*stream)
   await asyncio.gather(*(traffic(s) for s in streams));elapsed=time.monotonic()-start;used=cpu(process.pid)-c0
   metrics.append({'mode':mode,'payload_bytes_each_direction':8*256*len(payload),'seconds':elapsed,'process_CPU_seconds':used,'CPU_seconds_per_MiB':used/32})
   for _,w in streams:w.close();await w.wait_closed()
  report['local_CPU_comparison']=metrics;report['file_bytes']=len(payload);report['file_SHA_verified']=True;report['passed']=True
 finally:
  for _,w in held:w.close();await w.wait_closed()
  for s in servers:s.close();await s.wait_closed()

try:asyncio.run(asyncio.wait_for(exercise(),55))
finally:
 for p in reversed(children):
  p.terminate()
  try:p.wait(timeout=2)
  except subprocess.TimeoutExpired:p.kill();p.wait(timeout=2)
 report['cleanup_verified']=all(p.poll() is not None for p in children)
 report['private_fixture_directory']=str(directory)
 out=B/'local-results/native-front-local-receipt.json';out.parent.mkdir(exist_ok=True);out.write_text(json.dumps(report,indent=2));print(json.dumps(report))
