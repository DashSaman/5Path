"""Isolated Linux network + actual systemd worker/watchdog; no WAN or real users."""
import asyncio,contextlib,hashlib,http.client,importlib.util,json,os,pathlib,secrets,shutil,signal,socket,subprocess,sys,tempfile,time
sys.path[:0]=[str(pathlib.Path(__file__).resolve().parents[1]/x)for x in ('core','experimental')]
from native_front_config import build
import native_front_policy as policy
B=pathlib.Path(__file__).resolve().parents[1]
assert socket.if_nameindex()==[(1,'lo')],'ISOLATED_NETNS_REQUIRED'
rid='tp-opt-de-'+secrets.token_hex(4);root=pathlib.Path('/var/lib')/rid
directory=B/'local-results'/('native-front-lifecycle-'+secrets.token_hex(4));directory.mkdir(mode=0o700,parents=True)
units=[];children=[];owned_roots=[];report=dict(local_only=True,WAN_proven=False,WAN_bytes=0,full300_fixture_simulated=True,source_sha256={n:policy.sha(B/'experimental'/n)for n in ['native_front_policy.py','native_front_config.py']})
signal.alarm(100)
def cmd(a,check=True):
 z=subprocess.run(a,capture_output=True,text=True,timeout=8)
 if check and z.returncode:raise RuntimeError(str(a[:3])+':'+z.stderr[-500:])
 return z
def props(unit):return dict(x.split('=',1) for x in cmd(['systemctl','show',unit,'-p','Description','-p','MainPID','-p','ActiveState','-p','NRestarts','-p','FragmentPath','-p','ExecMainStatus']).stdout.splitlines() if '=' in x)
def freeport():
 with socket.socket()as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
ports=[]
while len(ports)<6:
 p=freeport()
 if p not in ports and p!=32101:ports.append(p)
def identity_commit(c):
 (root/'committed.json').write_text(json.dumps(dict(run_id=rid,ownership_sha256=policy.sha(root/'ownership.json'))))
def unit(name,mode):
 text=f'''[Unit]
Description={rid}
After=network.target
[Service]
Type=simple
ExecStartPre=/usr/bin/python3 {root}/native_front_policy.py admit {root}
ExecStart=/usr/bin/python3 {root}/native_front_policy.py {mode} {root}
WorkingDirectory={root}
NetworkNamespacePath=/proc/{os.getpid()}/ns/net
RuntimeMaxSec=85
Restart=no
Nice=10
CPUWeight=5
MemoryMax=384M
NoNewPrivileges=true
UMask=0077
'''
 if mode=='worker':text+='CapabilityBoundingSet=\n'
 else:text+='CapabilityBoundingSet=CAP_NET_ADMIN\n'
 text+='[Install]\nWantedBy=multi-user.target\n'
 target=pathlib.Path('/etc/systemd/system')/name
 assert not target.exists();target.write_text(text);units.append((name,target,hashlib.sha256(text.encode()).hexdigest()))
def active_status():return json.loads((root/'selected.json').read_text())
async def waitfor(pred,seconds=12):
 until=time.monotonic()+seconds
 while time.monotonic()<until:
  try:
   if pred():return
  except (OSError,ValueError,KeyError,AssertionError):pass
  await asyncio.sleep(.1)
 raise TimeoutError('FIXTURE_CONDITION_TIMEOUT')
spec=importlib.util.spec_from_file_location('mesh',B/'core/mesh_gateway.py');mesh=importlib.util.module_from_spec(spec);spec.loader.exec_module(mesh)
async def exercise():
 servers=[];held=[];api_bad=[False];counts={'old':0,'upstream':0};parent=None;client=None
 cmd(['ip','link','set','lo','up'])
 clientns=subprocess.Popen(['unshare','--net','--','sleep','90']);children.append(clientns)
 await asyncio.sleep(.1)
 cmd(['ip','link','add','nfgw','type','veth','peer','name','nfclient'])
 cmd(['ip','link','set','nfclient','netns',str(clientns.pid)])
 cmd(['ip','addr','add','192.0.2.30/24','dev','nfgw']);cmd(['ip','link','set','nfgw','up'])
 # Native monitors the default interface. The isolated peer has no forwarding
 # or WAN; this supplies realistic local route identity without external access.
 cmd(['ip','route','add','default','via','192.0.2.10','dev','nfgw'])
 for args in [['ip','link','set','lo','up'],['ip','addr','add','192.0.2.10/24','dev','nfclient'],['ip','link','set','nfclient','up']]:cmd(['nsenter','-t',str(clientns.pid),'-n',*args])
 async def echo(r,w):
  try:
   while data:=await r.read(16384):w.write(data);await w.drain()
  finally:w.close()
 origin=await asyncio.start_server(echo,'127.0.0.1',0);servers.append(origin);dest=origin.sockets[0].getsockname()[1]
 async def socks(r,w,kind):
  counts[kind]+=1
  await mesh.serve_socks(r,w,mesh.direct_connect,'front','fixture-front-password')
 servers.append(await asyncio.start_server(lambda r,w:socks(r,w,'upstream'),'127.0.0.1',ports[0]))
 servers.append(await asyncio.start_server(lambda r,w:socks(r,w,'old'),'192.0.2.30',32101))
 # Actual native API is behind an isolated fault injector. Production has none.
 async def proxy(r,w):
  upstream=None
  try:
   head=await r.readuntil(b'\r\n\r\n');n=next((int(x.split(b':',1)[1])for x in head.split(b'\r\n')if x.lower().startswith(b'content-length:')),0);body=await r.readexactly(n)
   if api_bad[0]:w.write(b'HTTP/1.1 503 Fixture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');await w.drain();return
   rr,ww=await asyncio.open_connection('127.0.0.1',ports[4]);upstream=ww;ww.write(head+body);await ww.drain();data=await rr.read(16384);w.write(data);await w.drain()
  except (OSError,asyncio.IncompleteReadError):pass
  finally:
   if upstream:upstream.close()
   w.close()
 servers.append(await asyncio.start_server(proxy,'127.0.0.1',ports[3]))
 assert not root.exists();root.mkdir(mode=0o700);owned_roots.append(root)
 asset=pathlib.Path(os.environ['SING_BOX_BINARY']).resolve();assert policy.sha(asset)=='768d31fa7f68debc067bb4626539498a1e8751d36a7b99e1a54bee6a23815f93'
 shutil.copyfile(asset,root/'sing-box');(root/'sing-box').chmod(0o700);shutil.copyfile(B/'experimental/native_front_policy.py',root/'native_front_policy.py')
 old=dict(listen_host='192.0.2.30',listen_port=32101,username='front',password='fixture-front-password',upstreams=[dict(id='DE-a',host='127.0.0.1',port=ports[0],username='front',password='fixture-front-password',probe=dict(host='127.0.0.1',port=dest,nonce='fixture'))])
 native=build(old,'DE',ports[1],ports[4],'fixture-control-secret-123456789',ports[2]);(root/'native.json').write_text(json.dumps(native))
 # A real separate parent PID with exact file arguments; its health is fixture data.
 parentroot=root/'parent';(parentroot/'gw').mkdir(parents=True);(parentroot/'gw/gateway.json').write_text('{}')
 parentcode="import os,json,pathlib,time,sys\np=pathlib.Path(sys.argv[2])\nwhile True:\n t=p.with_suffix('.tmp');t.write_text(json.dumps(dict(worker_pid=os.getpid(),updated_at=time.time(),healthy={'DE-a':True},probes={'DE-a':dict(ok=True,latency_ms=2)})));t.replace(p);time.sleep(.2)\n"
 (parentroot/'gw/mesh_gateway.py').write_text(parentcode)
 parent=subprocess.Popen([sys.executable,str(parentroot/'gw/mesh_gateway.py'),str(parentroot/'gw/gateway.json'),str(root/'parent-state.json')]);children.append(parent)
 await waitfor(lambda:(root/'parent-state.json').exists())
 c=dict(run_id=rid,root=str(root),purpose='OWN_TCP_NATIVE_FRONT',country='DE',members=['DE-a'],source='192.0.2.10',destination='192.0.2.30',old_port=32101,new_port=ports[1],reject_port=ports[2],control_port=ports[3],parent_root=str(parentroot),parent_config_sha256=policy.sha(parentroot/'gw/gateway.json'),parent_gateway_cgroup=pathlib.Path('/proc',str(parent.pid),'cgroup').read_text().strip(),state_path=str(root/'parent-state.json'),worker_cgroup='/system.slice/'+rid+'-worker.service',guards=[],deadline=time.time()+80,files={n:policy.sha(root/n)for n in ['sing-box','native.json','native_front_policy.py']})
 (root/'ownership.json').write_text(json.dumps(c))
 # A separate expired candidate is never restarted/adopted.
 badrid='tp-opt-de-'+secrets.token_hex(4);bad=pathlib.Path('/var/lib')/badrid;bad.mkdir(mode=0o700);owned_roots.append(bad)
 badc=dict(c,run_id=badrid,root=str(bad),files={})
 (bad/'ownership.json').write_text(json.dumps(badc));(bad/'lease.json').write_text(json.dumps(dict(run_id=badrid,epoch=time.time()-20)))
 z=cmd([sys.executable,str(root/'native_front_policy.py'),'admit',str(bad)],False);assert z.returncode==78 and (bad/'prepare-aborted.json').exists();report['expired_prepare_exit78']=True
 (root/'lease.json').write_text(json.dumps(dict(run_id=rid,epoch=time.time())))
 worker=rid+'-worker.service';watch=rid+'-watchdog.service';unit(worker,'worker');unit(watch,'watchdog');cmd(['systemctl','daemon-reload'])
 cmd(['systemctl','start',worker]);await waitfor(lambda:active_status().get('ready'))
 # Local client lives across the veth, so these exercise actual PREROUTING.
 clientcode=r'''import socket,sys,json,hashlib
sockets={}
def exact(s,n):
 b=b''
 while len(b)<n:
  d=s.recv(n-len(b))
  if not d:raise EOFError()
  b+=d
 return b
for line in sys.stdin:
 try:
  q=json.loads(line);key=q['id']
  if q['action']=='connect':
   s=socket.create_connection(('192.0.2.30',q.get('listen_port',32101)),4);s.settimeout(4);s.sendall(b'\x05\x01\x02');assert exact(s,2)==b'\x05\x02';u=b'front';p=b'fixture-front-password';s.sendall(b'\x01'+bytes([len(u)])+u+bytes([len(p)])+p);assert exact(s,2)==b'\x01\x00';s.sendall(b'\x05\x01\x00\x01'+socket.inet_aton('127.0.0.1')+int(q['port']).to_bytes(2,'big'));assert exact(s,4)==b'\x05\x00\x00\x01';exact(s,6);sockets[key]=s
  elif q['action']=='echo':
   data=b'x'*16384;s=sockets[key];s.sendall(data);assert exact(s,len(data))==data
  elif q['action']=='close':sockets.pop(key).close()
  print(json.dumps({'ok':True}),flush=True)
 except BaseException as e:print(json.dumps({'ok':False,'error':type(e).__name__}),flush=True)
'''
 client=subprocess.Popen(['nsenter','-t',str(clientns.pid),'-n',sys.executable,'-u','-c',clientcode],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True);children.append(client)
 async def request(action,key,listen_port=32101):
  client.stdin.write(json.dumps(dict(action=action,id=key,port=dest,listen_port=listen_port))+'\n');client.stdin.flush()
  response=await asyncio.to_thread(client.stdout.readline);assert response and json.loads(response).get('ok'),response
 await request('connect','old');await request('echo','old');assert counts['old']==1
 cmd(['systemctl','start',watch]);await asyncio.sleep(.2)
 assert policy.ipt(['-C',*policy.redirect_args(c)]).returncode==1,'UNCOMMITTED_PUBLISHED'
 before={name:props(name)for name in [worker,watch]};assert all(x['ActiveState']=='active'and x['NRestarts']=='0'for x in before.values())
 cmd(['systemctl','enable',worker,watch]);assert {name:props(name)for name in [worker,watch]}==before
 for name in [worker,watch]:assert pathlib.Path('/etc/systemd/system/multi-user.target.wants',name).resolve()==pathlib.Path('/etc/systemd/system',name)
 identity_commit(c);await waitfor(lambda:policy.ipt(['-C',*policy.redirect_args(c)]).returncode==0)
 report['enabled_before_commit_without_restart']=True
 await request('connect','native');await request('echo','native');assert counts['upstream']==1
 await request('connect','direct',ports[1]);await request('echo','direct')
 report['before_control_failure']=dict(status=active_status(),worker=props(worker),watchdog=props(watch))
 api_bad[0]=True
 await waitfor(lambda:not active_status().get('ready'));await waitfor(lambda:policy.ipt(['-C',*policy.redirect_args(c)]).returncode==1)
 report['after_control_failure']=dict(status=active_status(),worker=props(worker),watchdog=props(watch))
 await request('echo','direct');report['direct_native_flow_survives_control_failure']=True
 await request('echo','native');await request('echo','old');await request('connect','fallback');await request('echo','fallback');assert counts['old']==2
 assert props(worker)['MainPID']==before[worker]['MainPID'];report['control_503_preserves_existing_and_withdraws_only_new_flows']=True
 api_bad[0]=False;await waitfor(lambda:active_status().get('ready'));await waitfor(lambda:policy.ipt(['-C',*policy.redirect_args(c)]).returncode==0)
 directc=dict(c,control_port=ports[4]);await asyncio.to_thread(policy.selector_request,directc,'fixture-control-secret-123456789','PUT','DE-reject')
 await waitfor(lambda:policy.selector_request(directc,'fixture-control-secret-123456789','GET').get('now')=='DE-a')
 await request('echo','native');report['actual_readback_mismatch_corrected']=True
 for key in ['old','native','direct','fallback']:await request('close',key)
 # A boot-equivalent explicit restart is performed only after local streams close.
 oldpid=active_status()['native_identity']['pid'];cmd(['systemctl','stop',worker]);await waitfor(lambda:policy.ipt(['-C',*policy.redirect_args(c)]).returncode==1)
 cmd(['systemctl','start',worker]);await waitfor(lambda:active_status().get('ready')and active_status()['native_identity']['pid']!=oldpid);await waitfor(lambda:policy.ipt(['-C',*policy.redirect_args(c)]).returncode==0)
 await request('connect','boot');await request('echo','boot');await request('close','boot');report['committed_boot_new_identity_revalidated']=True
 cmd(['systemctl','stop',watch]);assert policy.ipt(['-C',*policy.redirect_args(c)]).returncode==1;report['exact_redirect_removed']=True
 report['passed']=True
 for s in servers:s.close();await s.wait_closed()

try:asyncio.run(exercise())
finally:
 if root.exists():
  diagnostic={p.name:p.read_text(errors='replace')[-5000:]for p in root.glob('*.log')};(directory/'logs.private.json').write_text(json.dumps(diagnostic))
 for name,target,digest in reversed(units):
  if props(name).get('ActiveState')in ['active','activating']:assert props(name)['Description']==rid;cmd(['systemctl','stop',name])
  cmd(['systemctl','disable',name],False)
  assert hashlib.sha256(target.read_bytes()).hexdigest()==digest;target.unlink()
 if units:cmd(['systemctl','daemon-reload'])
 if root.exists() and (root/'ownership.json').exists():
  c=json.loads((root/'ownership.json').read_text());args=policy.anchor_args(c)
  policy.filter_rule(c,False)
  if policy.ipt(['-C',*args]).returncode==0:assert policy.ipt(['-D',*args]).returncode==0
 for p in reversed(children):
  if p.poll()is None:p.terminate()
  try:p.wait(timeout=2)
  except subprocess.TimeoutExpired:p.kill();p.wait(timeout=2)
 for r in owned_roots:
  assert r.parent==pathlib.Path('/var/lib') and r.name.startswith('tp-opt-de-');shutil.rmtree(r)
 report['clean']=all(p.poll()is not None for p in children);(directory/'result.json').write_text(json.dumps(report,indent=2));print(json.dumps(dict(directory=str(directory),**report)));signal.alarm(0)
