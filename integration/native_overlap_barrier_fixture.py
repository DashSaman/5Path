"""LOCAL negative proof: kernel socket census may undercount legacy admission.

One finite K=3 fixture, fresh loopback-only netns, original legacy source,
already-built native asset. No SSH, build, download or production actions.
An early counterexample rejects the method; remaining acceptance cases then
cannot be claimed as passed and are deliberately not run.
"""
import asyncio,contextlib,ctypes,hashlib,importlib.util,json,os,pathlib,secrets
import signal,socket,struct,subprocess,sys,time
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'experimental'))
from native_front_config import build

B=pathlib.Path(__file__).resolve().parents[1]
ROOT=pathlib.Path(os.environ['FIVEPATH_LOCAL_BUILD_ROOT'])
assert socket.if_nameindex()==[(1,'lo')], 'EMPTY_NEW_NETNS_REQUIRED'
assert json.loads((ROOT/'ownership.json').read_text())['purpose']=='LOCAL_NATIVE_ADMISSION_BUILD_ONLY'
manifest=json.loads(pathlib.Path(os.environ['FIVEPATH_INLINE_BUILD_MANIFEST']).read_text())
asset=pathlib.Path(manifest['binaries']['patched']['path'])
assert hashlib.sha256(asset.read_bytes()).hexdigest()==manifest['binaries']['patched']['sha256']
original=B/'core/mesh_gateway.py'
spec=importlib.util.spec_from_file_location('overlap_mesh',original)
mesh=importlib.util.module_from_spec(spec);spec.loader.exec_module(mesh)
(B/'local-results').mkdir(exist_ok=True)
D=B/'local-results'/('native-overlap-barrier-'+secrets.token_hex(4));D.mkdir(mode=0o700)
R=dict(local_only=True,WAN_bytes=0,SSH_connections=0,production_changes=False,K=3,
       phase='RUNNING',source_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
       legacy_source_sha256=hashlib.sha256(original.read_bytes()).hexdigest(),
       native_binary_sha256=manifest['binaries']['patched']['sha256'],
       question='Can a sealed legacy ingress plus LISTENER-PORT TCP census safely allocate remaining strict application slots?',
       test_buffer_bytes=8*1024*1024,file_bytes=16384,CPU_benchmark=False,
       production_rollout_unlocked=False,checks={})
children=[];handles=[];writers=[];carrier_writers=[];rules=[]
signal.alarm(80);os.nice(15)

def save(): (D/'result.json').write_text(json.dumps(R,indent=2))
def command(args):
    q=subprocess.run(args,capture_output=True,text=True,timeout=4)
    assert q.returncode==0, 'LOCAL_COMMAND_FAILED:'+args[0]+':'+q.stderr[-180:]
    return q.stdout
command(['ip','link','set','lo','up'])
assert command(['iptables','-S']).strip()=='-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT'
assert command(['ip6tables','-S']).strip()=='-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT'
ports=[]
while len(ports)<7:
    with socket.socket()as s:
        s.bind(('127.0.0.1',0));port=s.getsockname()[1]
        if port not in ports:ports.append(port)

def pdeath():
    parent=os.getppid();lib=ctypes.CDLL(None)
    assert lib.prctl(1,signal.SIGKILL)==0
    if os.getppid()!=parent:os._exit(90)
def start(args,name):
    log=(D/(name+'.log')).open('wb');handles.append(log)
    p=subprocess.Popen(args,stdout=log,stderr=log,preexec_fn=pdeath)
    children.append(p);return p
def identity(p):
    return dict(pid=p.pid,start_ticks=pathlib.Path('/proc',str(p.pid),'stat').read_text().rsplit(') ',1)[1].split()[19])
def oracle():
    value=json.loads((D/'legacy-oracle.json').read_text())
    assert 0<=time.monotonic()-value['monotonic']<.5, 'ORACLE_STALE_OR_FUTURE'
    return value
def census():
    rows=[]
    for family in ['tcp','tcp6']:
        for line in pathlib.Path('/proc/net',family).read_text().splitlines()[1:]:
            row=line.split()
            if int(row[1].rsplit(':',1)[1],16)==ports[2]and row[3]!='0A':
                rows.append(dict(family=family,state=row[3],inode=row[9]))
    return rows
async def poll(check,timeout=3):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        try:
            value=check()
            if value:return value
        except(FileNotFoundError,json.JSONDecodeError):pass
        await asyncio.sleep(.025)
    raise AssertionError('FIXTURE_CONDITION_NOT_REACHED')
async def witness(after_sequence=-1):
    def check():
        value=oracle()
        return value if value['sequence']>after_sequence else None
    value=await poll(check)
    R.setdefault('oracle_witnesses',[]).append(value)
    return value
async def opened(port):
    r,w=await asyncio.open_connection('127.0.0.1',port);writers.append(w);return r,w
async def greeting(port):
    r,w=await opened(port);w.write(b'\x05\x01\x02');await w.drain()
    try:reply=await asyncio.wait_for(r.readexactly(2),1)
    except(asyncio.IncompleteReadError,ConnectionResetError):reply=b''
    return r,w,reply
async def connected(port,destination):
    r,w,reply=await greeting(port);assert reply==b'\x05\x02'
    user,secret=b'front',b'local-front-only-secret'
    w.write(b'\x01'+bytes([len(user)])+user+bytes([len(secret)])+secret);await w.drain()
    assert await asyncio.wait_for(r.readexactly(2),1)==b'\x01\x00'
    w.write(b'\x05\x01\x00'+mesh.address_bytes('127.0.0.1',destination));await w.drain()
    reply=await asyncio.wait_for(r.readexactly(4),2);assert reply[:3]==b'\x05\x00\x00'
    await mesh.read_address(r,reply[3]);return r,w
async def payload(stream,data):
    r,w=stream;w.write(data);await w.drain()
    assert hashlib.sha256(await asyncio.wait_for(r.readexactly(len(data)),2)).digest()==hashlib.sha256(data).digest()
async def choose():
    r,w=await opened(ports[4]);body=b'{"name":"DE-one"}'
    w.write(b'PUT /proxies/DE-latency HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer local-control-secret-sufficient-length\r\nContent-Type: application/json\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body);await w.drain()
    assert(await asyncio.wait_for(r.read(),2)).startswith(b'HTTP/1.1 204');w.close();await w.wait_closed()

async def exercise():
    hold=asyncio.Event();slow_ready=asyncio.Event()
    upstream_accepts=0
    async def carrier(r,w):
        nonlocal upstream_accepts
        carrier_writers.append(w)
        try:
            header=await r.readexactly(2);await r.readexactly(header[1])
            w.write(b'\x05\x02');await w.drain()
            header=await r.readexactly(2);await r.readexactly(header[1]);size=(await r.readexactly(1))[0];await r.readexactly(size)
            w.write(b'\x01\x00');await w.drain()
            header=await r.readexactly(4);_,destination=await mesh.read_address(r,header[3])
            w.write(b'\x05\x00\x00\x01'+bytes(6));await w.drain();upstream_accepts+=1
            if destination==ports[6]:
                slow_ready.set();await hold.wait()
            else:
                while data:=await r.read(16384):w.write(data);await w.drain()
        except(asyncio.IncompleteReadError,ConnectionResetError,BrokenPipeError):pass
        finally:w.close()
    sock=socket.socket();sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    sock.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4096)
    sock.bind(('127.0.0.1',ports[1]));sock.listen(16);sock.setblocking(False)
    server=await asyncio.start_server(carrier,sock=sock,limit=4096)
    old=dict(listen_host='127.0.0.1',listen_port=ports[2],username='front',password='local-front-only-secret',max_connections=3,mode='failover',
       upstreams=[dict(id='DE-one',host='127.0.0.1',port=ports[1],username='up',password='local-upstream-only',
                      probe=dict(host='127.0.0.1',port=ports[0],nonce='local-fixture-only'))])
    cfg=D/'legacy.json';cfg.write_text(json.dumps(old));cfg.chmod(0o600)
    # The oracle observes the existing task set. It neither wraps handle/close
    # nor changes the original source, max_connections, transports or callbacks.
    code='''import asyncio,json,sys,pathlib,os,time
sys.path.insert(0,sys.argv[1]);from mesh_gateway import Gateway,atomic_json
g=Gateway(json.load(open(sys.argv[2])),sys.argv[3]);g.policy.healthy={'DE-one':True}
def task_state(task):
 c=task.get_coro();chain=[];remote_close_pending=False
 for _ in range(16):
  frame=getattr(c,'cr_frame',None);code=getattr(c,'cr_code',None)
  if frame is not None and code is not None:
   chain.append(dict(function=code.co_name,line=frame.f_lineno))
   if code.co_name=='serve_socks':
    local=frame.f_locals
    remote_close_pending=local.get('remote_writer')is not None and local.get('stream')is local.get('remote_writer')
  c=getattr(c,'cr_await',None)
  if c is None:break
 return dict(await_chain=chain,waiting_for_remote_close=remote_close_pending)
async def observe():
 sequence=0
 while True:
  sequence+=1
  states=[task_state(task)for task in g._connections]
  atomic_json(sys.argv[4],dict(pid=os.getpid(),accepted_pending_tasks=len(g._connections),legacy_source_unchanged=True,sequence=sequence,monotonic=time.monotonic(),task_states=states))
  await asyncio.sleep(.01)
async def main():
 await g.start_listener();observer=asyncio.create_task(observe())
 observer.add_done_callback(lambda task:None if task.cancelled()else os._exit(91))
 async with g.server:await g.server.serve_forever()
asyncio.run(main())
'''
    op=start([sys.executable,'-c',code,str(original.parent),str(cfg),str(D/'unused-state.json'),str(D/'legacy-oracle.json')],'legacy')
    await poll(lambda:(D/'legacy-oracle.json').exists())
    before=identity(op)
    data=secrets.token_bytes(16384);survivor=await connected(ports[2],ports[0]);await payload(survivor,data)
    slow=await connected(ports[2],ports[6]);await slow_ready.wait()
    await poll(lambda:oracle()['accepted_pending_tasks']==2)
    slow[1].write(data*512)
    # Give the deliberately non-reading peer enough time to close its window;
    # no throughput or CPU sample is taken from this bounded local setup.
    await asyncio.sleep(.6)
    slow[1].get_extra_info('socket').setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0))
    slow[1].transport.abort()
    await poll(lambda:len(census())==1 and oracle()['accepted_pending_tasks']==2,4)
    first_witness=await witness()
    assert first_witness['pid']==op.pid and any(s['waiting_for_remote_close']for s in first_witness['task_states'])
    R['checks']['legacy_task_survives_client_RST_while_upstream_close_is_backpressured']=True
    # Stronger than a source-specific production barrier: deny ALL fresh SYNs
    # to the legacy port in both families inside the empty owned namespace.
    for tool in ['iptables','ip6tables']:
        args=['INPUT','-p','tcp','--dport',str(ports[2]),'--syn','-m','comment','--comment',D.name,'-j','REJECT','--reject-with','tcp-reset']
        command([tool,'-w','2','-I',*args]);rules.append((tool,args))
    try:
        r,w=await opened(ports[2]);raise AssertionError('LEGACY_FRESH_SYN_NOT_SEALED')
    except ConnectionRefusedError:pass
    await payload(survivor,data)
    visible=census();actual=oracle()['accepted_pending_tasks'];N=3-len(visible)
    assert len(visible)==1 and actual==2 and N==2
    sealed_witness=await witness(first_witness['sequence'])
    assert sealed_witness['accepted_pending_tasks']==2 and any(s['waiting_for_remote_close']for s in sealed_witness['task_states'])
    R['checks']['both_family_all_source_SYN_barriers_installed']=True
    R['checks']['fresh_IPv4_legacy_connection_refused']=True
    R['checks']['legacy_survivor_SHA_after_barrier']=True
    R['counterexample']=dict(visible_legacy_TCP_entries=len(visible),actual_legacy_application_slots=actual,
       counted_TCP_states=visible,proposed_native_N=N,computed_sum=len(visible)+N,actual_sum=actual+N,
       hidden_slot_kind='Original legacy task waiting for remote_writer close after client RST; live coroutine frame and fresh advancing oracle observed',
       limitation='Only inbound/listener-port census is disproven; PID-all-sockets/FD bounds or stronger accounting are not disproven')
    native=build(old,'DE',ports[3],ports[4],'local-control-secret-sufficient-length',ports[5])
    native['inbounds'][0]['five_path_tcp_admission_limit']=N
    np=D/'native.json';np.write_text(json.dumps(native));np.chmod(0o600)
    check=subprocess.run([str(asset),'check','-c',str(np)],capture_output=True,text=True,timeout=4)
    (D/'native-config-check.log').write_text(check.stdout+check.stderr);assert check.returncode==0
    child=start([str(asset),'run','-c',str(np)],'native')
    # Readiness uses listening socket state and opens no admission slot.
    await poll(lambda:any(int(line.split()[1].rsplit(':',1)[1],16)==ports[4]and line.split()[3]=='0A'for line in pathlib.Path('/proc/net/tcp').read_text().splitlines()[1:]))
    await choose()
    new=[await connected(ports[3],ports[0])for _ in range(N)]
    count=upstream_accepts
    assert(await greeting(ports[3]))[2]==b'' and upstream_accepts==count
    for stream in [survivor,*new]:await payload(stream,data)
    assert oracle()['accepted_pending_tasks']==2 and len(census())==1
    final_witness=await witness(sealed_witness['sequence'])
    assert final_witness['accepted_pending_tasks']==2 and any(s['waiting_for_remote_close']for s in final_witness['task_states'])
    R['checks']['fresh_advancing_oracle_before_after_barrier_and_native_occupancy']=True
    R['checks']['remote_close_wait_observed_in_actual_legacy_coroutine_frame']=True
    R['checks']['native_respects_own_N_and_N_plus_1_has_no_backend']=True
    R['checks']['all_live_survivor_payload_SHA_preserved']=True
    R['checks']['legacy_PID_start_ticks_unchanged']=identity(op)==before
    assert R['checks']['legacy_PID_start_ticks_unchanged']
    try:
        assert actual+len(new)<=3, 'STRICT_AGGREGATE_K_EXCEEDED:4>3'
    except AssertionError as error:
        R['expected_red_assertion']=str(error)
        R['method_verdict']='REJECTED_LISTENER_PORT_CENSUS_IS_NOT_CONSERVATIVE_APPLICATION_BOUND'
        R['phase']='LOCAL_COUNTEREXAMPLE_COMPLETE_METHOD_REJECTED'
    else:raise AssertionError('COUNTEREXAMPLE_NOT_REPRODUCED')
    R['not_executed_after_early_rejection']=['IPv6_client_probe','other_namespace_ingress','SYN_cookie_backlog','half_close','guard_failure','lease','boot','return']
    R['fixture_scope']='Real original legacy Gateway plus pinned inline native; only IPv4 data clients, IPv4/IPv6 SYN rules; no universal ingress/lifecycle acceptance claimed'
    # Python3.12 Server.wait_closed also waits for accepted transports. Close
    # only our fixture clients/peer transports first; no server service exists.
    hold.set();server.close()
    for writer in [*writers,*carrier_writers]:writer.transport.abort()
    await asyncio.wait_for(server.wait_closed(),2)

try:
    save();asyncio.run(asyncio.wait_for(exercise(),65))
except BaseException as error:
    R.update(phase='INCOMPLETE_FAILED_NO_AUTOMATIC_RETRY',error_type=type(error).__name__,error=str(error)[-300:]);raise
finally:
    for p in reversed(children):
        if p.poll()is None:p.terminate()
        try:p.wait(timeout=2)
        except subprocess.TimeoutExpired:p.kill();p.wait(timeout=2)
    for h in handles:h.close()
    R['all_owned_children_reaped']=all(p.poll()is not None for p in children)
    R['local_rules_existed_before_namespace_exit']=[dict(tool=tool,comment=D.name)for tool,_ in rules]
    R['namespace_cleanup']='Ephemeral unshare netns destroyed after final owned child exits; no host namespace rule is modified'
    save();print(json.dumps(dict(directory=str(D),phase=R['phase'],verdict=R.get('method_verdict'),all_owned_children_reaped=R['all_owned_children_reaped'],WAN_bytes=0)),flush=True)
