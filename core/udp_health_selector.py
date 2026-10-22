"""Small UDP-only selector. No unit control, restarting, routes, or firewall access."""
import pathlib,json,time,sys,os,http.client,signal
from udp_socks_probe import UDPSession
def atomic(p,v):
 t=p.with_name(p.name+'.tmp');t.write_text(json.dumps(v));os.replace(t,p)
def run(cfg,directory):
 states={p['id']:dict(up=0,down=0,healthy=False)for p in cfg['paths']};selected=None;changed=0
 def api(name=None):
  h=http.client.HTTPConnection('127.0.0.1',cfg['api_port'],timeout=2)
  try:
   h.request('GET'if name is None else'PUT','/proxies/'+cfg['group'],body=None if name is None else json.dumps(dict(name=name)),headers={'Authorization':'Bearer '+cfg['api_secret']});r=h.getresponse();body=r.read();assert r.status in[200,204],'SELECTOR_API_FAILED';return json.loads(body)if body else{}
  finally:h.close()
 while time.time()<cfg.get('deadline',float('inf')):
  start=time.monotonic();measurements={}
  for p in cfg['paths']:
   s=None
   try:
    s=UDPSession(p);payload=os.urandom(48);got,ms=s.exchange(cfg['target_host'],cfg['target_port'],payload);ok=got==payload and ms<=cfg.get('max_rtt_ms',1000);measurements[p['id']]=dict(ok=ok,rtt_ms=ms)
   except Exception as e:ok=False;measurements[p['id']]=dict(ok=False,error=type(e).__name__)
   finally:
    if s:s.close()
   st=states[p['id']];st['up']=st['up']+1 if ok else 0;st['down']=0 if ok else st['down']+1
   if st['up']>=cfg.get('successes',2):st['healthy']=True
   if st['down']>=cfg.get('failures',3):st['healthy']=False
  candidates=[p['id']for p in cfg['paths']if states[p['id']]['healthy']]
  try:
   current=api().get('now');preferred=candidates[0]if candidates else None
   if preferred and preferred!=current and (not states.get(current,{}).get('healthy')or time.monotonic()-changed>=cfg.get('hold_s',15)):
    api(preferred);current=api().get('now');assert current==preferred;changed=time.monotonic()
  except (OSError,TimeoutError,http.client.HTTPException,ValueError,AssertionError)as exc:
   # Native units may start together. An unavailable loopback API must not
   # kill the selector or cause a service restart; retry at the same low rate.
   atomic(directory/'udp-health-state.json',dict(epoch=time.time(),selected=None,api_available=False,selection_unavailable=True,error=type(exc).__name__,measurements=measurements,states=states,all_failed=not candidates,scope='UDP_NEW_FLOW_SELECTION_ONLY_NO_TCP_SESSION_CONTROL'))
   time.sleep(max(.05,cfg['interval_s']-(time.monotonic()-start)));continue
  selected=current;atomic(directory/'udp-health-state.json',dict(epoch=time.time(),selected=selected,api_available=True,selection_unavailable=False,measurements=measurements,states=states,all_failed=not candidates,scope='UDP_NEW_FLOW_SELECTION_ONLY_NO_TCP_SESSION_CONTROL'))
  time.sleep(max(.05,cfg['interval_s']-(time.monotonic()-start)))
if __name__=='__main__':
 signal.signal(signal.SIGTERM,lambda *_:sys.exit(0));path=pathlib.Path(sys.argv[1]);run(json.loads(path.read_text()),path.parent)
