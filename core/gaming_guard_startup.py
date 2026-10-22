"""Bounded initialization wait for a new owned guard; never fabricates telemetry."""
import pathlib,json,time,subprocess,re

def wait_initial_state(root,rid):
 assert root.parent==pathlib.Path('/var/lib')and root.name==rid and re.fullmatch('tp-udp-[a-f0-9]{8}',rid)and not root.is_symlink(),'EXACT_NEW_GUARD_SCOPE'
 c=json.loads((root/'ownership.json').read_text());assert c['run_id']==rid and c['root']==str(root),'GUARD_OWNER'
 until=time.monotonic()+6
 while True:
  assert time.time()<c['deadline']and not(root/'guard-stop.json').exists(),'GUARD_STOPPED_OR_EXPIRED'
  assert time.monotonic()<until,'GUARD_INITIALIZATION_TIMEOUT'
  z=subprocess.run(['systemctl','show',rid+'-guard.service','-p','Description','-p','ActiveState','-p','MainPID'],capture_output=True,text=True,timeout=2);v=dict(x.split('=',1)for x in z.stdout.splitlines()if'='in x)
  assert z.returncode==0 and v.get('Description')==rid and v.get('ActiveState')in['active','activating'],'NEW_GUARD_UNIT_NOT_LIVE'
  if(root/'guard-state.json').exists():
   s=json.loads((root/'guard-state.json').read_text());assert s['run_id']==rid and 0<=time.time()-s['epoch']<=12,'INITIAL_TELEMETRY_INVALID'
   pid=int(v.get('MainPID')or 0);assert pid>0 and any(a.startswith((str(root)+'/').encode())for a in pathlib.Path('/proc',str(pid),'cmdline').read_bytes().split(bytes([0]))),'NEW_GUARD_PID_SCOPE'
   return s
  time.sleep(.15)
