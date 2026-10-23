import pathlib,json,subprocess,time,signal,os
signal.alarm(55);os.nice(15);dev=os.environ['FIVEPATH_DIAGNOSTIC_DEVICE'];root=pathlib.Path('/sys/class/net')/dev;assert root.exists()
def cmd(args):
 try:
  q=subprocess.run(args,capture_output=True,text=True,timeout=5);assert len(q.stdout)+len(q.stderr)<256*1024
  return dict(available=True,code=q.returncode,stdout=q.stdout,stderr=q.stderr[-200:])
 except FileNotFoundError:return dict(available=False)
def snapshot():
 result={}
 for p in(root/'statistics').iterdir():
  try:result[p.name]=int(p.read_text())
  except(ValueError,OSError):pass
 raw=cmd(['ethtool','-S',dev]);stats={}
 if raw.get('code')==0:
  for line in raw['stdout'].splitlines():
   if ':'not in line:continue
   key,value=line.rsplit(':',1)
   try:stats[key.strip()]=int(value.strip())
   except ValueError:pass
 return dict(epoch=time.time(),monotonic=time.monotonic(),sysfs=result,driver_stats=stats,driver_stats_available=raw.get('code')==0)
metadata={name:cmd(args)for name,args in {'driver':['ethtool','-i',dev],'offloads':['ethtool','-k',dev],'rings':['ethtool','-g',dev],'channels':['ethtool','-l',dev],'qdisc':['tc','-j','-s','qdisc','show','dev',dev]}.items()}
first=snapshot();time.sleep(10);last=snapshot()
def delta(key):
 result={k:last[key][k]-v for k,v in first[key].items()if k in last[key]};assert all(v>=0 for v in result.values());return result
print(json.dumps(dict(read_only=True,configuration_changes=False,generated_test_traffic=False,service_control_actions=0,duration=last['monotonic']-first['monotonic'],sysfs_delta=delta('sysfs'),driver_counters_delta=delta('driver_stats'),driver_stats_available=first['driver_stats_available']and last['driver_stats_available'],metadata=metadata,interface_scope='Observed WAN device only; no attribution to a tunnel or T6',started_epoch=first['epoch'],ended_epoch=last['epoch'])))
