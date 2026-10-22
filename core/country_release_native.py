"""Native units for a fresh accepted release; no installer or production unit edits."""
import json,pathlib,shlex
from country_release_runtime import validate_role
from country_instance import slice_name as owned_slice

def native_units(c):
 validate_role(c);rid=c['run_id'];root=c['root'];role=c['role'];runtime=root+'/country_release_runtime.py';cfg=root+'/'+role+'-runtime.json';slice_name=owned_slice(rid)
 result={}
 for p in c['processes']:
  name=rid+'-'+p['id'].replace('_','-')+'.service';fw=p['id']=='firewall'
  props=dict(Description=rid,WorkingDirectory=p['cwd'],Restart='on-failure',RestartSec='2',StartLimitIntervalSec='300',StartLimitBurst='3',KillMode='control-group',TimeoutStopSec='8',NoNewPrivileges='yes',CapabilityBoundingSet='CAP_NET_ADMIN'if fw else'',ProtectSystem='strict',ReadWritePaths=root,ProtectKernelTunables='yes',ProtectKernelModules='yes',ProtectControlGroups='yes',PrivateTmp='yes',UMask='0077',Nice='10',LimitCORE='0',LimitNOFILE='8192',TasksMax='64',CPUAccounting='yes',MemoryAccounting='yes',MemoryMax='192M',CPUQuota='30%',Slice=slice_name,Environment='GOMAXPROCS=2 GOMEMLIMIT=64MiB',ExecStartPre='/usr/bin/python3 '+runtime+' admit '+cfg+' '+p['id'])
  if fw:
   props['ExecStopPost']='/usr/bin/python3 '+runtime+' cleanup-firewall '+cfg
   props['ProtectSystem']='no' # Exact helper also needs the existing xtables lock.
  # A shared hard quota caused measured burst stalls despite ample host headroom.
  # Low relative weight preserves production priority without artificial idle CPU.
  props.pop('CPUQuota',None);props['CPUWeight']='5'
  result[name]=dict(argv=p['argv'],props=props,boot=True,process=p['id'])
 tx=rid+'-transaction.service';seconds=max(1,int(c['commit_deadline']-__import__('time').time()))
 result[tx]=dict(argv=['/usr/bin/python3',runtime,'guard',cfg],props=dict(Description=rid,WorkingDirectory=root,Restart='no',RuntimeMaxSec=str(seconds),TimeoutStopSec='30',KillMode='control-group',NoNewPrivileges='yes',CapabilityBoundingSet='',MemoryMax='80M',CPUQuota='5%',ExecStopPost='/usr/bin/python3 '+runtime+' abort '+cfg),boot=False,process='transaction')
 return result

def unit_text(unit):
 props=unit['props'];unit_keys=['Description','StartLimitIntervalSec','StartLimitBurst'];lines=['[Unit]']+[k+'='+v for k,v in props.items()if k in unit_keys]
 lines+=['After=network-online.target','Wants=network-online.target','[Service]','Type=simple']+[k+'='+v for k,v in props.items()if k not in unit_keys]+['ExecStart='+shlex.join(unit['argv']),'[Install]','WantedBy=multi-user.target','']
 return '\n'.join(lines)

def slice_config(c):
 tr=c['role']=='foreign';name=owned_slice(c['run_id'])
 props=dict(CPUWeight='5',MemoryHigh='192M'if tr else'384M',MemoryMax='256M'if tr else'512M',TasksMax='192')
 text='[Unit]\nDescription='+c['run_id']+'\n[Slice]\n'+'\n'.join(k+'='+v for k,v in props.items())+'\n'
 return name,props,text
