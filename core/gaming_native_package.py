"""Pure new native UDP country package. No SSH, installation or X-UI mutation."""
import hashlib,json,pathlib,re,secrets,time
from gaming_pool_profile import build as profile
from gaming_native_runtime import validate
B=pathlib.Path(__file__).parent
SINGBOX_SHA='768d31fa7f68debc067bb4626539498a1e8751d36a7b99e1a54bee6a23815f93'

def write(path,value):
 path.parent.mkdir(parents=True,exist_ok=True)
 path.write_bytes(value if isinstance(value,bytes)else json.dumps(value,indent=2).encode()if isinstance(value,dict)else value.encode())

def unit(c,name):
 root=c['root'];rid=c['run_id'];firewall=name=='firewall'
 args='/usr/bin/python3 '+root+'/gaming_native_runtime.py '+('firewall '+root+'/runtime.json'if firewall else'worker '+root+'/runtime.json '+name)
 return ('[Unit]\nDescription='+rid+'\nWants=network-online.target\nAfter=network-online.target\nStartLimitIntervalSec=60\nStartLimitBurst=3\n\n[Service]\nType=simple\nWorkingDirectory='+root+'\nExecStart='+args+'\n'+('ExecStopPost=/usr/bin/python3 '+root+'/gaming_native_runtime.py cleanup '+root+'/runtime.json\n'if firewall else'')+'Restart=on-failure\nRestartPreventExitStatus=78\nRestartSec=2\nKillMode=control-group\nTimeoutStopSec=6\nNoNewPrivileges=yes\nCapabilityBoundingSet='+('CAP_NET_ADMIN'if firewall else'')+'\nProtectSystem='+('full'if firewall else'strict')+'\nReadWritePaths='+root+'\nProtectHome=yes\nPrivateTmp=yes\nLimitNOFILE=32768\nTasksMax=64\nMemoryMax='+('48M'if name in['firewall','selector','echo']else'128M')+'\nCPUWeight=5\nNice=10\nEnvironment=GOMAXPROCS=2\nEnvironment=GOMEMLIMIT=64MiB\n\n[Install]\nWantedBy=multi-user.target\n')

def build(directory,cc,ports,tcp_upstream,guard_root,guard_rid,deadline,*,carrier='HYSTERIA2'):
 d=pathlib.Path(directory)
 if d.exists():raise FileExistsError('FRESH_NATIVE_PACKAGE_REQUIRED')
 if not re.fullmatch('tp-udp-[a-f0-9]{8}',guard_rid)or guard_root!='/var/lib/'+guard_rid or not 600<=deadline-time.time()<=3600:raise ValueError('FRESH_PREPARATION_GUARD_REQUIRED')
 rid='tp-game-'+cc.lower()+'-'+secrets.token_hex(4);root='/var/lib/'+rid
 v=profile(root,cc,ports,tcp_upstream,carrier=carrier)
 processes={'gw':{'gateway':[root+'/sing-box','run','-c',root+'/gateway.json'],'selector':['/usr/bin/python3',root+'/udp_health_selector.py',root+'/health.private.json']},'foreign':{n:[root+'/sing-box','run','-c',root+'/'+n+'-server.json']for n in['primary','backup']}}
 processes['foreign']['echo']=['/usr/bin/python3',root+'/gaming_native_runtime.py','echo',root+'/runtime.json']
 units={};configs={}
 d.mkdir(mode=0o700)
 for role in['gw','foreign']:
  names=['gateway.json','health.private.json']if role=='gw'else[n+'-'+s for n in['primary','backup']for s in['server.json','cert.pem','key.pem']]
  for n in names:write(d/role/n,v['files'][n])
  scripts=['gaming_native_runtime.py']+(['udp_health_selector.py','udp_socks_probe.py']if role=='gw'else[])
  for n in scripts:write(d/role/n,(B/n).read_bytes())
  c=dict(run_id=rid,root=root,country=cc,foreign=v['foreign'],role=role,ports=ports,commit_deadline=deadline,guard_root=guard_root,guard_run_id=guard_rid,processes=processes[role],files={})
  units[role]=[rid+'-'+n+'.service'for n in[*processes[role],'firewall']]
  for n in[*processes[role],'firewall']:write(d/role/'units'/(rid+'-'+n+'.service'),unit(c,n))
  c['files']={p.relative_to(d/role).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()for p in(d/role).rglob('*')if p.is_file()}
  c['files']['sing-box']=SINGBOX_SHA;validate(c);configs[role]=c
  write(d/role/'runtime.json',c)
  sha=hashlib.sha256((d/role/'runtime.json').read_bytes()).hexdigest()
  write(d/role/'ownership.json',dict(run_id=rid,role=role,config_sha256=sha,purpose='NEW_NATIVE_GAMING_RELEASE_NOT_OLD_TEST_ADOPTION'))
 write(d/'candidate-XUI-outbound.private.json',v['outbound'])
 out=dict(run_id=rid,root=root,country=cc,foreign=v['foreign'],ports=ports,units=units,deadline=deadline,guard_root=guard_root,guard_run_id=guard_rid,deployed=False,published=False,ready_for_users=False,source_sha256={n:hashlib.sha256((B/n).read_bytes()).hexdigest()for n in['gaming_pool_profile.py','tuic_health_profile.py','gaming_native_runtime.py','gaming_native_package.py','udp_health_selector.py','udp_socks_probe.py']},singbox_sha256=SINGBOX_SHA,logical_instances=2,canonical_protocols=[carrier],physical_diversity_proven=False,existing_flow_continuity_proven=False,capacity_proven=False)
 write(d/'package.json',out);return out
