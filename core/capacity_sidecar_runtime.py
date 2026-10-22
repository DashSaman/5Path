"""Exact loopback-only capacity extension for an owner-authorized country repair."""
import hashlib,json,pathlib,re,subprocess,sys,time,signal,os
SCOPE={'de':24239,'fi':24339,'tr':24305,'us':24271}
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def load(root):
 root=pathlib.Path(root);m=re.fullmatch(r'tp-cap-(de|fi|tr|us)-[a-f0-9]{8}',root.name)
 if not m or str(root)!='/var/lib/'+root.name or root.is_symlink():raise ValueError('CAPACITY_OWNER_ROOT')
 c=json.loads((root/'ownership.json').read_text());assert c['run_id']==root.name and c['country']==m[1]and c['old_port']==SCOPE[m[1]]and c['new_port']!=c['old_port']and 24000<=c['new_port']<=24999
 for n,h in c['files'].items():
  p=root/n;assert p.parent==root and not p.is_symlink()and sha(p)==h,'CAPACITY_DEPENDENCY_HASH'
 return root,c
def rule(c):return ['OUTPUT','-d','127.0.0.1/32','-p','tcp','--dport',str(c['old_port']),'--syn','-m','comment','--comment',c['run_id'],'-j','REDIRECT','--to-ports',str(c['new_port'])]
def ipt(a):return subprocess.run(['iptables','-w','3','-t','nat']+a,capture_output=True,text=True,timeout=6)
def remove(root):
 _,c=load(root);r=rule(c);z=ipt(['-C']+r)
 if z.returncode==0:assert ipt(['-D']+r).returncode==0
 elif z.returncode!=1:raise RuntimeError('CAPACITY_RULE_CHECK')
def redirect(root):
 root,c=load(root);assert(root/'accepted.json').is_file(),'CAPACITY_NOT_ACCEPTED'
 r=rule(c);z=ipt(['-C']+r)
 if z.returncode==1:assert ipt(['-I',r[0],'1']+r[1:]).returncode==0,'CAPACITY_EXACT_RULE_INSERT'
 elif z.returncode!=0:raise RuntimeError('CAPACITY_EXACT_RULE_CHECK')
 print('CAPACITY_EXACT_LOOPBACK_SYN_REDIRECT_READY',flush=True)
def prepare_guard(root,deadline):
 root,c=load(root);assert time.time()<deadline<time.time()+240
 while time.time()<deadline:
  if(root/'accepted.json').is_file():return
  time.sleep(.3)
 # Before acceptance no redirection exists, hence no user flow can use this new listener.
 assert not(root/'accepted.json').exists()
 name=c['run_id']+'-egress.service';p=subprocess.run(['systemctl','show',name,'-p','Description','--value'],capture_output=True,text=True,timeout=5)
 if p.stdout.strip()==c['run_id']:subprocess.run(['systemctl','stop',name],check=True,timeout=12)
if __name__=='__main__':
 mode,root=sys.argv[1:3]
 if mode=='admit':load(root)
 elif mode=='redirect':redirect(root)
 elif mode=='remove':remove(root)
 elif mode=='prepare-guard':prepare_guard(root,float(sys.argv[3]))
 else:raise ValueError('CAPACITY_MODE')
