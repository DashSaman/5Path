"""LOCAL ONLY: socket-scoped routing, unchanged peers, and fail-closed routing."""
import json, pathlib, secrets, subprocess, sys

token = secrets.token_hex(4)
names = ['w5mc'+token, 'w5ms'+token]
processes, made = [], []
mark, table, priority = 0x57510123, 59123, 18123
result = {'scope': 'LOCAL_PRIVATE_NETNS_ONLY'}

def cmd(args, check=True):
    p = subprocess.run(args, capture_output=True, text=True, timeout=7)
    if check and p.returncode:
        raise RuntimeError(str(args)+'\n'+p.stdout+p.stderr)
    return p

def ip(ns, *args):
    return cmd(['ip', '-n', ns, *args])

def launch(ns, code):
    p = subprocess.Popen(['nsenter', '--net=/run/netns/'+ns, sys.executable, '-u', '-c', code],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    processes.append(p)
    return p

server = r'''import socket,threading,json
s=socket.socket();s.bind(('0.0.0.0',27571));s.listen();print('ready',flush=True)
def one(c,a):
 try:
  f=c.makefile('rwb')
  while f.readline(): f.write((json.dumps(a[0])+'\n').encode());f.flush()
 finally:c.close()
while True:
 c,a=s.accept();threading.Thread(target=one,args=(c,a),daemon=True).start()
'''
probe = r'''import socket,json
def connect(mark=0):
 s=socket.socket();s.settimeout(1)
 if mark:s.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,mark)
 s.connect(('198.18.0.1',27571));return s
def read(s):
 s.sendall(b'x\n');return json.loads(s.makefile('rb').readline())
old=connect();print(json.dumps({'old':read(old)}),flush=True)
for line in __import__('sys').stdin:
 try:
  if line.strip()=='old':answer=read(old)
  else:
   with connect(__MARK__ if line.strip()=='marked' else 0) as s:answer=read(s)
  print(json.dumps({'ok':True,'source':answer}),flush=True)
 except OSError:print(json.dumps({'ok':False}),flush=True)
'''.replace('__MARK__', str(mark))
try:
    for ns in names:
        cmd(['ip', 'netns', 'add', ns]); made.append(ns); ip(ns, 'link', 'set', 'lo', 'up')
    for left, right, net in [('d0','d1','10.224.91.'), ('w0','w1','10.224.92.')]:
        cmd(['ip','link','add',left,'type','veth','peer','name',right])
        for ns, dev, tail in [(names[0],left,'1'), (names[1],right,'2')]:
            cmd(['ip','link','set',dev,'netns',ns]); ip(ns,'addr','add',net+tail+'/30','dev',dev); ip(ns,'link','set',dev,'up')
    ip(names[1],'addr','add','198.18.0.1/32','dev','lo')
    ip(names[0],'route','add','198.18.0.1/32','via','10.224.91.2','dev','d0')
    p = launch(names[1], server); assert p.stdout.readline().strip()=='ready'
    p = launch(names[0], probe); assert json.loads(p.stdout.readline())=={'old':'10.224.91.1'}
    ip(names[0],'route','add','table',str(table),'default','via','10.224.92.2','dev','w0','src','10.224.92.1')
    ip(names[0],'route','add','unreachable','default','table',str(table),'metric','42760')
    ip(names[0],'rule','add','priority',str(priority),'fwmark',hex(mark)+'/0xffffffff','lookup',str(table))
    def exchange(command):
        p.stdin.write(command+'\n'); p.stdin.flush(); return json.loads(p.stdout.readline())
    assert exchange('marked')=={'ok':True,'source':'10.224.92.1'}
    result['marked_source_is_owned_route']=True
    assert exchange('direct')=={'ok':True,'source':'10.224.91.1'}
    assert exchange('old')=={'ok':True,'source':'10.224.91.1'}
    result['unmarked_and_existing_flows_unchanged']=True
    ip(names[0],'link','set','w0','down')
    assert exchange('marked')=={'ok':False}
    assert exchange('direct')=={'ok':True,'source':'10.224.91.1'}
    result['no_direct_fallback_on_owned_route_failure']=True
    result['passed']=True
finally:
    for p in processes:
        p.terminate()
        try:p.wait(timeout=2)
        except subprocess.TimeoutExpired:p.kill();p.wait(timeout=2)
    for ns in reversed(made):cmd(['ip','netns','delete',ns],check=False)
    listed=cmd(['ip','netns','list']).stdout.split()
    result['cleanup_verified']=all(ns not in listed for ns in names)
    print(json.dumps(result))
