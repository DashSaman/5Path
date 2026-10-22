"""Real stdin/EOF/lease/deadline fixture, local only; no WAN or CPU baseline."""
import unittest,pathlib,tempfile,subprocess,json,os,time,threading,hashlib,tarfile,io,secrets

B=pathlib.Path(__file__).resolve().parents[1]/'core'

class Receiver(unittest.TestCase):
 def setUp(self):
  self.assertTrue((B/'owned_asset_receiver.py').exists(),'Bounded independently leased receiver is not implemented')
  self.rid='tp-lv19-'+secrets.token_hex(4);self.gid='tp-udp-'+secrets.token_hex(4);self.root=pathlib.Path('/var/lib')/self.rid;self.guard=pathlib.Path('/var/lib')/self.gid
  self.root.mkdir(mode=0o700);self.guard.mkdir(mode=0o700);self.stop=threading.Event();self.children=[];self.body=os.urandom(32768);a=io.BytesIO()
  with tarfile.open(fileobj=a,mode='w:gz')as t:
   info=tarfile.TarInfo('official-fixture/sing-box');info.size=len(self.body);t.addfile(info,io.BytesIO(self.body))
  self.archive=a.getvalue();self.config=dict(run_id=self.rid,root=str(self.root),deadline=time.time()+25,guard_root=str(self.guard),guard_run_id=self.gid,archive_bytes=len(self.archive),archive_sha256=hashlib.sha256(self.archive).hexdigest(),binary_bytes=len(self.body),binary_sha256=hashlib.sha256(self.body).hexdigest(),rate_Bps=131072,chunk_bytes=16384)
  self.write('asset-receive.json',self.config);self.write('ownership.json',dict(run_id=self.rid,root=str(self.root),role='OFFICIAL_SOURCE_STAGE',files={'asset-receive.json':hashlib.sha256((self.root/'asset-receive.json').read_bytes()).hexdigest()}))
  (self.guard/'ownership.json').write_text(json.dumps(dict(run_id=self.gid,root=str(self.guard))))
  self.pulse()
  self.thread=threading.Thread(target=self.renew,daemon=True);self.thread.start()
 def write(self,name,value):
  target=self.root/name;tmp=self.root/(name+'.tmp');tmp.write_text(json.dumps(value));os.replace(tmp,target)
 def pulse(self):
  self.write('lease.json',dict(run_id=self.rid,epoch=time.time()));p=self.guard/'guard-state.json';tmp=p.with_suffix('.tmp');tmp.write_text(json.dumps(dict(run_id=self.gid,epoch=time.time(),ready=True,duration=301,cpu_mean=30,available_kB=500000)));os.replace(tmp,p)
 def renew(self):
  while not self.stop.wait(.5):self.pulse()
 def start(self):
  p=subprocess.Popen(['/usr/bin/unshare','--net','/usr/bin/python3',str(B/'owned_asset_receiver.py'),'--root',str(self.root)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE);self.children.append(p);return p
 def finish(self,p,content):return p.communicate(content,timeout=18)
 def tearDown(self):
  self.stop.set()
  if hasattr(self,'thread'):self.thread.join(2)
  for p in self.children:
   if p.poll()is None:p.kill();p.wait(3)
   for pipe in[p.stdin,p.stdout,p.stderr]:
    if pipe and not pipe.closed:pipe.close()
  import shutil
  for path,rid in[(self.root,self.rid),(self.guard,self.gid)]:
   assert path.parent==pathlib.Path('/var/lib')and path.name==rid
   shutil.rmtree(path)
 def test_actual_file_hash_rate_and_exact_source_ready(self):
  p=self.start();out,err=self.finish(p,self.archive);self.assertEqual(p.returncode,0,err.decode());v=json.loads(out);self.assertTrue(v['source_ready']);self.assertEqual((self.root/'bin/sing-box').read_bytes(),self.body);self.assertGreaterEqual(v['elapsed_seconds'],len(self.archive)/131072-.02);self.assertFalse((self.root/'archive.part').exists())
 def test_wrong_archive_hash_is_terminal_and_removes_own_partial(self):
  p=self.start();out,err=self.finish(p,bytes([self.archive[0]^1])+self.archive[1:]);self.assertNotEqual(p.returncode,0);self.assertIn('ARCHIVE_SHA',err.decode());self.assertFalse((self.root/'archive.part').exists());self.assertTrue((self.root/'asset-aborted.json').exists());self.assertFalse((self.root/'bin/sing-box').exists());q=self.start();out,err=self.finish(q,b'');self.assertNotEqual(q.returncode,0);self.assertIn('TERMINAL_RUN',err.decode())
 def test_controller_EOF_stops_receiver_and_keeps_foreign_file(self):
  sentinel=self.root/'unrelated-file';sentinel.write_text('preserve');p=self.start();out,err=self.finish(p,self.archive[:500]);self.assertNotEqual(p.returncode,0);self.assertIn('INPUT_LENGTH',err.decode());self.assertEqual(sentinel.read_text(),'preserve');self.assertFalse((self.root/'archive.part').exists())
 def test_stalled_input_lease_expiry_stops_without_controller(self):
  p=self.start();p.stdin.write(self.archive[:500]);p.stdin.flush();time.sleep(.4);self.stop.set();self.thread.join(2);start=time.monotonic();p.wait(timeout=13);self.assertNotEqual(p.returncode,0);self.assertLess(time.monotonic()-start,11.5);self.assertIn('LEASE_EXPIRED',p.stderr.read().decode());self.assertFalse((self.root/'archive.part').exists())
 def test_absolute_deadline_stops_with_fresh_lease(self):
  self.config['deadline']=time.time()+1.5;self.write('asset-receive.json',self.config);owner=json.loads((self.root/'ownership.json').read_text());owner['files']['asset-receive.json']=hashlib.sha256((self.root/'asset-receive.json').read_bytes()).hexdigest();self.write('ownership.json',owner);p=self.start();p.wait(timeout=4);self.assertNotEqual(p.returncode,0);self.assertFalse((self.root/'archive.part').exists());self.assertTrue((self.root/'asset-aborted.json').exists())
 def test_concurrent_fresh_lease_write_is_not_false_future_expiry(self):
  from unittest.mock import patch
  from owned_asset_receiver import healthy
  original=pathlib.Path.read_text;done=[False]
  def scheduled(path,*args,**kwargs):
   if path==self.root/'lease.json'and not done[0]:done[0]=True;self.pulse()
   return original(path,*args,**kwargs)
  with patch.object(pathlib.Path,'read_text',scheduled):healthy(self.root,self.config)
  self.assertTrue(done[0])
 def test_concurrent_fresh_guard_write_is_not_false_future_telemetry(self):
  from unittest.mock import patch
  from owned_asset_receiver import healthy
  original=pathlib.Path.read_text;done=[False]
  def scheduled(path,*args,**kwargs):
   if path==self.guard/'guard-state.json'and not done[0]:done[0]=True;self.pulse()
   return original(path,*args,**kwargs)
  with patch.object(pathlib.Path,'read_text',scheduled):healthy(self.root,self.config)
  self.assertTrue(done[0])

if __name__=='__main__':unittest.main()
