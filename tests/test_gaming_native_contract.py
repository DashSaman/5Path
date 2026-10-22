import copy,hashlib,json,pathlib,tempfile,time,unittest
import gaming_native_runtime as r

def cfg():
 rid='tp-game-de-1234abcd'
 return dict(run_id=rid,root='/var/lib/'+rid,country='DE',foreign='198.51.100.10',role='foreign',commit_deadline=1000,ports=dict(front=9410,primary=9431,backup=9432,force_primary=9411,force_backup=9412,api=9413,health=9439),files={'sing-box':'a'*64},processes={'primary':['/var/lib/'+rid+'/sing-box','run','-c','/var/lib/'+rid+'/primary-server.json']})

class Contract(unittest.TestCase):
 def test_prepare_stop_is_latched_and_cannot_be_renewed(self):
  with tempfile.TemporaryDirectory()as t:
   root=pathlib.Path(t);c=cfg();sha='b'*64
   with self.assertRaises(r.PreparationStopped):r.stop_preparation(root,c,sha,'GAMING_LEASE_EXPIRED')
   a=json.loads((root/'prepare-aborted.json').read_text());self.assertEqual(a['run_id'],c['run_id']);self.assertEqual(a['reason'],'GAMING_LEASE_EXPIRED')
   with self.assertRaises(r.PreparationStopped):r.reject_aborted(root,c,sha)
 def test_preparation_stop_racing_exact_commit_preserves_committed_worker(self):
  with tempfile.TemporaryDirectory()as t:
   root=pathlib.Path(t);c=cfg();sha='b'*64;(root/'committed.json').write_text(json.dumps(dict(run_id=c['run_id'],config_sha256=sha)))
   self.assertIsNone(r.stop_preparation(root,c,sha,'GAMING_LEASE_EXPIRED'));self.assertFalse((root/'prepare-aborted.json').exists())
 def test_no_lease_after_exact_commit(self):
  c=cfg();self.assertFalse(r.requires_lease(c,dict(run_id=c['run_id'],config_sha256='b'*64),'b'*64))
 def test_invalid_commit_does_not_adopt(self):
  c=cfg()
  for change in [dict(run_id='foreign'),dict(config_sha256='c'*64)]:
   commit=dict(run_id=c['run_id'],config_sha256='b'*64);commit.update(change)
   with self.assertRaises(ValueError):r.requires_lease(c,commit,'b'*64)
 def test_uncommitted_lease_fails_on_expiry_stale_guard_or_high_cpu(self):
  c=cfg();lease=dict(run_id=c['run_id'],epoch=995);guard=dict(run_id=c['run_id'],epoch=995,ready=True,cpu_mean=60,available_kB=300000)
  r.check_prepare(c,lease,guard,999)
  for now,l,g in [(1001,lease,guard),(999,dict(lease,epoch=980),guard),(999,lease,dict(guard,epoch=980)),(999,lease,dict(guard,ready=False)),(999,lease,dict(guard,cpu_mean=86))]:
   with self.assertRaises(ValueError):r.check_prepare(c,l,g,now)
 def test_exact_same_country_firewall(self):
  c=cfg();self.assertEqual(r.rule_tuples(c),{('203.0.113.30','198.51.100.10','udp',9431),('203.0.113.30','198.51.100.10','udp',9432)})
  c['role']='gw';self.assertEqual(r.rule_tuples(c),{('192.0.2.10','192.0.2.30','tcp',9410),('192.0.2.10','192.0.2.30','udp',9410)})
 def test_reject_country_borrow_and_port_collision(self):
  for key,value in [('foreign','198.51.100.30'),('run_id','tp-country-de-4bbde4b5')]:
   c=cfg();c[key]=value
   with self.assertRaises(ValueError):r.validate(c)
  c=cfg();c['ports']['backup']=c['ports']['primary']
  with self.assertRaises(ValueError):r.validate(c)
 def test_reject_external_binary_or_shell(self):
  c=cfg();c['processes']['primary']=['/bin/sh','-c','true']
  with self.assertRaises(ValueError):r.validate(c)
 def test_accept_valid_native_root(self):self.assertTrue(r.validate(cfg()))

if __name__=='__main__':unittest.main()
