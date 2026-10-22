import hashlib,json,pathlib,tempfile,time,unittest
from country_release_runtime import validate_role,lease_required,firewall_rules
class RuntimeTests(unittest.TestCase):
 def cfg(self):return dict(run_id='tp-country-tr-1234abcd',role='gw',root='/var/lib/tp-country-tr-1234abcd',commit_deadline=time.time()+300,guard_run_id='tp-lv19-1111aaaa',guard_root='/var/lib/tp-lv19-1111aaaa',processes=[dict(id='gateway',argv=['/usr/bin/python3','/var/lib/tp-country-tr-1234abcd/gw/mesh_gateway.py','/var/lib/tp-country-tr-1234abcd/gw/gateway.json','/var/lib/tp-country-tr-1234abcd/gw/state.json'])],files={})
 def test_expected_fresh_role_and_commit_bound(self):validate_role(self.cfg())
 def test_fresh_FI_scope_never_allows_TR_rule(self):
  c=json.loads(json.dumps(self.cfg()).replace('tp-country-tr-','tp-country-fi-'));validate_role(c)
  c['rules']=[dict(source='198.51.100.20',destination='203.0.113.30',protocol='udp',port=24332)];self.assertIn(c['run_id'],firewall_rules(c)[0])
  for source,port in [('198.51.100.30',24332),('198.51.100.20',24298),('192.0.2.10',32103)]:
   with self.subTest(source=source,port=port),self.assertRaises(ValueError):firewall_rules(dict(c,rules=[dict(source=source,destination='203.0.113.30',protocol='udp',port=port)]))
 def test_foreign_root_or_unregistered_binary_or_secret_argv_refused(self):
  for patch in [dict(root='/usr/local/x-ui'),dict(role='other'),dict(processes=[dict(id='x',argv=['/usr/bin/bash','-c','restart'])])]:
   with self.subTest(patch=patch),self.assertRaises(ValueError):validate_role(dict(self.cfg(),**patch))
 def test_only_valid_matching_commit_disables_test_lease(self):
  cfg=self.cfg();digest='a'*64
  self.assertTrue(lease_required(cfg,None,digest))
  self.assertFalse(lease_required(cfg,dict(run_id=cfg['run_id'],config_sha256=digest),digest))
  with self.assertRaises(ValueError):lease_required(cfg,dict(run_id='tp-country-tr-deadbeef',config_sha256=digest),digest)
 def test_firewall_never_accepts_global_or_other_service_rule(self):
  c=self.cfg();c['rules']=[dict(source='192.0.2.10',destination='192.0.2.30',protocol='tcp',port=32103)]
  self.assertIn(c['run_id'],firewall_rules(c)[0])
  for patch in [dict(port=22),dict(source='0.0.0.0'),dict(destination='0.0.0.0'),dict(protocol='all')]:
   bad=dict(c,rules=[dict(c['rules'][0],**patch)])
   with self.subTest(patch=patch),self.assertRaises(ValueError):firewall_rules(bad)
if __name__=='__main__':unittest.main()
