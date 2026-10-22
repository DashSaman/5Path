import json,pathlib,tempfile,time,unittest
import gaming_native_package as p
from gaming_native_runtime import validate,rule_tuples

class Package(unittest.TestCase):
 def test_separate_role_roots_and_exact_rules(self):
  with tempfile.TemporaryDirectory()as t:
   d=pathlib.Path(t)/'fresh';v=p.build(d,'DE',dict(front=9410,primary=9431,backup=9432,force_primary=9411,force_backup=9412,api=9413,health=9439),dict(address='192.0.2.30',port=32101,username='fixture',password='local-fixture-only'),'/var/lib/tp-udp-12345678','tp-udp-12345678',time.time()+1200)
   self.assertEqual(v['country'],'DE');self.assertFalse(v['deployed']);self.assertNotEqual(v['run_id'],'tp-country-de-4bbde4b5')
   self.assertEqual(len(v['units']['gw']),3);self.assertEqual(len(v['units']['foreign']),4)
   for role in['gw','foreign']:
    cfg=json.loads((d/role/'runtime.json').read_text());self.assertTrue(validate(cfg))
    self.assertEqual(len(rule_tuples(cfg)),2)
    for unit in(d/role/'units').glob('*.service'):
     text=unit.read_text();self.assertNotIn('CPUQuota',text);self.assertNotIn('systemctl restart',text)
     self.assertIn('KillMode=control-group',text);self.assertIn('NoNewPrivileges=yes',text)
     self.assertIn('RestartPreventExitStatus=78',text)
   gw=json.loads((d/'gw/gateway.json').read_text());servers=[o for o in gw['outbounds']if o['type']=='hysteria2']
   self.assertEqual({o['server']for o in servers},{'198.51.100.10'})
   self.assertEqual({o['server_port']for o in servers},{9431,9432});self.assertTrue(all('up_mbps'not in o and'down_mbps'not in o for o in servers))
   with self.assertRaises(FileExistsError):p.build(d,'DE',cfg['ports'],{},'/var/lib/tp-udp-12345678','tp-udp-12345678',time.time()+1200)

if __name__=='__main__':unittest.main()
