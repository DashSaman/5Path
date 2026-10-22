import unittest
from native_front_config import build

def sample():
 return {'listen_host':'192.0.2.30','listen_port':32101,'username':'fixture','password':'fixture-secret-16','upstreams':[{'id':'DE-'+x,'host':'127.0.0.1','port':24001+i,'username':'up','password':'fixture-up-secret','probe':{'host':'127.0.0.1','port':24000,'nonce':'owned-fixture'}} for i,x in enumerate(('FRP_TCP','FRP_KCP','GOST_HTTP2','GOST_GRPC','WATERWALL_REVERSE'))]}

class ConfigTest(unittest.TestCase):
 def test_preserves_auth_and_only_existing_same_country_upstreams(self):
  old=sample(); c=build(old,'DE',32201,32251,'fixture-control-secret-32-letters',32252)
  self.assertEqual(c['inbounds'][0]['users'],[{'username':old['username'],'password':old['password']}])
  self.assertEqual(c['inbounds'][0]['listen_port'],32201)
  self.assertEqual({o['tag'] for o in c['outbounds'] if o['type']=='socks'},{u['id'] for u in old['upstreams']}|{'DE-reject'})
  group=next(x for x in c['outbounds'] if x['type']=='selector')
  self.assertFalse(group['interrupt_exist_connections'])
  self.assertEqual(group['default'],'DE-reject')
  self.assertFalse(any(x['type']=='urltest' for x in c['outbounds']))
  self.assertEqual(c['route']['final'],'DE-latency')
  self.assertTrue(all(o.get('server')=='127.0.0.1' for o in c['outbounds'] if o['type']=='socks'))
  self.assertTrue(any(r.get('network')=='udp' and r.get('action')=='reject' for r in c['route']['rules']))
  self.assertNotIn('endpoints',c);self.assertNotIn('services',c)
 def test_rejects_foreign_member_missing_auth_nonloopback_and_listener_reuse(self):
  for change in ('foreign','auth','server','old_port'):
   with self.subTest(change=change):
    s=sample();port=32201
    if change=='foreign':s['upstreams'][0]['id']='US-FRP_TCP'
    if change=='auth':s['password']=''
    if change=='server':s['upstreams'][0]['host']='1.1.1.1'
    if change=='old_port':port=s['listen_port']
    with self.assertRaises(ValueError):build(s,'DE',port,32251,'fixture-control-secret-32-letters',32252)

if __name__=='__main__':unittest.main()
