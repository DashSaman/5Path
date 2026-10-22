import math,unittest
from native_front_policy import select

class PolicyTest(unittest.TestCase):
 def state(self):return {'worker_pid':12,'updated_at':99,'healthy':{'DE-a':True,'DE-b':True},'probes':{'DE-a':{'ok':True,'latency_ms':800},'DE-b':{'ok':True,'latency_ms':120}}}
 def test_degraded_preferred_path_does_not_flatten_with_fast_path(self):
  self.assertEqual(select(self.state(),12,['DE-a','DE-b'],100,'DE-a',{}),'DE-b')
 def test_stale_future_wrong_pid_all_down_reject_new_flows(self):
  for key,value in [('updated_at',70),('updated_at',102),('worker_pid',13)]:
   s=self.state();s[key]=value;self.assertIsNone(select(s,12,['DE-a','DE-b'],100,'DE-a',{}))
  s=self.state();s['healthy']={'DE-a':False,'DE-b':False};self.assertIsNone(select(s,12,['DE-a','DE-b'],100,None,{}))
 def test_missing_nonce_probe_or_invalid_latency_is_not_usable(self):
  s=self.state();s['probes']['DE-b']['latency_ms']=math.nan
  self.assertEqual(select(s,12,['DE-a','DE-b'],100,None,{}),'DE-a')
 def test_small_latency_noise_preserves_current_member(self):
  s=self.state();s['probes']['DE-a']['latency_ms']=130
  self.assertEqual(select(s,12,['DE-a','DE-b'],100,'DE-a',{}),'DE-a')

if __name__=='__main__':unittest.main()
