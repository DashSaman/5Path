import math,unittest
from unittest.mock import patch
import native_front_policy as policy
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

class PublicationSafetyTest(unittest.TestCase):
 def status(self):
  return dict(run_id='tp-opt-de-12345678',epoch=99,ready=True,selected='DE-a',native_identity={'pid':12})
 def config(self):return dict(run_id='tp-opt-de-12345678',members=['DE-a','DE-b'])
 def test_no_publication_for_stale_future_wrong_run_or_reject(self):
  for update in [dict(epoch=80),dict(epoch=102),dict(epoch=math.nan),dict(run_id='other'),dict(ready=False),dict(selected='DE-reject')]:
   s=self.status();s.update(update)
   with patch.object(policy,'process_identity',return_value={'pid':12}):
    self.assertFalse(policy.status_ready(s,self.config(),100))
 def test_recycled_native_pid_not_ready(self):
  with patch.object(policy,'process_identity',return_value={'pid':12,'start_ticks':'new'}):
   self.assertFalse(policy.status_ready(self.status(),self.config(),100))
 def test_fresh_verified_native_process_ready(self):
  with patch.object(policy,'process_identity',return_value={'pid':12}):
   self.assertTrue(policy.status_ready(self.status(),self.config(),100))
 def test_api_failure_is_recoverable_and_returns_not_ready(self):
  c=dict(country='DE',control_port=8655)
  with patch.object(policy,'selector_request',side_effect=TimeoutError('fixture')):
   self.assertFalse(policy.verify_selector(c,'secret','DE-a'))
 def test_unchanged_desired_state_still_requires_get_and_correction(self):
  c=dict(country='DE',control_port=8655)
  with patch.object(policy,'selector_request',side_effect=[{'now':'DE-b'},None,{'now':'DE-a'}]) as api:
   self.assertTrue(policy.verify_selector(c,'secret','DE-a'))
   self.assertEqual([x.args[2] for x in api.call_args_list],['GET','PUT','GET'])

if __name__=='__main__':unittest.main()
