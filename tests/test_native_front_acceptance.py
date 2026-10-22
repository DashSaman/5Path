import unittest
from native_front_acceptance import nonregressing

class RegressionGate(unittest.TestCase):
 def test_recorded_us_shadow_and_published_regressions_are_rejected(self):
  self.assertFalse(nonregressing(1.032685768965166,1.6950893569737673))
  self.assertFalse(nonregressing(1.032685768965166,5.067885233962443))
 def test_small_timing_noise_and_faster_results_pass(self):
  self.assertTrue(nonregressing(.3,.4))
  self.assertTrue(nonregressing(1,1.3))
  self.assertTrue(nonregressing(1,.7))
  self.assertFalse(nonregressing(.3,.6))
 def test_invalid_measurements_cannot_pass(self):
  for x in [0,-1,float('nan'),float('inf'),None,True,'1']:
   self.assertFalse(nonregressing(x,1))
   self.assertFalse(nonregressing(1,x))
