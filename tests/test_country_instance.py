import unittest
from country_instance import instance,from_rid,firewall_tuples,slice_name

class CountryInstanceTests(unittest.TestCase):
 def test_exact_countries_and_disjoint_proposed_blocks(self):
  seen=set()
  for cc,ip,base,entry in [('TR','198.51.100.30',24296,32103),('FI','198.51.100.20',24330,32102),('DE','198.51.100.10',24230,32101),('US','198.51.100.40',24262,32104)]:
   c=instance(cc);self.assertEqual((c['foreign'],c['base'],c['entry']),(ip,base,entry));ports=set(range(base,base+30))|{entry};self.assertFalse(seen&ports);seen|=ports
 def test_RID_cannot_smuggle_other_country_or_foreign_units(self):
  self.assertEqual(from_rid('tp-country-fi-1234abcd')['country'],'FI');self.assertEqual(slice_name('tp-country-fi-1234abcd'),'tpcountryfi1234abcd.slice')
  for rid in ['tp-country-x-1234abcd','tp-country-fi-1234abcd;stop','tp-country-fi-zzzzzzzz','tp-lv19-1234abcd']:
   with self.subTest(rid=rid),self.assertRaises(ValueError):from_rid(rid)
 def test_firewall_is_fixed_same_country_and_independent_port_block(self):
  rules=firewall_tuples('FI');self.assertEqual(len(rules),7);self.assertIn(('198.51.100.20','203.0.113.30','udp',24332),rules);self.assertIn(('192.0.2.10','192.0.2.30','tcp',32102),rules)
  self.assertFalse(any(x[0]=='198.51.100.30'or x[3]==32103 or 24296<=x[3]<=24325 for x in rules))

if __name__=='__main__':unittest.main()
