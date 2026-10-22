import pathlib,json,unittest,importlib
B=pathlib.Path(__file__).resolve().parents[1]/'core'
class RuleScope(unittest.TestCase):
 def setUp(self):
  self.assertTrue((B/'country_rule_audit.py').exists(),'Field-aware firewall reservation audit is missing');self.m=importlib.import_module('country_rule_audit')
 def test_packet_counters_handles_and_comment_ID_are_not_ports(self):
  v={'nftables':[{'rule':{'handle':9752,'expr':[{'counter':{'packets':9752,'bytes':9750}},{'comment':'tp-game-us-b9752abc'}]}}]};self.assertFalse(self.m.firewall_port_conflicts('nft',json.dumps(v),[9750,9751,9752,9753]))
 def test_actual_nft_ports_sets_and_ranges_still_block(self):
  for v in[{'match':{'left':{'payload':{'field':'dport'}},'right':9752}},{'set':{'elem':[80,9752]}},{'dnat':{'port':{'range':[9750,9760]}}}]:self.assertTrue(self.m.firewall_port_conflicts('nft',json.dumps(v),[9752]))
 def test_IPv4_IPv6_translation_redirect_and_multiport_ranges_block(self):
  for text in['-A INPUT -p tcp --dport 9752 -j ACCEPT','-A INPUT -m multiport --ports 9750:9760 -j ACCEPT','-A PREROUTING -j REDIRECT --to-ports 9752','-A POSTROUTING -j SNAT --to-source :9752','-A PREROUTING -j DNAT --to-destination [2001:db8::1]:9750-9760','-A PREROUTING -j DNAT --to-destination 192.0.2.1:9752']:
   self.assertTrue(self.m.firewall_port_conflicts('iptables-save',text,[9752]),text)
 def test_comment_numbers_and_IPv6_address_suffix_are_not_port_reservations(self):
  for text in['-A INPUT -m comment --comment tp-game-us-b9752abc -j ACCEPT','-A PREROUTING -j DNAT --to-destination 2001:db8::9752']:
   self.assertFalse(self.m.firewall_port_conflicts('ip6tables-save',text,[9752]))
 def test_unknown_port_syntax_fails_closed(self):
  with self.assertRaises(ValueError):self.m.firewall_port_conflicts('iptables-save','-A INPUT --dport unknown-service -j ACCEPT',[9752])
 def test_masquerade_source_allocator_is_not_a_listener_reservation(self):
  text='-A LIBVIRT_PRT -s 192.0.2.0/24 -p udp -j MASQUERADE --to-ports 1024-65535';self.assertFalse(self.m.firewall_port_conflicts('iptables-save',text,[9752]))
  self.assertTrue(self.m.firewall_port_conflicts('iptables-save',text+' --dport 9752',[9752]))
if __name__=='__main__':unittest.main()
