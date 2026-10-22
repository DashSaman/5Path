"""Read-only firewall reservation parsing, without treating counters as ports."""
import re,json,shlex,inspect

def _port_value(value,ports):
 for part in value.split(','):
  if re.fullmatch(r'\d+[:-]\d+',part):
   lo,hi=map(int,re.split('[:-]',part));assert 0<=lo<=hi<=65535,'PORT_RANGE_INVALID'
   if any(lo<=p<=hi for p in ports):return True
  elif part.isdecimal():
   n=int(part);assert 0<=n<=65535,'PORT_INVALID'
   if n in ports:return True
  else:raise ValueError('UNPARSED_PORT_RESERVATION')
 return False

def _nft_values(value,ports):
 if type(value)is int:return value in ports
 if isinstance(value,str):
  return _port_value(value,ports)if value.isdecimal()or re.fullmatch(r'\d+[:-]\d+',value)else False
 if isinstance(value,list):return any(_nft_values(x,ports)for x in value)
 if isinstance(value,dict):
  if 'range'in value:
   span=value['range']
   if isinstance(span,list)and len(span)==2 and all(type(x)is int for x in span)and any(span[0]<=p<=span[1]for p in ports):return True
  return any(_nft_values(x,ports)for key,x in value.items()if key not in['counter','handle','metainfo'])
 return False

def firewall_port_conflicts(tool,text,ports):
 if not ports:return False
 if tool=='nft':return _nft_values(json.loads(text),ports)
 if tool not in['iptables','ip6tables','iptables-save','ip6tables-save']:raise ValueError('UNKNOWN_FIREWALL_TOOL')
 direct={'--dport','--sport','--dports','--sports','--ports','--destination-port','--source-port','--to-ports','--on-port'};nat={'--to-destination','--to-source'}
 for line in text.splitlines():
  words=shlex.split(line);i=0;jump=words[words.index('-j')+1]if'-j'in words else words[words.index('--jump')+1]if'--jump'in words else None
  while i<len(words):
   key,eq,inline=words[i].partition('=')
   if key not in direct|nat:i+=1;continue
   if eq:value=inline
   else:i+=1;assert i<len(words),'MISSING_FIREWALL_PORT_VALUE';value=words[i]
   i+=1
   # MASQUERADE allocates source translation ports per connection; its pool
   # does not own/bind every listening port in that range. Keep packet match
   # dports/sports, DNAT, REDIRECT, TPROXY and fixed SNAT checks intact.
   if key=='--to-ports'and jump=='MASQUERADE':continue
   if key in nat:
    if value.startswith('['):value=value.split(']:',1)[1]if']:'in value else''
    elif value.startswith(':'):value=value[1:]
    elif value.count(':')==1 and'.'in value:value=value.rsplit(':',1)[1]
    else:value=''
    if not value:continue
   if _port_value(value,ports):return True
 return False

def build_audit_template(original):
 # Only these two verified reservation checks change; the existing complete
 # address/route/socket/namespace/config/clock/ownership audit is preserved.
 old="for port in ports:\n assert not any(re.search(r'(?<![0-9])'+str(port)+r'(?![0-9])',audit[k])for k in['iptables','ip6tables','nft']),'EXISTING_RULE_PORT_CONFLICT'"
 new="for key in ['iptables','ip6tables','nft']:\n conflicts=[p for p in ports if firewall_port_conflicts(key,audit[key],[p])]\n assert not conflicts,'EXISTING_RULE_PORT_CONFLICT:'+key+':'+repr(conflicts)"
 oldns="assert not any(re.search(r'(?<![0-9])'+str(port)+r'(?![0-9])',z.stdout)for port in ports),'NAMESPACE_RULE_PORT_CONFLICT'"
 newns="assert not any(firewall_port_conflicts(command[0],z.stdout,[p])for p in ports),'NAMESPACE_RULE_PORT_CONFLICT'"
 assert original.count(old)==original.count(oldns)==1,'AUDIT_TEMPLATE_DRIFT'
 body=original.replace(old,new).replace(oldns,newns)
 return 'import re,json,shlex\n'+'\n'.join(inspect.getsource(f)for f in[_port_value,_nft_values,firewall_port_conflicts])+'\n'+body
