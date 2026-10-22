"""Explicit owned country/port scopes. Proposals must still pass live preflight."""
import re
_SPEC={'TR':('198.51.100.30',24296,32103),'FI':('198.51.100.20',24330,32102),'DE':('198.51.100.10',24230,32101),'US':('198.51.100.40',24262,32104)}
METHODS=['WATERWALL_REVERSE','FRP_TCP','FRP_KCP','GOST_HTTP2','GOST_GRPC']

def instance(country):
 if country not in _SPEC:raise ValueError('EXPLICIT_COUNTRY_SCOPE')
 foreign,base,entry=_SPEC[country]
 return dict(country=country,foreign=foreign,base=base,entry=entry,health=base+8,egress=base+9,origin=base+28,cover=base+29,controls=[base+i for i in [0,1,2,6,12]],raws=[base+i for i in [16,17,18,10,14]])

def from_rid(rid):
 if not isinstance(rid,str):raise ValueError('COUNTRY_RID_SCOPE')
 m=re.fullmatch(r'tp-country-(tr|fi|de|us)-[a-f0-9]{8}',rid)
 if not m:raise ValueError('COUNTRY_RID_SCOPE')
 return instance(m[1].upper())

def slice_name(rid):
 c=from_rid(rid);return'tpcountry'+c['country'].lower()+rid.rsplit('-',1)[1]+'.slice'

def firewall_tuples(country):
 c=instance(country)
 return {(c['foreign'],'203.0.113.30','tcp',port)for port in c['controls']}|{(c['foreign'],'203.0.113.30','udp',c['base']+2),('192.0.2.10','192.0.2.30','tcp',c['entry'])}
