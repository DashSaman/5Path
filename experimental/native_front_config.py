"""Native TCP front on a NEW listener; existing country transports are unchanged."""
import ipaddress

def build(old, country, new_port, control_port, control_secret, reject_port):
 if country not in ('DE','FI','TR','US') or not isinstance(new_port,int) or not 1024<new_port<65536 or new_port==old['listen_port']:
  raise ValueError('NEW_LISTENER_SCOPE')
 if len({new_port,control_port,reject_port,old['listen_port']})!=4 or any(type(x)is not int or not 1024<x<65536 for x in (control_port,reject_port)) or len(control_secret)<24:
  raise ValueError('NEW_PRIVATE_CONTROL_SCOPE')
 if not old.get('username') or len(old.get('password',''))<16 or old.get('listen_host') not in ('192.0.2.30','127.0.0.1'):
  raise ValueError('AUTHENTICATED_OWN_FRONT_REQUIRED')
 upstreams=old['upstreams'];ids=[u['id'] for u in upstreams]
 if not 1<=len(ids)<=5 or len(ids)!=len(set(ids)) or any(not x.startswith(country+'-') for x in ids):
  raise ValueError('EXACT_SAME_COUNTRY_MEMBERSHIP')
 outbounds=[];probes=set()
 for u in upstreams:
  if not ipaddress.ip_address(u['host']).is_loopback or not u.get('username') or not u.get('password'):
   raise ValueError('LOCAL_AUTHENTICATED_TRANSPORT_ONLY')
  p=u['probe']
  if p['host']!='127.0.0.1' or not 1024<int(p['port'])<65536 or not p.get('nonce'):
   raise ValueError('OWN_EXISTING_HEALTH_REQUIRED')
  probes.add((p['host'],p['port'],p['nonce']))
  outbounds.append({'type':'socks','tag':u['id'],'server':u['host'],'server_port':u['port'],'version':'5','username':u['username'],'password':u['password'],'network':'tcp','connect_timeout':'6s','tcp_keep_alive':'30s','tcp_keep_alive_interval':'15s'})
 if len(probes)!=1:raise ValueError('ONE_OWN_COUNTRY_HEALTH')
 host,port,_=next(iter(probes));tag=country+'-latency'
 outbounds.append({'type':'socks','tag':country+'-reject','server':'127.0.0.1','server_port':reject_port,'version':'5','network':'tcp','connect_timeout':'1s'})
 outbounds.append({'type':'selector','tag':tag,'outbounds':ids+[country+'-reject'],'default':country+'-reject','interrupt_exist_connections':False})
 return {'log':{'level':'error','timestamp':True},'inbounds':[{'type':'socks','tag':country+'-front','listen':old['listen_host'],'listen_port':new_port,'users':[{'username':old['username'],'password':old['password']}]}],'outbounds':outbounds,'route':{'rules':[{'network':'udp','action':'reject'}],'final':tag},'experimental':{'clash_api':{'external_controller':'127.0.0.1:'+str(control_port),'secret':control_secret}}}
