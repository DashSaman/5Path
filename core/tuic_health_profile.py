"""Catalog TUIC with pinned TLS and the same one-origin TCP health restriction."""
import uuid
from hy2_health_profile import paired as validated_h2_scope
def paired(root,host,udp_port,socks_port,origin_port,cover_port,ident,password,socks_user,socks_password,pin):
 uuid.UUID(ident)
 server,client=validated_h2_scope(root,host,udp_port,socks_port,origin_port,cover_port,password,'scope-validation',socks_user,socks_password,pin)
 sin=server['inbounds'][0];cout=client['outbounds'][0]
 for obj in[sin,cout]:
  obj.update(type='tuic',congestion_control='bbr',zero_rtt_handshake=False,heartbeat='10s');obj['tls']['alpn']=['h3']
  for field in['up_mbps','down_mbps','obfs']:obj.pop(field,None)
 sin['users']=[dict(name='owned-health',uuid=ident,password=password)]
 cout.update(uuid=ident,udp_relay_mode='native')
 return server,client
