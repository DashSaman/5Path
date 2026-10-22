"""Pinned catalog HYSTERIA2/Salamander recipe restricted to one owned TCP origin.

Protocol fields derive from pinned TunnelPannel plan_executor/executor.py:4810.
No installer, system routes, tun device or production config is invoked here.
"""
import base64,copy,ipaddress,pathlib

def paired(root,host,udp_port,socks_port,origin_port,cover_port,password,obfs,socks_user,socks_password,public_key_pin):
 ipaddress.IPv4Address(host)
 if not pathlib.PurePosixPath(root).is_absolute()or'..'in pathlib.PurePosixPath(root).parts:raise ValueError('OWN_CONFIG_ROOT')
 if any(type(p)is not int or not 1024<=p<=65535 for p in [udp_port,socks_port,origin_port,cover_port]):raise ValueError('PORT_SCOPE')
 if len({udp_port,socks_port,origin_port,cover_port})!=4:raise ValueError('OWN_LISTENER_OR_COVER_COLLISION')
 try:pin=base64.b64decode(public_key_pin,validate=True)
 except (ValueError,TypeError):raise ValueError('PUBLIC_KEY_PIN')from None
 if len(pin)!=32:raise ValueError('PUBLIC_KEY_PIN')
 if not all(isinstance(s,str)and s for s in [password,obfs,socks_user,socks_password]):raise ValueError('OWN_AUTH_REQUIRED')
 tls_server=dict(enabled=True,server_name='owned-health.local',min_version='1.3',certificate_path=root+'/cert.pem',key_path=root+'/key.pem')
 tls_client=dict(enabled=True,server_name='owned-health.local',min_version='1.3',insecure=False,certificate_public_key_sha256=[public_key_pin])
 shared=dict(up_mbps=2,down_mbps=2,obfs=dict(type='salamander',password=obfs))
 sin=dict(type='hysteria2',tag='owned-hy2',listen=host,listen_port=udp_port,users=[dict(name='owned-health',password=password)],tls=tls_server,**copy.deepcopy(shared))
 cout=dict(type='hysteria2',tag='owned-hy2-out',server=host,server_port=udp_port,password=password,network='tcp',tls=tls_client,**copy.deepcopy(shared))
 def rules(tag):return [dict(ip_cidr=['127.0.0.1/32'],port=[origin_port],network='tcp',action='route',outbound=tag),dict(action='reject')]
 server=dict(log=dict(level='error'),inbounds=[sin],outbounds=[dict(type='direct',tag='health-only')],route=dict(rules=rules('health-only')))
 client=dict(log=dict(level='error'),inbounds=[dict(type='socks',tag='owned-socks',listen='127.0.0.1',listen_port=socks_port,users=[dict(username=socks_user,password=socks_password)])],outbounds=[cout],route=dict(rules=rules('owned-hy2-out')))
 return server,client
