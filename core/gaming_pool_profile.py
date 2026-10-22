"""Pure fresh-instance builder. Does not install, access a server, or alter X-UI."""
import pathlib,json,secrets,base64,datetime,hashlib,ipaddress,uuid
from cryptography import x509
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from hy2_health_profile import paired
from tuic_health_profile import paired as tuic_paired
COUNTRIES={'DE':'198.51.100.10','FI':'198.51.100.20','TR':'198.51.100.30','US':'198.51.100.40'}
def build(root,cc,ports,tcp_upstream,*,local=False,carrier='HYSTERIA2'):
 if carrier not in ['HYSTERIA2','TUIC']:raise ValueError('EXPLICIT_REAL_UDP_CARRIER_REQUIRED')
 assert cc in COUNTRIES and pathlib.PurePosixPath(root).is_absolute()and'..'not in pathlib.PurePosixPath(root).parts
 assert set(ports)=={'front','primary','backup','force_primary','force_backup','api','health'}and len(set(ports.values()))==7 and all(type(v)is int and 1024<=v<10000 for v in ports.values())if not local else True
 foreign='127.0.0.1'if local else COUNTRIES[cc];gw='127.0.0.1'if local else'192.0.2.30';files={};servers=[];outs=[];force=[];paths=[];u=secrets.token_hex(8);pw=secrets.token_hex(24);sskey=base64.b64encode(secrets.token_bytes(16)).decode();api=secrets.token_hex(24)
 for index,name in enumerate(['primary','backup']):
  k=ec.generate_private_key(ec.SECP256R1());subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'owned-health.local')]);now=datetime.datetime.now(datetime.timezone.utc);cert=x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(k.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=2)).not_valid_after(now+datetime.timedelta(days=365)).add_extension(x509.SubjectAlternativeName([x509.DNSName('owned-health.local')]),False).sign(k,hashes.SHA256());pin=base64.b64encode(hashlib.sha256(k.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)).digest()).decode()
  files[name+'-cert.pem']=cert.public_bytes(serialization.Encoding.PEM);files[name+'-key.pem']=k.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption());auth=secrets.token_hex(24);obfs=secrets.token_hex(24)
  s,c=tuic_paired(root,foreign,ports[name],ports['force_'+name],ports['health'],ports['health']+1,str(uuid.uuid4()),auth,u,pw,pin)if carrier=='TUIC'else paired(root,foreign,ports[name],ports['force_'+name],ports['health'],ports['health']+1,auth,obfs,u,pw,pin)
  s['inbounds'][0]['tls'].update(certificate_path=root+'/'+name+'-cert.pem',key_path=root+'/'+name+'-key.pem');s['inbounds'][0]['tag']='udp-'+name
  if carrier=='HYSTERIA2':s['inbounds'][0]['ignore_client_bandwidth']=True
  for obj in[s['inbounds'][0],c['outbounds'][0]]:
   obj.pop('up_mbps',None);obj.pop('down_mbps',None)
  c['outbounds'][0].update(network='udp',tag='udp-'+name);outs.append(c['outbounds'][0]);force.append(dict(type='socks',tag='force-'+name,listen='127.0.0.1',listen_port=ports['force_'+name],users=[dict(username=u,password=pw)]));paths.append(dict(id='udp-'+name,host='127.0.0.1',port=ports['force_'+name],username=u,password=pw,timeout=2))
  s['outbounds']=[dict(type='direct',tag='public-udp-exit')];s['dns']=dict(servers=[dict(type='local',tag='system-dns')]);s['route']=dict(default_domain_resolver='system-dns',rules=[dict(action='resolve',strategy='prefer_ipv4'),dict(ip_cidr=['127.0.0.1/32'],port=[ports['health']],network='udp',action='route',outbound='public-udp-exit'),dict(ip_cidr=['0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12','192.168.0.0/16','224.0.0.0/4','240.0.0.0/4','::1/128','fc00::/7','fe80::/10','ff00::/8'],action='reject'),dict(network='udp',action='route',outbound='public-udp-exit'),dict(action='reject')]);servers.append(s)
 client=dict(log=dict(level='error'),inbounds=[dict(type='shadowsocks',tag='encrypted-lan',listen=gw,listen_port=ports['front'],method='2022-blake3-aes-128-gcm',password=sskey),*force],outbounds=[*outs,dict(type='selector',tag='game-pool',outbounds=['udp-primary','udp-backup'],default='udp-primary',interrupt_exist_connections=False),dict(type='socks',tag='existing-tcp-pool',server=tcp_upstream['address'],server_port=tcp_upstream['port'],username=tcp_upstream['username'],password=tcp_upstream['password'],network='tcp')],route=dict(rules=[dict(inbound=['force-'+n],network='udp',action='route',outbound='udp-'+n)for n in['primary','backup']]+[dict(network='udp',action='route',outbound='game-pool'),dict(network='tcp',action='route',outbound='existing-tcp-pool'),dict(action='reject')]),experimental=dict(clash_api=dict(external_controller='127.0.0.1:'+str(ports['api']),secret=api)))
 health=dict(paths=paths,target_host='localhost',target_port=ports['health'],api_port=ports['api'],api_secret=api,group='game-pool',successes=2,failures=3,hold_s=15,interval_s=5,max_rtt_ms=1000)
 files.update({'primary-server.json':json.dumps(servers[0]).encode(),'backup-server.json':json.dumps(servers[1]).encode(),'gateway.json':json.dumps(client).encode(),'health.private.json':json.dumps(health).encode()})
 outbound=dict(tag=cc+'-GAMING',protocol='shadowsocks',settings=dict(servers=[dict(address=gw,port=ports['front'],method='2022-blake3-aes-128-gcm',password=sskey)]))
 return dict(files=files,outbound=outbound,ports=ports,country=cc,foreign=foreign,canonical_methods=[carrier,carrier],path_instances=['udp-primary','udp-backup'],physical_path_diversity_proven=False,automatic_elastic_capacity=False)
