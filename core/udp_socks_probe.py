"""Standard SOCKS5 control/UDP probe. No secrets in argv, logging, or results."""
import socket,struct,time,os,hashlib,statistics
def recv(s,n):
 result=b''
 while len(result)<n:
  v=s.recv(n-len(result))
  if not v:raise ConnectionError('SOCKS_CONTROL_EOF')
  result+=v
 return result
def address(host,port):
 try:body=b'\x01'+socket.inet_aton(host)
 except OSError:
  h=host.encode('idna');assert 0<len(h)<256;body=b'\x03'+bytes([len(h)])+h
 return body+struct.pack('!H',port)
def control(c,cmd,target):
 s=socket.create_connection((c['host'],c['port']),timeout=c.get('timeout',4));s.sendall(b'\x05\x01\x02');assert recv(s,2)==b'\x05\x02';u=c['username'].encode();p=c['password'].encode();assert len(u)<256 and len(p)<256;s.sendall(b'\x01'+bytes([len(u)])+u+bytes([len(p)])+p)
 if recv(s,2)!=b'\x01\x00':s.close();raise PermissionError('SOCKS_AUTH_REJECTED')
 s.sendall(b'\x05'+bytes([cmd])+b'\x00'+address(*target));a=recv(s,4)
 if a[:3]!=b'\x05\x00\x00':s.close();raise ConnectionError('SOCKS_REQUEST_REJECTED')
 if a[3]==1:h=socket.inet_ntoa(recv(s,4))
 elif a[3]==3:h=recv(s,recv(s,1)[0]).decode()
 elif a[3]==4:h=socket.inet_ntop(socket.AF_INET6,recv(s,16))
 else:s.close();raise ValueError('SOCKS_BIND_ADDRESS')
 port=int.from_bytes(recv(s,2),'big');return s,(h,port)
class UDPSession:
 def __init__(self,c):
  self.control,self.relay=control(c,3,('0.0.0.0',0))
  if self.relay[0]in['0.0.0.0','::']:self.relay=(c['host'],self.relay[1])
  self.socket=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);self.socket.settimeout(c.get('timeout',4))
 def exchange(self,host,port,payload):
  start=time.monotonic();self.socket.sendto(b'\x00\x00\x00'+address(host,port)+payload,self.relay);raw,peer=self.socket.recvfrom(65536);assert raw[:3]==b'\x00\x00\x00','UDP_FRAGMENT_OR_HEADER';t=raw[3]
  offset=10 if t==1 else 22 if t==4 else 7+raw[4]if t==3 else None
  if offset is None:raise ValueError('UDP_REPLY_ADDRESS')
  return raw[offset:],(time.monotonic()-start)*1000
 def close(self):self.control.close();self.socket.close()
def screen(c,host,port):
 s=UDPSession(c);sent=[];received=[];times=[]
 try:
  for _ in range(16):
   data=os.urandom(1024);got,ms=s.exchange(host,port,data);assert got==data,'UDP_BYTES_CHANGED';sent.append(data);received.append(got);times.append(ms)
  echoes=[]
  for _ in range(24):
   data=os.urandom(256);got,ms=s.exchange(host,port,data);assert got==data,'UDP_ECHO_CHANGED';echoes.append(ms)
  x=hashlib.sha256(b''.join(sent)).hexdigest();y=hashlib.sha256(b''.join(received)).hexdigest();assert x==y;ordered=sorted(echoes);return dict(bytes=16384,sha256=x,received_sha256=y,complete=True,echo_success=24,echo_total=24,p95_ms=ordered[int(.95*(len(ordered)-1))],p99_ms=ordered[int(.99*(len(ordered)-1))],max_ms=max(echoes),jitter_ms=statistics.mean(abs(a-b)for a,b in zip(echoes,echoes[1:])),first_data_ms=times[0])
 finally:s.close()
