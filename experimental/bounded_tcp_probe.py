"""One authenticated 16KiB origin read, with a single absolute deadline."""
def run_probe(c):
    import socket,time,hashlib,re
    assert type(c['front_port']) is int and 1024<c['front_port']<65536
    assert type(c['origin_port']) is int and 1024<c['origin_port']<65536
    assert re.fullmatch('[a-f0-9]{40}',c['token'])
    assert re.fullmatch('[a-f0-9]{64}',c['payload_sha256'])
    u,p=c['username'].encode(),c['password'].encode()
    assert 0<len(u)<=255 and 0<len(p)<=255
    start=time.monotonic();deadline=start+15;marks={}
    def mark(name):marks[name]=time.monotonic()-start
    def exact(s,n):
        result=b''
        while len(result)<n:
            remaining=deadline-time.monotonic()
            if remaining<=0:raise TimeoutError('BOUNDED_PROBE_DEADLINE')
            s.settimeout(min(6,remaining));part=s.recv(n-len(result))
            if not part:raise EOFError('BOUNDED_PROBE_SHORT_READ')
            result+=part
        return result
    s=socket.create_connection((c['front_host'],c['front_port']),min(6,deadline-time.monotonic()))
    try:
        mark('gateway_tcp_connected')
        s.sendall(b'\x05\x01\x02');assert exact(s,2)==b'\x05\x02';mark('gateway_method_confirmed')
        s.sendall(b'\x01'+bytes([len(u)])+u+bytes([len(p)])+p);assert exact(s,2)==b'\x01\x00';mark('gateway_authenticated')
        s.sendall(b'\x05\x01\x00\x01'+socket.inet_aton('127.0.0.1')+c['origin_port'].to_bytes(2,'big'))
        reply=exact(s,4);assert reply[:3]==b'\x05\x00\x00'
        if reply[3]==1:exact(s,6)
        elif reply[3]==4:exact(s,18)
        elif reply[3]==3:exact(s,exact(s,1)[0]+2)
        else:raise ValueError('SOCKS_ADDRESS')
        mark('destination_connected')
        s.sendall(('GET /'+c['token']+' HTTP/1.0\r\nHost: own-origin.local\r\nConnection: close\r\n\r\n').encode())
        body=b''
        while b'\r\n\r\n'not in body:
            body+=exact(s,1);assert len(body)<=2048
        header,data=body.split(b'\r\n\r\n',1);assert header.startswith(b'HTTP/1.0 200');mark('origin_headers_received')
        data+=exact(s,16384-len(data));assert hashlib.sha256(data).hexdigest()==c['payload_sha256'];mark('file_sha_verified')
        names=list(marks);previous=0;durations={}
        for name in names:durations[name]=marks[name]-previous;previous=marks[name]
        return dict(bytes=16384,sha256=hashlib.sha256(data).hexdigest(),complete=True,seconds=marks['file_sha_verified'],elapsed_seconds=marks,phase_seconds=durations,one_absolute_deadline_seconds=15)
    finally:s.close()
