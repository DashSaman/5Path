import unittest,socket,threading,hashlib
from bounded_tcp_probe import run_probe

class ProbeTiming(unittest.TestCase):
    def test_authenticated_single_file_and_complete_phase_timing(self):
        payload=b'L'*16384;listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1);port=listener.getsockname()[1];errors=[]
        def exact(s,n):
            b=b''
            while len(b)<n:
                x=s.recv(n-len(b))
                if not x:raise EOFError()
                b+=x
            return b
        def serve():
            try:
                with listener.accept()[0]as s:
                    s.settimeout(3);assert exact(s,3)==b'\x05\x01\x02';s.sendall(b'\x05\x02')
                    assert exact(s,1)==b'\x01';u=exact(s,exact(s,1)[0]);p=exact(s,exact(s,1)[0]);assert u==b'fixture' and p==b'fixture-password';s.sendall(b'\x01\x00')
                    assert exact(s,10)[:4]==b'\x05\x01\x00\x01';s.sendall(b'\x05\x00\x00\x01'+bytes(6))
                    request=b''
                    while not request.endswith(b'\r\n\r\n'):request+=exact(s,1)
                    assert request.startswith(b'GET /'+b'1'*40+b' HTTP/1.0')
                    s.sendall(b'HTTP/1.0 200 OK\r\nContent-Length: 16384\r\n\r\n'+payload)
            except BaseException as e:errors.append(e)
        t=threading.Thread(target=serve,daemon=True);t.start()
        try:
            v=run_probe(dict(front_host='127.0.0.1',front_port=port,origin_port=9998,username='fixture',password='fixture-password',token='1'*40,payload_sha256=hashlib.sha256(payload).hexdigest()))
            self.assertTrue(v['complete']);self.assertEqual(v['bytes'],16384);self.assertEqual(len(v['elapsed_seconds']),6)
            self.assertTrue(all(x>=0 for x in v['phase_seconds'].values()));self.assertAlmostEqual(sum(v['phase_seconds'].values()),v['seconds'])
        finally:listener.close();t.join(4)
        self.assertFalse(t.is_alive());self.assertEqual(errors,[])
