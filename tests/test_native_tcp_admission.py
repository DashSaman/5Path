"""Actual local TCP tests of pending admission, teardown and half-close."""
import asyncio,contextlib,hashlib,pathlib,socket,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
from native_tcp_admission import AdmissionRelay


def freeport():
    with socket.socket()as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]


class AdmissionTCP(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.accepted=0;self.streams=[];self.handlers=set();self.finish=None
        self.backend=await asyncio.start_server(self.backend_handler,'127.0.0.1',0)
        self.relay=await AdmissionRelay(freeport(),self.backend.sockets[0].getsockname()[1],3).start()

    async def asyncTearDown(self):
        for w in self.streams:w.close()
        await self.relay.close();self.backend.close();await self.backend.wait_closed()
        tasks=list(self.handlers)
        for t in tasks:t.cancel()
        if tasks:await asyncio.gather(*tasks,return_exceptions=True)

    async def backend_handler(self,r,w):
        task=asyncio.current_task();self.handlers.add(task);self.accepted+=1
        try:
            assert await r.readexactly(3)==b'\x05\x01\x02'
            # Deliberately fragment replies across real TCP writes.
            for b in (b'\x05',b'\x02'):w.write(b);await w.drain();await asyncio.sleep(0)
            n=await r.readexactly(2);u=await r.readexactly(n[1]);size=(await r.readexactly(1))[0];password=await r.readexactly(size)
            w.write(b'\x01'+(b'\x00'if password==b'secret'else b'\x01'));await w.drain()
            if password!=b'secret':return
            await r.readexactly(10)
            for b in (b'\x05\x00',b'\x00\x01'+bytes(6)):w.write(b);await w.drain();await asyncio.sleep(0)
            if self.finish:
                data=await r.read();await self.finish.wait();w.write(data+b'END');await w.drain()
            else:
                while data:=await r.read(65536):w.write(data);await w.drain()
        except (OSError,asyncio.IncompleteReadError):pass
        finally:w.close();self.handlers.discard(task)

    async def connect(self):
        r,w=await asyncio.open_connection('127.0.0.1',self.relay.listen_port);self.streams.append(w);return r,w

    async def greet(self):
        r,w=await self.connect();w.write(b'\x05\x01\x02');await w.drain();self.assertEqual(await r.readexactly(2),b'\x05\x02');return r,w

    async def auth(self,r,w,password=b'secret'):
        w.write(b'\x01\x01u'+bytes([len(password)])+password);await w.drain();return await r.readexactly(2)

    async def establish(self):
        r,w=await self.greet();self.assertEqual(await self.auth(r,w),b'\x01\x00');w.write(b'\x05\x01\x00\x01'+bytes([127,0,0,1,1,1]));await w.drain();self.assertEqual((await r.readexactly(10))[:2],b'\x05\x00');return r,w

    async def drained(self):
        for _ in range(100):
            if not self.relay.active:return
            await asyncio.sleep(.01)
        self.fail('ADMISSION_SLOT_NOT_RELEASED')

    async def test_N_pending_rejects_N_plus_1_and_held_payload_survives(self):
        held=[await self.greet()for _ in range(3)];r,w=await self.connect()
        with contextlib.suppress(ConnectionResetError):self.assertEqual(await asyncio.wait_for(r.read(1),1),b'')
        self.assertEqual(self.accepted,3);self.assertEqual(len(self.relay.active),3);self.assertEqual(self.relay.peak,3)
        r,w=held[0];self.assertEqual(await self.auth(r,w),b'\x01\x00');w.write(b'\x05\x01\x00\x01'+bytes([127,0,0,1,1,1]));await w.drain();await r.readexactly(10)
        data=bytes(range(256))*64;w.write(data);await w.drain();self.assertEqual(hashlib.sha256(await r.readexactly(len(data))).digest(),hashlib.sha256(data).digest())

    async def test_pending_timeout_and_failed_auth_release_slots(self):
        self.relay.handshake_timeout=.15;r,w=await self.connect();self.assertEqual(await asyncio.wait_for(r.read(1),1),b'');await self.drained()
        self.relay.handshake_timeout=1;r,w=await self.greet();self.assertEqual(await self.auth(r,w,b'bad'),b'\x01\x01');self.assertEqual(await asyncio.wait_for(r.read(1),1),b'');await self.drained()
        self.assertEqual(self.relay.peak,1)

    async def test_half_close_retains_slot_until_response_finishes(self):
        self.finish=asyncio.Event();self.relay.maximum=1;r,w=await self.establish();data=b'a'*16384;w.write(data);await w.drain();w.write_eof();await asyncio.sleep(.03)
        self.assertEqual(len(self.relay.active),1);other,_=await self.connect()
        with contextlib.suppress(ConnectionResetError):self.assertEqual(await asyncio.wait_for(other.read(1),1),b'')
        self.finish.set();self.assertEqual(await asyncio.wait_for(r.read(),1),data+b'END');await self.drained()

    async def test_backend_connect_failure_and_cancellation_do_not_leak(self):
        self.relay.handshake_timeout=.2
        self.backend.close();await self.backend.wait_closed();r,w=await self.connect();self.assertEqual(await asyncio.wait_for(r.read(1),1),b'');await self.drained()
        self.backend=await asyncio.start_server(self.backend_handler,'127.0.0.1',self.relay.backend_port)
        r,w=await self.greet();self.assertEqual(len(self.relay.active),1);await self.relay.close();self.assertEqual(await asyncio.wait_for(r.read(),1),b'');self.assertEqual(len(self.relay.active),0)


if __name__=='__main__':unittest.main()
