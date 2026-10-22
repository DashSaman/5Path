"""LOCAL prototype: bounded authenticated-SOCKS TCP admission before native relay.

This is not connected to deployment. It caps one frontend, not old+new combined.
Closing/restarting it closes its own sessions; do not auto-restart it in production.
"""
import asyncio,contextlib,json,os,pathlib,sys,time


class HandshakeRejected(ConnectionError):
    pass


class ReplyTracker:
    """Observe only SOCKS server replies; never retain usernames or passwords."""
    def __init__(self):
        self.phase='method';self.needed=2;self.buffer=bytearray();self.connected=False;self.reply_ok=False

    def feed(self,data):
        cursor=0
        while cursor<len(data) and not self.connected:
            take=min(self.needed-len(self.buffer),len(data)-cursor)
            self.buffer.extend(data[cursor:cursor+take]);cursor+=take
            if len(self.buffer)<self.needed:return
            b=bytes(self.buffer);self.buffer.clear()
            if self.phase=='method':
                if b!=b'\x05\x02':raise HandshakeRejected('USERNAME_PASSWORD_METHOD_REQUIRED')
                self.phase='auth';self.needed=2
            elif self.phase=='auth':
                if b!=b'\x01\x00':raise HandshakeRejected('SOCKS_AUTH_REJECTED')
                self.phase='reply';self.needed=4
            elif self.phase=='reply':
                if b[0]!=5 or b[2]!=0:raise HandshakeRejected('SOCKS_REPLY_INVALID')
                self.reply_ok=b[1]==0
                if b[3] in (1,4):self.phase='tail';self.needed=6 if b[3]==1 else 18
                elif b[3]==3:self.phase='domain_size';self.needed=1
                else:raise HandshakeRejected('SOCKS_REPLY_ADDRESS_INVALID')
            elif self.phase=='domain_size':
                if not b[0]:raise HandshakeRejected('SOCKS_REPLY_DOMAIN_EMPTY')
                self.phase='tail';self.needed=b[0]+2
            else:
                if not self.reply_ok:raise HandshakeRejected('SOCKS_CONNECT_REJECTED')
                self.connected=True


class AdmissionRelay:
    def __init__(self,listen_port,backend_port,maximum,handshake_timeout=15):
        if any(type(p)is not int or not 1024<p<65536 for p in (listen_port,backend_port)) or listen_port==backend_port:
            raise ValueError('DISJOINT_LOCAL_LISTENERS_REQUIRED')
        if type(maximum)is not int or not 1<=maximum<=4096 or not .1<=handshake_timeout<=30:
            raise ValueError('BOUNDED_CONNECTION_POLICY_REQUIRED')
        self.listen_port=listen_port;self.backend_port=backend_port;self.maximum=maximum;self.handshake_timeout=handshake_timeout
        self.active=set();self.peak=0;self.rejected=0;self.accepted=0;self.completed=0;self.backend_failures=0;self.closing=False;self.server=None

    def status(self):
        return dict(active=len(self.active),peak=self.peak,rejected=self.rejected,accepted=self.accepted,completed=self.completed,maximum=self.maximum,backend_failures=self.backend_failures,closing=self.closing,pid=os.getpid(),epoch=time.time(),local_prototype_only=True,aggregate_old_native_cap=False)

    async def start(self):
        self.server=await asyncio.start_server(self.handle,'127.0.0.1',self.listen_port,limit=65536,backlog=min(128,2*self.maximum))
        return self

    async def handle(self,reader,writer):
        task=asyncio.current_task()
        # No await between checking and reserving; pending/idle clients occupy slots.
        if self.closing or len(self.active)>=self.maximum:
            self.rejected+=1;writer.close()
            with contextlib.suppress(OSError):await writer.wait_closed()
            return
        self.active.add(task);self.accepted+=1;self.peak=max(self.peak,len(self.active))
        remote=None;pipes=[];tracker=ReplyTracker();handshake_done=asyncio.Event();loop=asyncio.get_running_loop();deadline=loop.time()+self.handshake_timeout
        async def pipe(source,destination,observe=False):
            try:
                while data:=await source.read(65536):
                    destination.write(data);await destination.drain()
                    if observe and not tracker.connected:
                        tracker.feed(data)
                        if tracker.connected:handshake_done.set()
                if observe and not tracker.connected:raise HandshakeRejected('BACKEND_EOF_BEFORE_CONNECTED')
                if destination.can_write_eof():destination.write_eof();await destination.drain()
            finally:
                if observe:handshake_done.set()
        try:
            rr,remote=await asyncio.wait_for(asyncio.open_connection('127.0.0.1',self.backend_port,limit=65536),min(3,self.handshake_timeout))
            pipes=[asyncio.create_task(pipe(reader,remote)),asyncio.create_task(pipe(rr,writer,True))]
            await asyncio.wait_for(handshake_done.wait(),max(.001,deadline-loop.time()))
            if not tracker.connected:raise HandshakeRejected('BACKEND_HANDSHAKE_FAILED')
            # Established idle sessions are retained; FIN is relayed per direction.
            await asyncio.gather(*pipes)
        except (OSError,asyncio.TimeoutError,HandshakeRejected,asyncio.IncompleteReadError):
            self.backend_failures+=1
        finally:
            for p in pipes:
                if not p.done():p.cancel()
            if pipes:await asyncio.gather(*pipes,return_exceptions=True)
            for w in (remote,writer):
                if w:w.close()
            for w in (remote,writer):
                if w:
                    with contextlib.suppress(OSError,asyncio.TimeoutError):await asyncio.wait_for(w.wait_closed(),1)
            self.active.discard(task);self.completed+=1

    async def close(self):
        self.closing=True
        if self.server:self.server.close();await self.server.wait_closed()
        tasks=list(self.active)
        for t in tasks:t.cancel()
        if tasks:await asyncio.gather(*tasks,return_exceptions=True)


async def main(path):
    p=pathlib.Path(path);c=json.loads(p.read_text(encoding='utf-8'))
    if set(c)!={'listen_port','backend_port','maximum','state_path'}:raise ValueError('EXACT_LOCAL_PROTOTYPE_CONFIG_REQUIRED')
    state=pathlib.Path(c['state_path']);root=p.resolve().parent
    if state.parent.resolve()!=root or state.is_symlink():raise ValueError('OWN_LOCAL_STATE_REQUIRED')
    relay=await AdmissionRelay(c['listen_port'],c['backend_port'],c['maximum']).start()
    try:
        while True:
            tmp=state.with_suffix('.tmp');tmp.write_text(json.dumps(relay.status()),encoding='utf-8');os.replace(tmp,state);await asyncio.sleep(.25)
    finally:await relay.close()


if __name__=='__main__':asyncio.run(main(sys.argv[1]))
