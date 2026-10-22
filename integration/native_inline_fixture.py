"""Actual patched/pristine native TCP fixture in a NEW, loopback-only Linux netns.

No production connections, configuration, credentials, services or routes are used.
The custom option is given ONLY to the verified locally patched build.
"""
import asyncio
import contextlib
import copy
import hashlib
import importlib.util
import json
import os
import pathlib
import secrets
import signal
import socket
import subprocess
import sys
import time

sys.path[:0] = [str(pathlib.Path(__file__).resolve().parents[1] / name) for name in ['core', 'experimental']]
from native_front_config import build

B = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = pathlib.Path(os.environ['FIVEPATH_INLINE_BUILD_MANIFEST']).resolve()
ROOT = pathlib.Path(os.environ['FIVEPATH_LOCAL_BUILD_ROOT']).resolve()
assert socket.if_nameindex() == [(1, 'lo')], 'FRESH_EMPTY_NETNS_REQUIRED'
assert json.loads((ROOT / 'ownership.json').read_text())['purpose'] == 'LOCAL_NATIVE_ADMISSION_BUILD_ONLY'
provenance = json.loads(MANIFEST.read_text())
assert provenance['patch_sha256'] == 'b5cf6e62ee2f2047f11526364827de08623e2e5efa0f79ce476ba239b61f379f'
assert provenance['phase'] == 'BUILT_NOT_DEPLOYABLE'
assets = {role: pathlib.Path(provenance['binaries'][role]['path']) for role in ['pristine', 'patched']}
for role, asset in assets.items():
    assert hashlib.sha256(asset.read_bytes()).hexdigest() == provenance['binaries'][role]['sha256']
subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True, timeout=3)
spec = importlib.util.spec_from_file_location('mesh', B / 'core/mesh_gateway.py')
mesh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mesh)
directory = B / 'local-results' / ('native-inline-fixture-' + secrets.token_hex(4))
directory.mkdir(mode=0o700, parents=True)
report = dict(local_only=True, WAN_bytes=0, SSH_connections=0, production_changes=False,
              cap=3, phase='RUNNING', build_patch_sha256=provenance['patch_sha256'],
              fixture_source_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
              binary_SHA256={k: v['sha256'] for k, v in provenance['binaries'].items()},
              checks={}, production_rollout_unlocked=False)
children, streams, handles = [], [], []
signal.alarm(110)


def save():
    (directory / 'result.json').write_text(json.dumps(report, indent=2))


def freeport():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


ports = []
while len(ports) < 11:
    value = freeport()
    if value not in ports:
        ports.append(value)


def start(args, name):
    handle = (directory / (name + '.log')).open('wb')
    handles.append(handle)
    proc = subprocess.Popen(args, stdout=handle, stderr=handle)
    children.append(proc)
    return proc


def identity(proc):
    data = pathlib.Path('/proc', str(proc.pid), 'stat').read_text().rsplit(') ', 1)[1].split()
    return dict(pid=proc.pid, start_ticks=data[19])


def metrics(proc):
    data = pathlib.Path('/proc', str(proc.pid), 'stat').read_text().rsplit(') ', 1)[1].split()
    status = pathlib.Path('/proc', str(proc.pid), 'status').read_text().splitlines()
    values = {row.split(':', 1)[0]: row.split(':', 1)[1].split()[0] for row in status if ':' in row and row.split(':', 1)[1].split()}
    return dict(CPU_seconds=(int(data[11]) + int(data[12])) / os.sysconf('SC_CLK_TCK'),
                RSS_bytes=int(values['VmRSS']) * 1024,
                VmHWM_bytes=int(values['VmHWM']) * 1024,
                FDs=len(list(pathlib.Path('/proc', str(proc.pid), 'fd').iterdir())))


async def ready(port, proc):
    for _ in range(100):
        assert proc.poll() is None, 'LOCAL_CHILD_EXITED'
        try:
            _, writer = await asyncio.open_connection('127.0.0.1', port)
            writer.close()
            await writer.wait_closed()
            await asyncio.sleep(.05)
            return
        except OSError:
            await asyncio.sleep(.025)
    raise TimeoutError('LOCAL_LISTENER_NOT_READY')


async def opened(port):
    reader, writer = await asyncio.open_connection('127.0.0.1', port)
    streams.append(writer)
    return reader, writer


async def closed_read(reader, timeout=1):
    try:
        return await asyncio.wait_for(reader.read(1), timeout) == b''
    except ConnectionResetError:
        return True


async def greeting(port):
    reader, writer = await opened(port)
    writer.write(b'\x05\x01\x02')
    await writer.drain()
    try:
        reply = await asyncio.wait_for(reader.readexactly(2), 1)
    except (ConnectionResetError, asyncio.IncompleteReadError):
        reply = b''
    return reader, writer, reply


async def authenticate(reader, writer, password='local-front-only-secret'):
    user, secret = b'front', password.encode()
    writer.write(b'\x01' + bytes([len(user)]) + user + bytes([len(secret)]) + secret)
    await writer.drain()
    return await asyncio.wait_for(reader.readexactly(2), 1)


async def request(reader, writer, destination, port, command=1, allow_reject_close=False):
    writer.write(b'\x05' + bytes([command]) + b'\x00' + mesh.address_bytes(destination, port))
    await writer.drain()
    try:
        header = await asyncio.wait_for(reader.readexactly(4), 2)
    except (ConnectionResetError, asyncio.IncompleteReadError):
        if allow_reject_close:
            return None
        raise
    await asyncio.wait_for(mesh.read_address(reader, header[3]), 1)
    return header[1]


async def connected(port, destination_port=None):
    reader, writer, reply = await greeting(port)
    assert reply == b'\x05\x02'
    assert await authenticate(reader, writer) == b'\x01\x00'
    assert await request(reader, writer, '127.0.0.1', destination_port or ports[0]) == 0
    return reader, writer


async def close_all():
    for writer in streams:
        writer.close()
    for writer in streams:
        with contextlib.suppress(OSError):
            await writer.wait_closed()
    streams.clear()
    await asyncio.sleep(.12)


async def payload(reader, writer, data):
    writer.write(data)
    await writer.drain()
    assert hashlib.sha256(await asyncio.wait_for(reader.readexactly(len(data)), 2)).digest() == hashlib.sha256(data).digest()


async def choose(control_port, member):
    reader, writer = await asyncio.open_connection('127.0.0.1', control_port)
    body = json.dumps({'name': member}).encode()
    writer.write(('PUT /proxies/DE-latency HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer local-control-secret-sufficient-length\r\nContent-Type: application/json\r\nContent-Length: ' + str(len(body)) + '\r\nConnection: close\r\n\r\n').encode() + body)
    await writer.drain()
    response = await asyncio.wait_for(reader.read(), 2)
    writer.close()
    await writer.wait_closed()
    assert response.startswith(b'HTTP/1.1 204')


def check_config(role, config, label, success):
    path = directory / (label + '.json')
    path.write_text(json.dumps(config))
    path.chmod(0o600)
    result = subprocess.run([str(assets[role]), 'check', '-c', str(path)], capture_output=True, text=True, timeout=5)
    (directory / (label + '-check.log')).write_text(result.stdout + result.stderr)
    assert (result.returncode == 0) == success, 'CONFIG_CONTRACT:' + label
    return path


async def exercise():
    data = secrets.token_bytes(16384)
    half_received, half_release = asyncio.Event(), asyncio.Event()
    upstream_accepts = 0
    async def echo(reader, writer):
        try:
            while block := await reader.read(65536):
                writer.write(block)
                await writer.drain()
        finally:
            writer.close()
    async def half(reader, writer):
        received = await reader.read()
        half_received.set()
        await half_release.wait()
        writer.write(received)
        await writer.drain()
        writer.close()
    async def upstream(reader, writer):
        nonlocal upstream_accepts
        upstream_accepts += 1
        await mesh.serve_socks(reader, writer, mesh.direct_connect, 'up', 'local-upstream-only')
    origin = await asyncio.start_server(echo, '127.0.0.1', ports[0])
    carrier = await asyncio.start_server(upstream, '127.0.0.1', ports[1])
    half_origin = await asyncio.start_server(half, '127.0.0.1', ports[8])
    old = dict(listen_host='127.0.0.1', listen_port=ports[2], username='front', password='local-front-only-secret', max_connections=3,
               mode='failover', upstreams=[dict(id='DE-one', host='127.0.0.1', port=ports[1], username='up', password='local-upstream-only',
               probe=dict(host='127.0.0.1', port=ports[0], nonce='fixture-local-only'))])
    old_path = directory / 'old.json'
    old_path.write_text(json.dumps(old))
    old_path.chmod(0o600)
    code = 'import asyncio,json,sys;sys.path.insert(0,' + repr(str(B / 'core')) + ');from mesh_gateway import Gateway;c=json.load(open(sys.argv[1]));g=Gateway(c,sys.argv[2]);g.policy.healthy={x["id"]:True for x in c["upstreams"]}\nasync def main():\n await g.start_listener()\n async with g.server:await g.server.serve_forever()\nasyncio.run(main())'
    op = start([sys.executable, '-c', code, str(old_path), str(directory / 'old-state.json')], 'legacy')
    await ready(ports[2], op)
    configs = {role: build(old, 'DE', ports[3 if role == 'pristine' else 6], ports[4 if role == 'pristine' else 7],
                         'local-control-secret-sufficient-length', ports[5]) for role in assets}
    configs['patched']['inbounds'][0]['five_path_tcp_admission_limit'] = 3
    check_config('pristine', configs['patched'], 'pristine-unknown-key-rejected', False)
    for value in [-1, 4097]:
        invalid = copy.deepcopy(configs['patched'])
        invalid['inbounds'][0]['five_path_tcp_admission_limit'] = value
        check_config('patched', invalid, 'invalid-limit-' + str(value), False)
    for kind in ['no-auth', 'detour']:
        invalid = copy.deepcopy(configs['patched'])
        if kind == 'no-auth':
            invalid['inbounds'][0]['users'] = []
        else:
            invalid['inbounds'][0]['detour'] = 'unowned-inbound'
        check_config('patched', invalid, kind, False)
    report['checks']['config_opt_in_and_fail_closed'] = True
    native = {}
    for role in assets:
        path = check_config(role, configs[role], role + '-valid', True)
        proc = start([str(assets[role]), 'run', '-c', str(path)], role)
        native[role] = proc
        await ready(ports[3 if role == 'pristine' else 6], proc)
        await ready(ports[4 if role == 'pristine' else 7], proc)
        await choose(ports[4 if role == 'pristine' else 7], 'DE-one')
    before = {p.pid: identity(p) for p in children}
    port = ports[6]
    try:
        # Control build accepts four pending; changed build must hold three slots
        # even when clients send no greeting at all.
        control = [await greeting(ports[3]) for _ in range(4)]
        assert all(v[2] == b'\x05\x02' for v in control)
        await close_all()
        held = [await opened(port) for _ in range(3)]
        await asyncio.sleep(.05)
        backend_before = upstream_accepts
        excess_r, _ = await opened(port)
        assert await closed_read(excess_r)
        assert upstream_accepts == backend_before
        report['checks']['zero_byte_pending_N_plus_1_rejected_before_backend'] = True
        for reader, writer in held:
            writer.write(b'\x05\x01\x02')
            await writer.drain()
            assert await reader.readexactly(2) == b'\x05\x02'
            assert await authenticate(reader, writer) == b'\x01\x00'
            assert await request(reader, writer, '127.0.0.1', ports[0]) == 0
        await asyncio.sleep(.08)
        _, _, reply = await greeting(port)
        assert reply == b'', 'AUTHENTICATED_HANDOFF_RELEASED_SLOT_EARLY'
        for stream in held:
            await payload(*stream, data)
        report['checks']['authenticated_streams_keep_N_slots_and_payload_SHA'] = True
        # Old and native are separately bounded: K+N, never a strict aggregate K.
        legacy = [await greeting(ports[2]) for _ in range(3)]
        assert all(v[2] == b'\x05\x02' for v in legacy)
        assert (await greeting(ports[2]))[2] == b''
        report['overlap'] = dict(legacy_K=3, native_N=3, held_application_connections=6,
                                 strict_aggregate_K_preserved=False, SYN_backlog_included=False)
        await choose(ports[7], 'DE-reject')
        for stream in held:
            await payload(*stream, data)
        report['checks']['existing_payload_survives_new_flow_selector_reject'] = True
        await choose(ports[7], 'DE-one')
        await close_all()

        # All three kinds of incomplete handshake must expire, then all slots
        # must be reusable. Authenticated established idle streams do not expire.
        idle = [await opened(port) for _ in range(3)]
        idle[1][1].write(b'\x05\x01\x02')
        await idle[1][1].drain()
        assert await idle[1][0].readexactly(2) == b'\x05\x02'
        idle[2][1].write(b'\x05\x01\x02')
        await idle[2][1].drain()
        assert await idle[2][0].readexactly(2) == b'\x05\x02'
        assert await authenticate(*idle[2]) == b'\x01\x00'
        started = time.monotonic()
        assert all(await asyncio.gather(*(closed_read(r, 16.5) for r, _ in idle)))
        report['handshake_expiry_observation_seconds'] = time.monotonic() - started
        await close_all()
        held = [await connected(port) for _ in range(3)]
        await asyncio.sleep(15.2)
        for stream in held:
            await payload(*stream, data)
        assert (await greeting(port))[2] == b''
        report['checks']['incomplete_handshakes_expire_established_idle_does_not'] = True
        await close_all()

        # Keep two unrelated authenticated reservations alive. Reclaim the one
        # failing slot without closing its client writer or either survivor.
        udp_before = pathlib.Path('/proc/net/udp').read_text(), pathlib.Path('/proc/net/udp6').read_text()
        for label in ['bad-auth', 'backend-refused', 'malformed', 'UDP-associate', 'UoT-v2', 'UoT-v1']:
            survivors = [await connected(port) for _ in range(2)]
            for stream in survivors:
                await payload(*stream, data)
            reader, writer, reply = await greeting(port)
            assert reply == b'\x05\x02'
            if label == 'bad-auth':
                assert await authenticate(reader, writer, 'fixture-invalid-secret') == b'\x01\x01'
            else:
                assert await authenticate(reader, writer) == b'\x01\x00'
                if label == 'malformed':
                    writer.write(b'\x05\x01\x00\xff')
                    await writer.drain()
                else:
                    dest = {'UoT-v2': 'sp.v2.udp-over-tcp.arpa', 'UoT-v1': 'sp.udp-over-tcp.arpa'}.get(label, '127.0.0.1')
                    status = await request(reader, writer, dest, ports[10] if label == 'backend-refused' else ports[0],
                                           3 if label == 'UDP-associate' else 1,
                                           allow_reject_close=label in ['UDP-associate', 'UoT-v2', 'UoT-v1'])
                    assert status != 0, 'NON_TCP_OR_FAILED_BACKEND_ACCEPTED:' + label
            # A SOCKS failure may send a bounded failure frame before EOF.
            with contextlib.suppress(ConnectionResetError):
                remainder = await asyncio.wait_for(reader.read(), 2)
                assert len(remainder) <= 32, 'UNBOUNDED_FAILURE_RESPONSE'
            refill = [await connected(port)]
            assert (await greeting(port))[2] == b'', 'FAILURE_RELEASE_UNDERCOUNT:' + label
            for stream in survivors + refill:
                await payload(*stream, data)
            await close_all()
            report['checks'][label + '_rejects_releases_one_and_preserves_two_survivors'] = True
        assert udp_before == (pathlib.Path('/proc/net/udp').read_text(), pathlib.Path('/proc/net/udp6').read_text())
        report['checks']['UDP_associate_and_both_UoT_rejected_no_remaining_UDP_listeners'] = True
        report['UDP_observation_limit'] = 'Endpoint socket tables only; transient bind syscalls not traced. Deny-listener implementation inspected separately.'

        half_stream = await connected(port, ports[8])
        half_stream[1].write(data)
        await half_stream[1].drain()
        half_stream[1].write_eof()
        await asyncio.wait_for(half_received.wait(), 2)
        other = [await connected(port) for _ in range(2)]
        assert (await greeting(port))[2] == b'', 'FIRST_FIN_FREED_SLOT'
        half_release.set()
        assert hashlib.sha256(await asyncio.wait_for(half_stream[0].readexactly(len(data)), 2)).digest() == hashlib.sha256(data).digest()
        assert await closed_read(half_stream[0])
        await asyncio.sleep(.1)
        replacement = await connected(port)
        await payload(*replacement, data)
        assert (await greeting(port))[2] == b'', 'HALF_CLOSE_DOUBLE_RELEASE'
        report['checks']['first_FIN_retains_slot_second_FIN_releases_once_SHA_preserved'] = True
        await close_all()

        if os.environ.get('FIVEPATH_FUNCTIONAL_ONLY') == '1':
            report['CPU_comparison_skipped_functional_only'] = True
        else:
            samples = []
            for mode, listen_port, proc in [('old', ports[2], op), ('pristine-native', ports[3], native['pristine']), ('inline-native', port, native['patched'])]:
                held = [await connected(listen_port) for _ in range(2)]
                for stream in held:
                    await payload(*stream, data)
                initial = metrics(proc)
                peak = dict(initial)
                stop = asyncio.Event()
                async def sample():
                    while not stop.is_set():
                        value = metrics(proc)
                        for key in ['RSS_bytes', 'VmHWM_bytes', 'FDs']:
                            peak[key] = max(peak[key], value[key])
                        await asyncio.sleep(.01)
                task = asyncio.create_task(sample())
                began = time.monotonic()
                async def transfer(stream):
                    for _ in range(1024):
                        await payload(*stream, data)
                await asyncio.gather(*(transfer(stream) for stream in held))
                elapsed = time.monotonic() - began
                final = metrics(proc)
                stop.set()
                await task
                used = final['CPU_seconds'] - initial['CPU_seconds']
                samples.append(dict(mode=mode, file_bytes=len(data), bytes_each_direction=32 * 1048576, concurrency=2,
                                    wall_seconds=elapsed, whole_front_CPU_seconds=used,
                                    CPU_seconds_per_MiB=used / 32,
                                    initial_RSS_bytes=initial['RSS_bytes'], observed_peak_RSS_bytes=peak['RSS_bytes'],
                                    process_lifetime_VmHWM_bytes=final['VmHWM_bytes'], observed_peak_FDs=peak['FDs']))
                await close_all()
            report['local_CPU_memory_comparison'] = samples
            report['same_compiler_pristine_and_inline'] = True
            report['inline_CPU_not_above_pristine_in_this_sample'] = samples[2]['whole_front_CPU_seconds'] <= samples[1]['whole_front_CPU_seconds']
            report['inline_CPU_below_old_in_this_sample'] = samples[2]['whole_front_CPU_seconds'] < samples[0]['whole_front_CPU_seconds']
        report['checks']['child_PID_and_start_ticks_preserved'] = all(identity(p) == before[p.pid] for p in children)
        assert report['checks']['child_PID_and_start_ticks_preserved']
        report['phase'] = 'LOCAL_FIXTURE_COMPLETE_NOT_PRODUCTION_ACCEPTANCE'
    finally:
        half_release.set()
        await close_all()
        for server in [origin, carrier, half_origin]:
            server.close()
            await server.wait_closed()


try:
    save()
    asyncio.run(asyncio.wait_for(exercise(), 100))
except BaseException as error:
    report.update(phase='FAILED_NO_AUTOMATIC_RETRY', error_type=type(error).__name__, error=str(error)[-350:])
    raise
finally:
    for proc in reversed(children):
        if proc.poll() is None:
            proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
    for handle in handles:
        handle.close()
    report['all_owned_children_reaped'] = all(p.poll() is not None for p in children)
    save()
    print(json.dumps(dict(directory=str(directory), phase=report['phase'], checks=report['checks'],
                          all_owned_children_reaped=report['all_owned_children_reaped'], WAN_bytes=0)), flush=True)
