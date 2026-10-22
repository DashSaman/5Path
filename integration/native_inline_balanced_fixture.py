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
directory = B / 'local-results' / ('native-inline-balanced-' + secrets.token_hex(4))
directory.mkdir(mode=0o700, parents=True)
report = dict(local_only=True, WAN_bytes=0, SSH_connections=0, production_changes=False,
              cap=3, phase='RUNNING', build_patch_sha256=provenance['patch_sha256'],
              fixture_source_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
              binary_SHA256={k: v['sha256'] for k, v in provenance['binaries'].items()},
              checks={}, production_rollout_unlocked=False)
children, streams, handles = [], [], []
signal.alarm(190)


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
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    fixture_pid = os.getpid()
    def owned_parent_death_guard():
        # Only children of this empty-netns diagnostic, never a service.
        if libc.prctl(1, signal.SIGKILL) != 0 or os.getppid() != fixture_pid:
            os._exit(126)
    # Predetermined Latin/counterbalanced order: each role occupies each
    # position twice; every child starts fresh and reaches the same age.
    orders = [
        ['old', 'pristine', 'patched'], ['pristine', 'patched', 'old'],
        ['patched', 'old', 'pristine'], ['patched', 'pristine', 'old'],
        ['old', 'patched', 'pristine'], ['pristine', 'old', 'patched']]
    data = secrets.token_bytes(16384)
    iterations = 4096
    target_age = 2.0
    os.nice(15)
    report.update(diagnostic_question='Does inline cap retain dataplane CPU advantage versus legacy and bounded overhead versus pristine when runtime age/order/CPU precision are controlled?',
                  scope='DATAPLANE_PROCESSES_ONLY_NOT_POLICY_WORKER_WATCHDOG_OR_KERNEL',
                  runtime_age_target_seconds=target_age, balanced_orders=orders,
                  per_trial_bytes_each_direction=2*iterations*len(data),
                  file_bytes=len(data), concurrency=2, CPU_accounting_quantum_seconds=1/os.sysconf('SC_CLK_TCK'),
                  total_planned_loopback_bytes_each_direction=18*2*iterations*len(data),
                  new_downloads=0, new_builds=0, repeated_sequential_sample=False,
                  predeclared_criteria=dict(dataplane_inline_vs_old_total_ratio_max=.90,
                                           inline_vs_pristine_total_ratio_max=1.10,
                                           observed_age_tolerance_seconds=.05,
                                           minimum_each_role_total_CPU_seconds=2.0),
                  production_acceptance=False, samples=[])
    save()
    async def echo(reader, writer):
        try:
            while block := await reader.read(65536):
                writer.write(block)
                await writer.drain()
        finally:
            writer.close()
    async def upstream(reader, writer):
        await mesh.serve_socks(reader, writer, mesh.direct_connect, 'up', 'local-upstream-only')
    origin = await asyncio.start_server(echo, '127.0.0.1', ports[0])
    carrier = await asyncio.start_server(upstream, '127.0.0.1', ports[1])
    old = dict(listen_host='127.0.0.1', listen_port=ports[2], username='front', password='local-front-only-secret',
               max_connections=3, mode='failover', upstreams=[dict(id='DE-one', host='127.0.0.1', port=ports[1],
               username='up', password='local-upstream-only', probe=dict(host='127.0.0.1', port=ports[0], nonce='local-only'))])
    path = directory / 'legacy.json'
    path.write_text(json.dumps(old))
    path.chmod(0o600)
    legacy_code = 'import asyncio,json,sys;sys.path.insert(0,' + repr(str(B / 'core')) + ');from mesh_gateway import Gateway;c=json.load(open(sys.argv[1]));g=Gateway(c,sys.argv[2]);g.policy.healthy={x["id"]:True for x in c["upstreams"]}\nasync def main():\n await g.start_listener()\n async with g.server:await g.server.serve_forever()\nasyncio.run(main())'
    native_config = build(old, 'DE', ports[6], ports[7], 'local-control-secret-sufficient-length', ports[5])
    paths = {'old': path}
    for role in ['pristine', 'patched']:
        config = copy.deepcopy(native_config)
        if role == 'patched':
            config['inbounds'][0]['five_path_tcp_admission_limit'] = 3
        paths[role] = check_config(role, config, role + '-balanced-valid', True)
    try:
        for group, order in enumerate(orders):
            for position, role in enumerate(order):
                stamp = time.monotonic()
                env = os.environ.copy()
                env['GOMAXPROCS'] = '2'
                handle = (directory / f'{group}-{position}-{role}.log').open('wb')
                handles.append(handle)
                args = ([sys.executable, '-c', legacy_code, str(paths[role]), str(directory / 'legacy-state.json')]
                        if role == 'old' else [str(assets[role]), 'run', '-c', str(paths[role])])
                proc = subprocess.Popen(args, env=env, stdout=handle, stderr=handle,
                                        start_new_session=True, preexec_fn=owned_parent_death_guard)
                children.append(proc)
                listen_port = ports[2] if role == 'old' else ports[6]
                held = []
                try:
                    await ready(listen_port, proc)
                    if role != 'old':
                        await ready(ports[7], proc)
                        await choose(ports[7], 'DE-one')
                    held = [await connected(listen_port) for _ in range(2)]
                    for stream in held:
                        await payload(*stream, data)
                    await asyncio.sleep(max(0, target_age - (time.monotonic() - stamp)))
                    age = time.monotonic() - stamp
                    assert target_age <= age <= target_age + .05, 'UNEQUAL_PROCESS_AGE'
                    before_pid = identity(proc)
                    initial = metrics(proc)
                    peak = dict(initial)
                    done = asyncio.Event()
                    async def sample():
                        while not done.is_set():
                            value = metrics(proc)
                            for key in ['RSS_bytes', 'VmHWM_bytes', 'FDs']:
                                peak[key] = max(peak[key], value[key])
                            await asyncio.sleep(.02)
                    sampler = asyncio.create_task(sample())
                    began = time.monotonic()
                    async def transfer(stream):
                        for _ in range(iterations):
                            await payload(*stream, data)
                    try:
                        await asyncio.gather(*(transfer(stream) for stream in held))
                    finally:
                        done.set()
                        await sampler
                    seconds = time.monotonic() - began
                    final = metrics(proc)
                    assert identity(proc) == before_pid
                    cpu_used = final['CPU_seconds'] - initial['CPU_seconds']
                    report['samples'].append(dict(group=group, position=position, role=role,
                          process_age_at_measurement=age, wall_seconds=seconds,
                          dataplane_CPU_seconds=cpu_used, bytes_each_direction=2*iterations*len(data),
                          SHA_payload_verified=True, PID_start_ticks_preserved=True,
                          observed_peak_RSS_bytes=peak['RSS_bytes'], observed_peak_FDs=peak['FDs'],
                          process_lifetime_VmHWM_bytes=final['VmHWM_bytes']))
                    save()
                finally:
                    await close_all()
                    if proc.poll() is None:
                        proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=2)
        totals = {role: sum(v['dataplane_CPU_seconds'] for v in report['samples'] if v['role'] == role)
                  for role in ['old', 'pristine', 'patched']}
        report['totals_CPU_seconds'] = totals
        report['inline_to_old_CPU_ratio'] = totals['patched'] / totals['old']
        report['inline_to_pristine_CPU_ratio'] = totals['patched'] / totals['pristine']
        report['accounting_precision_criterion_met'] = min(totals.values()) >= 2.0
        report['local_dataplane_criteria_met'] = (report['accounting_precision_criterion_met'] and
                    report['inline_to_old_CPU_ratio'] <= .90 and report['inline_to_pristine_CPU_ratio'] <= 1.10)
        report['checks'] = dict(all_18_trials_completed=len(report['samples']) == 18,
                               all_payload_SHA_and_PID_preserved=all(v['SHA_payload_verified'] and v['PID_start_ticks_preserved'] for v in report['samples']),
                               every_role_each_position_twice=True, all_process_ages_within_50ms=True)
        assert len(report['samples']) == 18
        report['phase'] = 'LOCAL_BALANCED_DATAPLANE_COMPLETE_NOT_PRODUCTION_ACCEPTANCE'
    finally:
        await close_all()
        for server in [origin, carrier]:
            server.close()
            await server.wait_closed()


try:
    save()
    asyncio.run(asyncio.wait_for(exercise(), 180))
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
