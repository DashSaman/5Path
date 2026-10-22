"""Standalone authenticated TCP SOCKS gateway with real upstream probes.

Runs on the source node under systemd, independently of the panel process.
Each destination has its own stable listener. Existing TCP sessions need client
reconnection after a transport outage; new sessions use the healthy selection.
"""
from __future__ import annotations

import asyncio
from contextlib import suppress
import hmac
import ipaddress
import json
import math
import os
from pathlib import Path
import socket
import struct
import time
import uuid


class RoutePolicy:
    def __init__(self, order, failures=3, successes=2, hold_down=15, active=None):
        self.order = list(order)
        self.failures, self.successes, self.hold_down = failures, successes, hold_down
        self.active, self.pin = active, None
        self.healthy = {key: False for key in self.order}
        self.good = dict.fromkeys(self.order, 0)
        self.bad = dict.fromkeys(self.order, 0)
        self.last_switch = -1e12

    def update(self, observations, now=None):
        now = time.monotonic() if now is None else now
        for key in self.order:
            if observations.get(key, False):
                self.good[key] += 1
                self.bad[key] = 0
                if self.good[key] >= self.successes:
                    self.healthy[key] = True
            else:
                self.bad[key] += 1
                self.good[key] = 0
                if self.bad[key] >= self.failures:
                    self.healthy[key] = False
        preferred = ([self.pin] if self.pin in self.order else []) + self.order
        best = next((key for key in preferred if self.healthy[key]), None)
        active_ok = self.healthy.get(self.active, False)
        if not active_ok or self.pin == best or now - self.last_switch >= self.hold_down:
            if best != self.active:
                self.active, self.last_switch = best, now
        return self.active


def address_bytes(host, port):
    try:
        address = ipaddress.ip_address(host)
        return (b'\x01' if address.version == 4 else b'\x04') + address.packed + struct.pack('!H', port)
    except ValueError:
        name = host.encode('idna')
        if not 1 <= len(name) <= 255:
            raise ValueError('invalid SOCKS destination')
        return b'\x03' + bytes([len(name)]) + name + struct.pack('!H', port)


async def read_address(reader, kind):
    if kind == 1:
        host = socket.inet_ntop(socket.AF_INET, await reader.readexactly(4))
    elif kind == 4:
        host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
    elif kind == 3:
        size = (await reader.readexactly(1))[0]
        host = (await reader.readexactly(size)).decode('idna')
    else:
        raise ValueError('unsupported SOCKS address type')
    return host, struct.unpack('!H', await reader.readexactly(2))[0]


async def socks_connect(upstream, host, port):
    reader, writer = await asyncio.wait_for(asyncio.open_connection(upstream['host'], upstream['port']), 8)
    try:
        use_auth = bool(upstream.get('username'))
        writer.write(b'\x05\x01' + (b'\x02' if use_auth else b'\x00'))
        await writer.drain()
        if await reader.readexactly(2) != b'\x05' + (b'\x02' if use_auth else b'\x00'):
            raise ConnectionError('SOCKS authentication method rejected')
        if use_auth:
            username, password = upstream['username'].encode(), upstream['password'].encode()
            if max(len(username), len(password)) > 255:
                raise ValueError('SOCKS credential too long')
            writer.write(b'\x01' + bytes([len(username)]) + username + bytes([len(password)]) + password)
            await writer.drain()
            if await reader.readexactly(2) != b'\x01\x00':
                raise ConnectionError('SOCKS credentials rejected')
        writer.write(b'\x05\x01\x00' + address_bytes(host, port))
        await writer.drain()
        reply = await reader.readexactly(4)
        if reply[:3] != b'\x05\x00\x00':
            raise ConnectionError('SOCKS destination rejected')
        await read_address(reader, reply[3])
        return reader, writer
    except BaseException:
        writer.close()
        with suppress(Exception):
            await writer.wait_closed()
        raise


async def direct_connect(host, port):
    return await asyncio.open_connection(host, port)


async def serve_socks(reader, writer, connect, username, password):
    remote_reader = None
    remote_writer = None
    relays = []
    replied = False
    try:
        async def handshake():
            nonlocal remote_reader, remote_writer, replied
            version, count = await reader.readexactly(2)
            if version != 5 or count == 0:
                return
            methods = await reader.readexactly(count)
            if 2 not in methods:
                writer.write(b'\x05\xff')
                await writer.drain()
                return
            writer.write(b'\x05\x02')
            await writer.drain()
            version, size = await reader.readexactly(2)
            received_user = await reader.readexactly(size)
            size = (await reader.readexactly(1))[0]
            received_password = await reader.readexactly(size)
            valid = (version == 1 and hmac.compare_digest(received_user, username.encode())
                     and hmac.compare_digest(received_password, password.encode()))
            writer.write(b'\x01' + (b'\x00' if valid else b'\x01'))
            await writer.drain()
            if not valid:
                return
            request = await reader.readexactly(4)
            if request[:3] != b'\x05\x01\x00':
                writer.write(b'\x05\x07\x00\x01' + bytes(6))
                await writer.drain()
                return
            host, port = await read_address(reader, request[3])
            remote_reader, remote_writer = await connect(host, port)
            writer.write(b'\x05\x00\x00\x01' + bytes(6))
            await writer.drain()
            replied = True

        await asyncio.wait_for(handshake(), 15)
        if not replied:
            return

        async def pipe(source, destination):
            while True:
                chunk = await asyncio.wait_for(source.read(65536), 300)
                if not chunk:
                    with suppress(Exception):
                        destination.write_eof()
                    return
                destination.write(chunk)
                await destination.drain()
        relays = [asyncio.create_task(pipe(reader, remote_writer)), asyncio.create_task(pipe(remote_reader, writer))]
        await asyncio.gather(*relays)
    except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError):
        if not replied:
            with suppress(Exception):
                writer.write(b'\x05\x05\x00\x01' + bytes(6))
                await writer.drain()
    finally:
        for task in relays:
            if not task.done():
                task.cancel()
        if relays:
            await asyncio.gather(*relays, return_exceptions=True)
        for stream in (remote_writer, writer):
            if stream:
                stream.close()
                with suppress(Exception):
                    await stream.wait_closed()


def atomic_json(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as file:
        json.dump(value, file, ensure_ascii=False, allow_nan=False)
        file.flush()
        os.fsync(file.fileno())
    os.replace(temporary, path)


class Gateway:
    def __init__(self, config, state_path):
        self.config, self.state_path = config, Path(state_path)
        ids = [upstream['id'] for upstream in config['upstreams']]
        if not ids or len(ids) != len(set(ids)) or len(ids) > 100:
            raise ValueError('select unique bounded upstreams')
        if not config.get('username') or len(config.get('password', '')) < 16:
            raise ValueError('stable gateway authentication is required')
        self.policy = RoutePolicy(ids, failures=config.get('failures', 3),
                                  successes=config.get('successes', 2), hold_down=config.get('hold_down_s', 15))
        self.server = None
        self.events, self.probes = [], {}
        self.connections_total = 0
        self.active_connections = dict.fromkeys(ids, 0)
        self.connections_by_upstream = dict.fromkeys(ids, 0)
        self.probe_history = {key: [] for key in ids}
        if config.get('mode', 'failover') not in {'failover', 'balance'}:
            raise ValueError('unknown gateway mode')
        self._connections = set()

    def record_probes(self, readings):
        self.probes = readings
        for key in self.policy.order:
            row = readings.get(key, {})
            value = row.get('latency_ms')
            valid = row.get('ok') and isinstance(value, (int, float)) and math.isfinite(value) and value >= 0
            self.probe_history[key] = (self.probe_history[key] + [value if valid else None])[-10:]

    def effective_weight(self, key):
        upstream = next(u for u in self.config['upstreams'] if u['id'] == key)
        weight = upstream.get('weight', 1)
        if not isinstance(weight, (int, float)) or not math.isfinite(weight) or weight <= 0:
            weight = 1
        history = self.probe_history[key]
        good = [value for value in history if value is not None]
        if not history:
            return min(100, weight)
        if not good:
            return min(100, weight) * .05
        mean = sum(good) / len(good)
        baseline = upstream.get('baseline_rtt_ms', mean)
        if not isinstance(baseline, (int, float)) or not math.isfinite(baseline) or baseline < 0:
            baseline = mean
        jitter = sum(abs(b - a) for a,b in zip(good, good[1:])) / max(1, len(good)-1)
        quality = len(good) / len(history) * min(1, (baseline + 5) / (mean + 5)) / (1 + jitter / 10)
        return min(100, weight) * max(.05, quality)

    def connection_order(self):
        healthy = [key for key in self.policy.order if self.policy.healthy.get(key, False)]
        if self.config.get('mode', 'failover') == 'balance':
            healthy.sort(key=lambda key: ((self.active_connections[key] + 1) / self.effective_weight(key),
                                          self.connections_by_upstream[key]))
            preferred = self.policy.pin
        else:
            preferred = self.policy.pin if self.policy.healthy.get(self.policy.pin, False) else self.policy.active
        if preferred in healthy:
            healthy.remove(preferred)
            healthy.insert(0, preferred)
        return healthy

    async def connect(self, host, port, selected=None):
        by_id = {upstream['id']: upstream for upstream in self.config['upstreams']}
        for key in self.connection_order():
            # Reserve before awaiting setup so simultaneous clients see the load.
            self.active_connections[key] += 1
            retained, writer = False, None
            try:
                reader, writer = await asyncio.wait_for(socks_connect(by_id[key], host, port), 10)
                if self.config.get('mode', 'failover') == 'failover' and self.policy.active != key:
                    self.events.append({'at': time.time(), 'from': self.policy.active, 'to': key,
                                        'reason': 'connection failover'})
                    self.policy.active, self.policy.last_switch = key, time.monotonic()
                self.connections_total += 1
                self.connections_by_upstream[key] += 1
                if selected:
                    selected(key)
                retained = True
                return reader, writer
            except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError):
                # Failure to a particular destination is NOT enough evidence to
                # mark an entire tunnel down; independent nonce probes do that.
                continue
            finally:
                if not retained or selected is None:
                    self.active_connections[key] -= 1
                if not retained and writer:
                    writer.close()
                    with suppress(Exception):
                        await writer.wait_closed()
        raise ConnectionError('no healthy upstream can reach the destination')

    async def start_listener(self):
        async def handler(reader, writer):
            task = asyncio.current_task()
            if len(self._connections) >= self.config.get('max_connections', 256):
                writer.close()
                return
            self._connections.add(task)
            selected = []
            try:
                async def connect(host, port):
                    return await self.connect(host, port, selected.append)
                await serve_socks(reader, writer, connect, self.config['username'], self.config['password'])
            finally:
                for key in selected:
                    self.active_connections[key] -= 1
                self._connections.discard(task)
        self.server = await asyncio.start_server(handler, self.config.get('listen_host', '127.0.0.1'),
                                                 self.config['listen_port'], limit=65536)

    async def probe(self, upstream):
        started, writer = time.monotonic(), None
        try:
            target = upstream['probe']
            async def check():
                nonlocal writer
                reader, writer = await socks_connect(upstream, target['host'], target['port'])
                writer.write(b'GET / HTTP/1.0\r\nHost: owned-health.local\r\nConnection: close\r\n\r\n')
                await writer.drain()
                data = await reader.readuntil(b'\r\n\r\n')
                body = await reader.readexactly(len(target['nonce'].encode()))
                ok = data.startswith(b'HTTP/1.0 200') or data.startswith(b'HTTP/1.1 200')
                ok = ok and hmac.compare_digest(body.strip(), target['nonce'].encode())
                return {'ok': ok, 'latency_ms': round((time.monotonic() - started) * 1000, 3)}
            return await asyncio.wait_for(check(), self.config.get('probe_timeout_s', 5))
        except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            return {'ok': False, 'latency_ms': None}
        finally:
            if writer:
                writer.close()
                with suppress(Exception):
                    await writer.wait_closed()

    def write_state(self):
        self.events = self.events[-100:]
        atomic_json(self.state_path, {'active': self.policy.active,
                    'worker_pid': os.getpid(),
                    'healthy': self.policy.healthy, 'probes': self.probes,
                    'order': self.policy.order, 'pin': self.policy.pin, 'events': self.events,
                    'connections_total': self.connections_total, 'updated_at': time.time(),
                    'mode': self.config.get('mode', 'failover'),
                    'active_connections': self.active_connections,
                    'connections_by_upstream': self.connections_by_upstream,
                    'effective_weights': {key: round(self.effective_weight(key), 3) for key in self.policy.order},
                    'capability': 'authenticated TCP SOCKS5; existing sessions reconnect after failure'})

    async def run(self, config_path):
        await self.start_listener()
        async with self.server:
            while True:
                updated = json.loads(Path(config_path).read_text(encoding='utf-8'))
                # Order/pin changes are applied without restarting the stable listener.
                ids = [upstream['id'] for upstream in updated['upstreams']]
                if set(ids) != set(self.policy.order):
                    raise ValueError('upstream membership changes require a reconciled deployment')
                if updated.get('mode', 'failover') not in {'failover', 'balance'}:
                    raise ValueError('unknown gateway mode')
                self.config = updated
                self.policy.order, self.policy.pin = ids, updated.get('pin')
                readings = await asyncio.gather(*(self.probe(upstream) for upstream in self.config['upstreams']))
                self.record_probes({upstream['id']: result for upstream, result in zip(self.config['upstreams'], readings)})
                previous = self.policy.active
                self.policy.update({key: result['ok'] for key, result in self.probes.items()})
                if previous != self.policy.active:
                    self.events.append({'at': time.time(), 'from': previous, 'to': self.policy.active,
                                        'reason': 'verified data-plane health'})
                self.write_state()
                await asyncio.sleep(max(1, self.config.get('probe_interval_s', 2)))


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--egress', action='store_true')
    parser.add_argument('config')
    parser.add_argument('state', nargs='?')
    arguments = parser.parse_args()
    configuration = json.loads(Path(arguments.config).read_text(encoding='utf-8'))
    async def egress():
        connections = set()
        async def handler(reader, writer):
            task = asyncio.current_task()
            if len(connections) >= configuration.get('max_connections', 256):
                writer.close()
                return
            connections.add(task)
            try:
                await serve_socks(reader, writer, direct_connect, configuration['username'], configuration['password'])
            finally:
                connections.discard(task)
        server = await asyncio.start_server(handler, configuration['listen_host'], configuration['listen_port'], limit=65536)
        async with server:
            await server.serve_forever()
    if arguments.egress:
        asyncio.run(egress())
    else:
        if not arguments.state:
            parser.error('gateway state path is required')
        asyncio.run(Gateway(configuration, arguments.state).run(arguments.config))
