"""Single finite RO network-cost diagnostic; no test traffic/config/service actions."""
import hashlib
import json
import os
import pathlib
import signal
import subprocess
import time

ROLE = os.environ.get('FIVEPATH_DIAGNOSTIC_ROLE', '')
assert ROLE in ['IR', 'GW']
signal.alarm(105)
os.nice(15)
import re
ROOTS = json.loads(os.environ['FIVEPATH_OWN_COUNTRY_ROOTS_JSON'])
assert set(ROOTS) == {'DE','FI','TR','US'}
assert all(re.fullmatch('tp-country-'+cc.lower()+'-[a-f0-9]{8}', rid) for cc,rid in ROOTS.items())
NATIVE_ROOTS = json.loads(os.environ.get('FIVEPATH_OWN_NATIVE_ROOTS_JSON', '{}'))
assert set(NATIVE_ROOTS) <= {'TR','US'}
assert all(re.fullmatch('tp-opt-'+cc.lower()+'-[a-f0-9]{8}', rid) for cc,rid in NATIVE_ROOTS.items())


def read(path):
    return pathlib.Path(path).read_text()

def command(args, timeout=5):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    assert len(result.stdout) + len(result.stderr) <= 256*1024, 'BOUNDED_READ_OUTPUT'
    return dict(code=result.returncode, stdout=result.stdout, stderr=result.stderr[-200:])

def units():
    result = command(['systemctl', 'list-units', '--type=service', '--state=active', '--no-legend', '--plain', '--no-pager'])
    assert result['code'] == 0
    names = [line.split()[0] for line in result['stdout'].splitlines() if line.strip()]
    result = command(['systemctl', 'show', *names, '-p', 'Id', '-p', 'ActiveState', '-p', 'MainPID', '-p', 'NRestarts'], 8)
    assert result['code'] == 0
    rows = {}
    for block in result['stdout'].strip().split('\n\n'):
        row = dict(line.split('=', 1) for line in block.splitlines() if '=' in line)
        if row.get('Id'):
            rows[row.pop('Id')] = row
    return rows

def own_groups():
    result, missing = {}, []
    for country, rid in ROOTS.items():
        root = pathlib.Path('/var/lib') / rid
        try:
            assert not root.is_symlink() and json.loads((root/'ownership.json').read_text())['run_id'] == rid
            path = pathlib.Path('/sys/fs/cgroup') / ('tpcountry' + country.lower() + rid.rsplit('-', 1)[1] + '.slice')
            assert path.is_dir()
            result[country+'-country-slice'] = path
        except (OSError, KeyError, ValueError, AssertionError):
            missing.append(country+'-country-slice')
    if ROLE == 'GW':
        for country, rid in NATIVE_ROOTS.items():
            root = pathlib.Path('/var/lib') / rid
            assert not root.is_symlink() and json.loads((root/'ownership.json').read_text())['run_id'] == rid
            for role in ['worker', 'watchdog']:
                path = pathlib.Path('/sys/fs/cgroup/system.slice') / (rid+'-'+role+'.service')
                if path.is_dir():
                    result[country+'-native-'+role] = path
                else:
                    missing.append(country+'-native-'+role)
    return result, missing

paths, missing_groups = own_groups()

def snapshot():
    network = {}
    for name in ['/proc/net/snmp', '/proc/net/netstat']:
        lines = read(name).splitlines()
        for first, second in zip(lines[::2], lines[1::2]):
            keys, values = first.split(), second.split()
            assert keys[0] == values[0] and len(keys) == len(values)
            network.update({keys[0].rstrip(':')+'.'+k: int(v) for k, v in zip(keys[1:], values[1:])})
    interfaces = {}
    for line in read('/proc/net/dev').splitlines()[2:]:
        name, data = line.rsplit(':', 1)
        values = list(map(int, data.split()))
        interfaces[name.strip()] = dict(zip(['rx_bytes', 'rx_packets', 'rx_errors', 'rx_drop', 'rx_fifo', 'rx_frame', 'rx_compressed', 'rx_multicast',
                                            'tx_bytes', 'tx_packets', 'tx_errors', 'tx_drop', 'tx_fifo', 'tx_collisions', 'tx_carrier', 'tx_compressed'], values))
    softnet = [[int(value, 16) for value in line.split()[:3]] for line in read('/proc/net/softnet_stat').splitlines()]
    softirqs = {}
    for line in read('/proc/softirqs').splitlines()[1:]:
        key, values = line.split(':', 1)
        if key.strip() in ['NET_RX', 'NET_TX']:
            softirqs[key.strip()] = list(map(int, values.split()))
    groups = {}
    for label, path in paths.items():
        value = dict(line.split() for line in (path/'cpu.stat').read_text().splitlines())
        groups[label] = dict(usage_usec=int(value['usage_usec']), memory=int((path/'memory.current').read_text()),
                             oom=dict(line.split() for line in (path/'memory.events').read_text().splitlines()))
    cpu = {line.split()[0]: list(map(int, line.split()[1:9])) for line in read('/proc/stat').splitlines() if line.startswith('cpu')}
    known_ports = {'DE-old':32101, 'FI-old':32102, 'TR-old':32103, 'US-old':32104, 'TR-native':8871, 'US-native':8681}
    listener_counts = {}
    if ROLE == 'GW':
        for family in ['tcp', 'tcp6']:
            rows = [line.split() for line in read('/proc/net/'+family).splitlines()[1:]]
            for label, port in known_ports.items():
                selected = [row for row in rows if int(row[1].rsplit(':',1)[1],16)==port and row[3]!='0A']
                listener_counts[label+'-'+family] = dict(non_listen_sockets=len(selected), established=sum(row[3]=='01' for row in selected), close_wait=sum(row[3]=='08' for row in selected))
    return dict(epoch=time.time(), monotonic=time.monotonic(), network=network, interfaces=interfaces, softnet=softnet,
                softirqs=softirqs, groups=groups, cpu=cpu, known_listener_socket_counts=listener_counts,
                MemAvailable_kB=int(next(line.split()[1] for line in read('/proc/meminfo').splitlines() if line.startswith('MemAvailable:'))))

def counter_delta(before, after):
    result = {key: after[key]-value for key, value in before.items() if key in after}
    assert all(value >= 0 for value in result.values()), 'COUNTER_RESET_OR_NAMESPACE_CHANGED'
    return result

boot = read('/proc/sys/kernel/random/boot_id').strip()
before_units = units()
first = snapshot()
time.sleep(60)
last = snapshot()
after_units = units()
assert boot == read('/proc/sys/kernel/random/boot_id').strip()
duration = last['monotonic'] - first['monotonic']
assert 60 <= duration <= 75
cpu = {}
for label, values in first['cpu'].items():
    if label not in last['cpu']:
        continue
    delta = [a-b for a, b in zip(last['cpu'][label], values)]
    assert min(delta) >= 0
    if not sum(delta):
        continue
    cpu[label] = {key: 100*value/sum(delta) for key, value in zip(['user', 'nice', 'system', 'idle', 'iowait', 'irq', 'softirq', 'steal'], delta)}
softnet = [[b-a for a, b in zip(x, y)] for x, y in zip(first['softnet'], last['softnet'])]
assert len(first['softnet']) == len(last['softnet']) and all(value >= 0 for row in softnet for value in row)
groups = {key: dict(mean_CPU_cores=(last['groups'][key]['usage_usec']-value['usage_usec'])/1e6/duration,
                   memory_before=value['memory'], memory_after=last['groups'][key]['memory'],
                   memory_events_delta=counter_delta({k:int(v) for k,v in value['oom'].items()}, {k:int(v) for k,v in last['groups'][key]['oom'].items()}))
          for key, value in first['groups'].items()}
selected_network = ['Tcp.InSegs', 'Tcp.OutSegs', 'Tcp.RetransSegs', 'Tcp.InErrs', 'Tcp.OutRsts',
                    'Tcp.ActiveOpens', 'Tcp.PassiveOpens', 'Tcp.AttemptFails', 'Tcp.EstabResets',
                    'Ip.InReceives', 'Ip.InDiscards', 'Ip.OutDiscards', 'Ip.ReasmReqds', 'Ip.ReasmOKs', 'Ip.ReasmFails',
                    'Ip.FragOKs', 'Ip.FragFails', 'Ip.FragCreates', 'IpExt.InOctets', 'IpExt.OutOctets',
                    'TcpExt.ListenOverflows', 'TcpExt.ListenDrops', 'TcpExt.TCPBacklogDrop', 'TcpExt.TCPRcvQDrop',
                    'TcpExt.TCPTimeouts', 'TcpExt.TCPSynRetrans', 'TcpExt.TCPLostRetransmit',
                    'TcpExt.TCPSpuriousRTOs', 'TcpExt.TCPOFOQueue', 'TcpExt.TCPOFODrop', 'TcpExt.TCPMemoryPressures']
net_delta = counter_delta({k:first['network'][k] for k in selected_network if k in first['network']}, last['network'])
own_units = {key: value for key, value in before_units.items() if any(key.startswith(rid) for rid in list(ROOTS.values()) + list(NATIVE_ROOTS.values()))}
own_after = {key: value for key, value in after_units.items() if key in own_units}
result = dict(role=ROLE, read_only=True, generated_test_traffic=False, service_control_actions=0, configuration_changes=False,
              started_epoch=first['epoch'], ended_epoch=last['epoch'], duration_seconds=duration,
              kernel_release=os.uname().release, boot_unchanged=True, CPU_modes_pct=cpu,
              minimum_endpoint_MemAvailable_kB=min(first['MemAvailable_kB'], last['MemAvailable_kB']),
              own_country_groups=groups, missing_group_coverage=missing_groups,
              TCP_CurrEstab_endpoints=[first['network'].get('Tcp.CurrEstab'),last['network'].get('Tcp.CurrEstab')],
              known_listener_socket_counts_before=first['known_listener_socket_counts'],
              known_listener_socket_counts_after=last['known_listener_socket_counts'],
              listener_socket_count_scope='Current netns TCP tables/known ports only; not exact private handler admission or per-flow byte attribution',
              interfaces_delta={key:counter_delta(value,last['interfaces'][key]) for key,value in first['interfaces'].items() if key in last['interfaces']},
              softnet_first_three_columns_delta=softnet,
              softirq_invocations_delta={key:[b-a for a,b in zip(value,last['softirqs'][key])] for key,value in first['softirqs'].items()},
              protocol_counters_delta={key:net_delta[key] for key in selected_network if key in net_delta},
              missing_protocol_counters=[key for key in selected_network if key not in net_delta],
              all_active_services_before=len(before_units), all_active_services_after=len(after_units),
              all_initial_active_service_identities_unchanged=all(after_units.get(key)==value for key,value in before_units.items()),
              own_service_count=len(own_units), own_service_PID_state_NRestarts_unchanged=own_units==own_after,
              changed_initial_services=[key for key,value in before_units.items() if after_units.get(key)!=value],
              no_equal_load_or_cross_host_simultaneity_claim=True)
print(json.dumps(result))
