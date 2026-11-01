import datetime
import hashlib
import ipaddress
import json
import os
import pwd
import re
import selectors
import socket
import stat
import subprocess
import time
import uuid

SPOOL = '/var/lib/cybershield360-agent/activity-spool'
STATE = '/var/lib/cybershield360-activity/state.json'
UTC = datetime.timezone.utc


def stamp(value=None):
    return (value or datetime.datetime.now(UTC)).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def ip(value):
    parsed = ipaddress.ip_address(value.split('%')[0])
    if getattr(parsed, 'ipv4_mapped', None):
        parsed = parsed.ipv4_mapped
    return None if parsed.is_loopback or parsed.is_unspecified else str(parsed)


def event(kind, payload, occurred=None, identity=None):
    return dict(sourceEventId=identity or 'activity:' + uuid.uuid4().hex, kind=kind, severity='INFO', occurredAt=occurred or stamp(), payload=payload)


def bounded_lines(command, limit):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    content = b''
    deadline = time.monotonic() + 4
    complete = False
    try:
        while time.monotonic() < deadline and len(content) < 131072 and content.count(b'\n') <= limit:
            if not selector.select(max(0, deadline - time.monotonic())):
                break
            chunk = os.read(process.stdout.fileno(), 8192)
            if not chunk:
                complete = True
                break
            content += chunk
    finally:
        selector.close()
        if process.poll() is None:
            try:
                process.wait(timeout=0.5 if complete else 0)
            except subprocess.TimeoutExpired:
                process.kill()
        result = process.wait()
        process.stdout.close()
    if complete and result != 0:
        raise RuntimeError('metadata source command failed')
    lines = content.decode('utf-8', errors='replace').splitlines()
    return lines[:limit], not complete or len(lines) > limit


def save(state):
    content = json.dumps(state, separators=(',', ':')).encode()
    if len(content) > 262144:
        raise RuntimeError('collector state limit')
    temporary = STATE + '.tmp-' + uuid.uuid4().hex
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(content)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, STATE)
    directory = os.open(os.path.dirname(STATE), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def publish(state, spool, owner):
    pending = state.get('pending')
    if not pending:
        return
    content = ('\n'.join(json.dumps(item, separators=(',', ':')) for item in pending['events']) + '\n').encode()
    if len(content) > 32768 or len(pending['events']) > 90:
        raise RuntimeError('batch size limit')
    filename = pending['file']
    try:
        descriptor = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=spool)
    except FileNotFoundError:
        temporary = '.tmp-' + uuid.uuid4().hex
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=spool)
        with os.fdopen(descriptor, 'wb') as output:
            os.fchown(output.fileno(), owner.pw_uid, owner.pw_gid)
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.rename(temporary, filename, src_dir_fd=spool, dst_dir_fd=spool)
        os.fsync(spool)
    else:
        with os.fdopen(descriptor, 'rb') as existing:
            if not stat.S_ISREG(os.fstat(existing.fileno()).st_mode) or existing.read(32769) != content:
                raise RuntimeError('immutable spool conflict')
    state.pop('pending')
    save(state)


def auth_events(state):
    command = ['/usr/bin/journalctl', '--no-pager', '--output=json', '--output-fields=__CURSOR,__REALTIME_TIMESTAMP,_COMM,MESSAGE']
    command += ['--after-cursor', state['cursor']] if state.get('cursor') else ['--since', state['auth_since']]
    command += ['_COMM=sshd', '+', '_COMM=sshd-session']
    lines, partial = bounded_lines(command, 30)
    output = []
    next_cursor = state.get('cursor')
    for line in lines:
        record = json.loads(line)
        cursor = record.get('__CURSOR')
        if not isinstance(cursor, str) or len(cursor) > 4096:
            raise RuntimeError('journal cursor unavailable')
        message = record.get('MESSAGE', '')
        match = re.match(r'^(Failed (?:password|publickey)|Accepted (?:password|publickey)) for (?:invalid user )?(\S+) from (\S+) port \d+(?: |$)', message) if isinstance(message, str) else None
        if match:
            try:
                remote = ip(match[3])
                occurred = stamp(datetime.datetime.fromtimestamp(int(record['__REALTIME_TIMESTAMP']) / 1000000, UTC))
                if remote and len(match[2]) <= 128:
                    output.append(event('AUTH_FAILURE' if match[1].startswith('Failed') else 'AUTH_SUCCESS', dict(source='linux-journal-sshd', service='SSH', sourceIp=remote, account=match[2]), occurred, 'journal:' + hashlib.sha256(cursor.encode()).hexdigest()))
            except (ValueError, KeyError, OverflowError):
                pass
        next_cursor = cursor
    if next_cursor:
        state['cursor'] = next_cursor
    return output, partial


def network_events(state):
    day = (datetime.datetime.now(UTC) + datetime.timedelta(minutes=330)).date().isoformat()
    if state.get('connection_day') != day:
        state['connections'] = []
        state['connection_day'] = day
    lines, partial = bounded_lines(['/usr/bin/ss', '-Htn', 'state', 'established'], 500)
    current = set()
    output = []
    for line in lines:
        fields = line.split()
        if len(fields) < 4:
            continue
        try:
            local, local_port = fields[-2].rsplit(':', 1)
            remote, remote_port = fields[-1].rsplit(':', 1)
            remote = ip(remote.strip('[]'))
            if not remote or not 0 <= int(local_port) <= 65535 or not 0 <= int(remote_port) <= 65535:
                continue
            identity = f'{local}:{local_port}:{remote}:{remote_port}'
            if identity not in state.get('connections', []) and len(output) >= 20:
                partial = True
                continue
            current.add(identity)
            if identity not in state.get('connections', []) and len(output) < 20:
                output.append(event('NETWORK_CONNECTION', dict(source='linux-ss-snapshot', peerIp=remote, direction='UNKNOWN', transport='TCP', localPort=local_port, peerPort=remote_port)))
        except ValueError:
            continue
    state['connections'] = sorted(current)
    return output, partial


def main():
    if os.geteuid() != 0:
        raise RuntimeError('dedicated metadata collector requires reviewed root service')
    owner = pwd.getpwnam('cybershield360-agent')
    info = os.lstat(SPOOL)
    if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077 or info.st_uid != owner.pw_uid:
        raise RuntimeError('private spool permissions')
    spool = os.open(SPOOL, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    if os.path.exists(STATE):
        if os.path.islink(STATE) or os.stat(STATE).st_size > 262144:
            raise RuntimeError('invalid collector state')
        with open(STATE, encoding='utf-8') as source:
            state = json.load(source)
    else:
        today = datetime.datetime.now(UTC).astimezone(datetime.timezone(datetime.timedelta(minutes=330))).replace(hour=0, minute=0, second=0, microsecond=0)
        state = dict(auth_since=today.astimezone(UTC).strftime('%Y-%m-%d %H:%M:%S UTC'))
    publish(state, spool, owner)
    started = stamp()
    selector = selectors.DefaultSelector()
    for family, protocol in [(socket.AF_INET, socket.IPPROTO_ICMP), (socket.AF_INET6, socket.IPPROTO_ICMPV6)]:
        try:
            listener = socket.socket(family, socket.SOCK_RAW, protocol)
            listener.setblocking(False)
            selector.register(listener, selectors.EVENT_READ, family)
        except OSError:
            pass
    counts = {}
    next_flush = time.monotonic()
    while True:
        for key, _ in selector.select(max(0, min(1, next_flush - time.monotonic()))):
            packet, address = key.fileobj.recvfrom(80)
            offset = (packet[0] & 15) * 4 if key.data == socket.AF_INET and packet else 0
            expected = 8 if key.data == socket.AF_INET else 128
            if len(packet) > offset and packet[offset] == expected:
                remote = ip(address[0])
                if remote and (remote, key.data) not in counts and len(counts) >= 1024:
                    continue
                if remote:
                    counts[(remote, key.data)] = min(999999999, counts.get((remote, key.data), 0) + 1)
        if time.monotonic() < next_flush:
            continue
        next_flush = time.monotonic() + 30
        if len(os.listdir(spool)) >= 120:
            print('Metadata spool backpressure; journal cursor retained.', flush=True)
            continue
        publish(state, spool, owner)
        events = []
        for collector, function in [('AUTH', auth_events), ('NETWORK', network_events)]:
            try:
                produced, partial = function(state)
                events.extend(produced)
                status = 'BACKFILLING' if partial else 'RUNNING'
            except (OSError, ValueError, RuntimeError):
                status = 'ERROR'
            coverage_from = state['auth_since'].replace(' UTC', '').replace(' ', 'T') + '.000Z' if collector == 'AUTH' else started
            events.append(event('TELEMETRY_STATUS', dict(source='linux-activity-collector', collector=collector, collectorState=status, coverageFrom=coverage_from, coverageThrough=stamp(), message='Available journal only; retention may have gaps.' if collector == 'AUTH' else 'Periodic TCP snapshots; short-lived flows may be missed.')))
        for remote, family in list(counts)[:10]:
            events.append(event('ICMP_ECHO', dict(source='linux-icmp-echo-metadata', peerIp=remote, direction='INBOUND', transport='ICMP' if family == socket.AF_INET else 'ICMPV6', requestCount=str(counts.pop((remote, family))))))
        events.append(event('TELEMETRY_STATUS', dict(source='linux-activity-collector', collector='ICMP', collectorState='RUNNING' if len(selector.get_map()) == 2 else 'BACKFILLING' if selector.get_map() else 'ERROR', coverageFrom=started, coverageThrough=stamp(), message=f'{len(selector.get_map())}/2 IP-family listeners. Kernel-delivered echo requests; loopback excluded. No payloads saved. Restart/overload gaps possible.')))
        state['pending'] = dict(file=f'{time.time_ns()}-{uuid.uuid4().hex}.jsonl', events=events)
        save(state)
        publish(state, spool, owner)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Metadata collector stopped: ' + type(error).__name__, flush=True)
        raise SystemExit(1)
