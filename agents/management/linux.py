#!/usr/bin/python3
"""Opt-in, fixed-operation host helper. No remote shell or command-line execution."""
import datetime
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

DIRECTORY = Path('/var/lib/cybershield360-management')
CONFIG = Path('/etc/cybershield360/management.json')


def run(args, data=None):
    # All executables/verbs are fixed; target names are passed as individual argv entries.
    result = subprocess.run(args, input=data, text=True, capture_output=True, timeout=15, check=True)
    if len(result.stdout) > 2_000_000:
        raise ValueError('Inventory output too large')
    return result.stdout


def private(path):
    info = path.lstat()
    if path.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('Management configuration must be root-owned and not writable by other users')


def config():
    private(CONFIG.parent)
    private(CONFIG)
    return json.loads(CONFIG.read_text())


def save(rules):
    temporary = DIRECTORY / 'rules.tmp'
    with open(temporary, 'w', encoding='utf8') as output:
        os.chmod(temporary, 0o600)
        json.dump(rules, output)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, DIRECTORY / 'rules.json')


def table(rule):
    return 'sg_' + uuid.UUID(rule['id']).hex


def validate_rule(rule, settings):
    address = ipaddress.ip_address(rule['ip'])
    address = getattr(address, 'ipv4_mapped', None) or address
    if address.is_loopback or address.is_unspecified or address.is_multicast:
        raise ValueError('Loopback, unspecified and multicast addresses cannot be blocked')
    for protected in settings.get('protectedAddresses', []):
        if address in ipaddress.ip_network(protected, strict=False):
            raise ValueError('Address is protected by the host administrator')
    ports = rule['ports']
    if rule['scope'] not in ('LOGIN', 'TCP') or len(ports) > 16 or any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
        raise ValueError('Invalid TCP scope or ports')
    if rule['scope'] == 'LOGIN' and not ports:
        raise ValueError('Login requires explicit ports')
    return address


def nft_apply(rule, settings):
    address = validate_rule(rule, settings)
    name = table(rule)
    # Own an isolated table, before NAT, covering inbound host and forwarded container traffic.
    family = 'ip' if address.version == 4 else 'ip6'
    ports = ' tcp dport { ' + ', '.join(str(p) for p in rule['ports']) + ' }' if rule['ports'] else ' meta l4proto tcp'
    script = f'add table inet {name}\nadd chain inet {name} inbound {{ type filter hook prerouting priority -310; policy accept; }}\nflush chain inet {name} inbound\nadd rule inet {name} inbound {family} saddr {address}{ports} counter drop\n'
    run(['/usr/sbin/nft', '-f', '-'], script)


def applications(settings):
    apps, errors = [], []
    allow = settings.get('stopAllowlist', [])
    try:
        services = json.loads(run(['/usr/bin/systemctl', 'list-units', '--type=service', '--all', '--no-pager', '--output=json']))
        units = [item['unit'] for item in services if re.fullmatch(r'[A-Za-z0-9_.@:-]+\.service', item['unit'])][:200]
        properties = run(['/usr/bin/systemctl', 'show', '--property=Id,ActiveEnterTimestampMonotonic,MainPID,FragmentPath,MemoryCurrent,SubState', '--', *units]) if units else ''
        lookup = {}
        for block in properties.strip().split('\n\n'):
            values = dict(line.split('=', 1) for line in block.splitlines() if '=' in line)
            lookup[values.get('Id')] = values
        if len(services) > 200:
            errors.append('Systemd inventory truncated at 200 services')
        for service in services[:200]:
            unit = service['unit']
            if not re.fullmatch(r'[A-Za-z0-9_.@:-]+\.service', unit):
                continue
            app_id = 'systemd:' + unit
            # Active-enter timestamp prevents a queued stop applying to a restarted instance.
            props = lookup.get(unit, {})
            apps.append(dict(id=app_id, kind='SYSTEMD', name=unit, state=service['active'], instance=props.get('ActiveEnterTimestampMonotonic', ''), details=(service.get('description', '') + ' · PID ' + props.get('MainPID', '?') + ' · Memory bytes ' + props.get('MemoryCurrent', '?') + ' · ' + props.get('FragmentPath', ''))[:500], stoppable=app_id in allow and service['active'] == 'active'))
    except (OSError, ValueError, subprocess.SubprocessError):
        errors.append('systemd inventory unavailable')
    if shutil.which('docker'):
        try:
            records = run(['docker', 'ps', '-a', '--no-trunc', '--format', '{{json .}}'])
            if len(records.splitlines()) > 200:
                errors.append('Docker inventory truncated at 200 containers')
            containers = [json.loads(line) for line in records.splitlines()[:200]]
            identities = {}
            if containers:
                observed = run(['docker', 'inspect', '--format', '{{.Id}} {{.State.StartedAt}}', *[item['ID'] for item in containers]])
                identities = dict(line.split(' ', 1) for line in observed.splitlines() if ' ' in line)
            for item in containers:
                app_id = 'docker:' + item['ID']
                apps.append(dict(id=app_id, kind='DOCKER', name=item['Names'], state=item['State'], instance=item['ID'] + ':' + identities.get(item['ID'], ''), details=(item['Image'] + ' · ' + item['Status'] + ' · ' + item['Ports'])[:500], stoppable=('docker:' + item['Names']) in allow and item['State'] == 'running'))
        except (OSError, ValueError, subprocess.SubprocessError):
            errors.append('Docker inventory unavailable')
    return sorted(apps, key=lambda app: (app['kind'], app['name'])), errors


def stop(app, settings):
    apps, _ = applications(settings)
    current = next((item for item in apps if item['id'] == app['id'] and item['instance'] == app['instance'] and item['stoppable']), None)
    if not current:
        raise ValueError('Application changed or stopping is not allowed on this host')
    if app['kind'] == 'SYSTEMD':
        run(['/usr/bin/systemctl', 'stop', '--', app['id'].split(':', 1)[1]])
    elif app['kind'] == 'DOCKER' and re.fullmatch(r'docker:[a-f0-9]{64}', app['id']):
        run(['docker', 'stop', '--time', '8', app['id'].split(':', 1)[1]])
    else:
        raise ValueError('Unsupported application type')
    latest, errors = applications(settings)
    source = 'systemd' if app['kind'] == 'SYSTEMD' else 'Docker'
    if any(source in error for error in errors):
        raise ValueError('Cannot verify application state after stop')
    if any(item['id'] == app['id'] and item['state'].lower() in ('active', 'running') for item in latest):
        raise ValueError('Application is still running or was restarted by its supervisor')


def handle(request):
    settings = config()
    DIRECTORY.mkdir(mode=0o700, exist_ok=True)
    private(DIRECTORY)
    rules_file = DIRECTORY / 'rules.json'
    rules = json.loads(rules_file.read_text()) if rules_file.exists() else []
    firewall = bool(settings.get('firewallEnabled', False)) and os.path.isfile('/usr/sbin/nft')
    operation = request['operation']
    if operation == 'INVENTORY':
        apps, errors = applications(settings)
        confirmed = []
        if firewall:
            for rule in rules:
                try:
                    nft_apply(rule, settings)
                    confirmed.append(rule)
                except (OSError, ValueError, subprocess.SubprocessError):
                    errors.append('Could not restore or verify an IP block')
                    firewall = False
        return dict(applications=apps[:200], rules=confirmed, firewall=firewall, errors=list(dict.fromkeys(errors))[:10], truncated=len(apps) > 200 or any('truncated' in error for error in errors))
    uuid.UUID(request['id'])
    if datetime.datetime.fromisoformat(request['expiresAt'].replace('Z', '+00:00')) <= datetime.datetime.now(datetime.timezone.utc):
        raise ValueError('Command expired')
    payload = request['payload']
    if operation == 'STOP_APPLICATION':
        stop(payload['application'], settings)
    elif operation == 'BLOCK_IP':
        if not firewall or len(rules) >= 200:
            raise ValueError('Firewall management unavailable or rule limit reached')
        validate_rule(payload, settings)
        nft_apply(payload, settings)
        rules = [rule for rule in rules if rule['id'] != payload['id']] + [payload]
        try:
            save(rules)
        except OSError:
            run(['/usr/sbin/nft', 'delete', 'table', 'inet', table(payload)])
            raise
    elif operation == 'UNBLOCK_IP':
        if not firewall or not any(rule['id'] == payload['id'] for rule in rules):
            raise ValueError('Managed block not found or firewall unavailable')
        run(['/usr/sbin/nft', 'delete', 'table', 'inet', table(payload)])
        try:
            save([rule for rule in rules if rule['id'] != payload['id']])
        except OSError:
            nft_apply(payload, settings)
            raise
    else:
        raise ValueError('Unsupported operation')
    return dict(id=request['id'], success=True, message='Host action completed and verified')


if __name__ == '__main__':
    request = {}
    try:
        if os.geteuid() != 0:
            raise ValueError('Management helper requires a dedicated privileged agent')
        request = json.loads(sys.stdin.read(16385))
        print(json.dumps(handle(request)))
    except Exception as error:
        if 'id' in request:
            print(json.dumps(dict(id=request['id'], success=False, message=str(error)[:500] if isinstance(error, ValueError) else 'Host action failed; inspect service permissions and host logs')))
        else:
            print(json.dumps(dict(applications=[], rules=[], firewall=False, errors=['Management helper failed; inspect host configuration and permissions'], truncated=False)))
