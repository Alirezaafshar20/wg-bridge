#!/usr/bin/env python3
"""A small, self-hosted two-hop WireGuard manager. Python standard library only."""
import argparse
import base64
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

VERSION = '0.3.0'
MODE = 'port-forward-v1'
DEFAULT_SERVICE_PORT = '8443'
AUTHOR = 'alirezaw'
GITHUB_URL = 'https://github.com/itsalirezaw'
YOUTUBE_URL = 'https://www.youtube.com/@ialirezaw'
STATE = Path('/etc/wg-bridge')
WG = Path('/etc/wireguard')
APP = Path('/usr/local/lib/wg-bridge/wg_bridge.py')
LAUNCHER = Path('/usr/local/sbin/wg-bridge')
UNIT = Path('/etc/systemd/system/wg-bridge-network.service')
LINK = 'wgb-exit'
V4_LINK = '10.204.0.0/30'
ENTRY_IP = '10.204.0.2'
EXIT_IP = '10.204.0.1'


class BridgeError(Exception):
    pass


def run(args, data=None, check=True):
    p = subprocess.run([str(x) for x in args], input=data, text=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and p.returncode:
        # Never print arguments, input, or stderr: they may contain keys.
        raise BridgeError(f'{Path(str(args[0])).name} failed (exit {p.returncode}). Run wg-bridge doctor.')
    return p.stdout.strip() if check else p


def save(path, content, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(prefix='.'+path.name, dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'w') as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        d = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(d)
        finally:
            os.close(d)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def load():
    try:
        return normalize_state(json.loads((STATE/'state.json').read_text()))
    except FileNotFoundError:
        raise BridgeError('Not installed. Run the installer first.') from None


def normalize_state(s):
    s = dict(s)
    if s.get('mode') != MODE:
        raise BridgeError('Legacy full-routing installation. Uninstall with the old manager, then install v0.3 on both hosts; Outside first.')
    if s.get('role') not in ('entry', 'exit'):
        raise BridgeError('Unknown installation role; refusing to alter networking.')
    s['protocol'] = valid_protocol(s['protocol'])
    s['target_port'] = valid_port(s['target_port'])
    s['port'] = valid_port(s['port'])
    if s['role'] == 'entry':
        s['listen_port'] = valid_port(s['listen_port'])
        s['exit_ip'] = valid_ip(s['exit_ip'])
        s['exit_port'] = valid_port(s['exit_port'])
    return s


def role_label(s):
    return 'Server (Iran / entry)' if s['role'] == 'entry' else 'Client (Outside / exit)'


def persist(s):
    save(STATE/'state.json', json.dumps(s, indent=2)+'\n')


def valid_key(value):
    if not isinstance(value, str):
        raise BridgeError('Invalid pairing key.')
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError:
        raise BridgeError('Invalid pairing key.') from None
    if len(decoded) != 32 or len(value) != 44:
        raise BridgeError('Invalid pairing key.')
    return value


def valid_port(value):
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise BridgeError('Port must be a number from 1 to 65535.')
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise BridgeError('Port must be a number from 1 to 65535.') from None
    if not 1 <= port <= 65535:
        raise BridgeError('Port must be a number from 1 to 65535.')
    return port


def valid_ip(value):
    if not isinstance(value, str):
        raise BridgeError('Enter a public IPv4 address, without a port.')
    try:
        addr = ipaddress.IPv4Address(value)
    except (ValueError, TypeError):
        raise BridgeError('Enter a public IPv4 address, without a port.') from None
    if not addr.is_global or addr.is_multicast:
        raise BridgeError('A public IPv4 address is required.')
    return str(addr)


def valid_protocol(value):
    if value not in ('tcp', 'udp', 'both'):
        raise BridgeError('Protocol must be tcp, udp or both.')
    return value


def protocols(s):
    return ('tcp', 'udp') if s['protocol'] == 'both' else (s['protocol'],)


def pairing_encode(payload):
    raw = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
    return 'WGB2.'+base64.urlsafe_b64encode(raw).decode().rstrip('=')+'.'+hashlib.sha256(raw).hexdigest()[:16]


def pairing_decode(code):
    if len(code) > 4096:
        raise BridgeError('Pairing code is too long.')
    if code.strip().startswith('WGB1.'):
        raise BridgeError('WGB1 is the old full-routing mode. Reinstall Outside with v0.3 and use its new WGB2 code.')
    try:
        prefix, encoded, checksum = code.strip().split('.')
        raw = base64.b64decode(encoded+'='*(-len(encoded) % 4), altchars=b'-_', validate=True)
        p = json.loads(raw)
        expected = {'version', 'server_ip', 'server_port', 'server_public', 'client_private', 'psk', 'target_port', 'protocol'}
        if prefix != 'WGB2' or hashlib.sha256(raw).hexdigest()[:16] != checksum:
            raise ValueError()
        if not isinstance(p, dict) or set(p) != expected or type(p['version']) is not int or p['version'] != 2:
            raise ValueError()
        p['server_ip'] = valid_ip(p['server_ip'])
        for field in ['server_port', 'target_port']:
            p[field] = valid_port(p[field])
        p['protocol'] = valid_protocol(p['protocol'])
        for k in ['server_public', 'client_private', 'psk']:
            valid_key(p[k])
        return p
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise BridgeError('Invalid or incomplete pairing code. Copy it again from the outside server.') from None


def keypair():
    private = run(['wg', 'genkey'])
    return private, run(['wg', 'pubkey'], private+'\n')


def prompt(label, default=''):
    suffix = f' [{default}]' if default else ''
    return input(label+suffix+': ').strip() or default


def styled(text, color='36'):
    if sys.stdout.isatty() and os.environ.get('TERM', '') not in ('', 'dumb') and 'NO_COLOR' not in os.environ:
        return '\033['+color+'m'+text+'\033[0m'
    return text


def heading(section, subtitle=''):
    width = max(24, min(72, shutil.get_terminal_size((76, 24)).columns-4))
    rule = '  '+'-'*width
    print('\n'+styled(rule))
    print(styled('  WG BRIDGE', '1;36')+'  /  v'+VERSION)
    print('  One port. Two servers. WireGuard transport.')
    print(styled(rule))
    print('  Built by '+AUTHOR)
    print('  GitHub   '+GITHUB_URL)
    if YOUTUBE_URL:
        print('  YouTube  '+YOUTUBE_URL)
    print(styled(rule))
    print('\n  '+styled(section.upper(), '1'))
    if subtitle:
        print('  '+subtitle)
    print()


def menu_option(number, label, detail='', color='36'):
    print('  '+styled('['+number+']', color)+'  '+label)
    if detail:
        print('       '+detail)


def detect_ip():
    # No telemetry or credentials are sent; only an HTTPS request for the source IP.
    p = run(['curl', '-4', '-fsS', '--connect-timeout', '3', '--max-time', '5', 'https://api.ipify.org'], check=False)
    if p.returncode == 0:
        with contextlib.suppress(BridgeError):
            return valid_ip(p.stdout.strip())
    return ''


def default_device():
    routes = json.loads(run(['ip', '-j', '-4', 'route', 'show', 'default']))
    if not routes:
        raise BridgeError('No IPv4 default route found.')
    device = sorted(routes, key=lambda r: r.get('metric', 0))[0]['dev']
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', device):
        raise BridgeError('Unsupported network interface name.')
    return device


def free_port(port, protocol):
    kind = socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM
    with socket.socket(socket.AF_INET, kind) as sock:
        try:
            sock.bind(('0.0.0.0', port))
        except OSError:
            raise BridgeError(f'{protocol.upper()} port {port} is already in use. Choose another port.') from None


def conflicts(s):
    for name in [LINK, 'wgb-block']:
        if (WG/(name+'.conf')).exists() or run(['ip', 'link', 'show', name], check=False).returncode == 0:
            raise BridgeError(f'{name} already exists; refusing to replace it.')
    for route in json.loads(run(['ip', '-j', '-4', 'route', 'show', 'table', 'all'])):
        dst = route.get('dst', 'default')
        if dst in ['default', 'all']: continue
        with contextlib.suppress(ValueError):
            if ipaddress.ip_network(dst, strict=False).overlaps(ipaddress.ip_network(V4_LINK)):
                raise BridgeError(f'Address conflict with {dst}. Resolve the overlap before installing.')
    # Custom policy routing can redirect the private peer or UDP transport.
    if any(r.get('priority') not in [0, 32766, 32767] for r in json.loads(run(['ip', '-j', '-4', 'rule']))):
        raise BridgeError('Existing IPv4 policy routing requires manual integration.')
    free_port(s['port'], 'udp')
    if s['role'] == 'entry':
        check_listener(s)
    for table, _, chain in CHAINS:
        if run(['iptables', '-w', '-t', table, '-S', chain], check=False).returncode == 0:
            raise BridgeError('Existing WGB firewall chains found; investigate before installing.')
    if UNIT.exists() or Path('/etc/systemd/system/wg-quick@wgb-exit.service.d/wg-bridge.conf').exists():
        raise BridgeError('Existing WG Bridge systemd files found; investigate before installing.')


def check_listener(s):
    if 'udp' in protocols(s) and s['listen_port'] == s['port']:
        raise BridgeError('The forwarded UDP port must differ from the WireGuard transport port.')
    for protocol in protocols(s):
        free_port(s['listen_port'], protocol)


def link_config(s):
    outside = s['role'] == 'exit'
    local, peer = (EXIT_IP, ENTRY_IP) if outside else (ENTRY_IP, EXIT_IP)
    text = f'[Interface]\nPrivateKey = {s["link_private"]}\nAddress = {local}/30\nMTU = 1380\n'
    text += f'ListenPort = {s["port"]}\nTable = off\n'
    text += f'\n[Peer]\nPublicKey = {s["peer_public"]}\nPresharedKey = {s["psk"]}\nAllowedIPs = {peer}/32\n'
    if not outside:
        text += f'Endpoint = {s["exit_ip"]}:{s["exit_port"]}\nPersistentKeepalive = 25\n'
    return text


CHAINS = [('filter', 'INPUT', 'WGB_IN'), ('filter', 'FORWARD', 'WGB_FWD'),
          ('nat', 'PREROUTING', 'WGB_DNAT'), ('nat', 'POSTROUTING', 'WGB_NAT'),
          ('mangle', 'FORWARD', 'WGB_MSS')]


def firewall_rules(s):
    rules = []
    def add(chain, args, table='filter'):
        rules.append((table, chain, args.split()))
    outside = s['role'] == 'exit'
    local, peer = (EXIT_IP, ENTRY_IP) if outside else (ENTRY_IP, EXIT_IP)
    remote = '' if outside else f'-s {s["exit_ip"]} --sport {s["exit_port"]} '
    add('WGB_IN', f'-i {s["wan"]} -p udp {remote}--dport {s["port"]} -j ACCEPT')
    add('WGB_IN', f'-i {LINK} -s {peer} -d {local} -p icmp -j ACCEPT')
    if outside:
        for proto in protocols(s):
            add('WGB_IN', f'-i {LINK} -s {peer} -d {local} -p {proto} --dport {s["target_port"]} -j ACCEPT')
    else:
        add('WGB_IN', f'-i {LINK} -s {peer} -d {local} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT')
        add('WGB_FWD', f'-i {LINK} -o {s["wan"]} -s {peer} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT')
        for proto in protocols(s):
            destination = f'-p {proto} -d {peer} --dport {s["target_port"]}'
            tracked = f'-m conntrack --ctstate DNAT --ctorigdstport {s["listen_port"]}'
            add('WGB_DNAT', f'-i {s["wan"]} -p {proto} --dport {s["listen_port"]} -m addrtype --dst-type LOCAL -j DNAT --to-destination {peer}:{s["target_port"]}', 'nat')
            add('WGB_FWD', f'-i {s["wan"]} -o {LINK} {destination} {tracked} -j ACCEPT')
            # When wg-quick is stopped, the private connected route disappears.
            # Reject this mapping before it can follow the host's WAN default.
            add('WGB_FWD', f'-i {s["wan"]} {destination} {tracked} -j REJECT')
            add('WGB_NAT', f'-o {LINK} {destination} {tracked} -j SNAT --to-source {local}', 'nat')
    add('WGB_IN', f'-i {LINK} -j REJECT')
    add('WGB_FWD', f'-i {LINK} -j REJECT')
    add('WGB_FWD', f'-o {LINK} -j REJECT')
    add('WGB_MSS', f'-o {LINK} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu', 'mangle')
    return rules


def network(s, up):
    if s.get('mode') != MODE:
        raise BridgeError('Full-routing state is not supported. Uninstall the old version before installing v0.3.')
    if up:
        for table, _, chain in CHAINS:
            run(['iptables', '-w', '-t', table, '-N', chain], check=False)
        for table, chain, args in firewall_rules(s):
            if run(['iptables', '-w', '-t', table, '-C', chain]+args, check=False).returncode:
                run(['iptables', '-w', '-t', table, '-A', chain]+args)
        # Attach DNAT last, once the narrow forwarding and fallback guards exist.
        for table, parent, chain in sorted(CHAINS, key=lambda x: x[2] == 'WGB_DNAT'):
            if run(['iptables', '-w', '-t', table, '-C', parent, '-j', chain], check=False).returncode:
                run(['iptables', '-w', '-t', table, '-I', parent, '1', '-j', chain])
        if s['role'] == 'entry':
            run(['sysctl', '-w', 'net.ipv4.ip_forward=1'])
    else:
        for table, parent, chain in sorted(CHAINS, key=lambda x: x[2] != 'WGB_DNAT'):
            while run(['iptables', '-w', '-t', table, '-C', parent, '-j', chain], check=False).returncode == 0:
                run(['iptables', '-w', '-t', table, '-D', parent, '-j', chain])
            run(['iptables', '-w', '-t', table, '-F', chain], check=False)
            run(['iptables', '-w', '-t', table, '-X', chain], check=False)


def services(s):
    names = [LINK]
    save(UNIT, f'''[Unit]
Description=WG Bridge forwarding and firewall
Wants=network-online.target
After=network-online.target ufw.service firewalld.service docker.service
Before={' '.join('wg-quick@'+n+'.service' for n in names)}

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/python3 {APP} _network up
ExecStop=/usr/bin/python3 {APP} _network down

[Install]
WantedBy=multi-user.target
''', 0o644)
    for name in names:
        save(Path('/etc/systemd/system')/f'wg-quick@{name}.service.d/wg-bridge.conf', '''[Unit]
Requires=wg-bridge-network.service
After=wg-bridge-network.service
''', 0o644)
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', '--now', 'wg-bridge-network.service'])
    for name in names:
        run(['systemctl', 'enable', '--now', 'wg-quick@'+name])


def preflight():
    if os.geteuid() != 0:
        raise BridgeError('Run with sudo or as root.')
    if not Path('/run/systemd/system').is_dir():
        raise BridgeError('A systemd VPS/VM is required; ordinary Docker/OpenVZ containers are not supported.')
    if run(['systemctl', 'is-active', 'firewalld'], check=False).returncode == 0:
        raise BridgeError('firewalld is active. This release supports iptables/UFW hosts, not firewalld.')
    for cmd in ['wg', 'wg-quick', 'ip', 'iptables', 'sysctl', 'curl']:
        if shutil.which(cmd) is None:
            raise BridgeError('Missing dependency: '+cmd+'. Re-run install.sh.')
    run(['modprobe', 'wireguard'])
    run(['iptables', '-w', '-t', 'nat', '-S'])


def install():
    preflight()
    if (STATE/'state.json').exists():
        print('Existing installation detected. Keeping tunnel keys and settings.')
        return menu()
    if STATE.exists() and any(STATE.iterdir()):
        raise BridgeError('/etc/wg-bridge contains an incomplete install. Inspect it before retrying.')
    heading('Installation', 'Set up Client (Outside) first, then Server (Iran).')
    menu_option('1', 'Server (Iran / entry)', 'Forwards one chosen IPv4 port to the outside service.')
    print()
    menu_option('2', 'Client (Outside / exit)', 'Runs the destination service; generates the pairing code.')
    print()
    menu_option('0', 'Exit')
    print()
    role = prompt('  Select [1/2/0]')
    if role == '0':
        return
    if role not in ['1', '2']:
        raise BridgeError('Choose 1 or 2.')
    s = {'version': VERSION, 'mode': MODE, 'role': 'entry' if role == '1' else 'exit'}
    if s['role'] == 'entry':
        print('Initialize Client (Outside) first to obtain its pairing code.')
        # Hidden input prevents the pairing secret being copied into a screen recording.
        import getpass
        pairing = pairing_decode(getpass.getpass('Client (Outside) pairing code (hidden): '))
        s.update({'exit_ip': pairing['server_ip'], 'exit_port': pairing['server_port'],
                  'link_private': pairing['client_private'], 'peer_public': pairing['server_public'],
                  'psk': pairing['psk'], 'target_port': pairing['target_port'], 'protocol': pairing['protocol']})
    s['public_ip'] = valid_ip(prompt('This server PUBLIC IPv4', detect_ip()))
    label = 'UDP port (open it in the outside provider firewall)' if s['role'] == 'exit' else 'Local WireGuard UDP port'
    s['port'] = valid_port(prompt(label, '51830' if s['role'] == 'exit' else '51831'))
    s['wan'] = default_device()
    if s['role'] == 'exit':
        s['target_port'] = valid_port(prompt('Service port on Outside', DEFAULT_SERVICE_PORT))
        s['protocol'] = valid_protocol(prompt('Forward protocol: tcp / udp / both', 'both').lower())
        if 'udp' in protocols(s) and s['target_port'] == s['port']:
            raise BridgeError('The service UDP port must differ from the WireGuard transport port.')
    else:
        s['listen_port'] = valid_port(prompt('Public port on Iran to forward', str(s['target_port'])))
    conflicts(s)
    if s['role'] == 'exit':
        s['link_private'], server_public = keypair()
        client_private, s['peer_public'] = keypair()
        s['psk'] = run(['wg', 'genpsk'])
        s['pairing'] = pairing_encode({'version': 2, 'server_ip': s['public_ip'], 'server_port': s['port'],
                                      'server_public': server_public, 'client_private': client_private,
                                      'psk': s['psk'], 'target_port': s['target_port'], 'protocol': s['protocol']})
    keys = ['net.ipv4.ip_forward'] if s['role'] == 'entry' else []
    s['sysctl_before'] = {k: run(['sysctl', '-n', k]) for k in keys}
    STATE.mkdir(mode=0o700, exist_ok=True)
    os.chmod(STATE, 0o700)
    persist(s)
    try:
        save(WG/(LINK+'.conf'), link_config(s))
        services(s)
    except (Exception, KeyboardInterrupt):
        print('Installation failed. Rolling back WG Bridge network changes.')
        uninstall(s, confirm=False, purge=False)
        raise
    print('\nInstalled. Run: sudo wg-bridge')
    print('Host Internet routes are unchanged. Only the selected IPv4 port is forwarded.')
    if s['role'] == 'exit':
        print('\nPairing code: SECRET. Hide this part when recording a video. Use on ONE Iran server only.\n')
        print(s['pairing'])
        print('\nNow run the installer on Iran and choose 1) Server. Later: sudo wg-bridge status')
    else:
        if not doctor(s):
            print('Installed but NOT connected. Fix the reported issue, then run: sudo wg-bridge doctor')


def mapping(s):
    if s['role'] == 'entry':
        return f'{s["public_ip"]}:{s["listen_port"]} -> {EXIT_IP}:{s["target_port"]} ({s["protocol"]})'
    return f'Outside service: {EXIT_IP}:{s["target_port"]} ({s["protocol"]})'


def status(s):
    os.environ['WG_HIDE_KEYS'] = 'always'
    print('WG Bridge '+VERSION+' | '+role_label(s))
    print(mapping(s))
    result = run(['wg', 'show', LINK], check=False)
    print(result.stdout if result.returncode == 0 else LINK+': DOWN')
    print('Host Internet routes and IPv6 are unchanged.')


def doctor(s):
    print('\nChecking services and WireGuard connectivity...')
    for unit in ['wg-bridge-network', 'wg-quick@'+LINK]:
        if run(['systemctl', 'is-active', unit], check=False).returncode:
            print(unit+': NOT ACTIVE. Start the tunnel from the menu; inspect journalctl -u '+unit)
            return False
    print(mapping(s))
    if s['role'] == 'exit':
        print(f'The destination application must listen on 0.0.0.0:{s["target_port"]} or {EXIT_IP}:{s["target_port"]}.')
        print('Allow WireGuard UDP '+str(s['port'])+' in the outside provider firewall.')
        return True
    run(['ping', '-c', '1', '-W', '2', '-I', ENTRY_IP, EXIT_IP], check=False)
    for _ in range(10):
        result = run(['wg', 'show', LINK, 'latest-handshakes'], check=False)
        if result.returncode == 0 and any(int(line.split()[1]) > time.time()-180 for line in result.stdout.splitlines() if len(line.split()) == 2):
            break
        time.sleep(1)
    else:
        print('NO HANDSHAKE: verify the pairing code, outside IP, UDP '+str(s['exit_port'])+', and network filtering.')
        print('Only the selected forwarded port is unavailable; host Internet routes are unchanged.')
        return False
    print('WireGuard handshake: OK')
    if 'tcp' in protocols(s):
        try:
            with socket.create_connection((EXIT_IP, s['target_port']), timeout=4): pass
        except OSError:
            print('TCP destination is not accepting connections. Start the application on Outside or check its bind address/firewall.')
            return False
        print('TCP destination: reachable')
    if 'udp' in protocols(s):
        print('Test UDP with the destination application; a handshake alone does not verify the UDP service.')
    print('Test the public forwarded port from a third host. Local Iran connections are not redirected.')
    return True


def uninstall(s, confirm=True, purge=True):
    if confirm and prompt('Type REMOVE to uninstall WG Bridge and delete its keys') != 'REMOVE':
        print('Cancelled.')
        return
    names = [LINK]
    for name in names:
        run(['systemctl', 'disable', '--now', 'wg-quick@'+name], check=False)
        if run(['ip', 'link', 'show', name], check=False).returncode == 0:
            raise BridgeError('Interface still active; refusing to remove its configuration.')
    run(['systemctl', 'disable', '--now', 'wg-bridge-network.service'], check=False)
    network(s, False)
    # Restore only a knob whose current value is still the value we set.
    for k, value in s.get('sysctl_before', {}).items():
        expected = '1'
        if run(['sysctl', '-n', k]) == expected:
            run(['sysctl', '-w', k+'='+value])
    for name in names:
        (WG/(name+'.conf')).unlink(missing_ok=True)
        dropin = Path('/etc/systemd/system')/f'wg-quick@{name}.service.d/wg-bridge.conf'
        dropin.unlink(missing_ok=True)
        with contextlib.suppress(OSError): dropin.parent.rmdir()
    UNIT.unlink(missing_ok=True)
    run(['systemctl', 'daemon-reload'])
    if STATE.resolve() != Path('/etc/wg-bridge') or STATE.is_symlink():
        raise BridgeError('Unexpected state path; refusing recursive removal.')
    shutil.rmtree(STATE)
    if purge:
        remove_program()
        print('WG Bridge removed. Shared distribution packages retained.')
    else:
        print('Tunnel configuration removed; manager retained.')


def remove_program():
    # Delete only the two files installed by this project; never recurse through
    # a shared executable directory or an unexpected application directory.
    if APP.parent.resolve() != Path('/usr/local/lib/wg-bridge') or APP.parent.is_symlink():
        raise BridgeError('Unexpected application path; refusing program removal.')
    APP.unlink(missing_ok=True)
    LAUNCHER.unlink(missing_ok=True)
    with contextlib.suppress(OSError):
        APP.parent.rmdir()


def change_port(s, value=None):
    if s['role'] != 'entry':
        raise BridgeError('Change the public forwarding port on Server (Iran).')
    updated = dict(s, listen_port=valid_port(value or prompt('New public port on Iran', str(s['listen_port']))))
    if updated['listen_port'] == s['listen_port']:
        print('Port unchanged.')
        return
    check_listener(updated)
    # Network rules persist even when WireGuard is stopped; keep that guard.
    try:
        network(s, False)
        persist(updated)
        network(updated, True)
    except (Exception, KeyboardInterrupt):
        network(updated, False)
        persist(s)
        network(s, True)
        raise
    print('Updated: '+mapping(updated))


def menu():
    s = load()
    heading('Tunnel management', role_label(s)+' | '+mapping(s))
    menu_option('1', 'Status')
    menu_option('2', 'Diagnose connectivity')
    print()
    menu_option('3', 'Restart tunnel')
    menu_option('4', 'Show pairing code', 'Available on Client (Outside); keep this code private.')
    menu_option('5', 'Stop tunnel', 'Only the forwarded port stops; other services keep their routes.')
    menu_option('6', 'Start tunnel')
    print()
    menu_option('7', 'Uninstall completely', 'Remove WG Bridge, its tunnel configuration and keys.', '31')
    if s['role'] == 'entry':
        menu_option('8', 'Change public forwarding port', 'The outside service port and tunnel keys stay the same.')
    menu_option('0', 'Exit')
    print()
    choice = prompt('  Select')
    if choice == '1': status(s)
    elif choice == '2': doctor(s)
    elif choice in ['3', '6']:
        run(['systemctl', 'start', 'wg-bridge-network.service'])
        network(s, True)
        run(['systemctl', 'restart' if choice == '3' else 'start', 'wg-quick@'+LINK])
        doctor(s)
    elif choice == '4':
        if s['role'] != 'exit': raise BridgeError('Run this on Client (Outside).')
        print('SECRET: '+s['pairing'])
    elif choice == '5':
        run(['systemctl', 'stop', 'wg-quick@'+LINK])
        print('Tunnel stopped. Run wg-bridge and choose Start to resume.')
    elif choice == '7': uninstall(s)
    elif choice == '8': change_port(s)
    elif choice != '0': raise BridgeError('Unknown menu option.')


def main():
    parser = argparse.ArgumentParser(description='WG Bridge: Server (Iran / entry) and Client (Outside / exit)')
    parser.add_argument('command', nargs='?', default='menu', choices=['menu','install','status','doctor','uninstall','port','_network','version'])
    parser.add_argument('argument', nargs='?')
    args = parser.parse_args()
    if args.command == 'version':
        print(VERSION)
        return
    if os.geteuid() != 0:
        raise BridgeError('Run with sudo or as root.')
    os.umask(0o077)
    if args.command == '_network':
        if args.argument not in ['up','down']: raise BridgeError('Invalid internal operation.')
        network(load(), args.argument == 'up')
        return
    # Internal systemd operations do not take this lock; install waits for systemd.
    with open('/run/lock/wg-bridge.lock','w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise BridgeError('Another WG Bridge operation is running.') from None
        if args.command == 'install': install()
        elif args.command == 'menu': menu()
        else:
            s=load()
            if args.command == 'status': status(s)
            elif args.command == 'doctor':
                if not doctor(s): sys.exit(2)
            elif args.command == 'uninstall': uninstall(s)
            elif args.command == 'port': change_port(s, args.argument)


if __name__ == '__main__':
    try:
        main()
    except (BridgeError, KeyboardInterrupt, EOFError) as exc:
        print('\nERROR: '+(str(exc) or 'Cancelled.'), file=sys.stderr)
        sys.exit(1)
