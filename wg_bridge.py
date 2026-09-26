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

VERSION = '0.2.2'
AUTHOR = 'alirezaw'
GITHUB_URL = 'https://github.com/itsalirezaw'
YOUTUBE_URL = 'https://www.youtube.com/@ialirezaw'
STATE = Path('/etc/wg-bridge')
WG = Path('/etc/wireguard')
APP = Path('/usr/local/lib/wg-bridge/wg_bridge.py')
LAUNCHER = Path('/usr/local/sbin/wg-bridge')
UNIT = Path('/etc/systemd/system/wg-bridge-network.service')
LINK = 'wgb-exit'
BLOCK = 'wgb-block'
TABLE = '52031'
PRIORITY = '12131'
V4_LINK = '10.204.0.0/30'
V6_LINK = 'fd42:204::/64'
NETS = ((4, V4_LINK), (6, V6_LINK))
BYPASS = '0x40000000/0x40000000'


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
    """v0.1 named transport roles; v0.2 persists unambiguous topology roles."""
    s = dict(s)
    s['role'] = {'server': 'exit', 'client': 'entry'}.get(s.get('role'), s.get('role'))
    if s['role'] not in ('entry', 'exit'):
        raise BridgeError('Unknown installation role; refusing to alter routing.')
    if 'server_ip' in s:
        s['exit_ip'] = s.pop('server_ip')
    if 'server_port' in s:
        s['exit_port'] = s.pop('server_port')
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


def pairing_encode(payload):
    raw = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
    return 'WGB1.'+base64.urlsafe_b64encode(raw).decode().rstrip('=')+'.'+hashlib.sha256(raw).hexdigest()[:16]


def pairing_decode(code):
    if len(code) > 4096:
        raise BridgeError('Pairing code is too long.')
    try:
        prefix, encoded, checksum = code.strip().split('.')
        raw = base64.b64decode(encoded+'='*(-len(encoded) % 4), altchars=b'-_', validate=True)
        p = json.loads(raw)
        expected = {'version', 'server_ip', 'server_port', 'server_public', 'client_private', 'psk', 'ipv6'}
        if prefix != 'WGB1' or hashlib.sha256(raw).hexdigest()[:16] != checksum:
            raise ValueError()
        if not isinstance(p, dict) or set(p) != expected or type(p['version']) is not int or p['version'] != 1 or type(p['ipv6']) is not bool:
            raise ValueError()
        p['server_ip'] = valid_ip(p['server_ip'])
        p['server_port'] = valid_port(p['server_port'])
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
    print('  Server-to-server WireGuard tunnel')
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


def conflicts(port):
    for name in [LINK, BLOCK]:
        if (WG/(name+'.conf')).exists() or run(['ip', 'link', 'show', name], check=False).returncode == 0:
            raise BridgeError(f'{name} already exists; refusing to replace it.')
    for version, link_net in NETS:
        wanted = [ipaddress.ip_network(link_net)]
        for route in json.loads(run(['ip', '-j', f'-{version}', 'route', 'show', 'table', 'all'])):
            dst = route.get('dst', 'default')
            if dst in ['default', 'all']:
                continue
            with contextlib.suppress(ValueError):
                if any(ipaddress.ip_network(dst, strict=False).overlaps(n) for n in wanted):
                    raise BridgeError(f'Address conflict with {dst}. Use a clean server or resolve the overlap first.')
        rules = json.loads(run(['ip', '-j', f'-{version}', 'rule']))
        if any(r.get('priority') not in [0, 32766, 32767] for r in rules):
            raise BridgeError('Existing policy routing detected. This release requires a host without another policy-routing VPN.')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.bind(('0.0.0.0', port))
        except OSError:
            raise BridgeError(f'UDP port {port} is already in use. Choose another port.') from None
    for tool in ['iptables', 'ip6tables']:
        for table, _, chain in CHAINS:
            if run([tool, '-w', '-t', table, '-S', chain], check=False).returncode == 0:
                raise BridgeError('Existing WGB firewall chains found; investigate before installing.')
    if UNIT.exists() or Path('/etc/systemd/system/wg-quick@wgb-exit.service.d/wg-bridge.conf').exists():
        raise BridgeError('Existing WG Bridge systemd files found; investigate before installing.')


def link_config(s):
    exit_peer = s['role'] == 'exit'
    address = '10.204.0.1/30, fd42:204::1/64' if exit_peer else '10.204.0.2/30, fd42:204::2/64'
    allowed = '10.204.0.2/32, fd42:204::2/128' if exit_peer else '0.0.0.0/0, ::/0'
    text = f'[Interface]\nPrivateKey = {s["link_private"]}\nAddress = {address}\nMTU = 1380\n'
    text += f'ListenPort = {s["port"]}\n'
    if not exit_peer:
        text += f'Table = {TABLE}\nFwMark = {TABLE}\n'
    text += f'\n[Peer]\nPublicKey = {s["peer_public"]}\nPresharedKey = {s["psk"]}\nAllowedIPs = {allowed}\n'
    if not exit_peer:
        text += f'Endpoint = {s["exit_ip"]}:{s["exit_port"]}\nPersistentKeepalive = 25\n'
    return text


def firewall_rules(s, version):
    linknet = V4_LINK if version == 4 else V6_LINK
    rules = []
    def add(chain, args, table='filter'):
        rules.append((table, chain, args.split()))
    if s['role'] == 'exit':
        if version == 4:
            add('WGB_IN', f'-p udp --dport {s["port"]} -j ACCEPT')
        if version == 4 or s['ipv6']:
            add('WGB_FWD', f'-i {LINK} -o {s["wan"]} -s {linknet} -j ACCEPT')
            add('WGB_FWD', f'-i {s["wan"]} -o {LINK} -d {linknet} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT')
            add('WGB_NAT', f'-s {linknet} -o {s["wan"]} -j MASQUERADE', 'nat')
        add('WGB_FWD', f'-i {LINK} -j REJECT')
        add('WGB_FWD', f'-o {LINK} -j REJECT')
    else:
        # OUTPUT's hook interface can still be the initial route's device after
        # mangle reroutes a marked reply. Exempt replies before testing -o.
        add('WGB_OUTPUT', f'-m mark --mark {BYPASS} -j RETURN')
        add('WGB_OUTPUT', f'-o {BLOCK} -j REJECT')
        add('WGB_FWD', f'-o {BLOCK} -j REJECT')
        # Remember connections initiated toward this host (SSH, panel, proxy clients).
        # A connmark is NOT a packet mark: outgoing proxy connections still use VPN.
        add('WGB_PRE', f'-i {s["wan"]} -m conntrack --ctdir ORIGINAL -j CONNMARK --set-xmark {BYPASS}', 'mangle')
        add('WGB_OUT', '-j CONNMARK --restore-mark --nfmask 0x40000000 --ctmask 0x40000000', 'mangle')
        # Replies to routed/SNATed connections need their original return route too.
        add('WGB_PRE', f'-i {LINK} -j CONNMARK --restore-mark --nfmask 0x40000000 --ctmask 0x40000000', 'mangle')
        if version == 4 or s['ipv6']:
            add('WGB_FWD', f'-o {LINK} -j ACCEPT')
            add('WGB_FWD', f'-i {LINK} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT')
            add('WGB_NAT', f'-o {LINK} -j MASQUERADE', 'nat')
        else:
            add('WGB_OUTPUT', f'-o {LINK} ! -d {V6_LINK} -j REJECT')
        add('WGB_FWD', f'-i {LINK} -j REJECT')
        add('WGB_FWD', f'-o {LINK} -j REJECT')
    add('WGB_MSS', f'-o {LINK} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu', 'mangle')
    return rules


CHAINS = [('filter', 'INPUT', 'WGB_IN'), ('filter', 'FORWARD', 'WGB_FWD'),
          ('filter', 'OUTPUT', 'WGB_OUTPUT'), ('nat', 'POSTROUTING', 'WGB_NAT'),
          ('mangle', 'FORWARD', 'WGB_MSS'), ('mangle', 'PREROUTING', 'WGB_PRE'),
          ('mangle', 'OUTPUT', 'WGB_OUT')]


def policy_rules(s, version):
    rules = [['priority', '12128', 'fwmark', BYPASS, 'table', 'main']]
    if s.get('ssh_peer') and ipaddress.ip_address(s['ssh_peer']).version == version:
        rules.insert(0, ['priority', '12127', 'to', s['ssh_peer']+('/32' if version == 4 else '/128'), 'table', 'main'])
    if version == 4:
        rules.append(['priority', '12129', 'to', s['exit_ip']+'/32', 'table', 'main'])
    rules.append(['priority', '12130', 'table', 'main', 'suppress_prefixlength', '0'])
    rules.append(['priority', PRIORITY, 'not', 'fwmark', TABLE, 'table', TABLE])
    return rules


def network(s, up):
    # An always-present sink route lets OUTPUT restore incoming connection marks
    # before routing their replies to WAN. An unreachable route would fail before
    # OUTPUT, breaking incoming SSH whenever the WG interface disappeared.
    if s['role'] == 'entry' and up:
        if run(['ip', 'link', 'show', BLOCK], check=False).returncode:
            run(['ip', 'link', 'add', BLOCK, 'type', 'dummy'])
        run(['ip', 'link', 'set', BLOCK, 'up'])
        for version in [4, 6]:
            run(['ip', f'-{version}', 'route', 'replace', 'default', 'dev', BLOCK, 'table', TABLE, 'metric', '32767'])
    for version in [4, 6]:
        tool = 'iptables' if version == 4 else 'ip6tables'
        if up:
            # Populate only our chains, then attach hooks. No global firewall flush.
            for table, parent, chain in CHAINS:
                run([tool, '-w', '-t', table, '-N', chain], check=False)
            for table, chain, args in firewall_rules(s, version):
                if run([tool, '-w', '-t', table, '-C', chain]+args, check=False).returncode:
                    run([tool, '-w', '-t', table, '-A', chain]+args)
            for table, parent, chain in CHAINS:
                if run([tool, '-w', '-t', table, '-C', parent, '-j', chain], check=False).returncode:
                    run([tool, '-w', '-t', table, '-I', parent, '1', '-j', chain])
        if s['role'] == 'entry':
            if up:
                # Preserve already-established inbound sessions before changing routing.
                for dev in json.loads(run(['ip', '-j', f'-{version}', 'addr', 'show', 'dev', s['wan']])):
                    for addr in dev.get('addr_info', []):
                        run(['conntrack', '-U', '-f', 'ipv4' if version == 4 else 'ipv6', '--orig-dst', addr['local'], '--mark', BYPASS], check=False)
            for rule in policy_rules(s, version):
                if not up:
                    run(['ip', f'-{version}', 'rule', 'del']+rule, check=False)
                elif not json.loads(run(['ip', '-j', f'-{version}', 'rule', 'show', 'priority', rule[1]])):
                    run(['ip', f'-{version}', 'rule', 'add']+rule)
            if not up:
                run(['ip', f'-{version}', 'route', 'del', 'default', 'dev', BLOCK, 'table', TABLE, 'metric', '32767'], check=False)
        if not up:
            for table, parent, chain in reversed(CHAINS):
                while run([tool, '-w', '-t', table, '-C', parent, '-j', chain], check=False).returncode == 0:
                    run([tool, '-w', '-t', table, '-D', parent, '-j', chain])
                run([tool, '-w', '-t', table, '-F', chain], check=False)
                run([tool, '-w', '-t', table, '-X', chain], check=False)
    if not up and s['role'] == 'entry':
        run(['ip', 'link', 'del', BLOCK], check=False)
    if up:
        # Preserve providers' SLAAC routes. Loose rp_filter accepts the VPN return path.
        run(['sysctl', '-w', f'net.ipv6.conf.{s["wan"]}.accept_ra=2'])
        run(['sysctl', '-w', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1', 'net.ipv4.conf.all.rp_filter=2'])


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
    for cmd in ['wg', 'wg-quick', 'ip', 'iptables', 'ip6tables', 'sysctl', 'conntrack', 'curl']:
        if shutil.which(cmd) is None:
            raise BridgeError('Missing dependency: '+cmd+'. Re-run install.sh.')
    run(['modprobe', 'wireguard'])
    for tool in ['iptables', 'ip6tables']:
        run([tool, '-w', '-t', 'nat', '-S'])


def install():
    preflight()
    if (STATE/'state.json').exists():
        print('Existing installation detected. Keeping tunnel keys and settings.')
        return menu()
    if STATE.exists() and any(STATE.iterdir()):
        raise BridgeError('/etc/wg-bridge contains an incomplete install. Inspect it before retrying.')
    heading('Installation', 'Set up Client (Outside) first, then Server (Iran).')
    menu_option('1', 'Server (Iran / entry)', 'Hosts your panel; sends outbound traffic through the tunnel.')
    print()
    menu_option('2', 'Client (Outside / exit)', 'Provides Internet access; generates the pairing code.')
    print()
    menu_option('0', 'Exit')
    print()
    role = prompt('  Select [1/2/0]')
    if role == '0':
        return
    if role not in ['1', '2']:
        raise BridgeError('Choose 1 or 2.')
    s = {'version': VERSION, 'role': 'entry' if role == '1' else 'exit'}
    ssh_peer = os.environ.get('WGB_SSH_PEER') or os.environ.get('SSH_CONNECTION', '').split(' ')[0]
    if ssh_peer:
        try:
            s['ssh_peer'] = str(ipaddress.ip_address(ssh_peer))
        except ValueError:
            raise BridgeError('Cannot validate the current SSH address; reconnect using a standard SSH session.') from None
    if s['role'] == 'entry':
        print('Initialize Client (Outside) first to obtain its pairing code.')
        # Hidden input prevents the pairing secret being copied into a screen recording.
        import getpass
        pairing = pairing_decode(getpass.getpass('Client (Outside) pairing code (hidden): '))
        s.update({'exit_ip': pairing['server_ip'], 'exit_port': pairing['server_port'],
                  'link_private': pairing['client_private'], 'peer_public': pairing['server_public'],
                  'psk': pairing['psk'], 'ipv6': pairing['ipv6']})
    s['public_ip'] = valid_ip(prompt('This server PUBLIC IPv4', detect_ip()))
    label = 'UDP port (open it in the outside provider firewall)' if s['role'] == 'exit' else 'Local WireGuard UDP port'
    s['port'] = valid_port(prompt(label, '51830' if s['role'] == 'exit' else '51831'))
    s['wan'] = default_device()
    conflicts(s['port'])
    if s['role'] == 'exit':
        s['link_private'], server_public = keypair()
        client_private, s['peer_public'] = keypair()
        s['psk'] = run(['wg', 'genpsk'])
        s['ipv6'] = bool(json.loads(run(['ip', '-j', '-6', 'route', 'show', 'default'])))
        s['pairing'] = pairing_encode({'version': 1, 'server_ip': s['public_ip'], 'server_port': s['port'],
                                      'server_public': server_public, 'client_private': client_private,
                                      'psk': s['psk'], 'ipv6': s['ipv6']})
    keys = ['net.ipv4.ip_forward', 'net.ipv4.conf.all.rp_filter', 'net.ipv6.conf.all.forwarding', f'net.ipv6.conf.{s["wan"]}.accept_ra']
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
    if not s['ipv6']:
        print('Outside IPv6 is unavailable: outbound IPv6 Internet traffic will be blocked, not bypass the tunnel.')
    if s['role'] == 'exit':
        print('\nPairing code: SECRET. Hide this part when recording a video. Use on ONE Iran server only.\n')
        print(s['pairing'])
        print('\nNow run the installer on Iran and choose 1) Server. Later: sudo wg-bridge status')
    else:
        if not doctor(s):
            print('Installed but NOT connected. Fix the reported issue, then run: sudo wg-bridge doctor')


def status(s):
    os.environ['WG_HIDE_KEYS'] = 'always'
    print('WG Bridge '+VERSION+' | '+role_label(s))
    for iface in [LINK]:
        result = run(['wg', 'show', iface], check=False)
        print(result.stdout if result.returncode == 0 else iface+': DOWN')
    print('IPv6: '+('enabled' if s['ipv6'] else 'blocked for outgoing Internet traffic'))


def doctor(s):
    print('\nChecking services, handshake and outside connectivity...')
    for unit in ['wg-bridge-network', 'wg-quick@'+LINK]:
        if run(['systemctl', 'is-active', unit], check=False).returncode:
            print(unit+': NOT ACTIVE. Start the tunnel from the menu; inspect journalctl -u '+unit)
            return False
    if s['role'] == 'exit':
        status(s)
        print('If Iran cannot connect: check UDP '+str(s['port'])+' in the provider firewall.')
        return True
    run(['ping', '-c', '1', '-W', '2', '-I', '10.204.0.2', '10.204.0.1'], check=False)
    for _ in range(10):
        result = run(['wg', 'show', LINK, 'latest-handshakes'], check=False)
        if result.returncode == 0 and any(int(line.split()[1]) > time.time()-180 for line in result.stdout.splitlines() if len(line.split()) == 2):
            break
        time.sleep(1)
    else:
        print('NO HANDSHAKE: verify the pairing code, outside IP, UDP '+str(s['exit_port'])+', and network filtering.')
        return False
    good = True
    families = [(4, 'https://api.ipify.org')]
    if s['ipv6']:
        families.append((6, 'https://api64.ipify.org'))
    for version, url in families:
        p = run(['curl', f'-{version}', '-fsS', '--connect-timeout', '5', '--max-time', '10', url], check=False)
        try:
            if p.returncode: raise ValueError()
            observed = ipaddress.ip_address(p.stdout.strip())
            if observed.version != version or not observed.is_global: raise ValueError()
            if version == 4 and str(observed) == s['public_ip']: raise ValueError()
            print(f'IPv{version} outside address: {observed}')
        except ValueError:
            print(f'IPv{version} egress check FAILED. Check forwarding, NAT and the outside Internet route.')
            good = False
    print('Also test your existing panel users and a NEW SSH session before closing this terminal.')
    return good


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
        expected = '2' if k.endswith(('accept_ra','rp_filter')) else '1'
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


def menu():
    s = load()
    heading('Tunnel management', role_label(s))
    menu_option('1', 'Status')
    menu_option('2', 'Diagnose connectivity')
    print()
    menu_option('3', 'Restart tunnel')
    menu_option('4', 'Show pairing code', 'Available on Client (Outside); keep this code private.')
    menu_option('5', 'Stop tunnel', 'Outbound Internet is blocked; inbound SSH remains available.')
    menu_option('6', 'Start tunnel')
    print()
    menu_option('7', 'Uninstall completely', 'Remove WG Bridge, its tunnel configuration and keys.', '31')
    menu_option('0', 'Exit')
    print()
    choice = prompt('  Select [0-7]')
    if choice == '1': status(s)
    elif choice == '2': doctor(s)
    elif choice in ['3', '6']:
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
    elif choice != '0': raise BridgeError('Unknown menu option.')


def main():
    parser = argparse.ArgumentParser(description='WG Bridge: Server (Iran / entry) and Client (Outside / exit)')
    parser.add_argument('command', nargs='?', default='menu', choices=['menu','install','status','doctor','uninstall','_network','version'])
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


if __name__ == '__main__':
    try:
        main()
    except (BridgeError, KeyboardInterrupt, EOFError) as exc:
        print('\nERROR: '+(str(exc) or 'Cancelled.'), file=sys.stderr)
        sys.exit(1)
