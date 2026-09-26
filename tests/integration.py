#!/usr/bin/env python3
"""Root-only, isolated Linux network test. No host firewall/route modifications.

Creates four network namespaces; runs real wg-quick, NAT and policy routing.
Temporary fixtures live below /etc/wireguard for distribution AppArmor profiles.
Never calls the install/uninstall functions against the host filesystem.
"""
import concurrent.futures
import json
import os
import re
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import wg_bridge as w

PREFIX = 'wgbt'+str(os.getpid())
NAMES = {n: PREFIX+'-'+n for n in ['ir', 'out', 'wan', 'lan']}
PROCESSES = []


def command(args, check=True):
    p = subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=40)
    if check and p.returncode:
        raise RuntimeError('Command failed: '+str(args[:8])+'\n'+p.stderr[-1200:])
    return p


def ns(name, *args, check=True):
    return command(['ip', 'netns', 'exec', NAMES[name], *args], check=check)


def background(name, code, pipes=False):
    p = subprocess.Popen(['ip', 'netns', 'exec', NAMES[name], 'python3', '-u', '-c', code],
                         stdin=subprocess.PIPE if pipes else subprocess.DEVNULL,
                         stdout=subprocess.PIPE if pipes else subprocess.DEVNULL,
                         stderr=subprocess.PIPE if pipes else subprocess.DEVNULL, text=True)
    PROCESSES.append(p)
    return p


def connect(a, b, a_if, b_if, v4a, v4b, v6a, v6b):
    # Both ends are created inside a test namespace, never in the host namespace.
    ns(a, 'ip', 'link', 'add', a_if, 'type', 'veth', 'peer', 'name', 'temp-peer')
    ns(a, 'ip', 'link', 'set', 'temp-peer', 'netns', NAMES[b])
    ns(b, 'ip', 'link', 'set', 'temp-peer', 'name', b_if)
    for name, iface, v4, v6 in [(a, a_if, v4a, v6a), (b, b_if, v4b, v6b)]:
        ns(name, 'ip', 'addr', 'add', v4, 'dev', iface)
        ns(name, 'ip', '-6', 'addr', 'add', v6, 'dev', iface, 'nodad')
        ns(name, 'ip', 'link', 'set', iface, 'up')


HTTP = '''
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = self.client_address[0].encode()
        self.send_response(200); self.send_header('Content-Length', str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def log_message(self, *args): pass
class Server(ThreadingHTTPServer):
    request_queue_size = 1024
    address_family = FAMILY
Server((ADDRESS, PORT), Handler).serve_forever()
'''


def fetch(name, url, source=None, ok=True):
    # Shared CI runners may delay IPv6 neighbour discovery; allow its retries.
    args = ['curl', '--noproxy', '*', '-fsS', '--connect-timeout', '5', '--max-time', '8']
    if source: args += ['--interface', source]
    p = ns(name, *args, url, check=False)
    if ok and p.returncode:
        if '8082' in url:
            for target in ['ir', 'wan']:
                for args in [('ip6tables-save', '-c'), ('ip', '-6', 'rule'), ('ip', '-6', 'neigh'), ('conntrack', '-L', '-f', 'ipv6')]:
                    print(target, args, ns(target, *args, check=False).stdout, flush=True)
        raise AssertionError('Cannot reach '+url+' from '+name+': '+p.stderr)
    if not ok: assert p.returncode != 0, 'Traffic leaked while tunnel was down'
    return p.stdout.strip()


def apply(name, folder, up):
    ns(name, 'python3', '-c',
       'import sys,json;sys.path.insert(0,sys.argv[1]);import wg_bridge as w;'
       'w.network(json.load(open(sys.argv[2])),sys.argv[3]=="up")',
       str(ROOT), str(folder/name/'state.json'), 'up' if up else 'down')


def test(folder):
    print(command(['uname', '-r']).stdout.strip(), command(['iptables', '--version']).stdout.strip(),
          command(['ip6tables', '--version']).stdout.strip(), flush=True)
    for name in NAMES:
        command(['ip', 'netns', 'add', NAMES[name]])
        ns(name, 'ip', 'link', 'set', 'lo', 'up')
    connect('wan', 'ir', 'tow-ir', 'wan0', '192.0.2.1/30', '192.0.2.2/30', 'fd10:1::1/64', 'fd10:1::2/64')
    connect('wan', 'out', 'tow-out', 'wan0', '198.51.100.1/30', '198.51.100.2/30', 'fd10:2::1/64', 'fd10:2::2/64')
    connect('ir', 'lan', 'lan0', 'eth0', '10.222.0.1/24', '10.222.0.2/24', 'fd10:3::1/64', 'fd10:3::2/64')
    for name, gateway, gateway6 in [('ir', '192.0.2.1', 'fd10:1::1'), ('out', '198.51.100.1', 'fd10:2::1'), ('lan', '10.222.0.1', 'fd10:3::1')]:
        ns(name, 'ip', 'route', 'add', 'default', 'via', gateway)
        ns(name, 'ip', '-6', 'route', 'add', 'default', 'via', gateway6)
    ns('wan', 'ip', 'addr', 'add', '203.0.113.1/32', 'dev', 'lo')
    ns('wan', 'ip', 'addr', 'add', '203.0.113.2/32', 'dev', 'lo')
    ns('wan', 'ip', '-6', 'addr', 'add', 'fdff::1/128', 'dev', 'lo', 'nodad')
    ns('wan', 'ip', '-6', 'addr', 'add', 'fdff::2/128', 'dev', 'lo', 'nodad')
    ns('wan', 'sysctl', '-w', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1')
    # Test forwarding through default DROP chains, as on Docker/UFW hosts.
    for name in ['ir', 'out']:
        for tool in ['iptables', 'ip6tables']:
            ns(name, tool, '-P', 'FORWARD', 'DROP')
            ns(name, tool, '-N', 'UNRELATED')
            ns(name, tool, '-A', 'INPUT', '-j', 'UNRELATED')
    for name, family, address, port in [('wan', 'socket.AF_INET', '0.0.0.0', 8000),
                                      ('wan', 'socket.AF_INET6', '::', 8002),
                                      ('ir', 'socket.AF_INET6', '::', 8082),
                                      ('ir', 'socket.AF_INET', '0.0.0.0', 8080)]:
        background(name, HTTP.replace('FAMILY', family).replace('ADDRESS', repr(address)).replace('PORT', str(port)))
    background('ir', '''
import socket, threading
def handle(c):
    with c:
        while True:
            data=c.recv(1024)
            if not data: return
            c.sendall(data)
s=socket.socket();s.bind(('0.0.0.0',8081));s.listen(20)
while True:
    c,_=s.accept();threading.Thread(target=handle,args=(c,),daemon=True).start()
''')
    time.sleep(0.4)
    assert fetch('ir', 'http://203.0.113.1:8000') == '192.0.2.2'
    persistent = background('wan', '''
import socket,sys
s=socket.socket();s.settimeout(4);s.bind(('203.0.113.2',0));s.connect(('192.0.2.2',8081))
for line in sys.stdin:
    s.sendall(line.encode());print(s.recv(1024).decode().strip(),flush=True)
''', pipes=True)
    def existing_session():
        import select
        persistent.stdin.write('alive\n'); persistent.stdin.flush()
        assert select.select([persistent.stdout], [], [], 6)[0], 'Existing inbound session lost'
        reply = persistent.stdout.readline().strip()
        if reply != 'alive':
            print(ns('ir', 'conntrack', '-L', '-p', 'tcp', '--dport', '8081', check=False).stdout, flush=True)
            print(ns('ir', 'ip', 'rule').stdout, flush=True)
            print(ns('ir', 'ip', 'route', 'get', '203.0.113.2', 'from', '192.0.2.2', 'mark', '0x40000000', check=False).stdout, flush=True)
            print(ns('ir', 'iptables-save', '-c').stdout, flush=True)
            print('CLIENT ERROR', persistent.stderr.read(), flush=True)
        assert reply == 'alive'
    existing_session()

    server_private, server_public = w.keypair()
    client_private, client_public = w.keypair()
    psk = w.run(['wg', 'genpsk'])
    states = {
        'out': dict(role='exit', wan='wan0', ipv6=True, port=51830, link_private=server_private, peer_public=client_public, psk=psk),
        'ir': dict(role='entry', wan='wan0', ipv6=True, port=51831, link_private=client_private, peer_public=server_public, psk=psk, exit_ip='198.51.100.2', exit_port=51830)
    }
    for name, state in states.items():
        w.save(folder/name/'state.json', json.dumps(state))
        w.save(folder/name/'wgb-exit.conf', w.link_config(state))
        apply(name, folder, True)
        ns(name, 'wg-quick', 'up', folder/name/'wgb-exit.conf')
    existing_session()
    assert fetch('ir', 'http://203.0.113.1:8000') == '198.51.100.2'
    assert fetch('ir', 'http://[fdff::1]:8002') == 'fd10:2::2'
    assert fetch('lan', 'http://203.0.113.1:8000') == '198.51.100.2'
    assert fetch('lan', 'http://[fdff::1]:8002') == 'fd10:2::2'
    assert fetch('wan', 'http://192.0.2.2:8080', '203.0.113.2') == '203.0.113.2'
    assert fetch('wan', 'http://[fd10:1::2]:8082', 'fdff::2') == 'fdff::2'
    print('PASS: real WG handshake, IPv4/IPv6 egress and forwarded LAN; new/existing inbound TCP preserved', flush=True)
    # UDP travels through the same tunnel, independent of the number of panel users.
    background('wan', '''
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('203.0.113.1',8001))
while True:
    _,addr=s.recvfrom(1024);s.sendto(addr[0].encode(),addr)
''')
    time.sleep(0.2)
    udp = ns('ir', 'python3', '-c', "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(3);s.sendto(b'x',('203.0.113.1',8001));print(s.recv(100).decode())", check=False)
    if udp.returncode:
        for name in ['ir', 'out', 'wan']:
            print(name, ns(name, 'ss', '-unlp').stdout, flush=True)
            print(ns(name, 'conntrack', '-L', '-p', 'udp', check=False).stdout, flush=True)
            print(ns(name, 'iptables', '-t', 'filter', '-L', 'FORWARD', '-nv').stdout, flush=True)
            if name != 'wan':
                print(ns(name, 'iptables', '-t', 'nat', '-L', 'WGB_NAT', '-nv').stdout, flush=True)
        raise AssertionError('UDP failed: '+udp.stderr)
    assert udp.stdout.strip() == '198.51.100.2'
    with concurrent.futures.ThreadPoolExecutor(max_workers=40) as pool:
        results = list(pool.map(lambda _: fetch('ir', 'http://203.0.113.1:8000'), range(300)))
    assert all(ip == '198.51.100.2' for ip in results)
    print('PASS: UDP and 300 HTTP requests (40 workers); this is NOT a capacity benchmark', flush=True)
    before = ns('ir', 'ip', '-j', 'rule').stdout
    rules_before = ns('ir', 'iptables-save').stdout
    apply('ir', folder, True)
    assert ns('ir', 'ip', '-j', 'rule').stdout == before
    def stable_rules(value):
        return [re.sub(r'\[\d+:\d+\]', '[0:0]', line) for line in value.splitlines() if not line.startswith('#')]
    assert stable_rules(ns('ir', 'iptables-save').stdout) == stable_rules(rules_before)
    existing_session()
    for name in ['ir', 'out']:
        ns(name, 'wg-quick', 'down', folder/name/'wgb-exit.conf')
    fetch('ir', 'http://203.0.113.1:8000', ok=False)
    fetch('ir', 'http://[fdff::1]:8002', ok=False)
    fetch('lan', 'http://203.0.113.1:8000', ok=False)
    try:
        assert fetch('wan', 'http://192.0.2.2:8080', '203.0.113.2') == '203.0.113.2'
    except AssertionError:
        print(ns('ir', 'iptables-save', '-c').stdout, flush=True)
        print(ns('ir', 'ip', 'route', 'show', 'table', 'all').stdout, flush=True)
        print(ns('ir', 'conntrack', '-L', '-p', 'tcp', '--dport', '8080', check=False).stdout, flush=True)
        raise
    existing_session()
    assert fetch('wan', 'http://[fd10:1::2]:8082', 'fdff::2') == 'fdff::2'
    print('PASS: no outgoing fallback with tunnel stopped; inbound management remains available', flush=True)
    for name in ['out', 'ir']:
        ns(name, 'wg-quick', 'up', folder/name/'wgb-exit.conf')
    assert fetch('ir', 'http://203.0.113.1:8000') == '198.51.100.2'
    for name in ['ir', 'out']:
        ns(name, 'wg-quick', 'down', folder/name/'wgb-exit.conf')
        apply(name, folder, False)
        states[name]['ipv6'] = False
        w.save(folder/name/'state.json', json.dumps(states[name]))
    for name in ['out', 'ir']:
        apply(name, folder, True)
        ns(name, 'wg-quick', 'up', folder/name/'wgb-exit.conf')
    assert fetch('ir', 'http://203.0.113.1:8000') == '198.51.100.2'
    fetch('ir', 'http://[fdff::1]:8002', ok=False)
    fetch('lan', 'http://[fdff::1]:8002', ok=False)
    assert fetch('wan', 'http://[fd10:1::2]:8082', 'fdff::2') == 'fdff::2'
    print('PASS: IPv4-only exit blocks IPv6 for host and forwarded traffic', flush=True)
    for name in ['ir', 'out']:
        ns(name, 'wg-quick', 'down', folder/name/'wgb-exit.conf')
        apply(name, folder, False)
        for tool in ['iptables', 'ip6tables']:
            ns(name, tool, '-C', 'INPUT', '-j', 'UNRELATED')
            assert '-P FORWARD DROP' in ns(name, tool, '-S').stdout
            assert 'WGB_' not in ns(name, tool+'-save').stdout
        assert '12131' not in ns(name, 'ip', 'rule').stdout
    assert fetch('ir', 'http://203.0.113.1:8000') == '192.0.2.2'
    existing_session()
    print('PASS: restart and removal; unrelated firewall preserved; original Internet route restored', flush=True)


def cleanup():
    for p in PROCESSES:
        p.terminate()
    for p in PROCESSES:
        try: p.wait(timeout=3)
        except subprocess.TimeoutExpired: p.kill(); p.wait()
    for name in reversed(list(NAMES.values())):
        command(['ip', 'netns', 'del', name], check=False)


if __name__ == '__main__':
    if os.geteuid() != 0: sys.exit('Run as root on a Linux host with WireGuard support.')
    os.umask(0o077)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    try:
        # Ubuntu's wg-quick AppArmor profile permits configurations only under
        # /etc/wireguard. Keep confinement active and use a private, unique
        # fixture directory there; all interfaces remain in test namespaces.
        w.WG.mkdir(mode=0o700, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='.wgb-test-', dir=w.WG) as tmp:
            test(Path(tmp))
    finally:
        cleanup()
