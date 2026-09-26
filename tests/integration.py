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


    for target in [9443, 9444]:
        background('out', HTTP.replace('FAMILY', 'socket.AF_INET').replace('ADDRESS', repr('0.0.0.0')).replace('PORT', str(target)))
    background('out', """
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',9443))
while True:
    _,addr=s.recvfrom(1024);s.sendto(addr[0].encode(),addr)
""")
    # An unrelated LAN routing service must keep working independently.
    ns('ir', 'sysctl', '-w', 'net.ipv4.ip_forward=1')
    ns('ir', 'iptables', '-A', 'FORWARD', '-i', 'lan0', '-o', 'wan0', '-j', 'ACCEPT')
    ns('ir', 'iptables', '-A', 'FORWARD', '-i', 'wan0', '-o', 'lan0', '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT')
    ns('ir', 'iptables', '-t', 'nat', '-A', 'POSTROUTING', '-s', '10.222.0.0/24', '-o', 'wan0', '-j', 'MASQUERADE')
    routes_before = {name: {family: (ns(name, 'ip', family, '-j', 'route', 'show', 'default').stdout,
                                    ns(name, 'ip', family, '-j', 'rule').stdout)
                            for family in ['-4','-6']} for name in ['ir','out']}
    def stable_rules(value):
        return [re.sub(r'\[\d+:\d+\]', '[0:0]', line) for line in value.splitlines() if not line.startswith('#')]
    v6_rules_before = {name: stable_rules(ns(name, 'ip6tables-save').stdout) for name in ['ir','out']}
    def unchanged_routing():
        for name in ['ir','out']:
            for family in ['-4','-6']:
                assert (ns(name, 'ip', family, '-j', 'route', 'show', 'default').stdout,
                        ns(name, 'ip', family, '-j', 'rule').stdout) == routes_before[name][family]
            assert stable_rules(ns(name, 'ip6tables-save').stdout) == v6_rules_before[name]
    def direct_services():
        assert fetch('ir', 'http://203.0.113.1:8000') == '192.0.2.2'
        assert fetch('ir', 'http://[fdff::1]:8002') == 'fd10:1::2'
        assert fetch('out', 'http://203.0.113.1:8000') == '198.51.100.2'
        assert fetch('lan', 'http://203.0.113.1:8000') == '192.0.2.2'
        assert fetch('wan', 'http://192.0.2.2:8080', '203.0.113.2') == '203.0.113.2'
        assert fetch('wan', 'http://[fd10:1::2]:8082', 'fdff::2') == 'fdff::2'
        existing_session()
        unchanged_routing()
    def udp(port, ok=True):
        p = ns('wan', 'python3', '-c',
               "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2);"
               "s.sendto(b'probe',('192.0.2.2',"+str(port)+"));print(s.recv(100).decode())", check=False)
        if ok: assert p.returncode == 0 and p.stdout.strip() == w.ENTRY_IP
        else: assert p.returncode != 0

    server_private, server_public = w.keypair()
    client_private, client_public = w.keypair()
    psk = w.run(['wg', 'genpsk'])
    states = {
        'out': dict(mode=w.MODE, role='exit', wan='wan0', port=51830, target_port=9443, protocol='both',
                    public_ip='198.51.100.2', link_private=server_private, peer_public=client_public, psk=psk),
        'ir': dict(mode=w.MODE, role='entry', wan='wan0', port=51831, listen_port=8443, target_port=9443, protocol='both',
                   public_ip='192.0.2.2', link_private=client_private, peer_public=server_public, psk=psk,
                   exit_ip='198.51.100.2', exit_port=51830)
    }
    for name, state in states.items():
        w.save(folder/name/'state.json', json.dumps(state))
        w.save(folder/name/'wgb-exit.conf', w.link_config(state))
        apply(name, folder, True)
        ns(name, 'wg-quick', 'up', folder/name/'wgb-exit.conf')
    time.sleep(0.5)
    assert fetch('wan', 'http://192.0.2.2:8443') == w.ENTRY_IP
    udp(8443)
    # No local OUTPUT redirection, and no access to other outside service ports.
    fetch('ir', 'http://192.0.2.2:8443', ok=False)
    fetch('ir', 'http://10.204.0.1:9444', ok=False)
    direct_services()
    print('PASS: one selected TCP/UDP port reaches Outside; direct IPv4/IPv6, LAN and inbound services are unchanged', flush=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=40) as pool:
        assert all(x == w.ENTRY_IP for x in pool.map(lambda _: fetch('wan', 'http://192.0.2.2:8443'), range(300)))
    before = ns('ir', 'iptables-save').stdout
    apply('ir', folder, True)
    assert stable_rules(before) == stable_rules(ns('ir', 'iptables-save').stdout)
    print('PASS: idempotent rules and 300 forwarded HTTP requests (40 workers)', flush=True)
    # A peer failure must affect only the forwarded service.
    ns('out', 'wg-quick', 'down', folder/'out'/'wgb-exit.conf')
    fetch('wan', 'http://192.0.2.2:8443', ok=False)
    direct_services()
    ns('out', 'wg-quick', 'up', folder/'out'/'wgb-exit.conf')
    # Removing the Iran WG interface must not leak DNAT packets to WAN.
    ns('ir', 'wg-quick', 'down', folder/'ir'/'wgb-exit.conf')
    ns('wan', 'iptables', '-N', 'LEAK_CHECK')
    ns('wan', 'iptables', '-A', 'LEAK_CHECK', '-j', 'DROP')
    ns('wan', 'iptables', '-I', 'FORWARD', '1', '-d', w.EXIT_IP, '-j', 'LEAK_CHECK')
    fetch('wan', 'http://192.0.2.2:8443', ok=False)
    udp(8443, ok=False)
    leak = ns('wan', 'iptables', '-L', 'LEAK_CHECK', '-nvx').stdout
    assert any(re.match(r'\s*0\s+0\s+DROP', line) for line in leak.splitlines()), leak
    direct_services()
    ns('ir', 'wg-quick', 'up', folder/'ir'/'wgb-exit.conf')
    assert fetch('wan', 'http://192.0.2.2:8443') == w.ENTRY_IP
    print('PASS: unreachable peer, stopped interface and restart preserve other services; forwarded packets never escape to WAN', flush=True)
    # Custom port and protocol selection, without changing any default route.
    apply('ir', folder, False)
    states['ir'].update(listen_port=10443, protocol='tcp')
    w.save(folder/'ir'/'state.json', json.dumps(states['ir']))
    apply('ir', folder, True)
    assert fetch('wan', 'http://192.0.2.2:10443') == w.ENTRY_IP
    fetch('wan', 'http://192.0.2.2:8443', ok=False)
    udp(10443, ok=False)
    apply('ir', folder, False)
    states['ir']['protocol'] = 'udp'
    w.save(folder/'ir'/'state.json', json.dumps(states['ir']))
    apply('ir', folder, True)
    udp(10443)
    fetch('wan', 'http://192.0.2.2:10443', ok=False)
    direct_services()
    print('PASS: custom ports, TCP-only and UDP-only forwarding', flush=True)
    for name in ['ir', 'out']:
        ns(name, 'wg-quick', 'down', folder/name/'wgb-exit.conf')
        apply(name, folder, False)
        ns(name, 'iptables', '-C', 'INPUT', '-j', 'UNRELATED')
        assert '-P FORWARD DROP' in ns(name, 'iptables', '-S').stdout
        assert 'WGB_' not in ns(name, 'iptables-save').stdout
    for proto in ['tcp', 'udp']:
        assert not ns('ir', 'conntrack', '-L', '-p', proto, '--dst-nat', '--reply-src', w.EXIT_IP).stdout.strip()
    direct_services()
    print('PASS: complete rule cleanup preserves unrelated firewall and routing', flush=True)



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
