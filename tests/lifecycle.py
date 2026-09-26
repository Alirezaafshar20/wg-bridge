#!/usr/bin/env python3
"""CI-only installer/systemd test. Intentionally changes the disposable runner.

Never run this test on an existing server. Namespace tests are the safe local test.
"""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import wg_bridge as w


def call(args, data=None):
    # Installer output contains a pairing secret: never emit captured output.
    p = subprocess.run(args, input=data, capture_output=True, text=True, timeout=240, cwd=ROOT)
    if p.returncode: raise AssertionError(str(args[0])+' failed: exit '+str(p.returncode))
    return p.stdout


def absent():
    assert not w.STATE.exists()
    assert not (w.WG/(w.LINK+'.conf')).exists()
    assert not w.UNIT.exists()
    assert subprocess.run(['ip', 'link', 'show', w.LINK], capture_output=True).returncode
    for tool in ['iptables-save', 'ip6tables-save']:
        assert 'WGB_' not in call([tool])


def main():
    if os.environ.get('WGB_DISPOSABLE_CI') != 'YES' or os.environ.get('GITHUB_ACTIONS') != 'true':
        sys.exit('Only run on an explicitly opted-in disposable GitHub Actions VM.')
    absent()
    before = {k: w.run(['sysctl', '-n', k]) for k in ['net.ipv4.ip_forward', 'net.ipv6.conf.all.forwarding', 'net.ipv4.conf.all.rp_filter']}
    try:
        call(['script', '-q', '-e', '-c', 'bash install.sh', '/dev/null'], '2\n8.8.8.8\n51830\n8443\nboth\n')
        state = w.load()
        assert state['role'] == 'exit'
        assert w.pairing_decode(state['pairing'])['server_ip'] == '8.8.8.8'
        for name in ['wg-bridge-network', 'wg-quick@wgb-exit']:
            call(['systemctl', 'is-active', name]); call(['systemctl', 'is-enabled', name])
        config = w.WG/(w.LINK+'.conf')
        digest = hashlib.sha256(config.read_bytes()).digest()
        assert stat.S_IMODE(config.stat().st_mode) == 0o600
        call(['script', '-q', '-e', '-c', 'bash install.sh', '/dev/null'], '0\n')
        assert hashlib.sha256(config.read_bytes()).digest() == digest
        call(['systemctl', 'stop', 'wg-quick@wgb-exit'])
        call(['systemctl', 'is-active', 'wg-bridge-network'])
        call(['systemctl', 'start', 'wg-quick@wgb-exit'])
        # Upgrade only compatible port-forward installations without changing keys.
        state_bytes = (w.STATE/'state.json').read_bytes()
        call(['bash', 'install.sh', '--upgrade'])
        assert hashlib.sha256(config.read_bytes()).digest() == digest
        assert (w.STATE/'state.json').read_bytes() == state_bytes
        assert call(['/usr/local/sbin/wg-bridge', 'version']).strip() == w.VERSION
        # Legacy upgrades must fail before replacing the installed program/state.
        manager_bytes = w.APP.read_bytes()
        legacy = dict(state)
        legacy.pop('mode')
        w.save(w.STATE/'state.json', json.dumps(legacy))
        blocked = subprocess.run(['bash', 'install.sh', '--upgrade'], capture_output=True, text=True, cwd=ROOT)
        assert blocked.returncode != 0 and 'old full-routing mode' in blocked.stderr
        assert w.APP.read_bytes() == manager_bytes
        assert hashlib.sha256(config.read_bytes()).digest() == digest
        w.save(w.STATE/'state.json', state_bytes.decode())
        # A cancelled uninstall must preserve both network and manager.
        call(['script', '-q', '-e', '-c', 'bash install.sh --uninstall', '/dev/null'], 'CANCEL\n')
        assert config.exists() and w.APP.exists() and w.LAUNCHER.exists()
        with contextlib.redirect_stdout(io.StringIO()):
            w.uninstall(w.load(), confirm=False, purge=False)
        absent()
        assert all(w.run(['sysctl', '-n', k]) == v for k, v in before.items())
        # Fail after both units start; rollback must remove the partial install.
        real_services = w.services
        def fail_services(state):
            real_services(state)
            raise w.BridgeError('injected service failure')
        with patch.object(w, 'prompt', side_effect=['2', '8.8.8.8', '51830', '8443', 'both']), patch.object(w, 'detect_ip', return_value=''), patch.object(w, 'services', side_effect=fail_services), contextlib.redirect_stdout(io.StringIO()):
            try: w.install()
            except w.BridgeError as exc: assert str(exc) == 'injected service failure'
            else: raise AssertionError('Expected failure did not occur')
        absent()
        assert w.APP.exists() and w.LAUNCHER.exists()
        # Exercise Iran installation with an unreachable peer, then edit only
        # the public mapping. Host defaults and existing SSH routing must stay.
        route_before = call(['ip', '-j', 'route', 'show', 'default'])
        rules_before = call(['ip', '-j', 'rule'])
        entry_answers = '1\n'+state['pairing']+'\n9.9.9.9\n51831\n8443\n'
        call(['script', '-q', '-e', '-c', 'bash install.sh', '/dev/null'], entry_answers)
        entry = w.load()
        assert entry['role'] == 'entry' and entry['listen_port'] == 8443
        entry_config = config.read_bytes()
        call(['/usr/local/sbin/wg-bridge', 'port', '9443'])
        assert w.load()['listen_port'] == 9443 and config.read_bytes() == entry_config
        assert call(['ip', '-j', 'route', 'show', 'default']) == route_before
        assert call(['ip', '-j', 'rule']) == rules_before
        with contextlib.redirect_stdout(io.StringIO()):
            w.uninstall(w.load(), confirm=False, purge=False)
        absent()
        assert all(w.run(['sysctl', '-n', k]) == v for k, v in before.items())
        call(['script', '-q', '-e', '-c', 'bash install.sh', '/dev/null'], '2\n8.8.8.8\n51830\n8443\nboth\n')
        call(['script', '-q', '-e', '-c', 'bash install.sh --uninstall', '/dev/null'], 'REMOVE\n')
        absent()
        assert not w.APP.exists() and not w.LAUNCHER.exists()
        print('PASS: both roles, failed handshake isolation, port editing, upgrade, legacy rejection, cancellation, rollback and complete uninstall')
    finally:
        if (w.STATE/'state.json').exists():
            with contextlib.redirect_stdout(io.StringIO()): w.uninstall(w.load(), confirm=False)


if __name__ == '__main__':
    main()
