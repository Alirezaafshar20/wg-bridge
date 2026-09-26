#!/usr/bin/env python3
"""CI-only installer/systemd test. Intentionally changes the disposable runner.

Never run this test on an existing server. Namespace tests are the safe local test.
"""
import contextlib
import hashlib
import io
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
        call(['script', '-q', '-e', '-c', 'bash install.sh', '/dev/null'], '1\n8.8.8.8\n51830\n')
        state = w.load()
        assert state['role'] == 'server'
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
        call(['/usr/local/sbin/wg-bridge', 'uninstall'], 'REMOVE\n')
        absent()
        assert all(w.run(['sysctl', '-n', k]) == v for k, v in before.items())
        # Fail after both units start; rollback must remove the partial install.
        real_services = w.services
        def fail_services(state):
            real_services(state)
            raise w.BridgeError('injected service failure')
        with patch.object(w, 'prompt', side_effect=['1', '8.8.8.8', '51830']), patch.object(w, 'detect_ip', return_value=''), patch.object(w, 'services', side_effect=fail_services), contextlib.redirect_stdout(io.StringIO()):
            try: w.install()
            except w.BridgeError as exc: assert str(exc) == 'injected service failure'
            else: raise AssertionError('Expected failure did not occur')
        absent()
        print('PASS: actual installer, persistent systemd units, idempotent rerun, stop/start, uninstall and rollback')
    finally:
        if (w.STATE/'state.json').exists():
            with contextlib.redirect_stdout(io.StringIO()): w.uninstall(w.load(), confirm=False)


if __name__ == '__main__':
    main()
