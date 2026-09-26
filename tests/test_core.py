import base64
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import wg_bridge as w


class CoreTests(unittest.TestCase):
    def payload(self):
        key = base64.b64encode(bytes(range(32))).decode()
        return dict(version=1, server_ip='8.8.8.8', server_port=51830,
                    server_public=key, client_private=key, psk=key, ipv6=True)

    def test_pairing_round_trip(self):
        p = self.payload()
        self.assertEqual(w.pairing_decode(w.pairing_encode(p)), p)

    def test_pairing_rejects_corruption_and_extra_fields(self):
        encoded = w.pairing_encode(self.payload())
        for code in [encoded[:-3], encoded.replace('WGB1', 'WGB2'), 'x'*4097, 'WGB1.!@#.x']:
            with self.subTest(code=code[:20]), self.assertRaises(w.BridgeError):
                w.pairing_decode(code)
        for field, value in [('command', 'rm -rf /'), ('ipv6', 'yes'), ('version', True),
                             ('server_ip', '8.8.8.8\nPostUp = x'), ('server_port', 1.5),
                             ('client_private', 'invalid'), ('server_port', True)]:
            p = self.payload(); p[field] = value
            with self.subTest(field=field), self.assertRaises(w.BridgeError):
                w.pairing_decode(w.pairing_encode(p))

    def test_port_and_public_address(self):
        for value in [0, 65536, -1, True, 1.2, '2;reboot', None]:
            with self.assertRaises(w.BridgeError): w.valid_port(value)
        for value in ['127.0.0.1', '10.0.0.1', '::1', '8.8.8.8:9', 1234, None]:
            with self.assertRaises(w.BridgeError): w.valid_ip(value)
        self.assertEqual(w.valid_port('65535'), 65535)

    def test_atomic_private_storage(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'secret'
            w.save(p, 'first'); w.save(p, 'second')
            self.assertEqual(p.read_text(), 'second')
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
            self.assertEqual([x.name for x in p.parent.iterdir()], ['secret'])

    def test_command_errors_do_not_print_secrets(self):
        from subprocess import CompletedProcess
        with patch.object(w.subprocess, 'run', return_value=CompletedProcess([], 1, 'SECRET', 'SECRET')):
            with self.assertRaises(w.BridgeError) as caught: w.run(['wg', 'SECRET'], 'SECRET')
            self.assertNotIn('SECRET', str(caught.exception))

    def test_no_device_profiles_and_no_wg_quick_default_rule_ownership(self):
        s = dict(role='client', link_private='PRIVATE', peer_public='PUBLIC', psk='PSK',
                 port=51831, server_ip='8.8.8.8', server_port=51830)
        config = w.link_config(s)
        self.assertEqual(config.count('[Peer]'), 1)
        self.assertIn('Table = 52031', config)
        self.assertIn('ListenPort = 51831', config)
        self.assertNotIn('SaveConfig', config)
        self.assertNotIn('PostDown', config)

    def test_bypass_marks_keep_wireguard_bits(self):
        s = dict(role='client', wan='eth0', ipv6=False)
        rules = w.firewall_rules(s, 6)
        restore = [args for _, _, args in rules if '--restore-mark' in args]
        self.assertTrue(restore)
        self.assertTrue(all('--nfmask' in args and '0x40000000' in args for args in restore))
        self.assertFalse(any('MASQUERADE' in args for _, _, args in rules))
        self.assertTrue(any(chain == 'WGB_OUTPUT' and 'REJECT' in args for _, chain, args in rules))


if __name__ == '__main__':
    unittest.main()
