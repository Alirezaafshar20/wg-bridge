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
    def test_legacy_state_is_rejected_before_network_changes(self):
        for old in [{'role': 'client'}, {'role': 'entry'}, {'mode': 'future', 'role': 'entry'}]:
            with self.assertRaises(w.BridgeError): w.normalize_state(old)
        with self.assertRaises(w.BridgeError): w.pairing_decode('WGB1.old.code')

    def payload(self):
        key = base64.b64encode(bytes(range(32))).decode()
        return dict(version=2, server_ip='8.8.8.8', server_port=51830,
                    server_public=key, client_private=key, psk=key, target_port=8443, protocol="both")

    def test_pairing_round_trip(self):
        p = self.payload()
        self.assertEqual(w.pairing_decode(w.pairing_encode(p)), p)
        p.update(entry_ip='9.9.9.9', entry_port=9999)
        self.assertEqual(w.pairing_decode(w.pairing_encode(p)), p)

    def test_pairing_rejects_partial_or_invalid_iran_endpoint(self):
        for extra in [dict(entry_ip='9.9.9.9'), dict(entry_port=9999),
                      dict(entry_ip='9.9.9.9', entry_port=0), dict(entry_ip='127.0.0.1', entry_port=9999)]:
            with self.subTest(extra=extra), self.assertRaises(w.BridgeError):
                w.pairing_decode(w.pairing_encode(dict(self.payload(), **extra)))

    def test_iran_endpoint_must_match_pairing_before_install(self):
        p = dict(self.payload(), entry_ip='9.9.9.9', entry_port=9999)
        w.check_paired_entry(p, dict(public_ip='9.9.9.9', port=9999))
        for s in [dict(public_ip='1.1.1.1', port=9999), dict(public_ip='9.9.9.9', port=10000)]:
            with self.assertRaises(w.BridgeError): w.check_paired_entry(p, s)
        w.check_paired_entry(self.payload(), dict(public_ip='9.9.9.9', port=10000))

    def test_pairing_rejects_corruption_and_extra_fields(self):
        encoded = w.pairing_encode(self.payload())
        for code in [encoded[:-3], encoded.replace('WGB2', 'WGB3'), 'x'*4097, 'WGB1.!@#.x']:
            with self.subTest(code=code[:20]), self.assertRaises(w.BridgeError):
                w.pairing_decode(code)
        for field, value in [('command', 'rm -rf /'), ('protocol', 'icmp'), ('version', True),
                             ('server_ip', '8.8.8.8\nPostUp = x'), ('target_port', 1.5),
                             ('client_private', 'invalid'), ('server_port', True)]:
            p = self.payload(); p[field] = value
            with self.subTest(field=field), self.assertRaises(w.BridgeError):
                w.pairing_decode(w.pairing_encode(p))

    def test_port_and_public_address(self):
        for value in [0, 65536, -1, True, 1.2, '2;reboot', None]:
            with self.assertRaises(w.BridgeError): w.valid_port(value)
        for value in ['127.0.0.1', '10.0.0.1', '224.0.0.1', '::1', '8.8.8.8:9', 1234, None]:
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

    def test_private_peer_routes_only(self):
        for role, peer in [('entry', w.EXIT_IP), ('exit', w.ENTRY_IP)]:
            s = dict(role=role, link_private='PRIVATE', peer_public='PUBLIC', psk='PSK',
                     port=51831, exit_ip='8.8.8.8', exit_port=51830)
            config = w.link_config(s)
            self.assertEqual(config.count('[Peer]'), 1)
            self.assertIn('Table = off', config)
            self.assertIn('AllowedIPs = '+peer+'/32', config)
            self.assertNotIn('0.0.0.0/0', config)
            self.assertNotIn('::/0', config)
            self.assertNotIn('FwMark', config)
            self.assertNotIn('PostDown', config)
            self.assertIn('PersistentKeepalive = 25', config)

    def test_outside_can_initiate_and_custom_transport_port_is_retained(self):
        s = dict(role='exit', link_private='PRIVATE', peer_public='PUBLIC', psk='PSK',
                 port=9999, entry_ip='9.9.9.9', entry_port=32123)
        config = w.link_config(s)
        self.assertIn('Endpoint = 9.9.9.9:32123', config)
        self.assertIn('ListenPort = 9999', config)
        self.assertIn('PersistentKeepalive = 25', config)

    def test_only_the_selected_port_is_forwarded(self):
        s = dict(mode=w.MODE, role='entry', wan='eth0', port=51831, exit_ip='8.8.8.8',
                 exit_port=51830, listen_port=8443, target_port=9443, protocol='tcp')
        rules = w.firewall_rules(s)
        dnat = [args for _, chain, args in rules if chain == 'WGB_DNAT']
        self.assertEqual(len(dnat), 1)
        self.assertIn('--dst-type', dnat[0])
        self.assertIn('8443', dnat[0])
        self.assertIn('10.204.0.1:9443', dnat[0])
        guards = [args for _, chain, args in rules if chain == 'WGB_FWD' and '--ctorigdstport' in args]
        self.assertEqual(guards[0][-1], 'ACCEPT')
        self.assertEqual(guards[1][-1], 'REJECT')
        self.assertNotIn('-o', guards[1])
        self.assertFalse(any(parent == 'OUTPUT' for _, parent, _ in w.CHAINS))
        self.assertFalse(any('MARK' in ' '.join(args) for _, _, args in rules))

    def test_busy_port_and_transport_conflict(self):
        import socket
        with socket.socket() as listener:
            listener.bind(('0.0.0.0',0)); listener.listen()
            with self.assertRaises(w.BridgeError): w.free_port(listener.getsockname()[1], 'tcp')
        with self.assertRaises(w.BridgeError):
            w.check_listener(dict(port=51831, listen_port=51831, protocol='both'))
        for bad in ['TCP', 'icmp', '', None]:
            with self.assertRaises(w.BridgeError): w.valid_protocol(bad)

    def test_port_suggestion_retries_busy_and_excluded_ports(self):
        with patch.object(w.secrets, 'randbelow', side_effect=[1, 2, 3]), patch.object(w, 'free_port', side_effect=[w.BridgeError('busy'), None, None]):
            self.assertEqual(w.suggest_port('both', exclude=(20001,)), '20003')


if __name__ == '__main__':
    unittest.main()
