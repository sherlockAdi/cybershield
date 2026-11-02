import importlib.util
import unittest
from unittest.mock import patch
from pathlib import Path

spec = importlib.util.spec_from_file_location('helper', Path(__file__).with_name('linux.py'))
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


class ManagementTests(unittest.TestCase):
    def rule(self, **changes):
        return dict(id='12345678-1234-4234-9234-123456789abc', ip='192.0.2.10', scope='LOGIN', ports=[22], **changes)

    def test_reject_invalid_addresses_ports_and_protected_networks(self):
        for patch_value in [dict(ip='192.0.2.10; reboot'), dict(ip='127.0.0.1'), dict(ip='::'), dict(ip='ff02::1'), dict(ports=[]), dict(ports=[-1]), dict(ports=['22'])]:
            with self.assertRaises(ValueError):
                helper.validate_rule({**self.rule(), **patch_value}, {})
        with self.assertRaises(ValueError):
            helper.validate_rule(self.rule(), {'protectedAddresses': ['192.0.2.0/24']})

    @patch.object(helper, 'run')
    def test_isolated_tcp_rules_cover_host_and_container_ingress(self, run):
        helper.nft_apply(self.rule(), {})
        args, script = run.call_args.args
        self.assertEqual(args, ['/usr/sbin/nft', '-f', '-'])
        self.assertIn('hook prerouting', script)
        self.assertIn('ip saddr 192.0.2.10 tcp dport { 22 }', script)
        self.assertNotIn('flush ruleset', script)

    @patch.object(helper, 'run')
    @patch.object(helper, 'applications')
    def test_stop_rejects_changed_instance_and_unapproved_application(self, applications, run):
        app = dict(id='systemd:demo.service', instance='123', kind='SYSTEMD', stoppable=True, state='active')
        applications.return_value = ([{**app, 'instance': '456'}], [])
        with self.assertRaises(ValueError):
            helper.stop(app, {})
        applications.return_value = ([{**app, 'stoppable': False}], [])
        with self.assertRaises(ValueError):
            helper.stop(app, {})
        run.assert_not_called()

    @patch.object(helper, 'run')
    @patch.object(helper, 'applications')
    def test_stop_checks_result(self, applications, run):
        app = dict(id='systemd:demo.service', instance='123', kind='SYSTEMD', stoppable=True, state='active')
        applications.side_effect = [([app], []), ([{**app, 'state': 'inactive'}], [])]
        helper.stop(app, {})
        run.assert_called_once_with(['/usr/bin/systemctl', 'stop', '--', 'demo.service'])
        applications.side_effect = [([app], []), ([app], [])]
        with self.assertRaises(ValueError):
            helper.stop(app, {})


if __name__ == '__main__':
    unittest.main()
