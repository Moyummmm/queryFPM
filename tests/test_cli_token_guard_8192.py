import json
import os
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from fpm_benchmark import deepseek_token_guard_8192 as guard
from fpm_benchmark import revision_cli
from test_deepseek_token_guard_8192 import Counter, Response, Transport, client_and_transport


class GuardCliTests(unittest.TestCase):
    def config(self, root):
        manifest = root / 'templates.json'
        manifest.write_text('{"templates":[]}', encoding='utf-8')
        cfg = {'manifest': str(manifest), 'database': None, 'workers': 1,
               'llm': {'base_url': 'https://api.deepseek.com', 'model': 'deepseek-v4-flash',
                       'api_key_env': 'SYNTHETIC_UNUSED', 'thinking': 'disabled',
                       'use_environment_proxy': False,
                       'input_token_guard': {'enabled': True, 'assets_root': str(root / 'missing')}}}
        config = root / 'config.json'
        config.write_text(json.dumps(cfg), encoding='utf-8')
        inputs = root / 'input.jsonl'
        inputs.write_text(json.dumps({'alert_id': 'a', 'alert_contract': {'cwe': 'CWE-089'},
                       'ground_truth': {'alert_expected_vulnerable': False}}) + '\n', encoding='utf-8')
        out = root / 'not-created' / 'out.jsonl'
        args = ['run', '--config', str(config), '--input', str(inputs), '--out', str(out),
                '--method', 'matched_one_shot', '--budget', '0']
        return cfg, config, out, args

    def test_missing_assets_allow_only_coordination_lock_and_no_results(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); _, _, out, args = self.config(root)
            client, transport = client_and_transport([])
            with patch.object(revision_cli, 'make_client', return_value=client):
                with self.assertRaises(guard.GuardConfigurationError):
                    revision_cli.main(args)
            self.assertEqual(sorted(p.name for p in out.parent.iterdir()),
                             ['.fpm-output.lock', out.name + '.run.lock'])
            self.assertFalse(out.exists())
            self.assertFalse(out.with_suffix('.manifest.json').exists())
            self.assertFalse(out.with_suffix('.records').exists())
            self.assertEqual(transport.calls, 0)

    def test_disabled_guard_does_not_create_client_or_import_assets(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); cfg, _, out, _ = self.config(root)
            cfg['llm'].pop('input_token_guard')
            with patch.object(revision_cli, 'make_client', side_effect=AssertionError('should not construct')):
                self.assertEqual(revision_cli._prepare_token_guard(cfg, out, False), (None, None))
                cfg['llm']['input_token_guard'] = {'enabled': False}
                self.assertEqual(revision_cli._prepare_token_guard(cfg, out, False), (None, None))

    def test_bad_configuration_fails_before_client_or_output(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); cfg, _, out, _ = self.config(root)
            for settings in ({'enabled': 'true'}, {'enabled': True, 'assets_root': 'relative'},
                             {'enabled': True, 'assets_root': str(root), 'extra': 1}):
                cfg['llm']['input_token_guard'] = settings
                with self.assertRaises(ValueError):
                    revision_cli._prepare_token_guard(cfg, out, False)
            cfg['llm']['input_token_guard'] = {'enabled': True, 'assets_root': str(root)}
            cfg['llm']['use_environment_proxy'] = True
            with self.assertRaises(ValueError):
                revision_cli._prepare_token_guard(cfg, out, False)
            self.assertFalse(out.parent.exists())

    def test_sink_serializes_concurrent_events(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'audit.jsonl'
            sink = revision_cli._TokenAuditSink(path)
            with ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(lambda i: sink({'event': 'test', 'index': i}), range(100)))
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual(sorted(r['index'] for r in rows), list(range(100)))

    def test_install_pins_are_manifest_metadata_and_no_request(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); cfg, _, out, _ = self.config(root)
            client, _ = client_and_transport([])
            class EmptyTransport(Transport):
                def __init__(self): super().__init__([])
            with patch.object(revision_cli, 'make_client', return_value=client), \
                 patch.object(guard, 'ExactDeepSeekCounter', return_value=Counter([2])), \
                 patch.object(guard, 'DirectNoRedirectOpener', EmptyTransport):
                prepared, metadata = revision_cli._prepare_token_guard(cfg, out, False)
            self.assertIs(prepared, client)
            self.assertEqual(metadata['asset_sha256'], guard.PINS)
            self.assertEqual(metadata['limit'], 8192)
            self.assertEqual(client.opener.opener.calls, 0)
            self.assertFalse(out.parent.exists())

    def test_enabled_fake_run_freezes_guard_and_resumes(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); _, _, out, args = self.config(root)
            class FakeTransport(Transport):
                calls_total = 0
                def __init__(self): super().__init__([])
                def open(self, request, timeout=None):
                    type(self).calls_total += 1
                    response = Response(2)
                    response.data['choices'][0]['message']['content'] = json.dumps({
                        'verdict': 'TP', 'sufficient': True, 'missing_evidence': [],
                        'next_query': None, 'reason_summary': 'synthetic'})
                    return response
            def new_client(_):
                return client_and_transport([])[0]
            with patch.object(revision_cli, 'make_client', side_effect=new_client), \
                 patch.object(guard, 'ExactDeepSeekCounter', side_effect=lambda _: Counter([2])), \
                 patch.object(guard, 'DirectNoRedirectOpener', FakeTransport):
                self.assertEqual(revision_cli.main(args), 0)
                self.assertEqual(revision_cli.main(args + ['--resume']), 0)
            self.assertEqual(FakeTransport.calls_total, 1)
            saved = json.loads(out.with_suffix('.manifest.json').read_text())
            self.assertEqual(saved['frozen']['input_token_guard']['asset_sha256'], guard.PINS)
            self.assertTrue(saved['complete'])
            events = [json.loads(x) for x in out.with_suffix('.token_audit.jsonl').read_text().splitlines()]
            self.assertEqual([x['event'] for x in events],
                             ['token_pre_dispatch', 'token_response_received', 'token_post_response'])

if __name__ == '__main__':
    unittest.main()
