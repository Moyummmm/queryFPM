"""Persisted concurrent runs must retain all alerts and retry only infrastructure failures."""
import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from fpm_benchmark.llm import LLMInfrastructureError
from fpm_benchmark.revision_cli import main

class ConcurrentRunTests(unittest.TestCase):
    def test_concurrent_checkpoint_resume_has_no_missing_or_duplicate_alerts(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            manifest = root / 'templates.json'
            manifest.write_text('{"templates":[]}', encoding='utf-8')
            config = root / 'config.json'
            config.write_text(json.dumps({'manifest': str(manifest), 'database': None, 'workers': 4,
                'llm': {'base_url': 'https://example.test', 'model': 'test', 'api_key_env': 'TEST_KEY'}}), encoding='utf-8')
            inputs = root / 'input.jsonl'
            inputs.write_text('\n'.join(json.dumps({'alert_id': str(i), 'alert_contract': {'cwe': 'CWE-089'},
                'ground_truth': {'alert_expected_vulnerable': bool(i % 2)}}) for i in range(8)), encoding='utf-8')
            out = root / 'output.jsonl'
            calls = []
            mutex = threading.Lock()
            class Client:
                failing = True
                def chat_json(self, messages, **kwargs):
                    with mutex:
                        number = len(calls)
                        calls.append(number)
                    time.sleep(.005 * (3 - number % 4))
                    if number == 0 and self.failing:
                        raise LLMInfrastructureError('transient', error_type='network', attempts=1, retryable=True)
                    return {'verdict': 'TP', 'sufficient': True, 'missing_evidence': [],
                            'next_query': {'template_id': None, 'parameters': {}}, 'reason_summary': 'test'}, {}
            client = Client()
            command = ['run', '--config', str(config), '--input', str(inputs), '--out', str(out),
                       '--method', 'matched_one_shot', '--budget', '0']
            with patch('fpm_benchmark.revision_cli.make_client', return_value=client):
                self.assertEqual(main(command), 2)
                self.assertEqual(len(calls), 8)
                # Simulate an interrupted final append. Durable per-alert records recover it.
                with out.open('a', encoding='utf-8') as journal:
                    journal.write('{interrupted')
                client.failing = False
                self.assertEqual(main(command + ['--resume']), 0)
            rows = [json.loads(line) for line in out.read_text(encoding='utf-8').splitlines()]
            self.assertEqual([r['alert_id'] for r in rows], [str(i) for i in range(8)])
            self.assertEqual(len(calls), 9)
            self.assertEqual(len(list(root.glob('*.failed_attempts.*.jsonl'))), 1)
            self.assertTrue(json.loads(out.with_suffix('.manifest.json').read_text())['complete'])

if __name__ == '__main__':
    unittest.main()
