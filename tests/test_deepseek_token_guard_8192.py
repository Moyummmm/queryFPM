from __future__ import annotations

import json
import http.client
import tempfile
import threading
import unittest
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from fpm_benchmark import deepseek_token_guard_8192 as guard
from fpm_benchmark import revision_runner
from fpm_benchmark.llm import DeepSeekClient, LLMInfrastructureError

MESSAGES = [{'role': 'system', 'content': 'system'}, {'role': 'user', 'content': 'user'}]
VALIDATE = guard.ExactDeepSeekCounter.validate


class Counter:
    request = staticmethod(guard.ExactDeepSeekCounter.request)

    def __init__(self, counts):
        self.counts = list(counts)
        self.last = self.counts[-1]

    def count_request(self, body):
        VALIDATE(body)
        count = self.counts.pop(0) if self.counts else self.last
        return {'prompt_tokens': count, 'request_sha256': guard._digest_json(body),
                'encoder_version': guard.VERSION, 'tokenizer_sha256': guard.TOKENIZER_SHA256}


class Response:
    def __init__(self, prompt_tokens, *, finish='stop', model='deepseek-flash'):
        self.data = {'model': model, 'system_fingerprint': 'synthetic',
          'choices': [{'message': {'content': '{"verdict":"FP","sufficient":true}'},
                       'finish_reason': finish}],
          'usage': {'prompt_tokens': prompt_tokens, 'completion_tokens': 1,
                    'total_tokens': prompt_tokens + 1}}

    def __enter__(self): return self
    def __exit__(self, *args): return None
    def read(self): return json.dumps(self.data).encode()


class BrokenResponse:
    def __init__(self, mode): self.mode = mode
    def __enter__(self): return self
    def __exit__(self, *args): return None
    def read(self):
        if self.mode == 'incomplete':
            raise http.client.IncompleteRead(b'partial')
        return b'not-json' if self.mode == 'json' else b'{}'


class Transport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    def open(self, request, timeout=None):
        self.calls += 1
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def client_and_transport(responses):
    client = DeepSeekClient(api_key='OFFLINE_SYNTHETIC_KEY', base_url='https://api.deepseek.com',
        model='deepseek-v4-flash', thinking='disabled', capture_response_metadata=True,
        use_environment_proxy=False, retry_base_seconds=0, retry_max_seconds=0, max_retries=2)
    transport = Transport(responses)
    client.opener = transport
    return client, transport


class TokenGuardTest(unittest.TestCase):
    def install(self, client, counts, events, before_attempt=None):
        with patch.object(guard, 'ExactDeepSeekCounter', return_value=Counter(counts)), \
             patch.object(guard, 'DirectNoRedirectOpener', Transport):
            return guard.install_guard(client, '/not-used-by-fake-counter', audit_sink=events.append,
                                       before_attempt=before_attempt)

    def test_limit_8192_is_sent_and_verified(self):
        client, transport = client_and_transport([Response(8192)])
        events = []; self.install(client, [8192], events)
        result, usage = client.chat_json(MESSAGES, temperature=0, max_tokens=8192)
        self.assertEqual(result['verdict'], 'FP')
        self.assertEqual(transport.calls, 1)
        self.assertTrue(usage['_token_budget']['ok'])
        self.assertEqual([x['event'] for x in events],
                         ['token_pre_dispatch', 'token_response_received', 'token_post_response'])

    def test_limit_8193_is_rejected_before_transport(self):
        client, transport = client_and_transport([])
        events = []; self.install(client, [8193], events)
        with self.assertRaises(LLMInfrastructureError) as raised:
            client.chat_json(MESSAGES, temperature=0, max_tokens=8192)
        self.assertEqual(raised.exception.error_type, 'CONTEXT_LIMIT')
        self.assertFalse(raised.exception.retryable)
        self.assertEqual(transport.calls, 0)
        self.assertFalse(events[0]['dispatch_allowed'])

    def test_each_retry_rechecks_the_actual_request(self):
        client, transport = client_and_transport([urllib.error.URLError('reset'), Response(8192)])
        events = []; attempts = []; self.install(client, [8192], events, lambda: attempts.append(True))
        client.chat_json(MESSAGES, temperature=0, max_tokens=8192)
        self.assertEqual(transport.calls, 2)
        self.assertEqual(len(attempts), 2)
        self.assertEqual(sum(x['event'] == 'token_pre_dispatch' for x in events), 2)

    def test_retry_that_would_exceed_limit_is_not_sent(self):
        client, transport = client_and_transport([urllib.error.URLError('reset'), Response(8192)])
        events = []; self.install(client, [8192, 8192, 8193], events)
        with self.assertRaises(LLMInfrastructureError) as raised:
            client.chat_json(MESSAGES, temperature=0, max_tokens=8192)
        self.assertEqual(raised.exception.error_type, 'CONTEXT_LIMIT')
        self.assertEqual(transport.calls, 1)
        self.assertFalse(events[-1]['dispatch_allowed'])

    def test_usage_is_checked_per_response_not_retry_sum(self):
        client, transport = client_and_transport([Response(8192, finish='length'), Response(8192)])
        events = []; self.install(client, [8192], events)
        _, usage = client.chat_json(MESSAGES, temperature=0, max_tokens=8192)
        self.assertEqual(transport.calls, 2)
        self.assertEqual(usage['prompt_tokens'], 16384)
        self.assertTrue(usage['_token_budget']['ok'])
        self.assertEqual(len(usage['_token_budget']['responses']), 2)

    def test_complete_response_before_exit_error_is_checked_and_counted(self):
        class ExitErrorResponse(Response):
            def __exit__(self, *args):
                raise OSError('synthetic exit failure')
        client, transport = client_and_transport([ExitErrorResponse(9000), Response(2)])
        events = []; self.install(client, [2], events)
        with self.assertRaises(LLMInfrastructureError) as raised:
            client.chat_json(MESSAGES)
        self.assertEqual(raised.exception.error_type, 'ACTUAL_INPUT_TOKEN_LIMIT_EXCEEDED')
        self.assertEqual(raised.exception.usage['prompt_tokens'], 9002)
        self.assertEqual(len(raised.exception.usage['_response_metadata']['response_history']), 2)
        self.assertEqual(transport.calls, 2)
        self.assertFalse(events[-1]['ok'])

    def test_provider_usage_drift_fails_closed(self):
        client, transport = client_and_transport([Response(8191)])
        events = []; self.install(client, [8192], events)
        with self.assertRaises(LLMInfrastructureError) as raised:
            client.chat_json(MESSAGES, temperature=0, max_tokens=8192)
        self.assertEqual(raised.exception.error_type, 'TOKENIZER_PROVIDER_DRIFT')
        self.assertEqual(transport.calls, 1)
        self.assertFalse(events[-1]['ok'])

    def test_missing_or_malformed_provider_usage_fails_closed(self):
        for usage in ({}, {'_response_metadata': {'response_history': [{'usage': 'bad'}]}},
                      {'_response_metadata': {'response_history': [{'usage': {'prompt_tokens': 1},
                                                                     'returned_model': []}]}}):
            check = guard._check_usage(usage, 1)
            self.assertFalse(check['ok'])

    def test_post_audit_rejects_untrusted_metadata(self):
        secret = 'OFFLINE_SYNTHETIC_KEY'
        usage = {'_response_metadata': {'response_history': [{
            'attempt': secret, 'returned_model': secret,
            'usage': {'prompt_tokens': secret}}]}}
        check = guard._check_usage(usage, 2)
        self.assertFalse(check['ok'])
        self.assertEqual(check['error_type'], 'TOKEN_USAGE_UNAVAILABLE')
        self.assertNotIn(secret, json.dumps(check))
        self.assertIsNone(check['responses'][0]['attempt'])
        self.assertIsNone(check['responses'][0]['returned_model'])
        self.assertIsNone(check['responses'][0]['actual_prompt_tokens'])

        response = Response(2, model=secret)
        client, _ = client_and_transport([response])
        events = []; self.install(client, [2], events)
        with self.assertRaises(LLMInfrastructureError) as raised:
            client.chat_json(MESSAGES)
        self.assertEqual(raised.exception.error_type, 'TOKENIZER_PROVIDER_DRIFT')
        self.assertNotIn(secret, json.dumps(events))
        self.assertIsNone(events[-1]['responses'][0]['returned_model'])

    def test_late_audit_failure_retains_received_usage(self):
        for responses, failing_event, expected_attempts in (
            ([Response(2)], 'token_post_response', 1),
            ([Response(2, finish='length'), BrokenResponse('incomplete')], 'token_post_failure', 2),
        ):
            with self.subTest(event=failing_event):
                client, transport = client_and_transport(responses)
                def sink(event):
                    if event['event'] == failing_event:
                        raise OSError('synthetic sink failure')
                with patch.object(guard, 'ExactDeepSeekCounter', return_value=Counter([2])), \
                     patch.object(guard, 'DirectNoRedirectOpener', Transport):
                    guard.install_guard(client, '/unused', audit_sink=sink)
                with self.assertRaises(LLMInfrastructureError) as raised:
                    client.chat_json(MESSAGES)
                self.assertEqual(raised.exception.error_type, 'TOKEN_AUDIT_FAILURE')
                self.assertFalse(raised.exception.retryable)
                self.assertEqual(raised.exception.usage['prompt_tokens'], 2)
                self.assertEqual(raised.exception.attempts, expected_attempts)
                self.assertEqual(transport.calls, expected_attempts)

    def test_late_audit_failure_retains_only_captured_safe_usage(self):
        response = Response(2, model='OFFLINE_SYNTHETIC_KEY')
        response.data['usage']['untrusted'] = 'OFFLINE_SYNTHETIC_KEY'
        client, _ = client_and_transport([response])
        def sink(event):
            if event['event'] == 'token_post_response':
                raise OSError('synthetic sink failure')
        with patch.object(guard, 'ExactDeepSeekCounter', return_value=Counter([2])), \
             patch.object(guard, 'DirectNoRedirectOpener', Transport):
            guard.install_guard(client, '/unused', audit_sink=sink)
        with self.assertRaises(LLMInfrastructureError) as raised:
            client.chat_json(MESSAGES)
        self.assertEqual(raised.exception.error_type, 'TOKEN_AUDIT_FAILURE')
        self.assertEqual(raised.exception.usage['prompt_tokens'], 2)
        self.assertNotIn('OFFLINE_SYNTHETIC_KEY', json.dumps(raised.exception.usage))

    def test_missing_pinned_tokenizer_does_not_modify_client(self):
        client, transport = client_and_transport([])
        original_chat = client.chat_json; original_opener = client.opener
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(guard, 'DirectNoRedirectOpener', Transport):
                with self.assertRaises(guard.GuardConfigurationError):
                    guard.install_guard(client, directory)
        self.assertEqual(client.chat_json, original_chat)
        self.assertIs(client.opener, original_opener)
        self.assertEqual(transport.calls, 0)

    def test_unsupported_client_is_rejected_before_loading_assets(self):
        client, transport = client_and_transport([])
        original = client.opener; client.thinking = 'enabled'
        with patch.object(guard, 'ExactDeepSeekCounter') as factory:
            with self.assertRaises(guard.GuardConfigurationError):
                guard.install_guard(client, '/irrelevant')
        factory.assert_not_called()
        self.assertIs(client.opener, original)
        self.assertEqual(transport.calls, 0)

    def test_token_audit_failure_blocks_dispatch(self):
        client, transport = client_and_transport([Response(2)])
        def broken(event): raise OSError('synthetic audit error')
        with patch.object(guard, 'ExactDeepSeekCounter', return_value=Counter([2])), \
             patch.object(guard, 'DirectNoRedirectOpener', Transport):
            guard.install_guard(client, '/unused', audit_sink=broken)
        with self.assertRaises(LLMInfrastructureError) as raised:
            client.chat_json(MESSAGES)
        self.assertEqual(raised.exception.error_type, 'TOKEN_AUDIT_FAILURE')
        self.assertEqual(transport.calls, 0)

    def test_time_or_other_policy_can_block_before_transport(self):
        client, transport = client_and_transport([Response(2)])
        events = []
        def blocked(): raise RuntimeError('synthetic closed window')
        self.install(client, [2], events, blocked)
        with self.assertRaises(LLMInfrastructureError) as raised:
            client.chat_json(MESSAGES)
        self.assertEqual(raised.exception.error_type, 'PRE_DISPATCH_BLOCKED')
        self.assertEqual(transport.calls, 0)
        self.assertFalse(events[-1]['dispatch_allowed'])

    def test_redirect_handler_rejects_without_following(self):
        with self.assertRaises(LLMInfrastructureError) as raised:
            guard._RejectRedirect().redirect_request(None, None, 302, '', {}, 'https://other.example/')
        self.assertEqual(raised.exception.error_type, 'REDIRECT_BLOCKED')

    def test_default_redirect_capable_transport_is_not_accepted(self):
        client, transport = client_and_transport([])
        with patch.object(guard, 'ExactDeepSeekCounter') as factory:
            with self.assertRaises(guard.GuardConfigurationError):
                guard.install_guard(client, '/irrelevant')
        factory.assert_not_called()
        self.assertIs(client.opener, transport)

    def test_noncallable_audit_sink_is_rejected_during_setup(self):
        client, transport = client_and_transport([])
        with patch.object(guard, 'DirectNoRedirectOpener', Transport), \
             patch.object(guard, 'ExactDeepSeekCounter') as factory:
            with self.assertRaises(guard.GuardConfigurationError):
                guard.install_guard(client, '/irrelevant', audit_sink='not-callable')
        factory.assert_not_called()
        self.assertIs(client.opener, transport)

    def test_response_audit_failure_keeps_usage_and_does_not_retry(self):
        client, transport = client_and_transport([Response(2)])
        def broken_after_response(event):
            if event['event'] == 'token_response_received': raise OSError('synthetic failure')
        with patch.object(guard, 'ExactDeepSeekCounter', return_value=Counter([2])), \
             patch.object(guard, 'DirectNoRedirectOpener', Transport):
            guard.install_guard(client, '/unused', audit_sink=broken_after_response)
        with self.assertRaises(LLMInfrastructureError) as raised:
            client.chat_json(MESSAGES)
        self.assertEqual(raised.exception.error_type, 'TOKEN_AUDIT_FAILURE')
        self.assertEqual(raised.exception.usage['prompt_tokens'], 2)
        self.assertEqual(len(raised.exception.usage['_response_metadata']['response_history']), 1)
        self.assertEqual(transport.calls, 1)

    def test_prior_usage_survives_later_incomplete_read_in_same_call(self):
        client, transport = client_and_transport([Response(2, finish='length'), BrokenResponse('incomplete')])
        events = []; self.install(client, [2], events)
        with self.assertRaises(LLMInfrastructureError) as raised:
            client.chat_json(MESSAGES)
        self.assertEqual(raised.exception.error_type, 'MODEL_CLIENT_FAILURE')
        self.assertFalse(raised.exception.retryable)
        self.assertEqual(raised.exception.usage['prompt_tokens'], 2)
        self.assertEqual(len(raised.exception.usage['_response_metadata']['response_history']), 1)
        self.assertEqual(transport.calls, 2)
        self.assertEqual(sum(x['event'] == 'token_response_received' for x in events), 1)

    def test_immediate_audit_omits_prompt_response_and_credential(self):
        response = Response(2)
        response.data['system_fingerprint'] = 'OFFLINE_SYNTHETIC_KEY'
        response.data['usage']['untrusted_text'] = 'OFFLINE_SYNTHETIC_KEY'
        response.data['choices'][0]['message']['content'] = '{"note":"RESPONSE_PRIVATE_MARKER"}'
        client, _ = client_and_transport([response])
        events = []; self.install(client, [2], events)
        client.chat_json([{'role': 'system', 'content': 's'},
                          {'role': 'user', 'content': 'USER_PRIVATE_MARKER'}])
        captured = json.dumps(events)
        for value in ('OFFLINE_SYNTHETIC_KEY', 'RESPONSE_PRIVATE_MARKER', 'USER_PRIVATE_MARKER'):
            self.assertNotIn(value, captured)
        self.assertIsNone(next(x for x in events if x['event'] == 'token_response_received')['system_fingerprint'])

    def test_concurrent_calls_keep_response_metadata_thread_local(self):
        barrier = threading.Barrier(2)
        class ConcurrentTransport(Transport):
            def __init__(self): super().__init__([])
            def open(self, request, timeout=None):
                self.calls += 1
                body = json.loads(request.data.decode())
                marker = body['messages'][1]['content']
                response = Response(2)
                response.data['system_fingerprint'] = 'fingerprint-' + marker
                barrier.wait(timeout=5)
                return response
        client, _ = client_and_transport([])
        transport = ConcurrentTransport(); client.opener = transport
        events = []; event_lock = threading.Lock()
        def save(event):
            with event_lock: events.append(event)
        with patch.object(guard, 'ExactDeepSeekCounter', return_value=Counter([2])), \
             patch.object(guard, 'DirectNoRedirectOpener', ConcurrentTransport):
            guard.install_guard(client, '/unused', audit_sink=save)
        def call(marker):
            messages = [{'role':'system','content':'s'}, {'role':'user','content':marker}]
            _, usage = client.chat_json(messages)
            return guard._digest_json(guard.ExactDeepSeekCounter.request(
                messages, model=client.model, temperature=0, max_tokens=1200)), usage
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(call, ('alpha', 'beta')))
        received = {x['request_sha256']: x['system_fingerprint'] for x in events
                    if x['event'] == 'token_response_received'}
        self.assertEqual(len(received), 2)
        self.assertEqual(received[results[0][0]], 'fingerprint-alpha')
        self.assertEqual(received[results[1][0]], 'fingerprint-beta')
        self.assertTrue(all(usage['_token_budget']['ok'] for _, usage in results))

    def test_controller_keeps_alert_on_guard_failure(self):
        client, transport = client_and_transport([])
        events = []; self.install(client, [8193], events)
        evidence = {'alert_id': 'case-1', 'alert_contract': {'cwe': 'CWE-089',
                    'primary_location': {'file': 'Case.java', 'start_line': 10, 'start_column': 5}},
                    'evidence_slots': {}, 'query_history': []}
        with patch.object(revision_runner, 'messages', return_value=MESSAGES):
            result = revision_runner.triage_record(evidence, client=client,
                manifest={'templates': []}, cfg={'max_output_tokens': 8192}, budget=0)
        self.assertEqual(result['decision']['verdict'], 'INFRA_ERROR')
        self.assertEqual(result['operation'], 'KEEP')
        self.assertIn('llm_failure', result['infrastructure_errors'])
        self.assertEqual(transport.calls, 0)

    def test_controller_keeps_alert_on_provider_drift_after_response(self):
        client, transport = client_and_transport([Response(8191)])
        events = []; self.install(client, [8192], events)
        evidence = {'alert_id': 'case-1', 'alert_contract': {'cwe': 'CWE-089',
                    'primary_location': {'file': 'Case.java', 'start_line': 10, 'start_column': 5}},
                    'evidence_slots': {}, 'query_history': []}
        with patch.object(revision_runner, 'messages', return_value=MESSAGES):
            result = revision_runner.triage_record(evidence, client=client,
                manifest={'templates': []}, cfg={'max_output_tokens': 8192}, budget=0)
        self.assertEqual(result['decision']['verdict'], 'INFRA_ERROR')
        self.assertEqual(result['operation'], 'KEEP')
        self.assertEqual(transport.calls, 1)
        self.assertFalse(events[-1]['ok'])

    def test_controller_keeps_alert_on_truncated_or_malformed_response(self):
        for mode in ('incomplete', 'json', 'missing_choices'):
            with self.subTest(mode=mode):
                client, transport = client_and_transport([BrokenResponse(mode)])
                events = []; self.install(client, [2], events)
                evidence = {'alert_id': 'case-1', 'alert_contract': {'cwe': 'CWE-089',
                    'primary_location': {'file': 'Case.java', 'start_line': 10, 'start_column': 5}},
                    'evidence_slots': {}, 'query_history': []}
                with patch.object(revision_runner, 'messages', return_value=MESSAGES):
                    result = revision_runner.triage_record(evidence, client=client,
                        manifest={'templates': []}, cfg={'max_output_tokens': 8192}, budget=0)
                self.assertEqual(result['decision']['verdict'], 'INFRA_ERROR')
                self.assertEqual(result['operation'], 'KEEP')
                self.assertEqual(transport.calls, 1)

    def test_unsupported_payload_is_rejected_without_dispatch(self):
        client, transport = client_and_transport([])
        events = []; self.install(client, [2], events)
        with self.assertRaises(LLMInfrastructureError) as raised:
            client.chat_json([{'role': 'user', 'content': 'single message'}])
        self.assertEqual(raised.exception.error_type, 'TOKENIZER_CONTRACT_ERROR')
        self.assertEqual(transport.calls, 0)


if __name__ == '__main__':
    unittest.main()
