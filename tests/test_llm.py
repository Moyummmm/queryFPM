from __future__ import annotations

import json
import urllib.error
import unittest
from unittest.mock import patch

from fpm_benchmark.llm import DeepSeekClient, LLMInfrastructureError


class _Response:
    def __init__(self, body=None):
        self.body = body
    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        if self.body is not None:
            return json.dumps(self.body).encode('utf-8')
        return json.dumps(
            {
                "choices": [{"message": {"content": '{"status":"ok"}'}}],
                "usage": {"total_tokens": 1},
            }
        ).encode("utf-8")


class DeepSeekClientTest(unittest.TestCase):
    def test_truncation_is_retried_and_all_billable_tokens_are_recorded(self):
        bodies = [{'choices': [{'message': {'content': '{"status":"ok"}'}, 'finish_reason': reason}],
                   'model': 'deepseek-flash', 'system_fingerprint': 'actual-backend',
                   'usage': {'total_tokens': 5, 'prompt_tokens': 3, 'completion_tokens': 2}}
                  for reason in ('length', 'stop')]
        client = DeepSeekClient(api_key='test-key', max_retries=1, retry_base_seconds=0,
                               thinking='disabled', capture_response_metadata=True)
        with patch('urllib.request.urlopen', side_effect=[_Response(x) for x in bodies]) as opened:
            parsed, usage = client.chat_json([{'role':'user','content':'Return JSON'}])
        self.assertEqual(parsed, {'status': 'ok'})
        self.assertEqual(usage['total_tokens'], 10)
        self.assertEqual(usage['_response_metadata']['returned_model'], 'deepseek-flash')
        self.assertEqual(len(usage['_response_metadata']['response_history']), 2)
        self.assertEqual(json.loads(opened.call_args.args[0].data)['thinking'], {'type':'disabled'})

    def test_http_error_body_does_not_leak_credential(self):
        import io
        client = DeepSeekClient(api_key='test-key-secret', max_retries=0)
        error = urllib.error.HTTPError('https://example.test', 401, '', {}, io.BytesIO(b'test-key-secret'))
        with patch('urllib.request.urlopen', side_effect=error):
            with self.assertRaises(LLMInfrastructureError) as raised:
                client.chat_json([{'role':'user','content':'Return JSON'}])
        self.assertNotIn('test-key-secret', str(raised.exception))
    def test_chat_request_has_openai_compatible_headers(self) -> None:
        client = DeepSeekClient(
            api_key="test-key",
            base_url="https://example.test/v1",
            model="deepseek-v4-flash",
            max_retries=0,
        )

        with patch("urllib.request.urlopen", return_value=_Response()) as urlopen:
            result, usage = client.chat_json([{"role": "user", "content": "health"}])

        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "https://example.test/v1/chat/completions")
        self.assertEqual(request.get_header("Authorization"), "Bearer test-key")
        self.assertEqual(request.get_header("Accept"), "application/json")
        self.assertEqual(request.get_header("Content-type"), "application/json")
        self.assertEqual(
            request.get_header("User-agent"),
            "fpm-benchmark/0.1 (OpenAI-compatible API client)",
        )
        self.assertEqual(result, {"status": "ok"})
        self.assertEqual(usage, {"total_tokens": 1})

    def test_transient_failure_is_retried(self) -> None:
        client = DeepSeekClient(
            api_key="test-key",
            base_url="https://example.test",
            max_retries=2,
            retry_base_seconds=0,
        )
        with patch(
            "urllib.request.urlopen",
            side_effect=[urllib.error.URLError("connection reset"), _Response()],
        ) as urlopen:
            result, _ = client.chat_json([{"role": "user", "content": "health"}])
        self.assertEqual(result, {"status": "ok"})
        self.assertEqual(urlopen.call_count, 2)

    def test_non_retryable_http_error_is_classified(self) -> None:
        client = DeepSeekClient(api_key="test-key", base_url="https://example.test")
        error = urllib.error.HTTPError(
            "https://example.test/chat/completions", 405, "", {}, None
        )
        with patch("urllib.request.urlopen", side_effect=error):
            with self.assertRaises(LLMInfrastructureError) as raised:
                client.chat_json([{"role": "user", "content": "health"}])
        self.assertEqual(raised.exception.error_type, "http_405")
        self.assertEqual(raised.exception.attempts, 1)
        self.assertFalse(raised.exception.retryable)


if __name__ == "__main__":
    unittest.main()
