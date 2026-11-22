from __future__ import annotations

import json
import os
import random
import re
import threading
import time
import urllib.error
import urllib.request
from typing import Any


class LLMInfrastructureError(RuntimeError):
    def __init__(self, message: str, *, error_type: str, attempts: int, retryable: bool,
                 usage: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.error_type = error_type
        self.attempts = attempts
        self.retryable = retryable
        self.usage = usage or {}


_retry_limiters: dict[int, threading.BoundedSemaphore] = {}
_retry_limiters_lock = threading.Lock()


def _retry_limiter(limit: int) -> threading.BoundedSemaphore:
    with _retry_limiters_lock:
        return _retry_limiters.setdefault(limit, threading.BoundedSemaphore(limit))


class DeepSeekClient:
    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str = "deepseek-v4-flash",
        timeout: int = 90,
        max_retries: int = 2,
        retry_concurrency: int = 16,
        retry_base_seconds: float = 2.0,
        retry_max_seconds: float = 30.0,
        thinking: str | None = None,
        capture_response_metadata: bool = False,
        use_environment_proxy: bool = True,
    ) -> None:
        self.api_key = api_key or os.environ.get("DEEPSEEK_API_KEY")
        self.base_url = (base_url or os.environ.get("DEEPSEEK_BASE_URL") or "https://api.deepseek.com").rstrip("/")
        self.model = model
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_limiter = _retry_limiter(max(1, retry_concurrency))
        self.retry_base_seconds = max(0.0, retry_base_seconds)
        self.retry_max_seconds = max(self.retry_base_seconds, retry_max_seconds)
        if thinking not in (None, 'enabled', 'disabled'):
            raise ValueError('thinking must be enabled/disabled or omitted')
        self.thinking = thinking
        self.capture_response_metadata = capture_response_metadata
        self.opener = None if use_environment_proxy else urllib.request.build_opener(urllib.request.ProxyHandler({}))
        if not self.api_key:
            raise RuntimeError("DEEPSEEK_API_KEY is not set")

    def chat_json(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float = 0,
        max_tokens: int = 1200,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "response_format": {"type": "json_object"},
        }
        if self.thinking is not None:
            payload['thinking'] = {'type': self.thinking}
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "fpm-benchmark/0.1 (OpenAI-compatible API client)",
            },
            method="POST",
        )
        last_error: Exception | None = None
        malformed_content = ""
        retry_after_seconds: float | None = None
        attempts = self.max_retries + 1
        response_history = []
        spent = {}
        def recorded_usage(current=None):
            if not self.capture_response_metadata:
                return dict(current or {})
            output = dict(spent)
            output['_response_metadata'] = {
                'requested_model': self.model, 'thinking': self.thinking,
                'returned_model': response_history[-1].get('returned_model') if response_history else None,
                'system_fingerprint': response_history[-1].get('system_fingerprint') if response_history else None,
                'attempts': len(response_history), 'response_history': response_history,
            }
            return output
        for attempt in range(attempts):
            try:
                # Initial calls use the experiment worker limit. Retries use a
                # much smaller shared lane to avoid a synchronized retry storm.
                limiter = self.retry_limiter if attempt else _NullSemaphore()
                with limiter:
                    open_request = urllib.request.urlopen if self.opener is None else self.opener.open
                    with open_request(request, timeout=self.timeout) as response:
                        raw = json.loads(response.read().decode("utf-8"))
                choice = raw['choices'][0]
                content = choice['message'].get('content') or ''
                usage = dict(raw.get('usage', {}))
                if self.capture_response_metadata:
                    for key, value in usage.items():
                        if isinstance(value, int):
                            spent[key] = spent.get(key, 0) + value
                    response_history.append({
                        'attempt': attempt + 1, 'returned_model': raw.get('model'),
                        'system_fingerprint': raw.get('system_fingerprint'),
                        'response_id': raw.get('id'), 'created': raw.get('created'),
                        'finish_reason': choice.get('finish_reason'), 'usage': usage,
                        'raw_content': content.replace(self.api_key, '[REDACTED]'),
                    })
                try:
                    if choice.get('finish_reason') not in (None, 'stop'):
                        raise ValueError('Model response was interrupted or truncated')
                    return extract_json_object(content), recorded_usage(usage)
                except ValueError as exc:
                    malformed_content = content
                    last_error = exc
            except urllib.error.HTTPError as exc:
                body = exc.read().decode("utf-8", errors="replace").replace(self.api_key, '[REDACTED]')
                if exc.code < 500 and exc.code != 429:
                    raise LLMInfrastructureError(
                        f"DeepSeek API error {exc.code}: {body}",
                        error_type=f"http_{exc.code}",
                        attempts=attempt + 1,
                        retryable=False,
                        usage=recorded_usage(),
                    ) from exc
                last_error = RuntimeError(f"DeepSeek API error {exc.code}: {body}")
                retry_after_seconds = _retry_after(exc)
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last_error = exc
            if attempt < self.max_retries:
                delay = min(self.retry_max_seconds, self.retry_base_seconds * (2**attempt))
                if retry_after_seconds is not None:
                    delay = max(delay, min(self.retry_max_seconds, retry_after_seconds))
                time.sleep(delay * random.uniform(0.75, 1.25))

        if malformed_content or isinstance(last_error, ValueError):
            parsed = {
                "verdict": "UNKNOWN",
                "confidence": "low",
                "sufficient": False,
                "missing_evidence": ["MALFORMED_LLM_OUTPUT"],
                "next_query": {"template_id": None, "parameters": {}, "reason": ""},
                "reason_summary": "LLM response was not valid JSON: " + malformed_content[:300],
            }
            return parsed, recorded_usage()
        raise LLMInfrastructureError(
            f"DeepSeek API request failed after retries: {last_error}",
            error_type=_error_type(last_error),
            attempts=attempts,
            retryable=True,
            usage=recorded_usage(),
        ) from last_error


class _NullSemaphore:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *args: object) -> None:
        return None


def _error_type(error: Exception | None) -> str:
    text = str(error or "").lower()
    if "429" in text:
        return "rate_limit"
    if "connection reset" in text:
        return "connection_reset"
    if "ssl" in text or "eof" in text:
        return "tls_error"
    if "timed out" in text or "timeout" in text:
        return "timeout"
    if re.search(r"\b5\d\d\b", text):
        return "server_error"
    return "network_error"


def _retry_after(error: urllib.error.HTTPError) -> float | None:
    value = error.headers.get("Retry-After") if error.headers else None
    if value is None:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        return None


def extract_json_object(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass
    m = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if not m:
        raise ValueError("LLM response did not contain a JSON object")
    obj = json.loads(m.group(0))
    if not isinstance(obj, dict):
        raise ValueError("LLM response JSON is not an object")
    return obj
