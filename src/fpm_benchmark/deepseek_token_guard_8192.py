"""Optional DeepSeek V4.1 input-token guard; never installed automatically.

This adapter supports only the experiment's non-thinking JSON requests with
one system and one user message. Call :func:`install_guard` explicitly before
using a client. It requires the exact, locally provisioned tokenizer assets;
it never downloads them. Missing/mismatched assets or unexpected request and
response formats fail closed as infrastructure errors. This module uses only
the standard library unless the optional, pinned tokenizer is requested.

Provider model aliases are not immutable versions. Provider token-count drift
is detected after a response and invalidates that result; it cannot undo an
already sent request. Failed attempts with no returned usage remain unknown.
"""
from __future__ import annotations

import copy
import hashlib
import importlib
import json
import re
import sys
import threading
import urllib.request
from pathlib import Path

from .llm import LLMInfrastructureError

MAX_INPUT_TOKENS = 8192
VERSION = 'deepseek-v41-exact-input-guard-v1-8192'
TOKENIZER_SHA256 = 'c90dfa01249db1be4245780a052ede752e1361c612ac6d08e2bdada7d599476b'
MODELS = frozenset({'deepseek-v4-flash', 'deepseek-flash', 'DeepSeek-V4.1-Flash-1017'})
PINS = {
    'hf_v41_flash1017/tokenizer.json': TOKENIZER_SHA256,
    'deepseek_recipe-0.2.0-cp310-abi3-manylinux_2_28_x86_64.whl': '259812bf382bc82668b672707c5922095cc4f5f60a6c514ff89640bb62a746f7',
    'python_deps/deepseek_recipe/__init__.py': 'af06cc19cc216a6db2b8459c1a5a88d513dbd83e258090665880327abc0c73f3',
    'python_deps/deepseek_recipe/_native.abi3.so': '753bd43926f1b938bccb07b6e033054f1d1f1aab74eff47598baccafa612bb0d',
    'python_deps/deepseek_recipe-0.2.0.dist-info/METADATA': '8b84adcf8dfa7b38230686a96ba4c98980427ece3f5b1ccaf4541e907056c7e4',
    'python_deps/deepseek_recipe.libs/libopencv_core-14817538.so.412': '0a986a1a1f8d006328e775b8b35e3e7e19f265759285344b3b1983243672527c',
    'python_deps/deepseek_recipe.libs/libopencv_imgproc-f7999c05.so.412': '7e1008554c08402f401af38691c6a3fb82d071c415a262e6abe53e638269d3fd',
    'python_deps/deepseek_recipe.libs/libopencv_imgcodecs-6521e0d6.so.412': '9af11e72ae006c7f220500bdb0f02ad8c081992492eab4b7b8951c6bbfecbf8b',
}
_IMPORT_LOCK = threading.Lock()


class GuardConfigurationError(ValueError):
    """The optional guard cannot be enabled safely."""


class RequestContractError(ValueError):
    """The request is outside the validated token-count contract."""


class _RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise _infra('Redirect from the fixed DeepSeek endpoint was blocked', 'REDIRECT_BLOCKED')


class DirectNoRedirectOpener:
    """Direct transport with proxy discovery and redirects disabled."""
    def __init__(self):
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _RejectRedirect())

    def open(self, request, timeout=None):
        return self._opener.open(request, timeout=timeout)


def _digest_json(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                    separators=(',', ':')).encode()).hexdigest()


def _sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


class ExactDeepSeekCounter:
    """Load the study's pinned official recipe and tokenizer from an asset root."""

    def __init__(self, assets_root):
        try:
            root = Path(assets_root).resolve(strict=True)
            if not root.is_dir():
                raise OSError('asset root is not a directory')
            for name, expected in PINS.items():
                path = (root / name).resolve(strict=True)
                path.relative_to(root)
                if not path.is_file() or _sha256(path) != expected:
                    raise GuardConfigurationError('A required tokenizer asset differs from the pinned version')
        except (OSError, TypeError, ValueError) as exc:
            if isinstance(exc, GuardConfigurationError):
                raise
            raise GuardConfigurationError('Pinned optional tokenizer assets are unavailable') from exc

        deps = root / 'python_deps'
        expected_module = (deps / 'deepseek_recipe/__init__.py').resolve()
        with _IMPORT_LOCK:
            loaded = sys.modules.get('deepseek_recipe')
            if loaded is not None and Path(getattr(loaded, '__file__', '')).resolve() != expected_module:
                raise GuardConfigurationError('A different deepseek_recipe is already loaded')
            native = sys.modules.get('deepseek_recipe._native')
            expected_native = (deps / 'deepseek_recipe/_native.abi3.so').resolve()
            if native is not None and Path(getattr(native, '__file__', '')).resolve() != expected_native:
                raise GuardConfigurationError('A different tokenizer native module is already loaded')
            try:
                sys.path.insert(0, str(deps))
                try:
                    recipe = importlib.import_module('deepseek_recipe')
                finally:
                    sys.path.remove(str(deps))
                if Path(recipe.__file__).resolve() != expected_module:
                    raise GuardConfigurationError('Tokenizer import did not resolve to the pinned asset')
                native = sys.modules.get('deepseek_recipe._native')
                if native is None or Path(getattr(native, '__file__', '')).resolve() != expected_native:
                    raise GuardConfigurationError('Tokenizer native import did not resolve to the pinned asset')
                self._request = recipe.ChatCompletionRequest
                self._options = recipe.ConversionOptions
                self._encoding = recipe.DeepseekV41Encoding().with_tokenizer(
                    recipe.Tokenizer.from_file(str(root / 'hf_v41_flash1017/tokenizer.json')))
            except (ImportError, AttributeError, OSError, RuntimeError, ValueError) as exc:
                if isinstance(exc, GuardConfigurationError):
                    raise
                raise GuardConfigurationError('Pinned optional tokenizer could not be loaded') from exc
        self._lock = threading.Lock()

    @staticmethod
    def request(messages, *, model, temperature, max_tokens):
        return {'model': model, 'messages': copy.deepcopy(messages), 'temperature': temperature,
                'max_tokens': max_tokens, 'response_format': {'type': 'json_object'},
                'thinking': {'type': 'disabled'}}

    @staticmethod
    def validate(body):
        if not isinstance(body, dict) or set(body) != {
            'model', 'messages', 'temperature', 'max_tokens', 'response_format', 'thinking'
        }:
            raise RequestContractError('Unsupported request fields')
        if body['model'] not in MODELS or body['thinking'] != {'type': 'disabled'}:
            raise RequestContractError('Unsupported model or thinking mode')
        if body['response_format'] != {'type': 'json_object'}:
            raise RequestContractError('Only JSON-object responses are supported')
        messages = body['messages']
        if not isinstance(messages, list) or len(messages) != 2:
            raise RequestContractError('Exactly one system and one user message are required')
        for message, role in zip(messages, ('system', 'user')):
            if not isinstance(message, dict) or set(message) != {'role', 'content'}:
                raise RequestContractError('Only plain text role/content messages are supported')
            if message['role'] != role or not isinstance(message['content'], str):
                raise RequestContractError('Unsupported role or content')
        if type(body['max_tokens']) is not int or not 1 <= body['max_tokens'] <= 32768:
            raise RequestContractError('Unsupported output-token bound')
        if type(body['temperature']) not in (int, float) or body['temperature'] != 0:
            raise RequestContractError('This contract requires temperature zero')

    def count_request(self, body):
        self.validate(body)
        normalized = copy.deepcopy(body)
        normalized['model'] = 'DeepSeek-V4.1-Flash'
        with self._lock:
            converted = self._request(normalized).convert(self._options())
            count = len(self._encoding.encode(converted.conversation))
        return {'prompt_tokens': count, 'request_sha256': _digest_json(body),
                'encoder_version': VERSION, 'tokenizer_sha256': TOKENIZER_SHA256}

    def count_messages(self, messages, *, model, temperature, max_tokens):
        return self.count_request(self.request(messages, model=model, temperature=temperature,
                                               max_tokens=max_tokens))


def _infra(message, error_type, *, attempts=0, usage=None):
    return LLMInfrastructureError(message, error_type=error_type, attempts=attempts,
                                  retryable=False, usage=usage)


def _audit(sink, event, *, usage=None, attempts=0):
    if sink is None:
        return
    try:
        sink(event)
    except Exception as exc:
        raise _infra('Token audit could not be recorded', 'TOKEN_AUDIT_FAILURE',
                     usage=usage, attempts=attempts) from exc


def _checked_count(counter, body):
    try:
        result = counter.count_request(body)
        count = result['prompt_tokens']
        if type(count) is not int or count < 0:
            raise ValueError('invalid token count')
        return result
    except Exception as exc:
        raise _infra('Request is outside the exact token-count contract',
                     'TOKENIZER_CONTRACT_ERROR') from exc


class _TokenGuardOpener:
    """Validate the actual serialized request before every transport attempt."""

    def __init__(self, opener, counter, audit_sink, before_attempt, call_state, safe_identifier):
        self.opener, self.counter, self.audit_sink = opener, counter, audit_sink
        self.before_attempt = before_attempt
        self.call_state = call_state
        self.safe_identifier = safe_identifier

    def open(self, request, timeout=None):
        try:
            if request.full_url != 'https://api.deepseek.com/chat/completions' or request.get_method() != 'POST':
                raise RequestContractError('Unexpected endpoint or method')
            body = json.loads(request.data.decode('utf-8'))
        except (AttributeError, TypeError, UnicodeError, ValueError) as exc:
            raise _infra('Request is outside the exact token-count contract',
                         'TOKENIZER_CONTRACT_ERROR') from exc
        check = _checked_count(self.counter, body)
        allowed = check['prompt_tokens'] <= MAX_INPUT_TOKENS
        event = {'event': 'token_pre_dispatch', **check, 'limit': MAX_INPUT_TOKENS,
                 'dispatch_allowed': allowed}
        if not allowed:
            _audit(self.audit_sink, event)
            raise _infra('Input exceeds the 8192-token limit; no request sent', 'CONTEXT_LIMIT',
                         usage={'_token_budget': event})
        if self.before_attempt is not None:
            try:
                self.before_attempt()
            except Exception as exc:
                _audit(self.audit_sink, {**event, 'dispatch_allowed': False,
                                        'blocked_by': 'pre_dispatch_policy'})
                raise _infra('A pre-dispatch policy blocked the request', 'PRE_DISPATCH_BLOCKED') from exc
        _audit(self.audit_sink, event)
        state = getattr(self.call_state, 'current', None)
        if state is None:
            raise _infra('Guarded transport called outside a guarded chat', 'TOKENIZER_CONTRACT_ERROR')
        state['attempts'] += 1
        return _ResponseProxy(self.opener.open(request, timeout=timeout), state,
                              check['request_sha256'], self.audit_sink, self.safe_identifier)


class _ResponseProxy:
    """Keep usage metadata from each complete response even if a later retry fails."""

    def __init__(self, response, state, request_sha256, audit_sink, safe_identifier):
        self.response, self.state = response, state
        self.request_sha256, self.audit_sink = request_sha256, audit_sink
        self.safe_identifier = safe_identifier
        self.attempt = state['attempts']

    def __enter__(self):
        self.response.__enter__()
        return self

    def __exit__(self, *args):
        return self.response.__exit__(*args)

    def read(self, *args, **kwargs):
        raw = self.response.read(*args, **kwargs)
        try:
            parsed = json.loads(raw.decode('utf-8'))
            if not isinstance(parsed, dict):
                raise ValueError('response body is not an object')
        except (AttributeError, UnicodeError, ValueError):
            _audit(self.audit_sink, {'event': 'token_response_unavailable',
                                    'request_sha256': self.request_sha256,
                                    'attempt': self.attempt})
            return raw
        raw_usage = parsed.get('usage') if isinstance(parsed.get('usage'), dict) else {}
        numeric_keys = ('prompt_tokens', 'completion_tokens', 'total_tokens',
                        'prompt_cache_hit_tokens', 'prompt_cache_miss_tokens')
        usage = {key: raw_usage[key] for key in numeric_keys if type(raw_usage.get(key)) is int}
        details = raw_usage.get('prompt_tokens_details')
        if isinstance(details, dict) and type(details.get('cached_tokens')) is int:
            usage['prompt_tokens_details'] = {'cached_tokens': details['cached_tokens']}
        created = parsed.get('created')
        entry = {'attempt': self.attempt, 'returned_model': self.safe_identifier(parsed.get('model')),
                 'system_fingerprint': self.safe_identifier(parsed.get('system_fingerprint')),
                 'response_id': self.safe_identifier(parsed.get('id')),
                 'created': created if type(created) is int else None, 'usage': usage}
        self.state['responses'].append(entry)
        _audit(self.audit_sink, {'event': 'token_response_received',
          'request_sha256': self.request_sha256, 'attempt': self.attempt,
          'returned_model': entry['returned_model'], 'system_fingerprint': entry['system_fingerprint'],
          'response_id': entry['response_id'], 'usage': entry['usage']})
        return raw


def _with_captured_usage(usage, captured, model):
    """Complete transport captures are authoritative, including retried responses."""
    if captured:
        totals = {}
        for response in captured:
            for key, value in response['usage'].items():
                if type(value) is int:
                    totals[key] = totals.get(key, 0) + value
        totals['_response_metadata'] = {'requested_model': model, 'thinking': 'disabled',
                                        'response_history': copy.deepcopy(captured)}
        return totals
    return copy.deepcopy(usage) if isinstance(usage, dict) else {}


def _check_usage(usage, expected):
    if not isinstance(usage, dict) or not isinstance(usage.get('_response_metadata'), dict):
        return {'ok': False, 'error_type': 'TOKEN_USAGE_UNAVAILABLE', 'responses': []}
    history = usage['_response_metadata'].get('response_history')
    if not isinstance(history, list) or not history:
        return {'ok': False, 'error_type': 'TOKEN_USAGE_UNAVAILABLE', 'responses': []}
    responses = []
    for index, row in enumerate(history):
        if not isinstance(row, dict):
            return {'ok': False, 'error_type': 'TOKEN_USAGE_UNAVAILABLE', 'responses': responses}
        response_usage = row.get('usage')
        actual = response_usage.get('prompt_tokens') if isinstance(response_usage, dict) else None
        returned_model = row.get('returned_model')
        valid = type(actual) is int and actual >= 0
        attempt = row.get('attempt')
        known_model = isinstance(returned_model, str) and returned_model in MODELS
        responses.append({'response_index': index,
          'attempt': attempt if type(attempt) is int and attempt >= 0 else None,
          'actual_prompt_tokens': actual if valid else None, 'local_prompt_tokens': expected,
          'returned_model': returned_model if known_model else None,
          'within_limit': valid and actual <= MAX_INPUT_TOKENS,
          'exact_match': valid and actual == expected,
          'known_model': known_model})
    if any(type(x['actual_prompt_tokens']) is not int or x['actual_prompt_tokens'] < 0 for x in responses):
        error = 'TOKEN_USAGE_UNAVAILABLE'
    elif any(not x['within_limit'] for x in responses):
        error = 'ACTUAL_INPUT_TOKEN_LIMIT_EXCEEDED'
    elif any(not x['exact_match'] or not x['known_model'] for x in responses):
        error = 'TOKENIZER_PROVIDER_DRIFT'
    else:
        error = None
    return {'ok': error is None, 'error_type': error, 'responses': responses}


def install_guard(client, assets_root, *, audit_sink=None, before_attempt=None):
    """Explicit opt-in; create pinned counter and wrap the client's real opener.

    Caller must first configure a DeepSeek client using DirectNoRedirectOpener,
    thinking disabled, response metadata enabled, and the fixed endpoint. An
    optional before_attempt() callback can enforce a time window on every
    transport attempt. No credential is read and no request is sent here.
    """
    if getattr(client, '_exact_input_token_guard', False):
        raise GuardConfigurationError('Token guard is already installed')
    if (getattr(client, 'thinking', None) != 'disabled' or
        getattr(client, 'capture_response_metadata', None) is not True or
        getattr(client, 'model', None) not in MODELS or
        getattr(client, 'base_url', None) != 'https://api.deepseek.com'):
        raise GuardConfigurationError('Client is outside the supported DeepSeek contract')
    opener = getattr(client, 'opener', None)
    if type(opener) is not DirectNoRedirectOpener:
        raise GuardConfigurationError('DirectNoRedirectOpener is required')
    if before_attempt is not None and not callable(before_attempt):
        raise GuardConfigurationError('before_attempt must be callable')
    if not callable(getattr(client, 'chat_json', None)):
        raise GuardConfigurationError('A chat_json client is required')
    if audit_sink is not None and not callable(audit_sink):
        raise GuardConfigurationError('audit_sink must be callable')
    counter = ExactDeepSeekCounter(assets_root)
    call_state = threading.local()
    def safe_identifier(value):
        if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9._:-]{1,160}', value):
            return None
        secret = getattr(client, 'api_key', None)
        return None if isinstance(secret, str) and secret and secret in value else value
    guarded_opener = _TokenGuardOpener(opener, counter, audit_sink, before_attempt, call_state, safe_identifier)
    original_chat = client.chat_json

    def checked_chat(messages, *, temperature=0, max_tokens=1200):
        try:
            body = counter.request(messages, model=client.model, temperature=temperature, max_tokens=max_tokens)
        except Exception as exc:
            raise _infra('Request is outside the exact token-count contract',
                         'TOKENIZER_CONTRACT_ERROR') from exc
        local = _checked_count(counter, body)
        if local['prompt_tokens'] > MAX_INPUT_TOKENS:
            event = {'event': 'token_pre_client', **local, 'limit': MAX_INPUT_TOKENS,
                     'dispatch_allowed': False}
            _audit(audit_sink, event)
            raise _infra('Input exceeds the 8192-token limit; no request sent', 'CONTEXT_LIMIT',
                         usage={'_token_budget': event})
        if getattr(call_state, 'current', None) is not None:
            raise _infra('Nested guarded calls are unsupported', 'TOKENIZER_CONTRACT_ERROR')
        state = {'attempts': 0, 'responses': []}
        call_state.current = state
        try:
            raw, usage = original_chat(messages, temperature=temperature, max_tokens=max_tokens)
        except LLMInfrastructureError as exc:
            prior = _with_captured_usage(exc.usage, state['responses'], client.model)
            if (isinstance(prior.get('_response_metadata'), dict)
                    and prior['_response_metadata'].get('response_history')):
                check = _check_usage(prior, local['prompt_tokens'])
                if exc.error_type != 'TOKEN_AUDIT_FAILURE':
                    _audit(audit_sink, {'event': 'token_post_failure', **local, **check},
                           usage=_with_captured_usage({}, state['responses'], client.model),
                           attempts=state['attempts'])
                if not check['ok']:
                    raise _infra('Provider token accounting differs from the pinned contract',
                                 check['error_type'], attempts=len(check['responses']),
                                 usage={**prior, '_token_budget': check}) from exc
            if prior != exc.usage:
                raise LLMInfrastructureError('Model client or guard failed', error_type=exc.error_type,
                    attempts=exc.attempts, retryable=exc.retryable, usage=prior) from exc
            raise
        except Exception as exc:
            # Some malformed responses and truncated reads escape the existing
            # client as ordinary exceptions. The opted-in guard fails closed;
            # control-flow exceptions such as KeyboardInterrupt still propagate.
            prior = _with_captured_usage({}, state['responses'], client.model)
            if state['responses']:
                check = _check_usage(prior, local['prompt_tokens'])
                _audit(audit_sink, {'event': 'token_post_failure', **local, **check},
                       usage=_with_captured_usage({}, state['responses'], client.model),
                       attempts=state['attempts'])
                if not check['ok']:
                    raise _infra('Provider token accounting differs from the pinned contract',
                                 check['error_type'], attempts=len(check['responses']),
                                 usage={**prior, '_token_budget': check}) from exc
            raise _infra('Model transport or response processing failed',
                         'MODEL_CLIENT_FAILURE', attempts=state['attempts'], usage=prior) from exc
        finally:
            del call_state.current
        usage = _with_captured_usage(usage, state['responses'], client.model)
        check = _check_usage(usage, local['prompt_tokens'])
        _audit(audit_sink, {'event': 'token_post_response', **local, **check},
               usage=_with_captured_usage({}, state['responses'], client.model),
               attempts=state['attempts'])
        if not check['ok']:
            raise _infra('Provider token accounting differs from the pinned contract',
                         check['error_type'], attempts=len(check['responses']),
                         usage={**(usage if isinstance(usage, dict) else {}), '_token_budget': check})
        return raw, {**usage, '_token_budget': {**local, **check, 'limit': MAX_INPUT_TOKENS}}

    client.opener = guarded_opener
    client.chat_json = checked_chat
    client._exact_input_token_guard = True
    return {'version': VERSION, 'limit': MAX_INPUT_TOKENS, 'tokenizer_sha256': TOKENIZER_SHA256,
            'preflight': 'every actual HTTP attempt', 'postflight': 'each recorded HTTP response'}
