"""LLM providers. Code-touching prompts go ONLY to the provider the customer chose:

  byteramp   Byteramp VPS models via the opt-in proxy (EU, no third party, no logging)
  openai     any OpenAI-compatible endpoint (OpenAI, vLLM, LM Studio, …)
  azure      Azure OpenAI (T7_LLM_BASE_URL = https://<res>.openai.azure.com, model = deployment)
  anthropic  Anthropic Messages API (customer's own key)
  ollama     local Ollama next to the agent
"""
import json
import re
import threading
import time
import urllib.error
import urllib.request


class LLMError(RuntimeError):
    pass


def extract_json(text, default=None):
    if not text:
        return default
    m = re.search(r'```(?:json)?\s*(.*?)```', text, re.S)
    raw = m.group(1) if m else text
    for opener, closer in (('{', '}'), ('[', ']')):
        i, j = raw.find(opener), raw.rfind(closer)
        if i != -1 and j > i:
            try:
                return json.loads(raw[i:j + 1])
            except ValueError:
                continue
    return default


class LLM:
    def __init__(self, cfg, api):
        self.cfg = cfg
        self.api = api
        self.model = cfg.llm_model or ('byteramp-vps' if cfg.llm == 'byteramp' else '')
        self.calls = 0
        self.chars_in = 0
        self._lock = threading.Lock()

    def complete(self, purpose, system, prompt, *, json_mode=False, max_tokens=2000,
                 temperature=0.1, retries=2):
        with self._lock:
            self.calls += 1
            self.chars_in += len(prompt) + len(system or '')
        last = None
        for attempt in range(retries + 1):
            try:
                text = self._dispatch(purpose, system, prompt, json_mode, max_tokens, temperature)
                if text:
                    return text
                last = LLMError('empty response')
            except Exception as e:  # noqa: BLE001
                last = e
            time.sleep(1.5 * (attempt + 1))
        raise LLMError(f'{self.cfg.llm} failed for {purpose}: {last}')

    def json(self, purpose, system, prompt, default=None, **kw):
        text = self.complete(purpose, system + '\nRespond with JSON only.', prompt,
                             json_mode=True, **kw)
        data = extract_json(text, None)
        if data is None:  # one repair round
            text = self.complete(purpose, 'Convert the input into valid JSON. Output JSON only.',
                                 text[:12000], json_mode=True)
            data = extract_json(text, default)
        return data if data is not None else default

    # ── providers ──────────────────────────────────────────────────────────
    def _dispatch(self, purpose, system, prompt, json_mode, max_tokens, temperature):
        p = self.cfg.llm
        if p == 'byteramp':
            r = self.api.llm(purpose, system, prompt, json_mode, max_tokens, temperature)
            self.model = r.get('model') or self.model
            return r.get('text', '')
        if p == 'client':
            from .mcp import sample
            text, model = sample(system, prompt, max_tokens, temperature)
            if model:
                self.model = f'client:{model}'
            return text
        if p == 'ollama':
            return self._ollama(system, prompt, json_mode, max_tokens, temperature)
        if p in ('openai', 'azure'):
            return self._openai_compat(system, prompt, json_mode, max_tokens, temperature)
        if p == 'anthropic':
            return self._anthropic(system, prompt, max_tokens, temperature)
        raise LLMError(f'unknown provider {p}')

    def _ollama(self, system, prompt, json_mode, max_tokens, temperature):
        """Native Ollama API: the OpenAI-compatible endpoint cannot set num_ctx, so long
        prompts would be silently truncated to the model's small default window."""
        import os
        base = (self.cfg.llm_base_url or 'http://localhost:11434').rstrip('/')
        base = base[:-3] if base.endswith('/v1') else base
        payload = {'model': self.cfg.llm_model, 'stream': False,
                   'messages': [{'role': 'system', 'content': system or ''},
                                {'role': 'user', 'content': prompt}],
                   'options': {'temperature': temperature, 'num_predict': max_tokens,
                               'num_ctx': int(os.environ.get('T7_NUM_CTX', '16384'))}}
        if json_mode:
            payload['format'] = 'json'
        # Reasoning models (Qwen3/3.5, gpt-oss, DeepSeek-R1) otherwise spend the token budget
        # thinking and return an empty answer. gpt-oss cannot turn thinking off, only down.
        think = os.environ.get('T7_THINK', '').lower()
        if 'gpt-oss' in (self.cfg.llm_model or ''):
            payload['think'] = think if think in ('low', 'medium', 'high') else 'low'
        else:
            payload['think'] = think in ('1', 'true', 'yes')
        data = self._post(f'{base}/api/chat', {}, payload, timeout=900)
        return (data.get('message') or {}).get('content', '')

    def _post(self, url, headers, payload, timeout=240):
        req = urllib.request.Request(url, data=json.dumps(payload).encode(), method='POST',
                                     headers={'Content-Type': 'application/json', **headers})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())

    def _openai_compat(self, system, prompt, json_mode, max_tokens, temperature):
        c = self.cfg
        if c.llm == 'azure':
            url = (f'{c.llm_base_url.rstrip("/")}/openai/deployments/{c.llm_model}'
                   '/chat/completions?api-version=2024-10-21')
            headers = {'api-key': c.llm_api_key}
        else:
            base = c.llm_base_url or ('http://localhost:11434/v1' if c.llm == 'ollama'
                                      else 'https://api.openai.com/v1')
            url = f'{base.rstrip("/")}/chat/completions'
            headers = {'Authorization': f'Bearer {c.llm_api_key}'} if c.llm_api_key else {}
        payload = {'model': c.llm_model, 'temperature': temperature, 'max_tokens': max_tokens,
                   'messages': [{'role': 'system', 'content': system or ''},
                                {'role': 'user', 'content': prompt}]}
        if json_mode:
            payload['response_format'] = {'type': 'json_object'}
        data = self._post(url, headers, payload)
        return data['choices'][0]['message']['content']

    def _anthropic(self, system, prompt, max_tokens, temperature):
        c = self.cfg
        data = self._post(
            (c.llm_base_url or 'https://api.anthropic.com').rstrip('/') + '/v1/messages',
            {'x-api-key': c.llm_api_key, 'anthropic-version': '2023-06-01'},
            {'model': c.llm_model or 'claude-sonnet-5-5', 'max_tokens': max_tokens,
             'temperature': temperature, 'system': system or '',
             'messages': [{'role': 'user', 'content': prompt}]})
        return ''.join(b.get('text', '') for b in data.get('content', []) if b.get('type') == 'text')
