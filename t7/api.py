"""Byteramp client. Metadata is persisted; opt-in model prompts are transient."""
import json
import re
import urllib.error
import urllib.request

from . import __version__
from . import metadata
from .transport import open_request

_FENCE = re.compile(r'```.*?(```|$)', re.S)


def strip_code(text, limit=2000):
    """Redact fenced code from metadata before sending it to the portal."""
    return _FENCE.sub('[code omitted]', str(text or ''))[:limit]


class APIError(RuntimeError):
    def __init__(self, status, detail, *, retryable=True):
        super().__init__(f'{status}: {detail}')
        self.status = status
        self.detail = detail
        self.retryable = retryable


class Byteramp:
    def __init__(self, cfg):
        self.cfg = cfg

    def _headers(self):
        h = {'Authorization': f'Bearer {self.cfg.token}', 'Content-Type': 'application/json',
             'User-Agent': f't7-agent/{__version__}'}
        # Organisation tokens: which repository this call is about (the remote URL, not code).
        from urllib.parse import quote
        if getattr(self.cfg, 'context', '') == 'ci':
            h['X-T7-Context'] = 'ci'
        if getattr(self.cfg, 'remote', ''):
            h['X-T7-Remote'] = quote(self.cfg.remote[:500], safe=':/@.~')
        if getattr(self.cfg, 'repo_name', ''):
            h['X-T7-Repo-Name'] = quote(self.cfg.repo_name[:120], safe='')
        return h

    def _req(self, method, path, body=None, timeout=60):
        if self.cfg.offline:
            raise APIError(0, 'offline (no T7_TOKEN)')
        if body is not None and path != 'llm/' and not path.endswith('/map-chunks/'):
            body = metadata.clean(body)
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            f'{self.cfg.api_url}/tripleseven/agent/{path}', data=data, method=method,
            headers=self._headers())
        try:
            with open_request(req, timeout=timeout) as r:
                raw = r.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            try:
                body = json.loads(e.read())
                detail = body.get('detail', '')
                retryable = body.get('retryable') is not False
            except Exception:  # noqa: BLE001
                detail = e.reason
                retryable = True
            raise APIError(e.code, detail, retryable=retryable) from None
        except urllib.error.URLError as e:
            raise APIError(0, str(e.reason)) from None

    @staticmethod
    def public(api_url, path, body, timeout=30):
        """Unauthenticated agent call (browser sign-in)."""
        req = urllib.request.Request(
            f'{api_url.rstrip("/")}/tripleseven/agent/{path}', data=json.dumps(body).encode(),
            method='POST', headers={'Content-Type': 'application/json',
                                    'User-Agent': f't7-agent/{__version__}'})
        try:
            with open_request(req, timeout=timeout) as r:
                return json.loads(r.read() or b'{}')
        except urllib.error.HTTPError as e:
            try:
                body = json.loads(e.read())
            except Exception:  # noqa: BLE001
                body = {}
            if e.code == 404 and body.get('status'):
                return body
            raise APIError(e.code, body.get('detail') or e.reason) from None
        except urllib.error.URLError as e:
            raise APIError(0, str(e.reason)) from None

    def rotate(self):
        return self._req('POST', 'token/rotate/', {})

    def config(self):
        return self._req('GET', 'config/')

    def start_run(self, **meta):
        return self._req('POST', 'runs/', meta)

    def plan(self, run_id, plan):
        return self._req('POST', f'runs/{run_id}/plan/', {'plan': plan})

    def architecture(self, run_id, delta, enrich=False):
        return self._req('POST', f'runs/{run_id}/architecture/',
                         {'delta': delta, 'enrich': enrich}, timeout=120)

    def steps(self, run_id, steps):
        for s in steps:
            s['summary'] = strip_code(s.get('summary'))
        return self._req('POST', f'runs/{run_id}/steps/', {'steps': steps})

    def findings(self, run_id, findings):
        return self._req('POST', f'runs/{run_id}/findings/', {'findings': findings})

    def finish(self, run_id, **body):
        return self._req('POST', f'runs/{run_id}/finish/', body)

    def decision(self, **body):
        return self._req('POST', 'decisions/', body)

    def llm(self, purpose, system, prompt, json_mode=False, max_tokens=2000, temperature=0.1):
        return self._req('POST', 'llm/', {'purpose': purpose, 'system': system, 'prompt': prompt,
                                          'json': json_mode, 'max_tokens': max_tokens,
                                          'temperature': temperature}, timeout=900)
