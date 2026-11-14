"""Byteramp client. Sends metadata only — see t7/__init__.py."""
import json
import re
import urllib.error
import urllib.request

from . import __version__

_FENCE = re.compile(r'```.*?(```|$)', re.S)


def strip_code(text, limit=2000):
    """Belt and braces: the backend strips code too, but we never send it."""
    return _FENCE.sub('[code omitted]', str(text or ''))[:limit]


class APIError(RuntimeError):
    def __init__(self, status, detail):
        super().__init__(f'{status}: {detail}')
        self.status = status
        self.detail = detail


class Byteramp:
    def __init__(self, cfg):
        self.cfg = cfg

    def _req(self, method, path, body=None, timeout=60):
        if self.cfg.offline:
            raise APIError(0, 'offline (no T7_TOKEN)')
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            f'{self.cfg.api_url}/tripleseven/agent/{path}', data=data, method=method,
            headers={'Authorization': f'Bearer {self.cfg.token}',
                     'Content-Type': 'application/json',
                     'User-Agent': f't7-agent/{__version__}'})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            try:
                detail = json.loads(e.read()).get('detail', '')
            except Exception:  # noqa: BLE001
                detail = e.reason
            raise APIError(e.code, detail) from None
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
            with urllib.request.urlopen(req, timeout=timeout) as r:
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
