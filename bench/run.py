"""Benchmark a model on the Triple Seven pipeline prompts.

    python -m bench.run --model qwen3:8b [--ollama http://localhost:11434] [--tasks triage,analyze,fix]

Uses the agent's production prompts so results reflect what customers get:
  triage   triage → adversarial critic (as in the pipeline) on every case
           vulnerable → must end "confirmed"; decoy → must NOT end "confirmed"
  analyze  specialist analyst on the whole file; hit = finding within ±3 lines,
           noise = any medium+ finding on a decoy
  fix      fixer on cases with an executable test: test must fail before, pass after
Writes bench/results/<model>.json and prints a summary.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from statistics import median

from t7.agents.analysts import SYSTEM_TMPL
from t7.agents.fixer import FIX_SYSTEM, apply_edits
from t7.agents.planner import SPECIALISTS
from t7.agents.triage import CRITIC_SYSTEM, TRIAGE_SYSTEM
from t7.config import Config
from t7.llm import LLM

from .corpus import CASES

SPECIALIST = {'sqli': 'injection', 'cmdi': 'injection', 'ssrf': 'injection', 'path': 'injection',
              'deser': 'injection', 'xss': 'injection', 'authz': 'authz', 'authn': 'authz',
              'massassign': 'authz', 'crypto': 'secrets', 'llm-agency': 'llm', 'llm-output': 'llm',
              'network': 'iac'}
SPEC_BY_HYP_CWE = {'CWE-89': 'injection', 'CWE-943': 'injection', 'CWE-78': 'injection',
                   'CWE-918': 'injection', 'CWE-22': 'injection', 'CWE-502': 'injection',
                   'CWE-79': 'injection', 'CWE-639': 'authz', 'CWE-306': 'authz', 'CWE-915': 'authz',
                   'CWE-347': 'authz', 'CWE-327': 'secrets', 'CWE-916': 'secrets', 'CWE-269': 'llm',
                   'CWE-94': 'llm', 'CWE-77': 'llm', 'CWE-284': 'iac'}

STUBS = {  # minimal framework stubs so fix tests run without Django installed
    'django/__init__.py': '',
    'django/db.py': 'class _C:\n    def cursor(self):\n        raise RuntimeError("patched in tests")\nconnection = _C()\n',
    'django/http.py': 'class Http404(Exception):\n    pass\ndef FileResponse(fh, **k):\n    return fh.read()\n',
}


def numbered(code, mark_all=False):
    return '\n'.join(f"{'>>' if mark_all else '  '}{i:>5} | {line}"
                     for i, line in enumerate(code.splitlines(), 1))


class Timer:
    def __init__(self):
        self.calls = []

    def run(self, task, fn):
        t0 = time.time()
        try:
            out = fn()
            ok = out is not None and out != {}
        except Exception as e:  # noqa: BLE001
            out, ok = {'_error': str(e)[:200]}, False
        self.calls.append({'task': task, 'seconds': round(time.time() - t0, 1), 'json_ok': ok})
        return out or {}


def triage(llm, t, c):
    h = c['hypothesis']
    code = f"## {c['path']}\n{numbered(c['code'])}"
    d = t.run('triage', lambda: llm.json('triage', TRIAGE_SYSTEM,
                                         f"HYPOTHESIS: {h['title']}\nCWE: {h['cwe']}\nClaim: {h['description']}\n"
                                         f"Location hint: {c['path']}\n\nCODE:\n{code}", default={}))
    verdict = d.get('verdict', 'uncertain')
    final = verdict
    if verdict == 'confirmed':
        cr = t.run('critic', lambda: llm.json('critic', CRITIC_SYSTEM,
                                              f"FINDING: {h['title']} ({h['cwe']}) at {c['path']}\n"
                                              f"Reasoning: {d.get('reasoning', '')}\n\nCODE:\n{code}", default={}))
        try:
            from t7.agents.triage import critic_refutes
            refuted = critic_refutes(cr, c['code'])
        except ImportError:  # baseline agent versions
            refuted = bool(cr.get('refuted') and cr.get('line'))
        if refuted:
            final = 'refuted'
    expect_vuln = c['vuln'] is not None
    correct = (final == 'confirmed') if expect_vuln else (final != 'confirmed')
    return {'id': c['id'], 'vulnerable': expect_vuln, 'triage': verdict, 'final': final,
            'correct': correct, 'reasoning': str(d.get('reasoning', ''))[:300]}


def analyze(llm, t, c):
    fam = c['vuln']['family'] if c['vuln'] else None
    spec = SPECIALIST.get(fam) or SPEC_BY_HYP_CWE.get(c['hypothesis']['cwe'], 'logic')
    try:
        from t7.agents.checklists import checklist
        system = SYSTEM_TMPL.format(name=spec.upper(), scope=SPECIALISTS[spec], checklist=checklist(spec))
    except ImportError:  # older agent versions (baseline runs)
        system = SYSTEM_TMPL.format(name=spec.upper(), scope=SPECIALISTS[spec])
    d = t.run('analyze', lambda: llm.json('analyze', system,
                                          f"## {c['path']}\n{numbered(c['code'], mark_all=True)}", default={}))
    found = [f for f in (d.get('findings') or []) if isinstance(f, dict)]
    serious = [f for f in found if str(f.get('severity', '')).lower() in ('critical', 'high', 'medium')]
    if c['vuln']:
        hit = any(isinstance(f.get('line'), int) and abs(f['line'] - c['vuln']['line']) <= 3 for f in found)
        return {'id': c['id'], 'vulnerable': True, 'hit': hit, 'findings': len(found)}
    return {'id': c['id'], 'vulnerable': False, 'noise': len(serious), 'findings': len(found),
            'titles': [str(f.get('title', ''))[:80] for f in serious]}


def _prepare(tmp, c, code):
    for rel, body in STUBS.items():
        p = tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    pkg = tmp / Path(c['path']).parent
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / '__init__.py').touch()
    (tmp / c['path']).write_text(code)
    (tmp / 'test_case.py').write_text(c['fix_test'])


def _pytest(tmp):
    p = subprocess.run([sys.executable, '-m', 'pytest', '-q', '-p', 'no:cacheprovider', 'test_case.py'],
                       cwd=tmp, capture_output=True, text=True, timeout=120,
                       env={**os.environ, 'PYTHONPATH': str(tmp)})
    return p.returncode == 0, (p.stdout + p.stderr)[-600:]


def fix(llm, t, c):
    v = c['vuln']
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        _prepare(tmp, c, c['code'])
        before, _ = _pytest(tmp)
        raw = '\n'.join(c['code'].splitlines())
        prompt = (f"FINDING: {v['title']} ({c['hypothesis']['cwe']})\n{c['hypothesis']['description']}\n"
                  f"Location: {c['path']}:{v['line']}\n\nNUMBERED (for orientation):\n{numbered(c['code'])}\n\n"
                  f"RAW TEXT (copy `find` from here):\n{raw}")
        dd = t.run('fix', lambda: llm.json('fix', FIX_SYSTEM, prompt, default={}, max_tokens=2500))
        edits = [e for e in (dd.get('edits') or []) if isinstance(e, dict)]
        applied, err = apply_edits(tmp, edits) if edits else (False, 'no edits')
        after, log = _pytest(tmp) if applied else (False, err)
    return {'id': c['id'], 'test_failed_before': not before, 'applied': applied, 'passes_after': after,
            'correct': (not before) and applied and after, 'log': '' if after else str(log)[-300:]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--model', required=True)
    ap.add_argument('--ollama', default='http://localhost:11434')
    ap.add_argument('--tasks', default='triage,analyze,fix')
    ap.add_argument('--only', default='', help='comma-separated case ids')
    a = ap.parse_args()

    cfg = Config()
    cfg.llm, cfg.llm_model, cfg.llm_base_url, cfg.offline = 'ollama', a.model, a.ollama, True
    llm = LLM(cfg, None)
    t = Timer()
    cases = [c for c in CASES if not a.only or c['id'] in a.only.split(',')]
    tasks = a.tasks.split(',')
    res = {'model': a.model, 'triage': [], 'analyze': [], 'fix': []}
    t0 = time.time()
    # warm-up (model load is not part of per-call latency)
    llm.complete('plan', 'Reply with OK.', 'ping', max_tokens=5)
    for c in cases:
        if 'triage' in tasks:
            res['triage'].append(triage(llm, t, c))
        if 'analyze' in tasks:
            res['analyze'].append(analyze(llm, t, c))
        if 'fix' in tasks and c.get('fix_test'):
            res['fix'].append(fix(llm, t, c))
        print(f"[{time.time() - t0:6.0f}s] {c['id']}", file=sys.stderr, flush=True)

    tri, ana, fx = res['triage'], res['analyze'], res['fix']
    vul = [r for r in tri if r['vulnerable']]
    dec = [r for r in tri if not r['vulnerable']]

    def lat(task):
        xs = [x['seconds'] for x in t.calls if x['task'] == task]
        return round(median(xs), 1) if xs else None
    s = {
        'model': a.model,
        'triage_recall': round(sum(r['correct'] for r in vul) / len(vul), 3) if vul else None,
        'triage_decoy_rejection': round(sum(r['correct'] for r in dec) / len(dec), 3) if dec else None,
        # Triage alone (before the critic) — shows how much the critic adds or removes.
        'triage_only_recall': round(sum(r['triage'] == 'confirmed' for r in vul) / len(vul), 3) if vul else None,
        'triage_only_decoy_rejection': round(sum(r['triage'] != 'confirmed' for r in dec) / len(dec), 3) if dec else None,
        'triage_accuracy': round(sum(r['correct'] for r in tri) / len(tri), 3) if tri else None,
        'analyze_recall': round(sum(r['hit'] for r in ana if r['vulnerable']) /
                                max(1, sum(1 for r in ana if r['vulnerable'])), 3) if ana else None,
        'analyze_noise_per_decoy': round(sum(r['noise'] for r in ana if not r['vulnerable']) /
                                         max(1, sum(1 for r in ana if not r['vulnerable'])), 2) if ana else None,
        'fix_success': f"{sum(r['correct'] for r in fx)}/{len(fx)}" if fx else None,
        'json_valid_rate': round(sum(x['json_ok'] for x in t.calls) / len(t.calls), 3) if t.calls else None,
        'median_seconds': {k: lat(k) for k in ('triage', 'critic', 'analyze', 'fix')},
        'total_seconds': round(time.time() - t0),
    }
    res['summary'] = s
    out = Path(__file__).parent / 'results'
    out.mkdir(exist_ok=True)
    (out / (re.sub(r'[^A-Za-z0-9_.-]+', '_', a.model) + '.json')).write_text(json.dumps(res, indent=2))
    print(json.dumps(s, indent=2))


if __name__ == '__main__':
    main()
