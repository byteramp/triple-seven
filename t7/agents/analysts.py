"""Specialist analysts — run in parallel, one per area the planner selected.
Each sees only the changed regions (+context) of the files relevant to it."""
import hashlib
import re
from concurrent.futures import ThreadPoolExecutor

from . import GROUND_RULES, Hypothesis
from .planner import SPECIALISTS

SPEC_FILES = {
    'iac': lambda p: p.endswith(('.tf', '.yaml', '.yml', 'Dockerfile', '.json')),
    'llm': lambda p: True,
}

SYSTEM_TMPL = GROUND_RULES + (
    "\nYou are the {name} SPECIALIST. Scope: {scope}.\n"
    "Review ONLY the changed regions marked with '>>' and their direct context. Report real, "
    "exploitable weaknesses introduced or exposed by this change. Return JSON: "
    "{{\"findings\": [{{\"title\", \"severity\": critical|high|medium|low, \"cwe\": \"CWE-n\", "
    "\"owasp\", \"llm_code\": \"LLM0n or empty\", \"file\", \"line\": int, \"line_end\": int, "
    "\"description\", \"attack_scenario\": concrete steps, \"recommendation\"}}]}}. "
    "Max 6 findings. Empty list if none."
)

_SYM = re.compile(r'^\s*(?:async\s+)?(?:def|class|function|func|const|export\s+function)\s+([A-Za-z_]\w*)')


def enclosing_symbol(root, path, line):
    try:
        lines = (root / path).read_text(errors='replace').splitlines()
    except OSError:
        return ''
    for i in range(min(line or 1, len(lines)) - 1, -1, -1):
        m = _SYM.match(lines[i])
        if m:
            return m.group(1)
    return ''


def fingerprint(*parts):
    return hashlib.sha256('|'.join(str(p) for p in parts).encode()).hexdigest()


def changed_region_listing(root, f, context=25, cap=7000):
    try:
        lines = (root / f.path).read_text(errors='replace').splitlines()
    except OSError:
        return ''
    marked = {ln for ln, _ in f.added}
    keep = set()
    for ln in marked:
        keep.update(range(max(1, ln - context), min(len(lines), ln + context) + 1))
    out, prev = [], 0
    for i in sorted(keep):
        if prev and i != prev + 1:
            out.append('  ...')
        out.append(f"{'>>' if i in marked else '  '}{i:>5} | {lines[i - 1]}")
        prev = i
    return '\n'.join(out)[:cap]


def _run_one(name, why, files, root, llm, tracer, fork):
    with fork:
        with tracer.step(f'analyst:{name}', f'{name} review', why=why) as h:
            pick = SPEC_FILES.get(name, lambda p: not p.endswith(('.md', '.lock', '.svg')))
            relevant = [f for f in files if f.added and pick(f.path)][:20]
            if not relevant:
                h.skip('no relevant files in this diff')
                return []
            listing = '\n\n'.join(f'## {f.path}\n{changed_region_listing(root, f)}'
                                  for f in relevant)[:70000]
            system = SYSTEM_TMPL.format(name=name.upper(), scope=SPECIALISTS[name])
            data = llm.json('analyze', system, listing, default={}) or {}
            out = []
            for item in (data.get('findings') or [])[:6]:
                path = str(item.get('file', ''))
                if not any(path == f.path for f in relevant):
                    continue  # hallucinated path → drop
                line = item.get('line') if isinstance(item.get('line'), int) else None
                sev = item.get('severity') if item.get('severity') in ('critical', 'high', 'medium', 'low') else 'medium'
                cwe = str(item.get('cwe', ''))[:20]
                sym = enclosing_symbol(root, path, line)
                out.append(Hypothesis(
                    fingerprint=fingerprint('analyst', cwe or name, path, sym or line),
                    title=str(item.get('title', ''))[:280] or f'{name} issue',
                    severity=sev, cwe=cwe, owasp=str(item.get('owasp', ''))[:40],
                    llm_code=str(item.get('llm_code', ''))[:10], file_path=path,
                    line_start=line,
                    line_end=item.get('line_end') if isinstance(item.get('line_end'), int) else line,
                    description=str(item.get('description', ''))[:1500],
                    attack_scenario=str(item.get('attack_scenario', ''))[:1500],
                    recommendation=str(item.get('recommendation', ''))[:1500],
                    source='llm_sec' if name == 'llm' else 'agent', origin=f'analyst:{name}',
                    rule=f'analyst.{name}'))
            h.summary(f'{len(out)} candidate(s) across {len(relevant)} file(s)')
            return out


def run_analysts(chain, changed, root, llm, tracer, parallel=4):
    specs = chain['specialists']
    with tracer.step('orchestrator', f'Run {len(specs)} specialist analysts in parallel'):
        with ThreadPoolExecutor(max_workers=max(1, parallel)) as ex:
            futs = [ex.submit(_run_one, s['name'], s['why'], changed, root, llm, tracer,
                              tracer.fork()) for s in specs]
            results = []
            for f in futs:
                try:
                    results.extend(f.result())
                except Exception:  # noqa: BLE001 — one failed specialist must not sink the run
                    pass
    return results
