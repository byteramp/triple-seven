"""Specialist analysts — run in parallel, one per area the planner selected.
Each sees only the changed regions (+context) of the files relevant to it."""
import hashlib
import re
from concurrent.futures import ThreadPoolExecutor

from . import GROUND_RULES, Hypothesis
from .checklists import checklist
from .planner import SPECIALISTS
from ..llm import LLMError, input_budget

SPEC_FILES = {
    'iac': lambda p: p.endswith(('.tf', '.yaml', '.yml', 'Dockerfile', '.json')),
    'llm': lambda p: True,
}

SYSTEM_TMPL = GROUND_RULES + (
    "\nYou are the {name} SPECIALIST. Scope: {scope}.\nChecklist: {checklist}\n"
    "Lines marked -- removed are deleted code, not active code. Review the security impact of removals. "
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


def changed_region_listing(root, f, context=25, cap=7000, include_removed=True):
    try:
        lines = (root / f.path).read_text(errors='replace').splitlines()
    except OSError:
        if f.status != 'D':
            raise
        lines = []
    marked = {ln for ln, _ in f.added}
    for hunk in f.hunks:
        if include_removed and hunk.removed_lines and lines:
            marked.add(min(max(1, hunk.start), len(lines)))
    keep = set()
    for ln in marked:
        keep.update(range(max(1, ln - context), min(len(lines), ln + context) + 1))
    out, prev = [], 0
    for i in sorted(keep):
        if prev and i != prev + 1:
            out.append('  ...')
        out.append(f"{'>>' if i in marked else '  '}{i:>5} | {lines[i - 1]}")
        prev = i
    removed = [f'-- removed near line {hunk.start} | {line}'
               for hunk in f.hunks for line in hunk.removed_lines] if include_removed else []
    return '\n'.join(out + removed)[:cap]



def review_batches(root, files, context=25, listing_for=None, max_chars=36000):
    """Cover every changed region with overlapping bounded model inputs."""
    batch, size = [], 0
    for file in files:
        listing = (listing_for(file) if listing_for else
                   changed_region_listing(root, file, context=context, cap=None))
        for start in range(0, len(listing), 5600):
            excerpt = listing[start:start + 6000]
            part = f'## {file.path} (status {file.status}, excerpt {start // 5600 + 1})\n{excerpt}'
            if batch and size + len(part) > max_chars:
                yield '\n\n'.join(batch)
                batch, size = [], 0
            batch.append(part)
            size += len(part) + 2
    if batch:
        yield '\n\n'.join(batch)


def _run_one(name, why, files, root, llm, tracer, fork):
    with fork:
        with tracer.step(f'analyst:{name}', f'{name} review', why=why) as h:
            pick = SPEC_FILES.get(name, lambda p: not p.endswith(('.md', '.lock', '.svg')))
            relevant = [f for f in files if f.hunks and pick(f.path)]
            if not relevant:
                h.skip('no relevant files in this diff')
                return []
            system = SYSTEM_TMPL.format(name=name.upper(), scope=SPECIALISTS[name],
                                        checklist=checklist(name))
            findings, batches = [], 0
            inputs = list(review_batches(root, relevant, max_chars=input_budget(llm)))
            for index, listing in enumerate(inputs, 1):
                with tracer.step(f'analyst:{name}', f'{name}: batch {index}/{len(inputs)}'):
                    data = llm.json('analyze', system, listing, default={})
                if not isinstance(data, dict) or not isinstance(data.get('findings'), list):
                    raise LLMError(f'{name}: invalid findings response')
                findings.extend(data['findings'])
                batches += 1
            h.meta(reviewed_files=[f.path for f in relevant], batches=batches)
            out = []
            for item in findings:
                if not isinstance(item, dict):
                    raise LLMError(f'{name}: malformed finding')
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
            # Propagate analysis failures after workers finish; partial results cannot pass.
            for future in futs:
                results.extend(future.result())
    return results
