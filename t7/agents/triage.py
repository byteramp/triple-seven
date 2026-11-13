"""Triage + adversarial critic.

Every hypothesis — from the server threat model, the regex signals or the
specialist analysts — is checked against the real code. Confirmed high/critical
findings then face a critic whose only job is to refute them. What survives is
L1 (traced in code); anything the critic breaks is demoted, not shown in the PR.
"""
import hashlib
from concurrent.futures import ThreadPoolExecutor

from . import GROUND_RULES, SEV_RANK
from .analysts import changed_region_listing

# Verification rules adapted from Cloudflare's security-audit skill (MIT), see NOTICE.
TRIAGE_SYSTEM = GROUND_RULES + (
    "\nYou are the VERIFIER. You did not write this hypothesis — try to decide it from the code alone.\n"
    "1. Trace it: the first hop must be a real LOWER-TRUST entrypoint (request data, message, "
    "file, model output, another tenant's record) and the last hop the claimed SINK or boundary "
    "effect. No real entrypoint → rejected.\n"
    "2. Reconstruct the strongest controls on that path before deciding: validation, allow-lists, "
    "parameterisation, escaping, framework defaults, authentication, object-level authorization "
    "(queries scoped to the user/tenant), and containment. A control that blocks the path → rejected.\n"
    "3. Judge IMPACT, not patterns. Public-by-design endpoints (tracking pixel, health check, signed "
    "webhook, login, static page) are not findings unless they leak data, change state, or enable "
    "abuse (open redirect, SSRF, enumeration). Missing authentication alone is not enough. Weak "
    "hashes used for non-security purposes (cache keys, ETags) are not findings. A permissive rule "
    "that is the intended function (public HTTPS load balancer) is not a finding.\n"
    "4. Data classes in the hypothesis (pii, health, payment …) come from an automated sketch and "
    "are UNVERIFIED: claim data exposure only if the code shows that data leaving.\n"
    "5. Severity must not exceed what the code demonstrates.\n"
    "Verdicts: confirmed = complete source→sink path with no blocking control; "
    "uncertain = path is real but a decisive fact is outside the code (deployment, config); "
    "rejected = refuted by the code, a control, or no meaningful impact.\n"
    "Return JSON: {\"verdict\": \"confirmed\"|\"rejected\"|\"uncertain\", \"severity\": "
    "critical|high|medium|low, \"file\": path, \"line_start\": int, \"line_end\": int, "
    "\"trace\": [{\"file\", \"line\", \"label\": \"entrypoint|propagation|sink: short hop\"}], "
    "\"controls_checked\": [short strings], \"reasoning\": 2-4 sentences, no code}."
)

CRITIC_SYSTEM = GROUND_RULES + (
    "\nYou are an INDEPENDENT CRITIC. Another reviewer claims the finding below is exploitable. "
    "Re-read every cited line yourself and try to REFUTE it: a missing or fake entrypoint, input "
    "validation or allow-listing, parameterisation, escaping, a framework protection, an "
    "authorization check or tenant-scoped query, unreachable or test-only code, a static response "
    "with no data, behaviour that is public by design, or an impact that is not meaningful. "
    "Do not refute on speculation — only with a concrete line that blocks the path. "
    "Return JSON: {\"refuted\": bool, \"why\": 1-3 sentences, \"line\": int|null}."
)


def _key(h):
    return (h.file_path, (h.cwe or h.rule).upper(), (h.line_start or 0) // 8)


def merge(hypotheses):
    """Collapse duplicates from different sources, keeping the strongest."""
    best = {}
    for h in hypotheses:
        k = _key(h) if h.file_path else ('', h.fingerprint, 0)
        cur = best.get(k)
        if not cur:
            best[k] = h
            continue
        if h.origin.startswith('analyst') and not cur.origin.startswith('analyst'):
            h.fingerprint = cur.fingerprint if cur.origin == 'threat-model' else h.fingerprint
            best[k] = h
        elif h.rank > cur.rank:
            best[k] = h
    return list(best.values())


def _context(root, h, changed):
    if h.file_path:
        f = next((c for c in changed if c.path == h.file_path), None)
        if f:
            return f'## {f.path}\n' + changed_region_listing(root, f, context=60, cap=16000)
        from ..gitops import read
        return f'## {h.file_path}\n' + read(root, h.file_path, h.line_start or 1,
                                            h.line_end or h.line_start or 1, pad=60)
    # architecture-level threat: show the changed code of the component's files
    parts = [f'## {c.path}\n' + changed_region_listing(root, c, context=15, cap=4000)
             for c in changed if c.added][:8]
    return '\n\n'.join(parts)[:24000]


def region_hash(root, h):
    """Hash of the code a verdict was based on (file region around the finding). If it is
    unchanged, a previous rejection still holds. Only the hash leaves the machine."""
    from ..gitops import read
    if not h.file_path:
        return ''
    start = max(1, (h.line_start or 1) - 25)
    text = read(root, h.file_path, start, (h.line_end or h.line_start or 1) + 25, pad=0)
    return hashlib.sha256(f'{h.file_path}\n{text}'.encode()).hexdigest() if text else ''


def _triage_one(h, root, changed, llm, tracer, fork):
    try:
        return _triage_inner(h, root, changed, llm, tracer, fork)
    except Exception:  # noqa: BLE001 — step already marked failed in the trace
        h.verdict, h.confidence = 'uncertain', 'possible'
        return h


def _triage_inner(h, root, changed, llm, tracer, fork):
    with fork:
        with tracer.step('triage', f'Verify: {h.title[:80]}', fingerprint=h.fingerprint[:12]) as s:
            ctx = _context(root, h, changed)
            if not ctx.strip():
                h.verdict, h.confidence = 'uncertain', 'possible'
                s.summary('no code context available — kept as architecture-level hypothesis')
                return h
            prompt = (f'HYPOTHESIS: {h.title}\nCWE: {h.cwe}\nClaim: {h.description}\n'
                      f'Attack: {h.attack_scenario}\nLocation hint: {h.file_path}:{h.line_start}\n\n'
                      f'CODE:\n{ctx}')
            d = llm.json('triage', TRIAGE_SYSTEM, prompt, default={}) or {}
            h.verdict = d.get('verdict') if d.get('verdict') in ('confirmed', 'rejected', 'uncertain') else 'uncertain'
            if d.get('severity') in SEV_RANK and h.verdict == 'confirmed':
                # triage may lower severity, raising needs the critic later
                if SEV_RANK[d['severity']] < h.rank:
                    h.severity = d['severity']
            if d.get('file') and any(c.path == d['file'] for c in changed):
                h.file_path = d['file']
            if isinstance(d.get('line_start'), int):
                h.line_start = d['line_start']
                h.line_end = d.get('line_end') if isinstance(d.get('line_end'), int) else h.line_start
            h.trace = [{'file': str(t.get('file', ''))[:300], 'line': t.get('line'),
                        'label': str(t.get('label', ''))[:200]}
                       for t in (d.get('trace') or [])[:12] if isinstance(t, dict)]
            h.reasoning = str(d.get('reasoning', ''))[:1500]
            if h.verdict == 'confirmed':
                h.confidence = 'likely'
                h.proof_level = 'L1' if h.trace else 'L0'
            s.summary(f'{h.verdict}: {h.reasoning[:200]}')
            return h


def _critic_one(h, root, changed, llm, tracer, fork):
    try:
        return _critic_inner(h, root, changed, llm, tracer, fork)
    except Exception:  # noqa: BLE001 — critic unavailable: keep, but not 'verified'
        h.confidence = 'likely'
        return h


def _critic_inner(h, root, changed, llm, tracer, fork):
    with fork:
        with tracer.step('critic', f'Try to refute: {h.title[:80]}') as s:
            ctx = _context(root, h, changed)
            d = llm.json('critic', CRITIC_SYSTEM,
                         f'FINDING: {h.title} ({h.severity}, {h.cwe}) at {h.file_path}:{h.line_start}\n'
                         f'Reasoning: {h.reasoning}\nTrace: {h.trace}\n\nCODE:\n{ctx}',
                         default={}) or {}
            if d.get('refuted') and d.get('line'):
                h.verdict, h.confidence, h.proof_level = 'uncertain', 'possible', 'L0'
                s.summary(f"refuted: {str(d.get('why', ''))[:200]}")
            else:
                h.confidence = 'verified' if h.trace else 'likely'
                s.summary('survived the critic')
            return h


AUTH_FAMILY = {'CWE-306', 'CWE-287', 'CWE-862', 'CWE-863', 'CWE-284', 'CWE-639', 'CWE-285'}


def _family(h):
    c = (h.cwe or '').upper()
    if c in AUTH_FAMILY or 'auth' in h.title.lower():
        return 'auth'
    return c or h.rule


def dedupe_confirmed(hyps):
    """After triage every finding has a real location. Collapse findings that point at the
    same place for the same reason (e.g. an architecture threat, an analyst finding and a
    regex signal all describing one missing check). Keeps the strongest; returns merged count."""
    keep, merged = [], 0
    proof_rank = {'L3': 3, 'L2': 2, 'L1': 1, 'L0': 0}
    for h in sorted([x for x in hyps if x.verdict == 'confirmed'],
                    key=lambda x: (-x.rank, -proof_rank[x.proof_level], -len(x.trace))):
        dup = next((k for k in keep if k.file_path and k.file_path == h.file_path
                    and abs((k.line_start or 0) - (h.line_start or 0)) <= 12
                    and _family(k) == _family(h)), None)
        if dup:
            h.verdict = 'merged'
            merged += 1
        else:
            keep.append(h)
    return merged


def triage_all(hyps, root, changed, llm, tracer, parallel=4, rejections=frozenset(), memory=None):
    """memory (dict) collects 'rejected' records and 'reused' keys for the backend."""
    memory = memory if memory is not None else {}
    memory.setdefault('rejected', [])
    memory.setdefault('reused', [])
    merged = merge(hyps)
    active = [h for h in merged if not h.suppressed]
    with tracer.step('orchestrator', f'Triage {len(active)} hypotheses against the code') as s:
        todo = []
        for h in active:
            h.region_hash = region_hash(root, h)
            key = f'{h.fingerprint}:{h.region_hash}'
            if h.region_hash and key in rejections:
                h.verdict, h.confidence = 'rejected', 'possible'
                h.reasoning = 'Refuted in an earlier review; the code region is unchanged.'
                memory['reused'].append(key)
            else:
                todo.append(h)
        if len(todo) < len(active):
            tracer.skip('triage', f'Reuse {len(active) - len(todo)} earlier verdict(s)',
                        'code unchanged since the hypothesis was refuted — no model call needed')
        with ThreadPoolExecutor(max_workers=max(1, parallel)) as ex:
            forks = [tracer.fork() for _ in todo]
            list(ex.map(lambda hf: _triage_one(hf[0], root, changed, llm, tracer, hf[1]),
                        zip(todo, forks)))
        n_dupes = dedupe_confirmed(active)
        # Every surfaced finding (medium+) must survive the critic — noise costs trust.
        hot = [h for h in active if h.verdict == 'confirmed' and h.rank >= 2]
        if hot:
            with ThreadPoolExecutor(max_workers=max(1, parallel)) as ex:
                forks = [tracer.fork() for _ in hot]
                list(ex.map(lambda hf: _critic_one(hf[0], root, changed, llm, tracer, hf[1]),
                            zip(hot, forks)))
        for h in todo:
            if h.verdict == 'rejected' and h.region_hash:
                memory['rejected'].append({'fingerprint': h.fingerprint, 'region_hash': h.region_hash,
                                           'title': h.title[:300], 'file_path': h.file_path,
                                           'reason': h.reasoning[:1000]})
        confirmed = [h for h in active if h.verdict == 'confirmed']
        s.summary(f"{len(confirmed)} confirmed ({n_dupes} duplicates merged), "
                  f"{len([h for h in active if h.verdict == 'rejected'])} rejected, "
                  f"{len([h for h in active if h.verdict == 'uncertain'])} uncertain, "
                  f"{len(merged) - len(active)} suppressed by earlier decisions")
    return merged
