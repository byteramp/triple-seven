"""Orchestrator — the systematic pipeline. Fixed skeleton, dynamic middle:

  config → diff → detectors → PLANNER (chooses the chain)
  → MAPPER → server threat model → ANALYSTS (parallel, chosen by planner)
  → TRIAGE (parallel) → CRITIC (high/critical) → re-check previously open SEC-REQs
  → FIXER⇄VERIFIER loop (per confirmed finding) → PROVER (if a test runner exists)
  → noise budget → upload metadata → gate → PR comment / local report
"""
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

from . import __version__, gitops
from .agents import Hypothesis, SEV_RANK
from .agents.analysts import run_analysts
from .agents.fixer import Verifier, fix_one
from .agents.mapper import map_architecture
from .agents.planner import plan
from .agents.prover import prove_one
from .agents.reporter import (github_context, post_pr, select_for_pr, write_bundle,
                              write_last_scan)
from .agents.triage import TRIAGE_SYSTEM, _context, triage_all
from .api import APIError, Byteramp
from .config import Config
from .context import detect
from .llm import LLM
from .signals import scan
from .trace import Tracer


def _hyp_from_threat(t):
    return Hypothesis(
        fingerprint=t['fingerprint'], title=t['title'], severity=t['severity'], rule=t.get('rule', ''),
        cwe=t.get('cwe', ''), owasp=t.get('owasp', ''), llm_code=t.get('llm_code', ''),
        stride=t.get('stride', ''), component=t.get('component', ''),
        file_path=t.get('file_path', ''), line_start=t.get('line_start'),
        line_end=t.get('line_start'), description=t.get('description', ''),
        attack_scenario=t.get('attack_scenario', ''), recommendation=t.get('recommendation', ''),
        source=t.get('source', 'model'), origin='threat-model', suppressed=t.get('suppressed', False))


def _committed_fixes(root):
    """Patches from earlier local runs that are now in HEAD → the developer took the fix."""
    import json
    idx = root / '.t7' / 'fixes' / 'index.json'
    try:
        index = json.loads(idx.read_text())
    except (OSError, ValueError):
        return []
    out = []
    for meta in index.values():
        patch = meta.get('fix_only')
        if patch and meta.get('patch_sha256'):
            ok, _ = gitops.apply_patch(root, patch, check_only=True, reverse=True)
            if ok:
                out.append(meta['patch_sha256'])
    return out


def scan_repo(base=None, fix=True, ci=False, quiet=False, enrich=True, client=None):
    started = time.time()
    root = gitops.repo_root()
    cfg = Config.load(root)
    api = Byteramp(cfg)
    llm = LLM(cfg, api)
    gh = github_context() if ci else None

    base_sha = gitops.resolve_base(root, base)
    head = gitops.head_sha(root)
    changed = gitops.changed_files(root, base_sha, include_worktree=not ci, ignore=cfg.ignore_paths)
    profile = detect(root, cfg)

    policy, run_id = {}, None
    if not cfg.offline:
        try:
            r = api.start_run(trigger='pull_request' if gh else ('push' if ci else 'local'),
                              ref=os.environ.get('GITHUB_HEAD_REF') or gitops.git(
                                  root, 'rev-parse', '--abbrev-ref', 'HEAD').strip(),
                              base_sha=base_sha, head_sha=head,
                              pr_number=gh and gh['number'], pr_title=gh and gh['title'],
                              pr_url=gh and gh['url'], author=gh and gh['author'],
                              agent_version=__version__, stack=profile.stack,
                              llm_provider=cfg.llm_provider_kind, llm_model=cfg.llm_model,
                              client=client or ('action' if ci else 'cli'))
            run_id, policy = r['run_id'], r
        except APIError as e:
            print(f't7: cannot reach Byteramp ({e}).', file=sys.stderr)
            if e.status in (401, 403):
                sys.exit(2)
            cfg.offline = True
    if cfg.llm == 'byteramp' and cfg.offline:
        print('t7: Byteramp models need a token. Set T7_TOKEN or use T7_LLM=ollama|openai|azure|anthropic.',
              file=sys.stderr)
        sys.exit(2)

    if cfg.llm == 'byteramp':
        cfg.parallel = max(1, min(cfg.parallel, int((policy.get('llm') or {}).get('max_parallel') or 1)))
    tracer = Tracer(None if cfg.offline else api, run_id, quiet=quiet)
    suppressed = set(policy.get('suppressed_fingerprints', []))
    sec_ids, result = {}, {'gate': {'verdict': 'pass'}, 'summary_markdown': ''}
    try:
        with tracer.step('orchestrator', f'Review {len(changed)} changed file(s)',
                         base=base_sha[:12], head=head[:12]) as root_step:
            if not changed:
                root_step.skip('no changes against the base')
            else:
                signals, areas = scan(changed)
                chain = plan(changed, areas, signals, profile, llm, tracer)
                if run_id:
                    api.plan(run_id, chain)

                delta = map_architecture(root, changed, signals, chain, llm, tracer,
                                         gitops.numbered)
                hyps = []
                if run_id:
                    with tracer.step('threat-model', 'Delta threat model (Airframe engine)') as s:
                        tm = api.architecture(run_id, delta, enrich=enrich)
                        hyps += [_hyp_from_threat(t) for t in tm.get('threats', [])]
                        s.summary(f"{len(hyps)} hypotheses from {tm['stats']['components']} "
                                  f"components / {tm['stats']['flows']} flows")
                else:
                    tracer.skip('threat-model', 'Delta threat model', 'offline — local analysis only')

                hyps += run_analysts(chain, changed, root, llm, tracer, cfg.parallel)
                for h in hyps:
                    h.suppressed = h.suppressed or h.fingerprint in suppressed
                hyps = triage_all(hyps, root, changed, llm, tracer, cfg.parallel)
                confirmed = [h for h in hyps if h.verdict == 'confirmed' and not h.suppressed]

                resolved = _recheck_open(policy.get('open_findings', []), confirmed, root, changed,
                                         llm, tracer)

                if fix and confirmed:
                    verifier = Verifier(root, profile, cfg, llm, tracer)
                    fixable = [h for h in confirmed if h.file_path and h.rank >= SEV_RANK['low']]
                    with tracer.step('orchestrator', f'Fix + verify {len(fixable)} finding(s)'):
                        # Sequential on purpose: each verification uses its own worktree and
                        # the test suite; parallel suites fight over ports/DBs.
                        for h in sorted(fixable, key=lambda x: -x.rank):
                            try:
                                fix_one(h, root, changed, verifier, cfg, llm, tracer)
                                if chain['prove']:
                                    prove_one(h, root, profile, cfg, llm, tracer)
                            except Exception:  # noqa: BLE001 — trace has the failure
                                h.fix = h.fix or {'status': 'failed', 'checks': {}, 'attempts': 0,
                                                  'delivery': 'local',
                                                  'explanation': 'Fix step failed (model unavailable).'}
                elif not fix:
                    tracer.skip('fixer', 'Fix + verify', 'disabled (--no-fix)')

                budget = int(policy.get('noise_budget') or 5)
                surfaced, rest = select_for_pr(confirmed, budget)
                uncertain = [h for h in hyps if h.verdict == 'uncertain' and not h.suppressed
                             and h.rank >= SEV_RANK['high']]
                if run_id:
                    with tracer.step('reporter', 'Record findings, fixes and proofs') as s:
                        payload = ([h.to_api(True) for h in surfaced] + [h.to_api(False) for h in rest]
                                   + [h.to_api(False) for h in uncertain])
                        out = api.findings(run_id, payload) if payload else {'findings': []}
                        sec_ids = {f['fingerprint']: f['sec_req_id'] for f in out['findings']}
                        s.summary(f'{len(surfaced)} in PR, {len(rest)} dashboard-only, '
                                  f'{len(uncertain)} unconfirmed hypotheses kept for review')
                write_bundle(root, confirmed, sec_ids)
                result['surfaced'], result['resolved'] = surfaced, resolved
                result['_confirmed'] = confirmed
        tracer.flush()
        if run_id:
            result = {**result, **api.finish(
                run_id, resolved_fingerprints=result.get('resolved', []),
                committed_patches=_committed_fixes(root),
                stats={'changed_files': len(changed), 'llm_calls': llm.calls,
                       'llm_chars_in': llm.chars_in, 'llm_model': llm.model,
                       'seconds': round(time.time() - started, 1),
                       'steps': len(tracer.steps)})}
            if gh and result.get('summary_markdown'):
                try:
                    post_pr(gh, result['summary_markdown'], result.get('surfaced', []), sec_ids, tracer)
                except Exception as e:  # noqa: BLE001
                    print(f't7: could not post to the PR: {e}', file=sys.stderr)
                tracer.flush()
    except Exception as e:  # noqa: BLE001
        tracer.flush()
        if run_id:
            try:
                api.finish(run_id, status='error', error=f'{type(e).__name__}: {e}')
            except APIError:
                pass
        raise
    result['sec_ids'] = sec_ids
    result['seconds'] = round(time.time() - started, 1)
    write_last_scan(root, result.pop('_confirmed', []), sec_ids, result.get('gate') or {},
                    result['seconds'], result.get('resolved', []))
    result['run_id'] = run_id
    result['api_url'] = cfg.api_url
    return result


def _recheck_open(open_findings, confirmed, root, changed, llm, tracer):
    """Previously open SEC-REQs in files this change touched: still there?"""
    touched = {c.path for c in changed}
    seen = {h.fingerprint for h in confirmed}
    candidates = [f for f in open_findings if f.get('file_path') in touched
                  and f['fingerprint'] not in seen][:15]
    if not candidates:
        return []
    resolved = []
    with tracer.step('triage', f'Re-check {len(candidates)} open SEC-REQ(s) in touched files') as s:
        def check(f):
            h = Hypothesis(fingerprint=f['fingerprint'], title=f['title'], severity=f['severity'],
                           cwe=f.get('cwe', ''), file_path=f['file_path'],
                           line_start=f.get('line_start'), description=f.get('description', ''))
            d = llm.json('triage', TRIAGE_SYSTEM,
                         f'Is this previously reported issue STILL present?\nHYPOTHESIS: {h.title}\n'
                         f'{h.description}\n\nCODE:\n{_context(root, h, changed)}', default={}) or {}
            return f['fingerprint'] if d.get('verdict') == 'rejected' else None
        with ThreadPoolExecutor(max_workers=4) as ex:
            resolved = [r for r in ex.map(check, candidates) if r]
        s.summary(f'{len(resolved)} resolved by this change')
    return resolved
