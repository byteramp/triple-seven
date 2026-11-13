"""Prover — L2 proof: a regression test that FAILS on the vulnerable code and
PASSES with the fix. That is evidence a developer trusts, and it stays in the
repo as protection against the bug coming back."""
import re
from pathlib import PurePosixPath

from .. import gitops
from . import GROUND_RULES
from .fixer import _check, apply_edits

PROVE_SYSTEM = GROUND_RULES + (
    "\nYou are the PROVER. Write ONE focused regression test, in the project's test framework "
    "({framework}), that exercises the vulnerability through the real code path and asserts the "
    "SAFE behaviour. It must fail on the current (vulnerable) code and pass once the fix is "
    "applied. No network, no external services; use the framework's test client/fixtures. "
    "Return JSON: {{\"path\": new test file path, \"content\": full file content, "
    "\"asserts\": one sentence describing what the test proves}}."
)

_NAME_OK = {
    'django': re.compile(r'(^|/)tests?_?[\w]*\.py$|(^|/)tests/[\w/]*test[\w]*\.py$'),
    'pytest': re.compile(r'(^|/)test_[\w]+\.py$|_test\.py$'),
    'jest': re.compile(r'\.(test|spec)\.(t|j)sx?$'),
    'vitest': re.compile(r'\.(test|spec)\.(t|j)sx?$'),
    'go': re.compile(r'_test\.go$'),
}


def _target(framework, path):
    if framework == 'django':
        return str(PurePosixPath(path).with_suffix('')).replace('/', '.')
    if framework == 'go':
        return './' + str(PurePosixPath(path).parent)
    return path


def prove_one(h, root, profile, cfg, llm, tracer):
    if True:
        with tracer.step('prover', f'Prove: {h.title[:80]}') as s:
            if not (h.fix and h.fix.get('status') in ('verified', 'partial') and h.edits):
                s.skip('no verified fix to prove against')
                return h
            fw = profile.test_framework
            region = gitops.read(root, h.file_path, h.line_start or 1, h.line_end or h.line_start or 1,
                                 pad=60)
            d = llm.json('prove', PROVE_SYSTEM.format(framework=fw),
                         f'FINDING: {h.title} ({h.cwe}) at {h.file_path}:{h.line_start}\n'
                         f'Attack: {h.attack_scenario}\nTrace: {h.trace}\n\nCODE:\n{region}\n\n'
                         f'FIX EDITS: {h.edits}', default={}, max_tokens=3000) or {}
            path, content = str(d.get('path', '')), str(d.get('content', ''))
            if not path or not content or '..' in path.split('/') or path.startswith('/') \
                    or not _NAME_OK.get(fw, re.compile('.')).search(path) or (root / path).exists():
                s.summary('prover did not return a valid new test file')
                return h
            target = _target(fw, path)

            test_patch = {}

            def _with(apply_fix):
                with gitops.worktree(root) as wt:
                    (wt / path).parent.mkdir(parents=True, exist_ok=True)
                    (wt / path).write_text(content)
                    if not apply_fix:
                        gitops.git(wt, 'add', '-N', '--', path)
                        test_patch['diff'] = gitops.git(wt, 'diff', '--no-color', '--', path)
                    if apply_fix:
                        ok, _ = apply_edits(wt, h.edits)
                        if not ok:
                            return 'fail'
                    res, _ = _check(profile.test_cmd, wt, cfg.step_timeout, target=target)
                    return res

            before = _with(False)
            after = _with(True) if before == 'fail' else 'skip'
            proven = before == 'fail' and after == 'pass'
            if proven:
                h.proof_level, h.confidence = 'L2', 'verified'
                h.fix['checks']['regression_test'] = 'pass'
                h.test_patch = test_patch.get('diff', '')
            h.proofs.append({'kind': 'regression_test', 'level': 'L2' if proven else h.proof_level,
                             'test_path': path, 'summary': str(d.get('asserts', ''))[:500],
                             'fails_before_fix': before == 'fail',
                             'passes_after_fix': after == 'pass'})
            s.summary(f'test {"fails before / passes after — L2 proof" if proven else f"inconclusive (before={before}, after={after})"}')
            return h
