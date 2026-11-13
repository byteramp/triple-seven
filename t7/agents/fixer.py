"""Fixer + verifier loop.

The fixer proposes exact search/replace edits (far more reliable than asking a
model for a unified diff). The verifier applies them in a throw-away worktree
and runs: applies → lint → types → recheck (detectors + independent re-triage).
On any failure the evidence goes back to the fixer, up to N attempts. The full
test suite runs once on the final candidate. Only then is a fix "verified".
"""
import re
import shlex
import subprocess

from .. import gitops
from ..signals import scan
from . import GROUND_RULES
from .analysts import changed_region_listing

FIX_SYSTEM = GROUND_RULES + (
    "\nYou are the FIXER. Write the smallest correct fix for the finding, in the project's own "
    "style and with its existing helpers/frameworks. Do not refactor, rename or reformat "
    "unrelated code. Keep existing base classes, mixins and decorators unless removing one IS "
    "the fix. `find` and `replace` cover the same lines: never paste surrounding code that you "
    "did not change into `replace`. Return JSON: {\"edits\": [{\"file\": path, \"find\": exact existing text "
    "(copied verbatim from the file, unique, 1-30 lines, WITHOUT line-number prefixes), "
    "\"replace\": new text}], \"explanation\": 2-3 sentences for a reviewer, no code}."
)

RECHECK_SYSTEM = GROUND_RULES + (
    "\nYou are an INDEPENDENT VERIFIER. A fix was applied for the finding below. Is the "
    "vulnerability still exploitable in the patched code, and did the fix break intended "
    "behaviour? Return JSON: {\"still_vulnerable\": bool, \"breaks_behaviour\": bool, "
    "\"why\": 1-3 sentences}."
)


def apply_edits(wt, edits):
    """Apply exact search/replace edits. Returns (ok, error)."""
    for e in edits:
        path, find, repl = e.get('file', ''), e.get('find', ''), e.get('replace', '')
        if not path or not find or '..' in path.split('/'):
            return False, f'invalid edit for {path!r}'
        target = wt / path
        if not target.exists():
            return False, f'{path} does not exist'
        text = target.read_text()
        n = text.count(find)
        if n != 1:
            return False, (f"'find' text matched {n} times in {path} "
                           '(must match exactly once — copy it verbatim, without line numbers)')
        target.write_text(text.replace(find, repl, 1))
    return True, ''


_NO_TESTS = re.compile(r"Ran 0 tests|NO TESTS RAN|Found 0 test|collected 0 items|no tests ran|No tests found", re.I)


def structural_problems(wt, files):
    """Deterministic guard against patches that compile but are wrong: duplicate
    definitions in one scope (a model re-pasting a body), or a class/function
    that disappeared. Python only; returns a list of human-readable problems."""
    import ast
    problems = []
    for f in files:
        if not f.endswith('.py'):
            continue
        try:
            tree = ast.parse((wt / f).read_text())
        except (SyntaxError, OSError) as e:
            problems.append(f'{f}: does not parse ({e})')
            continue
        for node in ast.walk(tree):
            body = getattr(node, 'body', None)
            if not isinstance(body, list):
                continue
            seen = {}
            for child in body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    if child.name in seen and not any(
                            isinstance(d, ast.Attribute) and d.attr in ('setter', 'deleter', 'register')
                            or isinstance(d, ast.Name) and d.id == 'overload'
                            for d in child.decorator_list):
                        problems.append(f'{f}:{child.lineno}: `{child.name}` defined twice in the same '
                                        f'scope (first at line {seen[child.name]}) — the edit duplicated code')
                    seen[child.name] = child.lineno
    return problems


def _fmt(cmd, files=(), target=''):
    return cmd.replace('{files}', ' '.join(shlex.quote(f) for f in files)).replace('{target}', target)


def _check(cmd, wt, timeout, files=(), target=''):
    if not cmd:
        return 'skip', ''
    try:
        p = gitops.run(_fmt(cmd, files, target), wt, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 'fail', f'timed out after {timeout}s'
    out = p.stdout + p.stderr
    if _NO_TESTS.search(out) and not re.search(r'FAILED|Error|Traceback', out.replace('NO TESTS RAN', '')):
        return 'skip', out[-2500:]   # zero tests ran: never count that as a pass
    return ('pass' if p.returncode == 0 else 'fail'), out[-2500:]


class Verifier:
    def __init__(self, root, profile, cfg, llm, tracer):
        self.root, self.profile, self.cfg, self.llm, self.tracer = root, profile, cfg, llm, tracer
        self._baseline = {}

    def test_target(self, files):
        """Scope the suite to the packages a fix touches (big monoliths: minutes → seconds)."""
        # Django: tests live inside each app, so scope to the touched apps.
        # pytest/jest/go: tests live elsewhere — run the configured command as is.
        if self.profile.test_framework == 'django':
            pkgs = sorted({f.split('/')[0] for f in files if '/' in f and f.endswith('.py')})
            return ' '.join(p for p in pkgs if (self.root / p / '__init__.py').exists())
        return ''

    def baseline_tests(self, target=''):
        """Do the tests pass BEFORE any fix? If not, 'tests' can't prove anything."""
        if target not in self._baseline:
            if not self.profile.test_cmd:
                self._baseline[target] = 'skip'
            else:
                with self.tracer.step('verifier', f"Baseline: tests {target or '(full suite)'} before fixes") as s:
                    with gitops.worktree(self.root) as wt:
                        res, _ = _check(self.profile.test_cmd, wt, self.cfg.step_timeout, target=target)
                    self._baseline[target] = res
                    s.summary('green' if res == 'pass' else
                              'already failing — test check will be skipped')
        return self._baseline[target]

    def verify(self, h, edits, full_tests=False):
        checks, notes = {}, []
        with gitops.worktree(self.root) as wt:
            ok, err = apply_edits(wt, edits)
            checks['applies'] = 'pass' if ok else 'fail'
            if not ok:
                return checks, err, ''
            files = sorted({e['file'] for e in edits})
            checks['lint'], out = _check(self.profile.lint_cmd, wt, 300, files)
            if checks['lint'] == 'fail':
                notes.append(f'LINT FAILED:\n{out}')
            checks['types'], out = _check(self.profile.type_cmd, wt, 600, files)
            if checks['types'] == 'fail':
                notes.append(f'TYPECHECK FAILED:\n{out}')
            problems = structural_problems(wt, files)
            if problems:
                checks['lint'] = 'fail'
                notes.append('STRUCTURE CHECK FAILED — keep the edit minimal; `replace` must contain '
                             'only the changed lines, not a copy of the surrounding code:\n'
                             + '\n'.join(problems))

            # recheck 1: the deterministic detector that fired must be gone on touched lines
            # Patch = ONLY the files we edited (tools may have created caches etc.).
            patch = gitops.git(wt, 'diff', '--no-color', '--', *files)
            changed = gitops.changed_files(wt, 'HEAD', include_worktree=True)
            sigs, _ = scan(changed)
            still = [s for s in sigs if h.rule == f"signal.{s['kind']}" and s['file'] == h.file_path]
            # recheck 2: independent model re-triage of the patched code
            listing = '\n\n'.join(f'## {c.path}\n{changed_region_listing(wt, c, 30, 9000)}'
                                  for c in changed)
            d = self.llm.json('critic', RECHECK_SYSTEM,
                              f'FINDING: {h.title} ({h.cwe})\n{h.description}\n\nPATCHED CODE:\n{listing}',
                              default={}) or {}
            vulnerable = bool(d.get('still_vulnerable')) or bool(still)
            checks['recheck'] = 'fail' if vulnerable or d.get('breaks_behaviour') else 'pass'
            if checks['recheck'] == 'fail':
                notes.append(f"RECHECK FAILED: {d.get('why', 'detector still fires')}")

            if full_tests and all(v != 'fail' for v in checks.values()):
                target = self.test_target(files)
                if self.baseline_tests(target) == 'pass':
                    checks['tests'], out = _check(self.profile.test_cmd, wt, self.cfg.step_timeout,
                                                  target=target)
                    if checks['tests'] == 'fail':
                        notes.append(f'TESTS FAILED:\n{out}')
                else:
                    checks['tests'] = 'skip'
        return checks, '\n\n'.join(notes), patch


def fix_one(h, root, changed, verifier, cfg, llm, tracer):
    if True:
        with tracer.step('fixer', f'Fix: {h.title[:80]}', sec=h.fingerprint[:12]) as s:
            f = next((c for c in changed if c.path == h.file_path), None)
            if not f:
                s.skip('finding has no code location in this diff')
                return h
            listing = gitops.read(root, h.file_path, h.line_start or 1, h.line_end or h.line_start or 1,
                                  pad=80)
            # The model must copy `find` verbatim — give it the raw region without numbers too.
            raw = '\n'.join(l.split(' | ', 1)[1] if ' | ' in l else l for l in listing.splitlines())
            base_prompt = (f'FINDING: {h.title} ({h.severity}, {h.cwe})\n{h.description}\n'
                           f'Recommendation: {h.recommendation}\nLocation: {h.file_path}:{h.line_start}\n'
                           f'Trace: {h.trace}\n\nNUMBERED (for orientation):\n{listing}\n\n'
                           f'RAW TEXT (copy `find` from here):\n{raw}')
            feedback, edits, checks, patch, explanation = '', [], {}, '', ''
            for attempt in range(1, cfg.max_fix_attempts + 1):
                with tracer.step('fixer', f'Attempt {attempt}: propose patch') as a:
                    d = llm.json('fix', FIX_SYSTEM, base_prompt + (
                        f'\n\nPREVIOUS ATTEMPT FAILED VERIFICATION:\n{feedback}' if feedback else ''),
                        default={}, max_tokens=3000) or {}
                    edits = [e for e in (d.get('edits') or []) if isinstance(e, dict)][:8]
                    a.summary(f'{len(edits)} edit(s)')
                if not edits:
                    feedback = 'No edits returned. Return at least one exact search/replace edit.'
                    continue
                with tracer.step('verifier', f'Attempt {attempt}: verify in isolated worktree') as v:
                    checks, notes, patch = verifier.verify(h, edits, full_tests=False)
                    v.summary(', '.join(f'{k} {val}' for k, val in checks.items()))
                if all(val != 'fail' for val in checks.values()):
                    explanation = str(d.get('explanation', ''))[:1500]
                    break
                feedback = notes[:6000]
            else:
                h.fix = {'status': 'failed', 'checks': checks, 'attempts': cfg.max_fix_attempts,
                         'delivery': 'local', 'explanation': 'No candidate passed verification.'}
                s.summary(f'no verified fix after {cfg.max_fix_attempts} attempts')
                return h

            with tracer.step('verifier', 'Final verification incl. test suite') as v:
                checks, notes, patch = verifier.verify(h, edits, full_tests=True)
                v.summary(', '.join(f'{k} {val}' for k, val in checks.items()))
            failed = [k for k, val in checks.items() if val == 'fail']
            passed = [k for k, val in checks.items() if val == 'pass']
            status = 'failed' if failed else ('verified' if {'applies', 'recheck'} <= set(passed)
                                              and 'tests' in passed else 'partial')
            files, add, rem = gitops.patch_stats(patch)
            h.patch, h.edits = patch, edits
            h.fix = {'status': status, 'checks': checks, 'attempts': attempt,
                     'patch_sha256': gitops.patch_hash(patch) if patch else '',
                     'files_changed': files, 'lines_added': add, 'lines_removed': rem,
                     'explanation': explanation, 'delivery': 'local'}
            s.summary(f'{status} after {attempt} attempt(s) — {files} file(s), +{add}/-{rem}')
            return h
