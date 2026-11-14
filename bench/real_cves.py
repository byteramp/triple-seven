"""Build a benchmark corpus from REAL security fixes (GitHub advisories via OSV).

For every advisory (PyPI, npm) whose fix is a GitHub commit that changes exactly one
source file, we take
  * the file BEFORE the fix  → a vulnerable case (the vulnerable line = first removed line)
  * the file AFTER the fix   → a decoy: the same claim must now be rejected
so recall and precision are measured on code nobody wrote for this benchmark.

Only metadata and a window of each file (±70 lines around the change) are stored in
bench/real/cases.json, with the advisory id, repository and commit for traceability.

  python -m bench.real_cves --limit 150          # ~150 pairs = ~300 cases
"""
import argparse
import io
import json
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path

OUT = Path(__file__).parent / 'real' / 'cases.json'
ECOSYSTEMS = {'PyPI': {'.py'}, 'npm': {'.js', '.ts', '.mjs', '.cjs'}}
LANG = {'.py': 'python', '.js': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript', '.ts': 'typescript'}
# CWE → benchmark family (the specialist that should catch it)
FAMILY = {
    'CWE-89': 'sqli', 'CWE-78': 'cmdi', 'CWE-77': 'cmdi', 'CWE-94': 'cmdi', 'CWE-95': 'cmdi',
    'CWE-22': 'path', 'CWE-23': 'path', 'CWE-73': 'path', 'CWE-918': 'ssrf', 'CWE-502': 'deser',
    'CWE-79': 'xss', 'CWE-80': 'xss', 'CWE-601': 'redirect', 'CWE-639': 'idor', 'CWE-284': 'authz',
    'CWE-285': 'authz', 'CWE-862': 'authz', 'CWE-863': 'authz', 'CWE-287': 'authn', 'CWE-306': 'authn',
    'CWE-798': 'secrets', 'CWE-327': 'crypto', 'CWE-328': 'crypto', 'CWE-330': 'crypto',
    'CWE-611': 'xxe', 'CWE-1321': 'proto', 'CWE-915': 'massassign', 'CWE-1333': 'redos',
    'CWE-200': 'leak', 'CWE-209': 'leak', 'CWE-352': 'csrf', 'CWE-74': 'injection', 'CWE-20': 'validation',
}
COMMIT = re.compile(r'https://github\.com/([\w.-]+)/([\w.-]+)/commit/([0-9a-f]{7,40})')
UA = {'User-Agent': 't7-benchmark/1.0'}
WINDOW = 70


def get(url, timeout=60):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def advisories(eco):
    data = get(f'https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip', timeout=300)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for name in z.namelist():
            if not name.startswith('GHSA-'):
                continue
            adv = json.loads(z.read(name))
            if adv.get('withdrawn'):
                continue
            cwes = (adv.get('database_specific') or {}).get('cwe_ids') or []
            fam = next((FAMILY[c] for c in cwes if c in FAMILY), None)
            if not fam:
                continue
            fixes = [m.groups() for ref in adv.get('references') or []
                     for m in [COMMIT.match(ref.get('url', ''))] if m]
            if len(fixes) != 1:
                continue
            yield adv, cwes, fam, fixes[0]


def parse_diff(diff):
    """{path: [hunks]} for one-file source changes; hunk = (old_start, removed, added)."""
    files, cur = {}, None
    for line in diff.splitlines():
        if line.startswith('diff --git'):
            cur = None
        elif line.startswith('+++ b/'):
            cur = line[6:]
            files[cur] = []
        elif line.startswith('@@') and cur:
            m = re.match(r'@@ -(\d+)', line)
            files[cur].append([int(m.group(1)), [], []])
        elif cur and files[cur]:
            if line.startswith('-') and not line.startswith('---'):
                files[cur][-1][1].append(line[1:])
            elif line.startswith('+') and not line.startswith('+++'):
                files[cur][-1][2].append(line[1:])
    return files


def is_test(path):
    p = path.lower()
    return any(t in p for t in ('test', 'spec', '__mocks__', 'fixture', 'example', 'docs/', 'dist/', '.min.'))


def window(text, line):
    lines = text.splitlines()
    lo = max(0, line - 1 - WINDOW)
    hi = min(len(lines), line - 1 + WINDOW)
    return '\n'.join(lines[lo:hi]) + '\n', line - lo


def build(limit, sleep):
    cases, pairs, seen = [], 0, set()
    per_eco = max(1, limit // len(ECOSYSTEMS))
    for eco, exts in ECOSYSTEMS.items():
        print(f'loading {eco} advisories …', file=sys.stderr, flush=True)
        eco_pairs = 0
        for adv, cwes, fam, (owner, repo, sha) in advisories(eco):
            if eco_pairs >= per_eco:
                break
            key = (owner.lower(), repo.lower(), sha[:12])
            if key in seen:
                continue
            seen.add(key)
            try:
                diff = get(f'https://github.com/{owner}/{repo}/commit/{sha}.diff').decode('utf-8', 'replace')
            except Exception:  # noqa: BLE001
                continue
            time.sleep(sleep)
            files = {p: h for p, h in parse_diff(diff).items()
                     if Path(p).suffix in exts and not is_test(p)}
            if len(files) != 1:
                continue
            path, hunks = next(iter(files.items()))
            changed = sum(len(r) + len(a) for _, r, a in hunks)
            removed = [h for h in hunks if h[1]]
            if not removed or changed > 80:
                continue
            try:
                after = get(f'https://raw.githubusercontent.com/{owner}/{repo}/{sha}/{path}').decode('utf-8', 'replace')
            except Exception:  # noqa: BLE001
                continue
            if len(after) > 400_000:
                continue
            # Reconstruct the vulnerable file by reverse-applying the diff with `patch`.
            with tempfile.TemporaryDirectory() as d:
                f = Path(d) / 'f'
                f.write_text(after)
                one = re.search(r'(diff --git a/' + re.escape(path) + r' b/.*?)(?=\ndiff --git |\Z)', diff, re.S)
                if not one:
                    continue
                p = subprocess.run(['patch', '-R', '-s', '-f', str(f)], input=one.group(1) + '\n', text=True,
                                   capture_output=True)
                if p.returncode != 0:
                    continue
                before = f.read_text()
            # Vulnerable line: first removed line of the first hunk that removes something.
            start, rem, _ = removed[0]
            b_lines = before.splitlines()
            vline = next((i + 1 for i in range(max(0, start - 3), min(len(b_lines), start + 40))
                          if b_lines[i] == rem[0]), start)
            a_lines = after.splitlines()
            aline = min(len(a_lines), max(1, vline))
            code_b, line_b = window(before, vline)
            code_a, _ = window(after, aline)
            summary = (adv.get('summary') or adv.get('details') or '').strip().splitlines()[0][:160]
            hyp = {'title': summary or f'{fam} vulnerability', 'cwe': cwes[0],
                   'description': (adv.get('details') or summary)[:400]}
            meta = {'advisory': adv['id'], 'repo': f'{owner}/{repo}', 'commit': sha, 'ecosystem': eco}
            lang = LANG[Path(path).suffix]
            cases.append({'id': f"{adv['id']}-vuln", 'lang': lang, 'path': path, 'code': code_b,
                          'vuln': {'family': fam, 'line': line_b, 'title': summary}, 'hypothesis': hyp,
                          'source': meta})
            cases.append({'id': f"{adv['id']}-fixed", 'lang': lang, 'path': path, 'code': code_a,
                          'vuln': None, 'hypothesis': hyp, 'source': meta})
            pairs += 1
            eco_pairs += 1
            print(f'  + {adv["id"]} {owner}/{repo} {path} ({fam})  [{pairs}/{limit}]', file=sys.stderr, flush=True)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(cases, indent=1))
    print(f'{pairs} pairs, {len(cases)} cases → {OUT}', file=sys.stderr)


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--limit', type=int, default=150)
    ap.add_argument('--sleep', type=float, default=0.7)
    a = ap.parse_args()
    build(a.limit, a.sleep)
