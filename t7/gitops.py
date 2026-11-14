"""Git + workspace helpers. Every verification runs in a throw-away worktree so
the developer's checkout is never touched."""
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path


def run(cmd, cwd, timeout=600, env=None, check=False):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout,
                       shell=isinstance(cmd, str), env={**os.environ, **(env or {})})
    if check and p.returncode != 0:
        raise RuntimeError(f'{cmd}: {p.stderr.strip()[:400]}')
    return p


def git(root, *args, check=True, timeout=120):
    return run(['git', *args], root, timeout=timeout, check=check).stdout


@dataclass
class Hunk:
    start: int
    length: int
    added_lines: list = field(default_factory=list)   # [(line_no, text)]


@dataclass
class ChangedFile:
    path: str
    status: str                  # A, M, D, R
    hunks: list = field(default_factory=list)

    @property
    def added(self):
        return [ln for h in self.hunks for ln in h.added_lines]


def repo_root(start='.'):
    return Path(git(start, 'rev-parse', '--show-toplevel').strip())


def resolve_base(root, base=None):
    candidates = [base] if base else []
    for var in ('GITHUB_BASE_REF', 'CI_MERGE_REQUEST_TARGET_BRANCH_NAME',
                'BITBUCKET_PR_DESTINATION_BRANCH', 'SYSTEM_PULLREQUEST_TARGETBRANCH'):
        env_base = os.environ.get(var, '').replace('refs/heads/', '')
        if env_base:
            candidates.append(f'origin/{env_base}')
    candidates += ['origin/main', 'origin/master', 'main', 'master']
    for c in candidates:
        if c and run(['git', 'rev-parse', '--verify', '--quiet', c], root).returncode == 0:
            mb = run(['git', 'merge-base', c, 'HEAD'], root)
            if mb.returncode == 0:
                return mb.stdout.strip()
    if run(['git', 'rev-parse', '--verify', '--quiet', 'HEAD~1'], root).returncode == 0:
        return git(root, 'rev-parse', 'HEAD~1').strip()
    # First commit, or no commits yet: review everything against the empty tree.
    return EMPTY_TREE


EMPTY_TREE = '4b825dc642cb6eb9a060e54bf8d69288fbee4904'   # git's well-known empty tree


def has_commits(root):
    return run(['git', 'rev-parse', '--verify', '--quiet', 'HEAD'], root).returncode == 0


def head_sha(root):
    return git(root, 'rev-parse', 'HEAD').strip() if has_commits(root) else ''


def current_branch(root):
    p = run(['git', 'symbolic-ref', '--quiet', '--short', 'HEAD'], root)
    return p.stdout.strip() if p.returncode == 0 else 'HEAD'


def changed_files(root, base, include_worktree=True, ignore=()):
    """Parse a unified diff (base..HEAD, plus uncommitted work for local runs)."""
    args = ['diff', '--unified=0', '--no-color', '--find-renames', base]
    if not include_worktree and has_commits(root):
        args.append('HEAD')
    out = git(root, *args)
    files, cur, hunk = [], None, None
    for line in out.splitlines():
        if line.startswith('diff --git'):
            cur = None
        elif line.startswith('+++ '):
            path = line[4:].strip()
            if path == '/dev/null':
                continue
            path = path[2:] if path.startswith('b/') else path
            if any(path.startswith(i) or f'/{i}' in path for i in ignore):
                cur = None
                continue
            cur = ChangedFile(path=path, status='M')
            files.append(cur)
        elif line.startswith('new file mode') and files:
            pass
        elif line.startswith('@@') and cur is not None:
            m = re.match(r'@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@', line)
            if m:
                hunk = Hunk(int(m.group(1)), int(m.group(2) or 1))
                cur.hunks.append(hunk)
                hunk._next = hunk.start
        elif cur is not None and hunk is not None and line.startswith('+') and not line.startswith('+++'):
            hunk.added_lines.append((hunk._next, line[1:]))
            hunk._next += 1
    status = {}
    for ln in git(root, 'diff', '--name-status', base).splitlines():
        parts = ln.split('\t')
        if len(parts) >= 2:
            status[parts[-1]] = parts[0][0]
    for f in files:
        f.status = status.get(f.path, 'M')
    if include_worktree:   # local runs: brand-new files that are not added to git yet
        seen = {f.path for f in files}
        for rel in git(root, 'ls-files', '--others', '--exclude-standard').splitlines():
            if rel in seen or rel.startswith('.t7/') or any(rel.startswith(i) or f'/{i}' in rel for i in ignore):
                continue
            path = root / rel
            try:
                if path.stat().st_size > 512_000:
                    continue
                text = path.read_text()
            except (OSError, UnicodeDecodeError):
                continue   # binary or unreadable
            lines = text.splitlines()
            h = Hunk(1, len(lines))
            h.added_lines = list(enumerate(lines, 1))
            files.append(ChangedFile(path=rel, status='A', hunks=[h] if lines else []))
    return [f for f in files if (root / f.path).exists()]


def read(root, path, start=None, end=None, pad=0):
    try:
        lines = (root / path).read_text(errors='replace').splitlines()
    except OSError:
        return ''
    if start is None:
        return '\n'.join(lines)
    s, e = max(1, start - pad), min(len(lines), (end or start) + pad)
    return '\n'.join(f'{i:>5} | {lines[i - 1]}' for i in range(s, e + 1))


def numbered(root, path, max_lines=900):
    try:
        lines = (root / path).read_text(errors='replace').splitlines()
    except OSError:
        return ''
    return '\n'.join(f'{i:>5} | {l}' for i, l in enumerate(lines[:max_lines], 1))


def patch_hash(patch):
    norm = '\n'.join(l.rstrip() for l in patch.strip().splitlines())
    return hashlib.sha256(norm.encode()).hexdigest()


def patch_stats(patch):
    files = len(re.findall(r'^\+\+\+ ', patch, re.M))
    added = len([l for l in patch.splitlines() if l.startswith('+') and not l.startswith('+++')])
    removed = len([l for l in patch.splitlines() if l.startswith('-') and not l.startswith('---')])
    return files, added, removed


@contextmanager
def worktree(root, ref='HEAD', with_uncommitted=True):
    """Detached worktree at `ref` (+ the developer's uncommitted changes)."""
    tmp = Path(tempfile.mkdtemp(prefix='t7-wt-'))
    path = tmp / 'wt'
    git(root, 'worktree', 'add', '--detach', str(path), ref, timeout=300)
    try:
        if with_uncommitted:
            dirty = git(root, 'diff', 'HEAD', '--binary')
            untracked = git(root, 'ls-files', '--others', '--exclude-standard').splitlines()
            if dirty.strip():
                subprocess.run(['git', 'apply', '--whitespace=nowarn'], cwd=path,
                               input=dirty, text=True, capture_output=True)
            for rel in [u for u in untracked if not u.startswith('.t7/')][:500]:
                src, dst = root / rel, path / rel
                if src.is_file():
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src, dst)
            if dirty.strip() or untracked:
                # Snapshot the developer's work so later diffs contain ONLY our edits.
                run(['git', 'add', '-A'], path)
                run(['git', '-c', 'user.name=t7', '-c', 'user.email=t7@localhost', 'commit',
                     '-q', '--no-verify', '-m', 't7: snapshot of working tree'], path)
        yield path
    finally:
        run(['git', 'worktree', 'remove', '--force', str(path)], root)
        shutil.rmtree(tmp, ignore_errors=True)


def apply_patch(path, patch, check_only=False, reverse=False):
    args = ['git', 'apply', '--whitespace=nowarn', '--recount']
    if check_only:
        args.append('--check')
    if reverse:
        args.append('--reverse')
    p = subprocess.run(args, cwd=path, input=patch if patch.endswith('\n') else patch + '\n',
                       text=True, capture_output=True)
    return p.returncode == 0, p.stderr.strip()[:1500]
