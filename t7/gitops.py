"""Git + workspace helpers. Every verification runs in a throw-away worktree so
the developer's checkout is never touched."""
import codecs
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath

from .repo_graph import MAX_BYTES, read_file


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
    removed_lines: list = field(default_factory=list)


@dataclass
class ChangedFile:
    path: str
    status: str                  # A, M, D, R
    hunks: list = field(default_factory=list)
    skip_reason: str = ''

    @property
    def added(self):
        return [ln for h in self.hunks for ln in h.added_lines]


def repo_root(start='.'):
    return Path(git(start, 'rev-parse', '--show-toplevel').strip())


def resolve_base(root, base=None):
    if base == EMPTY_TREE:
        return EMPTY_TREE
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


def _git_bytes(root, *args, stdin=None):
    cmd = ['git', '--literal-pathspecs', '-c', 'core.quotePath=true', *args]
    p = subprocess.run(cmd, cwd=root, input=stdin, capture_output=True, timeout=120)
    if p.returncode:
        raise RuntimeError(f'git {args[0]} failed: {os.fsdecode(p.stderr)[:400]}')
    return p.stdout


def _patch_path(header):
    # With renames disabled, both halves contain the same pathname. Their byte
    # lengths match even for C-quoted names, tabs, newlines or embedded " b/".
    pair = header[len(b'diff --git '):]
    half = len(pair) // 2
    if pair[half:half + 1] != b' ':
        raise ValueError('unexpected Git patch header')
    name = pair[half + 1:]
    if name.startswith(b'"'):
        name, _ = codecs.escape_decode(name[1:-1])
    if not name.startswith(b'b/'):
        raise ValueError('unexpected Git destination prefix')
    return os.fsdecode(name[2:])


def _collect_hunks(root, revisions, paths, files):
    patch = _git_bytes(root, 'diff', '--no-relative', '--no-renames', '--no-ext-diff',
                       '--no-color', '--no-textconv', '--no-indent-heuristic', '--line-prefix=',
                       '--src-prefix=a/', '--dst-prefix=b/', '--unified=0', *revisions, '--', *paths)
    selected = set(paths)
    current = hunk = None
    line_number = 0
    for raw in patch.split(b'\n'):
        if raw.startswith(b'diff --git '):
            path = _patch_path(raw)
            current = files[path] if path in selected else None
            hunk = None
        elif current is None or current.skip_reason:
            continue
        elif raw.startswith(b'Binary files ') or raw == b'GIT binary patch':
            current.skip_reason = 'binary file'
            current.hunks.clear()
        elif raw.startswith(b'@@ '):
            match = re.match(rb'@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@', raw)
            if not match:
                raise ValueError('unexpected Git hunk header')
            line_number = int(match[1])
            hunk = Hunk(line_number, int(match[2] or 1))
            current.hunks.append(hunk)
        elif hunk is not None and raw.startswith((b'-', b'+')):
            try:
                text = raw[1:].removesuffix(b'\r').decode('utf-8')
                if '\0' in text:
                    raise ValueError
            except ValueError:
                current.skip_reason = 'binary or unsupported text encoding'
                current.hunks.clear()
                continue
            if raw.startswith(b'-'):
                hunk.removed_lines.append(text)
            else:
                hunk.added_lines.append((line_number, text))
                line_number += 1


def _worktree_data(root, path):
    try:
        return read_file(root, path)
    except (OSError, ValueError):
        return None, 'unreadable file or unsupported path'


def _add_whole_file(file, data):
    try:
        lines = data.decode('utf-8').splitlines()
    except UnicodeDecodeError:
        file.skip_reason = 'unsupported text encoding'
        return
    if lines:
        file.hunks.append(Hunk(1, len(lines), added_lines=list(enumerate(lines, 1))))


def included_path(path, ignore):
    from .agent_config import FILES
    return path in FILES or (not path.startswith('.t7/') and not any(
        path.startswith(i) or f'/{i}' in path for i in ignore))


def changed_files(root, base, include_worktree=True, ignore=()):
    """Inventory every included change; extract hunks only for bounded, regular text files."""
    root = Path(root).resolve()
    revisions = [base]
    if not include_worktree and has_commits(root):
        revisions.append('HEAD')
    raw = _git_bytes(root, 'diff', '--no-relative', '--raw', '--no-abbrev', '--no-renames',
                     '--no-ext-diff', '--no-textconv', '-z', *revisions, '--')

    records = raw.split(b'\0')[:-1]
    entries = {}
    objects = set()
    for header, name in zip(records[::2], records[1::2]):
        path = os.fsdecode(name)
        if not included_path(path, ignore):
            continue
        before, after, old, new, status = header[1:].split()
        entries[path] = (before, after, old, new, status.decode())
        objects.update(oid for oid in (old, new) if oid.strip(b'0'))
    sizes = {}
    if objects:
        info = _git_bytes(root, 'cat-file', '--batch-check=%(objectname) %(objectsize)',
                          stdin=b'\n'.join(objects) + b'\n')
        for row in info.splitlines():
            oid, size = row.split()
            # Gitlinks can legitimately refer to commits absent from this repository.
            if size.isdigit():
                sizes[oid] = int(size)
    files, patches = {}, []
    patch_bytes = arg_bytes = 0
    for path, (before, after, old, new, status) in entries.items():
        file = files[path] = ChangedFile(path, status)
        if status == 'U':
            file.skip_reason = 'unresolved Git merge conflict'
            continue
        if any(mode not in (b'000000', b'100644', b'100755') for mode in (before, after)):
            file.skip_reason = 'symlink or non-regular file'
            continue
        if any(sizes.get(oid, 0) > MAX_BYTES for oid in (old, new)):
            file.skip_reason = 'file exceeds 512 KB'
            continue
        byte_count = sizes.get(old, 0) + sizes.get(new, 0)
        if include_worktree and status != 'D':
            data, file.skip_reason = _worktree_data(root, path)
            if file.skip_reason:
                continue
            if status == 'A':
                _add_whole_file(file, data)
                continue
            byte_count += len(data)
        path_bytes = len(os.fsencode(path)) + 1
        if patches and (patch_bytes + byte_count > 4_000_000 or arg_bytes + path_bytes > 16_000):
            _collect_hunks(root, revisions, patches, files)
            patches = []
            patch_bytes = arg_bytes = 0
        patches.append(path)
        patch_bytes += byte_count
        arg_bytes += path_bytes
    if patches:
        _collect_hunks(root, revisions, patches, files)
    if include_worktree:
        names = _git_bytes(root, 'ls-files', '--others', '--exclude-standard', '-z')
        for name in names.split(b'\0')[:-1]:
            path = os.fsdecode(name)
            if path.startswith('.t7/') or not included_path(path, ignore):
                continue
            previous = files.get(path)
            if previous and previous.status != 'D':
                continue
            data, reason = _worktree_data(root, path)
            if previous:
                # Removed from the index, then recreated as an untracked file.
                file = previous
                file.status = 'M'
                file.skip_reason = file.skip_reason or reason
            else:
                file = files[path] = ChangedFile(path, 'A', skip_reason=reason)
            if not file.skip_reason:
                _add_whole_file(file, data)
    return list(files.values())


def read(root, path, start=None, end=None, pad=0):
    data, reason = _worktree_data(Path(root).resolve(), path)
    if reason:
        return ''
    lines = data.decode('utf-8', errors='replace').splitlines()
    if start is None:
        return '\n'.join(lines)
    s, e = max(1, start - pad), min(len(lines), (end or start) + pad)
    return '\n'.join(f'{i:>5} | {lines[i - 1]}' for i in range(s, e + 1))


def numbered(root, path, max_lines=900):
    data, reason = _worktree_data(Path(root).resolve(), path)
    if reason:
        return ''
    lines = data.decode('utf-8', errors='replace').splitlines()
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
            untracked = [os.fsdecode(name) for name in _git_bytes(
                root, 'ls-files', '--others', '--exclude-standard', '-z').split(b'\0')[:-1]]
            if dirty.strip():
                subprocess.run(['git', 'apply', '--whitespace=nowarn'], cwd=path,
                               input=dirty, text=True, capture_output=True)
            for rel in [u for u in untracked if not u.startswith('.t7/')][:500]:
                src, dst = root / rel, path / rel
                if not src.is_symlink() and src.is_file() and src.resolve().is_relative_to(root.resolve()):
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


def contained_path(root, relative):
    """Resolve a model-provided path inside the workspace, including symlinks."""
    if not isinstance(relative, str) or not relative or '\x00' in relative:
        raise ValueError('invalid file path')
    part = Path(relative)
    if part.is_absolute() or PureWindowsPath(relative).drive or relative.startswith('\\') or '..' in part.parts:
        raise ValueError('file path must be relative to the workspace')
    target = (root / part).resolve()
    if not target.is_relative_to(root.resolve()):
        raise ValueError('file path escapes the workspace')
    return target


def apply_patch(path, patch, check_only=False, reverse=False):
    args = ['git', 'apply', '--whitespace=nowarn', '--recount']
    if check_only:
        args.append('--check')
    if reverse:
        args.append('--reverse')
    p = subprocess.run(args, cwd=path, input=patch if patch.endswith('\n') else patch + '\n',
                       text=True, capture_output=True)
    return p.returncode == 0, p.stderr.strip()[:1500]
