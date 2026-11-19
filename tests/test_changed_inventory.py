from t7 import gitops


def git(repo, *args):
    return gitops.git(repo, '-c', 'user.name=test', '-c', 'user.email=test@example.test', *args)


def commit(repo):
    git(repo, 'add', '-A')
    git(repo, 'commit', '-qm', 'snapshot')
    return git(repo, 'rev-parse', 'HEAD').strip()


def test_full_scan_inventories_empty_binary_large_and_unsafe_paths(tmp_path):
    root = tmp_path / 'project'
    root.mkdir()
    git(root, 'init', '-q')
    secret = tmp_path / 'outside'
    secret.write_text('private content')
    (root / 'link').symlink_to(secret)
    (root / 'empty').touch()
    (root / 'image').write_bytes(b'binary\0data')
    (root / 'large').write_bytes(b'x' * 520_000)
    (root / 'text').write_text('hello\n')
    commit(root)
    (root / 'loose-link').symlink_to(secret)
    (root / 'ignored').write_text('ignored')
    result = {f.path: f for f in gitops.changed_files(root, gitops.EMPTY_TREE, ignore=('ignored',))}
    assert set(result) == {'link', 'loose-link', 'empty', 'image', 'large', 'text'}
    assert result['text'].added == [(1, 'hello')]
    assert result['empty'].added == [] and not result['empty'].skip_reason
    for name in ('link', 'loose-link', 'image', 'large'):
        assert result[name].skip_reason and not result[name].hunks
    assert gitops.read(root, 'loose-link') == ''
    assert gitops.numbered(root, 'link') == ''
    ci = {f.path: f for f in gitops.changed_files(root, gitops.EMPTY_TREE, include_worktree=False)}
    assert set(ci) == set(result) - {'loose-link'}
    assert ci['image'].skip_reason and ci['large'].skip_reason
    assert not ci['empty'].skip_reason and ci['text'].added == [(1, 'hello')]


def test_rename_unusual_paths_and_deleted_lines(tmp_path):
    git(tmp_path, 'init', '-q')
    before = 'dörr "Ö"\n.tsv'
    after = 'lock b/tät\t.py'
    (tmp_path / before).write_text('old guard()\n')
    base = commit(tmp_path)
    (tmp_path / 'lock b').mkdir()
    (tmp_path / before).rename(tmp_path / after)
    commit(tmp_path)
    result = {f.path: f for f in gitops.changed_files(tmp_path, base, include_worktree=False)}
    assert set(result) == {before, after}
    assert result[before].status == 'D'
    assert result[before].hunks[0].removed_lines == ['old guard()']
    assert result[after].status == 'A'
    assert result[after].added == [(1, 'old guard()')]
    (tmp_path / after).write_text('++ text\n--- also text\n')
    updated = gitops.changed_files(tmp_path, 'HEAD')[0]
    assert updated.path == after
    assert updated.added == [(1, '++ text'), (2, '--- also text')]
    assert updated.hunks[0].removed_lines == ['old guard()']


def test_ci_compares_commits_even_with_different_worktree(tmp_path):
    git(tmp_path, 'init', '-q')
    path = tmp_path / 'file'
    path.write_text('old\n')
    base = commit(tmp_path)
    path.write_text('committed\n')
    commit(tmp_path)
    path.unlink()
    (tmp_path / 'loose').write_text('local only\n')
    ci = gitops.changed_files(tmp_path, base, include_worktree=False)
    assert len(ci) == 1 and ci[0].status == 'M' and ci[0].added == [(1, 'committed')]
    local = {f.path: f for f in gitops.changed_files(tmp_path, base)}
    assert local['file'].status == 'D' and local['loose'].status == 'A'


def test_recreated_untracked_file_and_literal_pathspec(tmp_path):
    git(tmp_path, 'init', '-q')
    tricky = ':(exclude)guard[1].py'
    (tmp_path / tricky).write_text('prior\n')
    commit(tmp_path)
    git(tmp_path, '--literal-pathspecs', 'rm', '--cached', '--', tricky)
    (tmp_path / tricky).write_text('new\n')
    changed = gitops.changed_files(tmp_path, 'HEAD')
    assert len(changed) == 1
    assert changed[0].path == tricky and changed[0].status == 'M'
    assert changed[0].hunks[0].removed_lines == ['prior']
    assert changed[0].added == [(1, 'new')]
