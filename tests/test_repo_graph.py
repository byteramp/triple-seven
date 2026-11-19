import json
from unittest.mock import patch

import pytest

from t7 import repo_graph as graph


def write(root, files):
    for path, source in files.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source)


def test_python_static_imports_transitive_and_source_minimization(tmp_path):
    files = {'src/pkg/__init__.py': '',
             'src/pkg/auth.py': 'class Policy:\n def verify(self):\n  return "private test value"\n',
             'src/pkg/routes.py': 'from .auth import Policy',
             'service/entry.py': 'import pkg.routes as routes',
             'src/pkg/metrics.py': '# no dependency'}
    write(tmp_path, files)
    index = graph.build(tmp_path, files)
    assert graph.affected(index, index, ['src/pkg/auth.py']) == {
        'src/pkg/auth.py', 'src/pkg/routes.py', 'service/entry.py'}
    assert index['src/pkg/auth.py']['symbols'] == ['Policy', 'verify']
    assert 'private test value' not in json.dumps(index)


def test_update_reads_only_changes_and_preserves_old_graph(tmp_path):
    files = {'pkg/user.py': 'from . import auth', 'pkg/auth.py': 'def allow(): pass'}
    write(tmp_path, files)
    initial = graph.build(tmp_path, files)
    (tmp_path / 'pkg/auth.py').rename(tmp_path / 'pkg/policy.py')
    paths = ['pkg/auth.py', 'pkg/policy.py']
    with patch.object(graph, '_contents', wraps=graph._contents) as reader:
        revised = graph.update(tmp_path, initial, paths)
        assert [call.args[1] for call in reader.call_args_list] == [['pkg', 'auth.py'], ['pkg', 'policy.py']]
    assert 'pkg/auth.py' in initial and 'pkg/policy.py' not in initial
    assert 'pkg/auth.py' not in revised and 'pkg/policy.py' in revised
    assert graph.affected(initial, revised, paths) == set(paths) | {'pkg/user.py'}


def test_js_imports_re_exports_circular_transitive_and_new_target(tmp_path):
    files = {'lib/view.ts': 'export { auth } from "./auth.js";',
             'lib/auth.ts': 'import("./view");\nexport function auth() { return 1 }',
             'app/root.tsx': 'import { view } from "../lib/view";',
             'app/unused.ts': 'const note = "import(\'../lib/auth\')"; // require("../lib/auth")'}
    write(tmp_path, files)
    old = graph.build(tmp_path, files)
    assert graph.affected(old, old, ['lib/auth.ts']) == {'lib/auth.ts', 'lib/view.ts', 'app/root.tsx'}
    extra = {'web/index.ts': "export { api } from './api'", 'app/new.js': "require('../web')"}
    write(tmp_path, extra)
    base = graph.update(tmp_path, old, extra)
    write(tmp_path, {'web/api.ts': 'export const api = 4;'})
    current = graph.update(tmp_path, base, ['web/api.ts'])
    assert graph.affected(base, current, ['web/api.ts']) == {'app/new.js', 'web/api.ts', 'web/index.ts'}


def test_unparsed_files_still_have_inventory_entries(tmp_path):
    (tmp_path / 'bad.py').write_text('def (')
    (tmp_path / 'data.bin').write_bytes(b'foo\x00bar')
    (tmp_path / 'big.py').write_bytes(b'#' * (graph.MAX_BYTES + 1))
    (tmp_path / 'README').write_text('text')
    index = graph.build(tmp_path, ['bad.py', 'data.bin', 'big.py', 'README'])
    assert index['README']['kind'] == 'file'
    assert index['bad.py']['reason']
    assert index['data.bin']['reason'] == 'binary file'
    assert index['big.py']['reason'] == 'file exceeds 512 KB'


def test_symlinks_and_invalid_paths_cannot_read_outside(tmp_path):
    root = tmp_path / 'project'
    root.mkdir()
    secret_dir = tmp_path / 'external'
    secret_dir.mkdir()
    (secret_dir / 'secret.py').write_text('class InvisibleSecret: pass')
    (root / 'auth.py').symlink_to(secret_dir / 'secret.py')
    (root / 'sub').symlink_to(secret_dir, target_is_directory=True)
    data = graph.build(root, ['auth.py', 'sub/secret.py'])
    assert all(node['kind'] == 'skipped' for node in data.values())
    assert 'InvisibleSecret' not in json.dumps(data)
    for invalid in ('../external/secret.py', '/etc/something', '.git/HEAD', 'C:/secret', 'sub/C:/secret',
                    'sub\\..\\secret'):
        with pytest.raises(ValueError, match='invalid repository graph path'):
            graph.build(root, [invalid])


def test_literal_expressions_do_not_persist_arbitrary_strings(tmp_path):
    files = {'src/view.js': """
    // from "./false"
    const password = 'never store this';
    require("./credentials?api_key=secret");
    require("./dynamic" + suffix);
    import("https://third-party.example" + thing);
    export { feature } from './feature';
    """}
    write(tmp_path, files)
    node = graph.build(tmp_path, files)['src/view.js']
    assert node['imports'] == ['local:src/feature']
    assert 'never store' not in json.dumps(node)
