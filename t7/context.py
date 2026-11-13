"""Repository profile: stack, and the commands the verifier uses to prove a fix."""
import json
import shlex
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Profile:
    stack: list = field(default_factory=list)
    test_cmd: str = ''
    lint_cmd: str = ''
    type_cmd: str = ''
    test_framework: str = ''        # pytest | django | jest | vitest | go | ''
    test_dir: str = 'tests'

    @property
    def can_prove(self):
        return bool(self.test_framework and self.test_cmd)


def _has(root, *names):
    return any((root / n).exists() for n in names)


def _py():
    """The project's python: `python` if on PATH (venv/CI), else python3."""
    return 'python' if shutil.which('python') else ('python3' if shutil.which('python3')
                                                     else shlex.quote(sys.executable))


def detect(root: Path, cfg) -> Profile:
    p = Profile()
    py = _py()
    # ── Python ────────────────────────────────────────────────────────────
    if _has(root, 'pyproject.toml', 'requirements.txt', 'setup.py', 'manage.py'):
        p.stack.append('python')
        req = ''
        for n in ('requirements.txt', 'pyproject.toml'):
            if (root / n).exists():
                req += (root / n).read_text(errors='ignore').lower()
        if (root / 'manage.py').exists() or 'django' in req:
            p.stack.append('django')
            p.test_framework = 'django'
            p.test_cmd = f'{py} manage.py test {{target}} --noinput'
        if 'fastapi' in req:
            p.stack.append('fastapi')
        if 'flask' in req:
            p.stack.append('flask')
        if 'pytest' in req or _has(root, 'pytest.ini', 'conftest.py'):
            p.test_framework = 'pytest'
            p.test_cmd = f'{py} -m pytest -x -q {{target}}'
        if shutil.which('ruff'):
            p.lint_cmd = 'ruff check {files}'
        elif shutil.which('flake8'):
            p.lint_cmd = 'flake8 --select=E9,F63,F7,F82 {files}'
        else:
            p.lint_cmd = f'{shlex.quote(sys.executable)} -m py_compile {{files}}'
        if shutil.which('mypy') and _has(root, 'mypy.ini', 'setup.cfg'):
            p.type_cmd = 'mypy {files}'
    # ── JS / TS ───────────────────────────────────────────────────────────
    pkg = root / 'package.json'
    if pkg.exists():
        try:
            data = json.loads(pkg.read_text())
        except ValueError:
            data = {}
        deps = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
        scripts = data.get('scripts', {})
        p.stack.append('typescript' if 'typescript' in deps else 'javascript')
        for fw in ('react', 'next', 'express', 'fastify', '@nestjs/core'):
            if fw in deps:
                p.stack.append(fw.replace('@nestjs/core', 'nestjs'))
        if 'vitest' in deps:
            p.test_framework, p.test_cmd = 'vitest', 'npx vitest run {target}'
        elif 'jest' in deps:
            p.test_framework, p.test_cmd = 'jest', 'npx jest {target}'
        if 'eslint' in deps:
            p.lint_cmd = p.lint_cmd or 'npx eslint {files}'
        if 'typescript' in deps:
            p.type_cmd = p.type_cmd or 'npx tsc --noEmit -p .'
        if not p.test_cmd and 'test' in scripts:
            p.test_cmd = 'npm test --silent'
    # ── Go ────────────────────────────────────────────────────────────────
    if (root / 'go.mod').exists():
        p.stack.append('go')
        p.test_framework, p.test_cmd = 'go', 'go test ./...'
        p.lint_cmd, p.type_cmd = 'go vet ./...', 'go build ./...'
    # ── IaC ───────────────────────────────────────────────────────────────
    if list(root.glob('**/*.tf'))[:1]:
        p.stack.append('terraform')
    if list(root.glob('**/Chart.yaml'))[:1] or list(root.glob('k8s/**/*.y*ml'))[:1]:
        p.stack.append('kubernetes')
    if (root / 'Dockerfile').exists():
        p.stack.append('docker')

    p.test_cmd = cfg.test_command or p.test_cmd
    p.lint_cmd = cfg.lint_command or p.lint_cmd
    p.type_cmd = cfg.type_command or p.type_cmd
    p.stack = list(dict.fromkeys(p.stack))
    return p


LANG = {'.py': 'python', '.ts': 'typescript', '.tsx': 'typescript', '.js': 'javascript',
        '.jsx': 'javascript', '.go': 'go', '.tf': 'terraform', '.yaml': 'yaml', '.yml': 'yaml',
        '.java': 'java', '.cs': 'csharp', '.rb': 'ruby', '.php': 'php'}


def lang_of(path):
    return LANG.get(Path(path).suffix.lower(), 'other')
