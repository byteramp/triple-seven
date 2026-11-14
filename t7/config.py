"""Agent configuration — environment first, optional .t7.yml-style JSON file second.

Env:
  T7_TOKEN          repository token from the Triple Seven portal (t7_…)
  T7_API_URL        default https://t7.byteramp.se/api
  T7_LLM            byteramp | openai | azure | anthropic | ollama | client   (default byteramp;
                    under `t7 mcp` the editor's own model via MCP sampling when supported)
  T7_LLM_MODEL      model / deployment name for BYO and local providers
  T7_LLM_BASE_URL   base URL for openai-compatible / azure / ollama
  T7_LLM_API_KEY    key for the customer's own provider (never sent to Byteramp)
  T7_MAX_FIX_ATTEMPTS, T7_PARALLEL, T7_STEP_TIMEOUT

Token precedence: T7_TOKEN  >  token stored by `t7 setup` for this repository  >  stored default.
"""
import json
import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    token: str = ''
    api_url: str = 'https://t7.byteramp.se/api'
    llm: str = 'byteramp'
    llm_model: str = ''
    llm_base_url: str = ''
    llm_api_key: str = ''
    max_fix_attempts: int = 3
    parallel: int = 4
    step_timeout: int = 600
    test_command: str = ''
    lint_command: str = ''
    type_command: str = ''
    ignore_paths: list = field(default_factory=lambda: ['vendor/', 'node_modules/', 'dist/',
                                                        'build/', '.venv/', 'venv/', 'migrations/',
                                                        '.vscode/', '.cursor/', '.idea/', '.t7/',
                                                        '.github/ISSUE_TEMPLATE/'])
    offline: bool = False
    policy_label: str = ''        # set when an organisation model policy applies
    token_source: str = ''       # env | setup | ''
    token_key: str = None        # where a `t7 setup` token is stored (repo path, None = default)
    token_expires_at: str = ''
    token_kind: str = ''
    remote: str = ''             # git remote of this repository (sent so organisation tokens
    repo_name: str = ''          # map the call to a repository); folder name as fallback

    @classmethod
    def load(cls, root):
        c = cls()
        f = Path(root) / '.t7.json' if root else None
        if f and f.exists():
            try:
                for k, v in json.loads(f.read_text()).items():
                    if hasattr(c, k) and k not in ('token', 'llm_api_key'):  # secrets: env only
                        setattr(c, k, v)
            except (ValueError, OSError):
                pass
        env = os.environ
        stored = None
        if env.get('T7_TOKEN'):
            c.token, c.token_source = env['T7_TOKEN'], 'env'
        else:
            from . import credentials
            key, stored = credentials.lookup(root)
            if stored and stored.get('token'):
                c.token, c.token_source, c.token_key = stored['token'], 'setup', key
                c.token_expires_at = stored.get('expires_at') or ''
                c.token_kind = stored.get('kind') or ''
        c.api_url = (env.get('T7_API_URL') or (stored or {}).get('api_url') or c.api_url).rstrip('/')
        c.llm = env.get('T7_LLM') or env.get('T7_LLM_DEFAULT') or c.llm
        c.llm_model = env.get('T7_LLM_MODEL', c.llm_model)
        c.llm_base_url = env.get('T7_LLM_BASE_URL', c.llm_base_url)
        c.llm_api_key = env.get('T7_LLM_API_KEY', c.llm_api_key)
        c.max_fix_attempts = int(env.get('T7_MAX_FIX_ATTEMPTS', c.max_fix_attempts))
        c.parallel = int(env.get('T7_PARALLEL', c.parallel))
        c.step_timeout = int(env.get('T7_STEP_TIMEOUT', c.step_timeout))
        if root:
            c.remote, c.repo_name = _remote(root), Path(root).name
        c.offline = not c.token
        if c.llm == 'client':
            c.parallel = 1     # one sampling request at a time over the editor's channel
        return c

    @property
    def llm_provider_kind(self):
        """Value reported to Byteramp (byteramp | byo | local | editor)."""
        if self.llm == 'byteramp':
            return 'byteramp'
        if self.llm == 'ollama':
            return 'local'
        if self.llm == 'client':
            return 'editor'
        return 'byo'


def _remote(root):
    """origin's URL (or the first remote's). Only the URL is sent, never code."""
    import subprocess
    try:
        out = subprocess.run(['git', 'remote'], cwd=root, capture_output=True, text=True, timeout=10).stdout.split()
        if not out:
            return ''
        name = 'origin' if 'origin' in out else out[0]
        url = subprocess.run(['git', 'remote', 'get-url', name], cwd=root, capture_output=True, text=True,
                             timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ''
    return strip_credentials(url)


def strip_credentials(url):
    """https://user:token@host/x → https://host/x (a token in a remote URL never leaves)."""
    import re
    return re.sub(r'^([a-z][a-z0-9+.-]*://)[^/@]*@', r'\1', url, flags=re.I)

