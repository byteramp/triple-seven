"""The organisation's model policy, applied before any model call.

The administrator decides which model analyses code (portal → Repositories → Model
policy). It overrides T7_LLM, T7_LLM_DEFAULT and the editor's MCP sampling. If this
machine cannot satisfy it, the review stops with a clear message: t7 never silently
falls back to another model.
"""
import os
import urllib.request

from .access import AccessError

LABEL = {'byteramp': 'Byteramp EU models', 'editor': "the editor's own model",
         'local': 'a local model (Ollama)', 'byo': "your organisation's own model"}


def label(req):
    return (req or {}).get('label') or LABEL.get((req or {}).get('provider'), 'the required model')


def apply(cfg, req, can_sample=False):
    """Mutates cfg to follow the policy `req` ({provider, kind, base_url, model}) or raises."""
    if not req:
        return False
    p = req.get('provider')
    need = f'This repository requires {label(req)} (policy set by your administrator).'
    if p == 'byteramp':
        cfg.llm, cfg.llm_model = 'byteramp', ''
    elif p == 'editor':
        if not can_sample:
            raise AccessError(need + ' Run the review from your editor\'s AI assistant (for example '
                              'VS Code + GitHub Copilot in Agent mode) — not from the terminal or CI.')
        cfg.llm, cfg.llm_model = 'client', ''
        cfg.parallel = 1
    elif p == 'local':
        cfg.llm = 'ollama'
        cfg.llm_model = req.get('model') or cfg.llm_model
        base = (cfg.llm_base_url or 'http://localhost:11434').rstrip('/')
        try:
            urllib.request.urlopen(f'{base[:-3] if base.endswith("/v1") else base}/api/tags', timeout=3).read()
        except Exception:  # noqa: BLE001
            raise AccessError(need + f' Ollama is not reachable at {base}. Start it (`ollama serve`) and '
                              f'pull the model{(" " + cfg.llm_model) if cfg.llm_model else ""}.') from None
        if not cfg.llm_model:
            raise AccessError(need + ' Set T7_LLM_MODEL to the Ollama model to use.')
    elif p == 'byo':
        cfg.llm = req.get('kind') or 'openai'
        cfg.llm_base_url = req.get('base_url') or cfg.llm_base_url
        cfg.llm_model = req.get('model') or cfg.llm_model
        cfg.llm_api_key = os.environ.get('T7_LLM_API_KEY', cfg.llm_api_key)
        missing = [n for n, v in (('T7_LLM_API_KEY', cfg.llm_api_key), ('base URL', cfg.llm_base_url),
                                  ('model', cfg.llm_model)) if not v and not (n == 'base URL' and cfg.llm == 'anthropic')]
        if missing:
            raise AccessError(need + f' Missing on this machine: {", ".join(missing)}. The key stays with you '
                              '(set T7_LLM_API_KEY in your shell or CI secret); ask your administrator for '
                              'the endpoint details if they are not in the policy.')
    else:
        raise AccessError(f'Unknown model policy "{p}". Run `t7 update`.')
    cfg.policy_label = label(req)
    return True
