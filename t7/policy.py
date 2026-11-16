"""The organisation's model policy, applied before any model call.

The administrator decides which model analyses code (portal → Repositories → Model
policy). It overrides T7_LLM, T7_LLM_DEFAULT and the editor's MCP sampling. If this
machine cannot satisfy it, the review stops with a clear message: t7 never silently
falls back to another model.
"""
import os
import urllib.request

from .access import AccessError

LABEL = {'byteramp': 'Byteramp EU models', 'editor': "the developer's own AI assistant",
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
        # The developer's own AI: the editor's model (MCP sampling) when the review runs in an
        # editor that offers it, else a logged-in assistant CLI. `kind` may restrict which.
        allowed = [x.strip() for x in (req.get('kind') or '').split(',') if x.strip()]
        if can_sample and (not allowed or 'sampling' in allowed):
            cfg.llm, cfg.llm_model, cfg.parallel = 'client', '', 1
        else:
            from . import assistants
            cli_allowed = [a for a in allowed if a != 'sampling']
            if allowed and not cli_allowed:
                raise AccessError(need + ' Start the review through the Triple Seven MCP tool in '
                                  'Copilot Chat (Agent mode) in VS Code. The editor must enable '
                                  'model access for Triple Seven. Terminal `t7 scan` needs a CLI '
                                  'or another model provider allowed by your administrator.')
            key = assistants.pick(cli_allowed or None)
            if not key:
                names = ', '.join(assistants.label(a) for a in (allowed or assistants.ASSISTANTS) if a != 'sampling')
                raise AccessError(need + f' No signed-in AI assistant found on this machine. Install and sign in '
                                  f'to one of: {names} — or start the review from your editor.')
            cfg.llm, cfg.assistant, cfg.llm_model = 'assistant', key, ''
            cfg.parallel = min(cfg.parallel, 2)
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
