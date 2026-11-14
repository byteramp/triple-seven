"""Access rules shared by the CLI, the MCP server and CI.

Every analysis needs an active Triple Seven subscription, proven by a valid
repository token that the Byteramp API accepts when the run starts. The same
check applies however t7 is started (terminal, IDE via MCP, CI). Features
that live on the server (threat engine, portal, gate, Byteramp models) are
additionally enforced server-side by the token.

T7_ALLOW_OFFLINE=1 exists only for t7's own test suite and benchmark.
"""
import os

WELCOME = """Triple Seven · Byteramp

Agent installed. Connect your account to get started.
An active Triple Seven subscription is required.

In the repository you want to review, run:
  t7 setup

It signs you in through your browser (portal login, or the invitation
e-mail from your team) and adds Triple Seven to your editors — once.

Need access?
  Contact your organization's Triple Seven administrator."""

NOT_CONNECTED = ("This repository is not connected to Triple Seven. Run `t7 setup` inside it to sign in "
                 "through the browser (an active subscription is required). In CI, set T7_TOKEN.")

REJECTED = ("Access was not accepted ({detail}). If the token expired or was revoked, run `t7 setup` to "
            "sign in again. If the subscription is inactive, contact your Triple Seven administrator.")

UNREACHABLE = ("Cannot reach Triple Seven at {url} ({detail}). Access is checked on every run, so the "
               "review did not start. Check your network or T7_API_URL and try again.")


class AccessError(RuntimeError):
    """Raised before any analysis when access cannot be confirmed."""


def offline_allowed():
    return os.environ.get('T7_ALLOW_OFFLINE') == '1'


def _parse(ts):
    from datetime import datetime, timezone
    try:
        d = datetime.fromisoformat(str(ts).replace('Z', '+00:00'))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def days_left(expires_at):
    from datetime import datetime, timezone
    d = _parse(expires_at) if expires_at else None
    return None if d is None else (d - datetime.now(timezone.utc)).total_seconds() / 86400


def renew_if_due(cfg, api, renew_within_days=14):
    """Developer tokens stored by `t7 setup` renew themselves while the subscription is
    active: the server checks access, issues a successor and revokes the old token.
    Tokens from T7_TOKEN (CI secrets, shell) are left alone. Never raises: if renewal
    fails, the run's own access check reports the real problem."""
    from . import credentials
    from .api import APIError
    if cfg.offline or cfg.token_source != 'setup':
        return False
    try:
        if not cfg.token_expires_at or not cfg.token_kind:     # stored by an older t7
            info = api.config().get('token') or {}
            cfg.token_expires_at, cfg.token_kind = info.get('expires_at') or '', info.get('kind') or ''
            renew_within_days = info.get('renew_within_days') or renew_within_days
            credentials.update(cfg.token_key, expires_at=cfg.token_expires_at or None,
                               kind=cfg.token_kind or None)
        left = days_left(cfg.token_expires_at)
        if cfg.token_kind != 'developer' or left is None or left > renew_within_days:
            return False
        r = api.rotate()
    except APIError:
        return False
    credentials.update(cfg.token_key, token=r['token'], expires_at=r.get('expires_at'))
    cfg.token, cfg.token_expires_at = r['token'], r.get('expires_at') or ''
    return True
