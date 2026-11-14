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
An active Triple Seven subscription and repository token are required.

Already a customer?
  Get your token: Portal → Triple Seven → Repositories
  Then run:       t7 setup

Need access?
  Contact your organization's Triple Seven administrator."""

NOT_CONNECTED = ("Not connected. An active Triple Seven subscription and repository token are required.\n"
                 "Get your token in the portal (Triple Seven → Repositories), then run `t7 setup` in this "
                 "repository — or set T7_TOKEN (CI, MCP env).")

REJECTED = ("Your token was not accepted ({detail}). It may be revoked, expired, or the subscription "
            "inactive. Create a new token in the portal (Triple Seven → Repositories) and run `t7 setup`.")

UNREACHABLE = ("Cannot reach Triple Seven at {url} ({detail}). Access is checked on every run, so the "
               "review did not start. Check your network or T7_API_URL and try again.")


class AccessError(RuntimeError):
    """Raised before any analysis when access cannot be confirmed."""


def offline_allowed():
    return os.environ.get('T7_ALLOW_OFFLINE') == '1'
