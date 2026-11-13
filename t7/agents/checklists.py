"""Specialist checklists — what each analyst actively hunts for, and what it must
NOT report. Attack classes adapted from Cloudflare's security-audit skill (MIT,
see NOTICE) and mapped to OWASP Top 10 2021 / API Top 10 2023 / LLM Top 10 2025.
Short on purpose: small CPU models follow short, concrete lists best."""

COMMON_NOT = (
    "Do NOT report: style issues, missing comments, theoretical issues without a reachable "
    "lower-trust input, framework-protected patterns (ORM filters, auto-escaping templates), "
    "test code, or hardening wishes."
)

CHECKLISTS = {
    'authz': (
        "Hunt: (A01/API1) object fetched by an id from the request without scoping to the user or "
        "tenant; (API5) admin/privileged function reachable by a normal user; (API3) mass "
        "assignment — serializer/DTO accepts privileged fields (role, is_admin, owner, tenant); "
        "(A07/API2) authentication disabled or bypassable, JWT/signature not verified, session "
        "fixation; access-boundary mismatch — the check exists but enforces the wrong rule; tenant "
        "id taken from the request body instead of the session; export/backup/search endpoints that "
        "return data above the caller's level."
    ),
    'injection': (
        "Hunt: (A03) SQL/NoSQL built from input (string formatting, operator objects from JSON), "
        "shell commands with input or shell=True, template/eval injection, LDAP/XPath; (A10/API7) "
        "server-side requests to user-controlled URLs incl. webhooks and redirects; (A01) path "
        "traversal in file reads/writes/archives; (A08) unsafe deserialization (pickle, yaml.load, "
        "Java/PHP serialization); (A03) XSS — input rendered as HTML without escaping; second-order "
        "use — stored input later used as a path, URL, query or template."
    ),
    'secrets': (
        "Hunt: (A07) hard-coded credentials and keys; (A02) weak password hashing (MD5/SHA1/unsalted) "
        "or home-made crypto, ECB, static IVs, predictable tokens from random/Math.random; (A02) "
        "sensitive data over cleartext; (A09) secrets or personal data written to logs; tokens in URLs. "
        "Weak hashes used for non-security purposes (cache keys, ETags, dedupe) are NOT findings."
    ),
    'llm': (
        "Hunt: (LLM01) untrusted text (tickets, e-mails, web pages, files) reaching the model with "
        "authority to act; (LLM06) tools/functions with side effects executed with service "
        "credentials or without per-call authorization and human approval; (LLM05) model output "
        "used in eval/exec/SQL/shell/HTML or as a URL; (LLM02) other users' data or secrets in the "
        "model context; (LLM07) secrets in system prompts; (LLM10) unbounded loops/tokens. "
        "Constrained output (schema + allow-listed values, no side effects) is NOT a finding."
    ),
    'iac': (
        "Hunt: (A05) databases, caches, admin ports or storage reachable from 0.0.0.0/0 or public "
        "ACLs; IAM wildcards (Action \"*\" / Resource \"*\"); encryption disabled; containers as root, "
        "privileged, host mounts; secrets in plain environment variables. A public HTTPS load "
        "balancer or CDN on 443 is the intended design and NOT a finding."
    ),
    'logic': (
        "Hunt: state-machine violations (skip/replay steps), check-then-act races with business "
        "impact (double spend, double approve), negative/zero/overflowing quantities, time-boundary "
        "and expiry bugs, insecure defaults when config is missing, enumeration through different "
        "errors, preview/draft leakage, rollback/restore that skips current authorization."
    ),
}


def checklist(name):
    return f"{CHECKLISTS.get(name, CHECKLISTS['logic'])} {COMMON_NOT}"
