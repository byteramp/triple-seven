"""Triple Seven quality benchmark — labelled cases.

Every case is either a real vulnerability or a SAFE look-alike (a decoy that a
pattern-matcher or a careless model would flag). Precision on decoys is what
keeps PR comments quiet; recall on the real ones is what makes us worth having.

Fields
  id, lang, path, code              the file under review (line numbers matter)
  vuln                              None for decoys, else {family, line, title}
  hypothesis                        what an upstream stage claims (for triage)
  fix_test                          optional pytest module: must FAIL on the original
                                    code and PASS after a correct fix (python only)
"""

C = []


def case(**kw):
    C.append(kw)


# ─── Python / Django ────────────────────────────────────────────────────────

case(id='py-sqli-fstring', lang='python', path='app/reports.py', code='''\
from django.db import connection


def settlement_report(request):
    sort = request.GET.get("sort", "created_at")
    with connection.cursor() as c:
        c.execute(f"SELECT id, amount FROM settlements ORDER BY {sort}")
        return c.fetchall()
''', vuln={'family': 'sqli', 'line': 7, 'title': 'SQL injection via sort parameter'},
     hypothesis={'title': 'SQL built from request data', 'cwe': 'CWE-89',
                 'description': 'sort from the query string is interpolated into SQL.'})

case(id='py-sqli-params-safe', lang='python', path='app/reports.py', code='''\
from django.db import connection

ALLOWED_SORT = {"created_at": "created_at", "amount": "amount"}


def settlement_report(request):
    sort = ALLOWED_SORT.get(request.GET.get("sort"), "created_at")
    merchant = request.GET.get("merchant", "")
    with connection.cursor() as c:
        c.execute(f"SELECT id, amount FROM settlements WHERE merchant = %s ORDER BY {sort}",
                  [merchant])
        return c.fetchall()
''', vuln=None,
     hypothesis={'title': 'SQL built from request data', 'cwe': 'CWE-89',
                 'description': 'An f-string builds the SQL statement from request input.'})

case(id='py-idor', lang='python', path='billing/views.py', code='''\
from django.contrib.auth.decorators import login_required
from django.http import FileResponse
from .models import Invoice


@login_required
def download_invoice(request, invoice_id):
    invoice = Invoice.objects.get(pk=invoice_id)
    return FileResponse(invoice.pdf.open("rb"), filename=f"{invoice.number}.pdf")
''', vuln={'family': 'authz', 'line': 8, 'title': 'Invoice fetched by id without owner check'},
     hypothesis={'title': 'Object fetched by id without owner check', 'cwe': 'CWE-639',
                 'description': 'The invoice id comes from the URL and is not scoped to the user.'})

case(id='py-idor-scoped-safe', lang='python', path='billing/views.py', code='''\
from django.contrib.auth.decorators import login_required
from django.http import FileResponse
from django.shortcuts import get_object_or_404
from .models import Invoice


@login_required
def download_invoice(request, invoice_id):
    invoice = get_object_or_404(Invoice, pk=invoice_id, organisation=request.user.organisation)
    return FileResponse(invoice.pdf.open("rb"), filename=f"{invoice.number}.pdf")
''', vuln=None,
     hypothesis={'title': 'Object fetched by id without owner check', 'cwe': 'CWE-639',
                 'description': 'The invoice id comes from the URL.'})

case(id='py-cmdi', lang='python', path='media/thumbs.py', code='''\
import subprocess


def make_thumbnail(upload_name: str) -> str:
    out = f"/tmp/thumbs/{upload_name}.png"
    subprocess.run(f"convert /srv/uploads/{upload_name} -resize 200x200 {out}", shell=True, check=True)
    return out
''', vuln={'family': 'cmdi', 'line': 6, 'title': 'Shell command built from upload name'},
     hypothesis={'title': 'Shell command built from input', 'cwe': 'CWE-78',
                 'description': 'upload_name is placed in a shell=True command.'})

case(id='py-cmd-list-safe', lang='python', path='media/thumbs.py', code='''\
import re
import subprocess

SAFE_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}\\.(png|jpg)$")


def make_thumbnail(upload_name: str) -> str:
    if not SAFE_NAME.match(upload_name):
        raise ValueError("bad name")
    out = f"/tmp/thumbs/{upload_name}.png"
    subprocess.run(["convert", f"/srv/uploads/{upload_name}", "-resize", "200x200", out], check=True)
    return out
''', vuln=None,
     hypothesis={'title': 'Shell command built from input', 'cwe': 'CWE-78',
                 'description': 'subprocess is called with a value derived from the upload name.'})

case(id='py-ssrf', lang='python', path='integrations/webhooks.py', code='''\
import requests
from rest_framework.decorators import api_view
from rest_framework.response import Response


@api_view(["POST"])
def test_webhook(request):
    url = request.data["url"]
    r = requests.get(url, timeout=5)
    return Response({"status": r.status_code, "body": r.text[:500]})
''', vuln={'family': 'ssrf', 'line': 9, 'title': 'Server-side request to user-supplied URL'},
     hypothesis={'title': 'Server-side request to a user-controlled URL', 'cwe': 'CWE-918',
                 'description': 'The webhook URL from the request body is fetched by the server and the body returned.'})

case(id='py-fixed-url-safe', lang='python', path='integrations/fx.py', code='''\
import requests

FX_API = "https://api.exchangerate.example/v1/latest"


def rate(request):
    base = request.GET.get("base", "EUR")[:3].upper()
    r = requests.get(FX_API, params={"base": base}, timeout=5)
    return r.json()["rates"]
''', vuln=None,
     hypothesis={'title': 'Server-side request to a user-controlled URL', 'cwe': 'CWE-918',
                 'description': 'requests.get is called in a view with request data.'})

case(id='py-path-traversal', lang='python', path='docs/download.py', code='''\
import os
from django.http import FileResponse

BASE = "/srv/statements"


def statement(request):
    name = request.GET["file"]
    return FileResponse(open(os.path.join(BASE, name), "rb"))
''', vuln={'family': 'path', 'line': 9, 'title': 'Path traversal in statement download'},
     hypothesis={'title': 'Path traversal', 'cwe': 'CWE-22', 'description': 'file name from the query is joined to a base path.'},
     fix_test='''\
import pytest
from docs import download


class R:
    def __init__(self, f): self.GET = {"file": f}


def test_traversal_blocked(tmp_path, monkeypatch):
    base = tmp_path / "s"; base.mkdir(); (base / "a.pdf").write_text("ok")
    (tmp_path / "secret.txt").write_text("secret")
    monkeypatch.setattr(download, "BASE", str(base))
    monkeypatch.setattr(download, "FileResponse", lambda fh: fh.read())
    with pytest.raises(Exception):
        download.statement(R("../secret.txt"))


def test_normal_file_works(tmp_path, monkeypatch):
    base = tmp_path / "s"; base.mkdir(); (base / "a.pdf").write_text("ok")
    monkeypatch.setattr(download, "BASE", str(base))
    monkeypatch.setattr(download, "FileResponse", lambda fh: fh.read())
    assert download.statement(R("a.pdf")) in ("ok", b"ok")
''')

case(id='py-path-safe', lang='python', path='docs/download.py', code='''\
import os
from django.http import FileResponse, Http404

BASE = "/srv/statements"


def statement(request):
    name = request.GET["file"]
    full = os.path.realpath(os.path.join(BASE, name))
    if not full.startswith(os.path.realpath(BASE) + os.sep):
        raise Http404()
    return FileResponse(open(full, "rb"))
''', vuln=None,
     hypothesis={'title': 'Path traversal', 'cwe': 'CWE-22', 'description': 'A file name from the query is joined to a base path.'})

case(id='py-pickle', lang='python', path='sync/import_view.py', code='''\
import pickle
from rest_framework.decorators import api_view
from rest_framework.response import Response


@api_view(["POST"])
def import_settings(request):
    settings_obj = pickle.loads(request.body)
    request.user.profile.apply(settings_obj)
    return Response({"ok": True})
''', vuln={'family': 'deser', 'line': 8, 'title': 'Untrusted pickle deserialization'},
     hypothesis={'title': 'Untrusted deserialization', 'cwe': 'CWE-502',
                 'description': 'pickle.loads is called on the request body.'})

case(id='py-public-static-safe', lang='python', path='tower/views.py', code='''\
from django.http import HttpResponse
from rest_framework.views import APIView


class TestClickView(APIView):
    """Landing page for the link inside a *test* email (no tracking, no token)."""
    authentication_classes = []
    permission_classes = []

    def get(self, request):
        return HttpResponse("<h1>The link works</h1><p>This was a test email.</p>",
                            content_type="text/html")
''', vuln=None,
     hypothesis={'title': 'Unauthenticated endpoint', 'cwe': 'CWE-306',
                 'description': 'The view disables authentication and permissions.'})

case(id='py-mass-assign', lang='python', path='accounts/serializers.py', code='''\
from rest_framework import serializers, generics
from .models import User


class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = "__all__"


class ProfileUpdate(generics.UpdateAPIView):
    serializer_class = ProfileSerializer

    def get_object(self):
        return self.request.user
''', vuln={'family': 'massassign', 'line': 8, 'title': 'Mass assignment exposes is_staff / is_superuser'},
     hypothesis={'title': 'Mass assignment of privileged fields', 'cwe': 'CWE-915',
                 'description': 'Users can update every model field on their own profile.'})

case(id='py-jwt-noverify', lang='python', path='auth/tokens.py', code='''\
import jwt


def user_from_token(token: str) -> int:
    claims = jwt.decode(token, options={"verify_signature": False})
    return int(claims["sub"])
''', vuln={'family': 'authn', 'line': 5, 'title': 'JWT accepted without signature verification'},
     hypothesis={'title': 'JWT signature not verified', 'cwe': 'CWE-347',
                 'description': 'Tokens are decoded with verify_signature disabled.'})

case(id='py-password-hash-safe', lang='python', path='accounts/signup.py', code='''\
import hashlib
from django.contrib.auth.hashers import make_password


def create_user(email: str, password: str):
    cache_key = "signup:" + hashlib.md5(email.lower().encode()).hexdigest()
    return {"email": email, "password": make_password(password), "cache_key": cache_key}
''', vuln=None,
     hypothesis={'title': 'Weak cryptography', 'cwe': 'CWE-327',
                 'description': 'MD5 is used in the signup flow.'})

case(id='py-md5-password', lang='python', path='legacy/auth.py', code='''\
import hashlib


def check_password(stored_hash: str, password: str) -> bool:
    return hashlib.md5(password.encode()).hexdigest() == stored_hash
''', vuln={'family': 'crypto', 'line': 5, 'title': 'Passwords hashed with unsalted MD5'},
     hypothesis={'title': 'Weak password hashing', 'cwe': 'CWE-916', 'description': 'Passwords are compared as MD5 hashes.'})

# ─── JavaScript / TypeScript ────────────────────────────────────────────────

case(id='js-xss', lang='javascript', path='server/search.js', code='''\
const express = require("express");
const router = express.Router();

router.get("/search", (req, res) => {
  const q = req.query.q || "";
  res.send(`<h1>Results for ${q}</h1>`);
});

module.exports = router;
''', vuln={'family': 'xss', 'line': 6, 'title': 'Reflected XSS in search page'},
     hypothesis={'title': 'Reflected XSS', 'cwe': 'CWE-79', 'description': 'The q parameter is written into HTML.'})

case(id='js-json-safe', lang='javascript', path='server/search.js', code='''\
const express = require("express");
const router = express.Router();

router.get("/search", (req, res) => {
  const q = String(req.query.q || "").slice(0, 100);
  res.json({ query: q, results: [] });
});

module.exports = router;
''', vuln=None,
     hypothesis={'title': 'Reflected XSS', 'cwe': 'CWE-79', 'description': 'User input from q is returned in the response.'})

case(id='js-nosqli', lang='javascript', path='server/login.js', code='''\
const User = require("./models/user");

module.exports = async function login(req, res) {
  const user = await User.findOne({ email: req.body.email, password: req.body.password });
  if (!user) return res.status(401).end();
  req.session.userId = user.id;
  res.json({ ok: true });
};
''', vuln={'family': 'sqli', 'line': 4, 'title': 'NoSQL operator injection in login'},
     hypothesis={'title': 'NoSQL injection', 'cwe': 'CWE-943',
                 'description': 'Request body objects go straight into a Mongo query ({"$ne": null} bypasses the password).'})

case(id='ts-authz-safe', lang='typescript', path='src/routes/projects.ts', code='''\
import { Router } from "express";
import { requireAuth } from "../auth";
import { db } from "../db";

export const projects = Router();

projects.get("/projects/:id", requireAuth, async (req, res) => {
  const project = await db.project.findFirst({
    where: { id: req.params.id, orgId: req.user.orgId },
  });
  if (!project) return res.status(404).end();
  res.json(project);
});
''', vuln=None,
     hypothesis={'title': 'Object fetched by id without owner check', 'cwe': 'CWE-639',
                 'description': 'The project id comes from the URL path.'})

# ─── LLM / agents ───────────────────────────────────────────────────────────

case(id='py-llm-agency', lang='python', path='support/agent.py', code='''\
from openai import OpenAI
from payments import service_account

client = OpenAI()
TOOLS = [{"type": "function", "function": {"name": "refund", "parameters": {
    "type": "object", "properties": {"order_id": {"type": "string"}, "amount": {"type": "number"}}}}}]


def handle_ticket(ticket_text: str):
    msg = client.chat.completions.create(model="gpt-4.1", tools=TOOLS, messages=[
        {"role": "system", "content": "You are a helpful support agent."},
        {"role": "user", "content": ticket_text}]).choices[0].message
    for call in msg.tool_calls or []:
        args = call.function.arguments
        service_account.refund(**__import__("json").loads(args))
''', vuln={'family': 'llm-agency', 'line': 15, 'title': 'Prompt-injectable agent issues refunds with service account'},
     hypothesis={'title': 'LLM can call tools', 'cwe': 'CWE-269',
                 'description': 'Ticket text drives a refund tool executed with the service account.'})

case(id='py-llm-eval', lang='python', path='analytics/ask.py', code='''\
from openai import OpenAI

client = OpenAI()


def answer(question: str, rows: list):
    code = client.chat.completions.create(model="gpt-4.1-mini", messages=[
        {"role": "user", "content": f"Write one Python expression over `rows` answering: {question}"}
    ]).choices[0].message.content
    return eval(code, {"rows": rows})
''', vuln={'family': 'llm-output', 'line': 10, 'title': 'LLM output executed with eval'},
     hypothesis={'title': 'LLM output used unsafely', 'cwe': 'CWE-94',
                 'description': 'Model output is passed to eval.'})

case(id='py-llm-schema-safe', lang='python', path='support/classify.py', code='''\
import json
from openai import OpenAI

client = OpenAI()
LABELS = {"billing", "technical", "other"}


def classify(ticket_text: str) -> str:
    raw = client.chat.completions.create(model="gpt-4.1-mini", response_format={"type": "json_object"},
        messages=[{"role": "system", "content": "Classify the ticket. JSON: {\\"label\\": ...}"},
                  {"role": "user", "content": ticket_text}]).choices[0].message.content
    label = json.loads(raw).get("label")
    return label if label in LABELS else "other"
''', vuln=None,
     hypothesis={'title': 'Untrusted text concatenated into prompt', 'cwe': 'CWE-77',
                 'description': 'Ticket text from customers is sent to the model.'})

# ─── Go ─────────────────────────────────────────────────────────────────────

case(id='go-sqli', lang='go', path='internal/store/users.go', code='''\
package store

import (
\t"database/sql"
\t"fmt"
)

func FindUser(db *sql.DB, email string) (*sql.Rows, error) {
\tq := fmt.Sprintf("SELECT id, name FROM users WHERE email = '%s'", email)
\treturn db.Query(q)
}
''', vuln={'family': 'sqli', 'line': 9, 'title': 'SQL injection via Sprintf'},
     hypothesis={'title': 'SQL built from input', 'cwe': 'CWE-89', 'description': 'email is formatted into the SQL string.'})

case(id='go-param-safe', lang='go', path='internal/store/users.go', code='''\
package store

import (
\t"database/sql"
\t"fmt"
)

func FindUser(db *sql.DB, table string, email string) (*sql.Rows, error) {
\tif table != "users" && table != "admins" {
\t\treturn nil, fmt.Errorf("bad table")
\t}
\treturn db.Query(fmt.Sprintf("SELECT id, name FROM %s WHERE email = $1", table), email)
}
''', vuln=None,
     hypothesis={'title': 'SQL built from input', 'cwe': 'CWE-89', 'description': 'Sprintf builds the SQL query.'})

# ─── Terraform ──────────────────────────────────────────────────────────────

case(id='tf-open-db', lang='terraform', path='infra/db.tf', code='''\
resource "aws_security_group" "db" {
  name = "payments-db"
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
''', vuln={'family': 'network', 'line': 7, 'title': 'Postgres open to the internet'},
     hypothesis={'title': 'Infrastructure exposed publicly', 'cwe': 'CWE-284', 'description': 'Ingress from 0.0.0.0/0.'})

case(id='tf-https-lb-safe', lang='terraform', path='infra/lb.tf', code='''\
resource "aws_security_group" "public_lb" {
  name = "public-https"
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
''', vuln=None,
     hypothesis={'title': 'Infrastructure exposed publicly', 'cwe': 'CWE-284', 'description': 'Ingress from 0.0.0.0/0.'})

# Fix-task cases get an executable test (above: py-path-traversal). Add SQLi + cmdi.
for c in C:
    if c['id'] == 'py-cmdi':
        c['fix_test'] = '''\
import subprocess
from media import thumbs


def test_no_shell_injection(monkeypatch):
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: calls.append((a, k)))
    try:
        thumbs.make_thumbnail("x.png; touch /tmp/pwned")
    except Exception:
        return  # rejecting the name is a correct fix
    for a, k in calls:
        assert not k.get("shell"), "shell=True with user input"
        assert isinstance(a[0], (list, tuple)), "command must be an argument list"


def test_normal_name_still_works(monkeypatch):
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: calls.append((a, k)))
    thumbs.make_thumbnail("cat_01.png")
    assert calls
'''
    if c['id'] == 'py-sqli-fstring':
        c['fix_test'] = '''\
from app import reports


class Cur:
    def __init__(self, log): self.log = log
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def execute(self, sql, params=None): self.log.append(sql)
    def fetchall(self): return []


class R:
    def __init__(self, s): self.GET = {"sort": s}


def _run(monkeypatch, sort):
    log = []
    monkeypatch.setattr(reports.connection, "cursor", lambda: Cur(log))
    reports.settlement_report(R(sort))
    return log


def test_injection_not_in_sql(monkeypatch):
    log = _run(monkeypatch, "id; DROP TABLE settlements")
    assert all("DROP" not in s for s in log)


def test_valid_sort_used(monkeypatch):
    log = _run(monkeypatch, "amount")
    assert any("amount" in s for s in log)
'''

CASES = C
