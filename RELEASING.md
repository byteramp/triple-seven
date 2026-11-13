# Releasing

Releases are built in GitHub Actions from a tag, signed keylessly with Sigstore,
shipped with a CycloneDX SBOM and SLSA build provenance, and published to PyPI
with Trusted Publishing (no API token exists anywhere). Workflow:
`.github/workflows/release.yml`.

## One-time setup

1. **PyPI** → https://pypi.org/manage/account/publishing/ → *Add a new pending publisher*:
   | Field | Value |
   |---|---|
   | PyPI project name | `t7-agent` |
   | Owner | `byteramp` |
   | Repository name | `triple-seven` |
   | Workflow name | `release.yml` |
   | Environment name | `pypi` |
2. **GitHub environments** (`pypi`, `release`) with a required reviewer — already created.
3. After the first release: open the release and tick *Publish this Action to the
   GitHub Marketplace*.
4. Before v1: pin every `uses:` to a full commit SHA (Dependabot is enabled).

## Cut a release

```bash
# bump pyproject.toml and t7/__init__.py to the same version
git tag v0.1.0 && git push origin v0.1.0
```

tests (3.10–3.13) → version/tag check → stdlib-only check → wheel + sdist → SBOM →
SHA256SUMS → Sigstore → provenance + SBOM attestations → *(approve)* PyPI →
*(approve)* GitHub release + move `v0`.

## How customers verify

```bash
gh release download v0.1.0 --repo byteramp/triple-seven

# 1. Provenance: built by this workflow from this repository
gh attestation verify t7_agent-0.1.0-py3-none-any.whl --repo byteramp/triple-seven

# 2. Signature: signed by that workflow's identity
python -m pip install sigstore
python -m sigstore verify github t7_agent-0.1.0-py3-none-any.whl \
  --bundle t7_agent-0.1.0-py3-none-any.whl.sigstore.json \
  --repository byteramp/triple-seven --ref refs/tags/v0.1.0

# 3. SBOM: no third-party runtime dependencies
python -c "import json;print([c['name'] for c in json.load(open('t7-agent.cdx.json'))['components']])"
```

Pin the action by commit SHA in workflows: `uses: byteramp/triple-seven@<sha> # v0.1.0`.
