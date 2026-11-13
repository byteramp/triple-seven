#!/usr/bin/env sh
# Triple Seven in any CI (Bitbucket Pipelines, Azure DevOps, Jenkins, CircleCI, Buildkite …).
# Needs: full git history (merge base), Python 3.10+, T7_TOKEN as a secret variable.
# Exit code 1 = merge gate blocked (only when the gate is set to "enforce" in the portal).
set -eu
pip install --quiet "t7-agent==0.1.0"
export T7_API_URL="${T7_API_URL:-https://api.byteramp.se/api}"
t7 scan --ci --base "${T7_BASE:-origin/main}"
# The Markdown summary is written to t7-report.md — archive it as a build artifact.
