# Security

Report vulnerabilities in the Triple Seven agent privately to **security@byteramp.se**
(or GitHub *Report a vulnerability* on this repository). Please do not open public issues.

## What the agent sends to Byteramp

Only metadata: an abstract architecture model (components, flows, trust zones),
finding titles and file:line locations, fix/proof results as hashes and pass/fail,
and step summaries without code. Source code is sent to a model **only** to the
provider you configure (`T7_LLM`) — and to Byteramp's own EU models only after an
explicit per-repository opt-in in the portal. Read `t7/api.py` to verify.
