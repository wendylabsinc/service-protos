# Compatibility Review

Advisory semantic review alongside Buf. Runs for opened, reopened, ready and pushed
non-draft PRs from this repository, against their actual base (including stacks).
There is no manual dispatch or draft publishing. The workflow must land before it
can run. Buf is unchanged and remains responsible for structural checks.

Setup requires `ANTHROPIC_API_KEY` to be available to Actions. No repository secret
was listed during implementation. Without it the job fails visibly as unavailable,
never as a green compatibility assertion. Credential setup is a separate decision.
The direct Messages API uses Cloud's existing `claude-sonnet-5-5` model convention.
One call, at most 120 KB of source text, 16 KB per file and 3,000 output tokens, no
retries or tools, 180-second request timeout. Returned token usage is logged.
Cost is not estimated because this interface supplies no cost. No paid benchmarks.

Only the default branch's code executes. PR blobs are read from Git objects and
never checked out, imported or executed. The model receives no GitHub credentials
or tools. The publisher is a separate job with only PR write permission and
rechecks open/non-draft/same-repo status and both exact revisions before writing.
A final check marks a report superseded if revisions changed in the GET/write race
(GitHub comments have no atomic conditional write). Reports name immutable revisions.
No APPROVE, REQUEST_CHANGES, merge, labels or settings API is used.

There was no existing AI source filter in this repository to reuse. The positive
source selection runs before blob reads: `.proto`, Markdown, Buf/generator config,
conformance generator/verifier Go source and review scripts/workflows. In particular,
`GRPCGenerated.swift`, generated vectors and binary fixtures never enter prompts.
Unsupported paths and oversized snapshots are reported as omitted, including
renames (diffed as deletion/addition). This controls only this new review path.
Other tools are not filtered. Existing generation and Buf checks are separate.

Before/after source snapshots use the PR merge base. Nearby unchanged schemas are
included within the same budget. Imports elsewhere, consumer implementations and
historical released versions may be missing. Reports always say coverage is
incomplete. No findings establishes neither compatibility nor resolution of prior
findings. Quoted evidence is validated against supplied text, but semantic model
accuracy still needs human review. Untrusted source instructions cannot change
the trusted system guidance. No SDK, inventory, versioning or ownership framework.

Local tests are free and mock the provider. They validate real request construction,
source exclusions, context limits, evidence checks and known semantic fixtures.
They do not establish model recall/precision. No credentialed run was performed.

```
python3 -m unittest discover -s .github/compatibility-review -p 'test_*.py'
```
