# Contract compatibility policy

> **Historical / superseded draft.** The foundation was rolled back and
> `v0.1.0` was deleted on 2026-10-31. This retained proposal is not current
> policy. See the [current source-only approach](../README.md#current-source-only-approach).

The accountable contract and release owner role is unassigned.
Service domain owners still review semantics at their boundaries.

A service-protos tag versions the entire catalogue, independently of protobuf
package names. A catalogue SemVer major is not an automatic runtime
incompatibility signal. Runtime compatibility depends on the API versions and
features that the peers support, including newer CLIs talking to older Agents.
The superseded proposal gave each migrated consumer one `contracts.version`
containing one immutable stable tag. All generators, checks
and derived version metadata use that pin. Consumers upgrade independently.
Branch pins, per-file revisions, source-copy fallbacks and shared-contract
submodules are removed in later consumer PRs, after equivalence is proved.
Tagged inputs were the superseded migration target. Versioned generated Go and
Swift packages follow later, with the SDK work.

These support and retirement guarantees also apply throughout catalogue `0.x`.
A pre-1.0 catalogue version permits no break to a still-supported API version.

## Add within a version

Preserve every deployed RPC/type identity, field number/type/JSON name,
presence, enum value and meaning. Never renumber, reuse or reinterpret fields,
enum values, methods, errors, validation or authentication/authorization
behavior. Do not make an optional input required in a handler or change a
response's meaning merely because Buf permits it. Existing signed-request
options and signed artifact bytes are contracts too.

Breaking changes get a new API version alongside the old one. Deploy the
replacement server API first, migrate clients, then consider retirement.
Keep the old API for **at least 90 days AND two stable releases of every affected
client product**. Count each client's window from the later of availability of
the replacement server API and that product's first migrated stable client.
Contract tags, nightlies and prereleases do not count as stable client releases.
Retirement needs both thresholds, migration evidence and contract-owner approval.
Record retirement evidence in [the contract ledger](contract-ledger.md):
replacement API availability, each affected product's migrated stable releases
and dates, migration/rollout evidence covering older deployed Agents as well as
current sources, and remaining known legacy callers. Passing CI or migrating the
latest sources alone does not establish that deployed clients have migrated.
After both thresholds, the owner may explicitly approve a deliberate hard cutoff
to remove obsolete APIs. Eligibility alone does not authorize that cutoff.
Preserve retired identities and field/enum reservations. Never reuse them or
break a still-supported API version in place.

This window is tunable policy, not a runtime gate. It authorizes no weaker auth
fallback. Cloud/Auth/PKI work remains subject to the authoritative
[AAA Contract — Authentication, Authorization, Accounting (v0.25), §11.2](https://linear.app/wendylabsinc/document/aaa-contract-authentication-authorization-accounting-v025-dff5a8351650).

## Existing divergence

[The view catalogue](../contracts/README.md) freezes already divergent deployed
graphs. Cloud's local UUID invite contract and the root numeric invite contract
keep their identities in separate views. Agent video variants likewise stay
separate. Their behavior is not normalized. Exact-byte shared sources have one
internal copy, with explicit view/import mappings. New divergent behavior must
use a new API package, not another interpretation of an old identity.

The root catalogue may grow additively. Supported frozen migration views remain
unchanged. This preserves deployed differences during support, not an indefinite
promise to retain every view or source byte in future catalogue versions.
If an additive root edit affects a source shared by a frozen view, retain that
view's old bytes under `contracts/sources/` and point its existing import path
there using [the documented preservation path](../contracts/README.md#preserve-provenance-while-maintaining-canonical-apis).
Do not update the immutable source inventory, captured descriptors or provenance.
Add each new root file to both the catalogue's files and generation roots.
New frozen consumer/API views require an owner-reviewed checker/policy extension
with graph and independent baseline additions. JSON edits alone cannot extend
the current exact view-set and provenance checks.

## Review and enforcement

Every PR runs the `contracts` check, with no path-filter escape. Every view
must build and lint on Linux and Windows. Strict Buf `FILE` comparison uses
both the PR base's independently assembled graphs and the latest fetched
numeric stable catalogue tag. First-release comparisons use captured
pre-migration descriptors, even when no tag exists. Initial graphs remain checked
while supported.

The current checker rejects view removal and changes to capture evidence. An
approved retirement therefore also needs a separately reviewed change that
removes only retired content/baselines from future catalogues and comparisons,
while preserving strict checks for every supported API. Immutable released tags
retain the historical evidence. This migration implements no runtime cutoff or
retirement mechanism and authorizes no retirement.

Naming lint allowances are file-specific evidence of already-published names.
There are no breaking-rule exceptions. The check rejects omitted views/files,
unlisted sources, source drift, altered fixtures, changed signed-method options
and configuration bypasses. Before activating repository protections, assign an
eligible owner and establish CODEOWNERS coverage for schemas, policy, baselines,
generators and check configuration. Protections must require owner review and
the `contracts` status before this becomes an enforced merge gate. The prepared
settings do not claim those external protections are already active.

Buf does not prove behavior compatibility. Reviews must check errors, validation,
IDs, pagination, signing and auth semantics, backed by the existing conformance
fixtures and service tests. New/changed list APIs follow the governing API guide.
The unmerged list redesign in
[service-protos #143 — feat: add shared list ranges and API guidelines](https://github.com/wendylabsinc/service-protos/pull/143)
is not imported here. Frozen views retain their published paging behavior.
The full released-client N−1/N−2 runtime matrix is later work.
