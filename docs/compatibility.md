# Contract compatibility policy

Konstantin (`@konstantinbe`) is the interim accountable contract and release
owner. Service domain owners still review semantics at their boundaries.

A service-protos tag versions the entire catalogue, independently of protobuf
package names. Every consumer has exactly one `contracts.version` containing
one immutable tag such as `v1.0.0`. All generators, checks and derived version
metadata use that pin. Consumers upgrade independently. Branch pins, per-file
revisions, source-copy fallbacks and shared-contract submodules are removed in
later consumer PRs, after equivalence is proved. No consumer changes in this PR.

## Add within a version

Preserve every deployed RPC/type identity, field number/type/JSON name, presence,
enum value and meaning. Never renumber, reuse or reinterpret fields, enum
values, methods, errors, validation or authentication/authorization behavior.
Do not make an optional input required in a handler or change a response's
meaning merely because Buf permits it. Existing signed-request options and
signed artifact bytes are contracts too.

Breaking changes get a new API version alongside the old one. Deploy the
replacement server API first, migrate clients, then consider retirement.
Keep the old API for **at least 90 days AND two stable releases of every affected
client product**. Count each client's window from the later of availability of
the replacement server API and that product's first migrated stable client.
Contract tags, nightlies and prereleases do not count as stable client releases.
Retirement needs both thresholds, migration evidence and contract-owner approval.
Keep old schema identities and reservations after serving ends.

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

The root catalogue may grow additively. Frozen migration views remain unchanged.
If an additive root edit affects a source shared by a frozen view, retain that
view's old bytes under `contracts/sources/` and point its existing import path
there. Do not update its captured descriptor or provenance. Add the new root
path to the catalogue manifest when introducing a new root file. New
consumer/API views need explicit owner-reviewed graph and baseline additions.

## Review and enforcement

Every PR runs the `contracts` check, with no path-filter escape. Every view must
build and lint on Linux and Windows. Strict Buf `FILE` comparison uses both the
PR base's independently assembled graphs and the latest fetched stable catalogue tag. First-release comparisons use captured pre-migration
descriptors, even when no tag exists. The initial graphs stay checked forever
unless a separately reviewed policy change explicitly retires a baseline.

Naming lint allowances are file-specific evidence of already-published names.
There are no breaking-rule exceptions. The check rejects omitted views/files,
unlisted sources, source drift, altered fixtures, changed signed-method options
and configuration bypasses. CODEOWNERS covers schemas, policy, baselines,
generators and check configuration. Repository protections must require owner
review and the `contracts` status before this becomes an enforced merge gate.
The prepared settings do not claim those external protections are already active.

Buf does not prove behavior compatibility. Reviews must check errors, validation,
IDs, pagination, signing and auth semantics, backed by the existing conformance
fixtures and service tests. New/changed list APIs follow the governing API guide.
The unmerged list redesign in
[service-protos #143 — feat: add shared list ranges and API guidelines](https://github.com/wendylabsinc/service-protos/pull/143)
is not imported here. Frozen views retain their published paging behavior.
The full released-client N−1/N−2 runtime matrix is later work.
