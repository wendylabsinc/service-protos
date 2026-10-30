# Shared API contracts

Follow [the canonical compatibility policy](docs/compatibility.md) and the
[release procedure](docs/releases.md). The accountable contract and release
owner role is unassigned.

Consumers use their single `contracts.version` tag for every shared contract
view. Only add within an existing API version. Never renumber, reuse or
reinterpret fields, enum values, methods, validation, errors or auth behavior.
Breaking changes get a new API version served beside the old version.
Catalogue SemVer majors are not runtime compatibility gates. Check supported API
versions and features, including newer CLI to older Agent compatibility.

Keep the old API for at least 90 days AND two stable releases of every affected
client product. Count each client's window from the later of replacement server
API availability and that product's first migrated stable client. Retirement
also needs owner approval and migration evidence covering older deployed Agents.
An approved hard cutoff can end support. Preserve retired identities and
reservations, and never break a still-supported API in place.

Do not weaken compatibility checks, hide supported files/views, alter capture
evidence during normal evolution, or add breaking-rule exemptions. Retiring
obsolete content or baselines requires a separate approved change under the
canonical policy. This migration authorizes no retirement. Existing
file-specific naming lint allowances preserve published names. Run the all-view
check and its negative tests for every change, including configuration and
documentation changes.

Cloud/Auth/PKI boundaries remain governed by the authoritative
[AAA Contract — Authentication, Authorization, Accounting (v0.25)](https://linear.app/wendylabsinc/document/aaa-contract-authentication-authorization-accounting-v025-dff5a8351650).
This catalogue grants no runtime auth exception. Preserve signed-method options
and existing conformance fixtures. No compatibility header or runtime gate is
introduced here.

API guidelines are being refined separately in
[service-protos #143 — feat: add shared list ranges and API guidelines](https://github.com/wendylabsinc/service-protos/pull/143).
Do not copy its unmerged redesign into this migration or retrofit frozen views.
