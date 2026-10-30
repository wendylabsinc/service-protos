# Shared API contracts

Follow [the canonical compatibility policy](docs/compatibility.md) and the
[release procedure](docs/releases.md). Konstantin is the interim accountable
contract and release owner.

Consumers use their single `contracts.version` tag for every shared contract
view. Only add within an existing API version. Never renumber, reuse or
reinterpret fields, enum values, methods, validation, errors or auth behavior.
Breaking changes get a new API version served beside the old version.

Keep the old API for at least 90 days AND two stable releases of every affected
client product. Count each client's window from the later of replacement server
API availability and that product's first migrated stable client. Retirement
also needs owner approval and migration evidence. Preserve schema identities
and reservations after serving ends.

Do not weaken compatibility checks, alter the source inventory or migration
baselines, hide files or views, or add breaking-rule exemptions. Existing file-
specific naming lint allowances preserve published names. Run the all-view
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
