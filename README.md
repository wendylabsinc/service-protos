# Service Protos

This repository contains Protocol Buffer definitions shared between `wendylabsinc/wendy-agent` and cloud services.

## Purpose

These protobuf files define the common interfaces and data structures used for communication between:
- Wendy Agent components
- Cloud service implementations
- Inter-service communication protocols

## Usage

Import these protobuf definitions into your projects to ensure consistent data structures and API contracts across the Wendy ecosystem.

## Structure

The protobuf files are organized to support various service interactions and maintain backwards compatibility across different service versions.

## Contract catalogue versions

Publish immutable `vMAJOR.MINOR.PATCH` Git tags from reviewed commits on `master`
with passing CI. Never move or reuse a tag, including a deleted tag.

- **Patch:** compatible corrections, including documentation fixes.
- **Minor:** backward-compatible additions.
- **Major:** incompatible public contract changes, including wire or behavior changes.

A catalogue tag versions the whole repository. API package versions and their
coexistence are separate: incompatible APIs need a new version served alongside
the supported old version. A catalogue major bump alone does not establish that
all v1 and v2 clients cannot communicate, or authorize retiring an old API.

Retirement remains an explicit decision with migration evidence. The accepted
default is at least **90 days AND two stable releases of every affected client**,
counted for each client from the later of replacement API availability and its
first migrated stable release. Follow the existing
[migration and exit criteria](API_V2_MIGRATION.md) and, for Cloud/Auth/PKI,
[expand → migrate → contract](https://github.com/wendylabsinc/saasdocs/blob/main/security-invariants/expand-migrate-contract.md)
and the [AAA contract §11.2](https://linear.app/wendylabsinc/document/aaa-contract-authentication-authorization-accounting-v025-dff5a8351650).

Consumers pin one exact published tag, never a floating range, branch or `latest`.
Update the pin deliberately in a PR, regenerate with the consumer's pinned tools,
and review source/output parity and compatibility before adoption. Until the first
tag is approved and published, retain existing immutable commit pins.

Illustrative only: `v2.3.4` below is not a published or chosen initial version.
Inspect a published tag and export its selected source with Buf's existing
[Git input syntax](https://buf.build/docs/reference/inputs/#git):

```sh
git ls-remote https://github.com/wendylabsinc/service-protos.git \
  'refs/tags/v2.3.4' 'refs/tags/v2.3.4^{}'
buf export 'https://github.com/wendylabsinc/service-protos.git#ref=v2.3.4' \
  --path pkicore/v1/types.proto --output ./contract-source
```
