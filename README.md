# Service Protos

> **Held / superseded draft.** The foundation was rolled back by
> [service-protos #161 — revert: roll back prematurely merged contract foundation](https://github.com/wendylabsinc/service-protos/pull/161).
> The `v0.1.0` tag was deleted on 2026-10-31 and is no longer usable.
> The catalogue views, checks and policy below are historical draft content,
> not the current source-only approach.

This superseded draft described a shared protobuf/gRPC API catalogue covering:

- Cloud main and legacy services
- WendyOS CLI and Agents (Go and Mac)
- Companion SDK / WendyProtos
- Auth and PKI

Embedded Core joins as its migration into WendyOS permits. Deployed contract
variants remain separate compatibility views, preserving their existing import
paths and behavior without normalization.

## Current source-only approach

The incremental route uses commit-pinned generation from service-protos,
starting with [WendyOS #2623 — build: use Shared gRPC API contracts for Cloud v2 mesh, users and tunnel](https://github.com/wendylabsinc/WendyOS/pull/2623).
That change pins `3f29f59fc72f692a52b91a03a14d465d5e8dbfc7` for Cloud v2
Mesh, Users and Tunnel. It replaces selected local sources while keeping
existing generated code unchanged. No catalogue release is part of this route.

## Historical draft framework

The remaining sections describe the superseded foundation, not current setup
or migration instructions.

## Compatibility views and checks

See [frozen compatibility views](contracts/README.md) for build/generation
commands and independent compatibility baselines. Before editing root contracts,
follow the [historical-byte preservation procedure](contracts/README.md#preserve-provenance-while-maintaining-canonical-apis).
Existing root import paths remain available. Use Python 3.15.2 and Buf 1.75.0:

```sh
python3 scripts/contracts.py check --base <PR-base-commit>
python3 -m unittest discover -s scripts -p 'test_*.py' -v
```

## Contract policy

See the [compatibility and retirement policy](docs/compatibility.md) and
[release/protection procedure](docs/releases.md).
Changes within an API version are additive. Breaking changes need a new API
version alongside the old one. Retirement requires the policy's support window,
migration evidence and owner approval.
