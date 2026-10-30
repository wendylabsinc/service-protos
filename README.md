# Service Protos

The shared protobuf/gRPC API catalogue for the Wendy ecosystem covers:

- Cloud main and legacy services
- WendyOS CLI and Agents (Go and Mac)
- Companion SDK / WendyProtos
- Auth and PKI

Embedded Core joins as its migration into WendyOS permits. Deployed contract
variants remain separate compatibility views, preserving their existing import
paths and behavior without normalization.

## Tagged inputs

The initial catalogue tag, [v0.1.0](https://github.com/wendylabsinc/service-protos/tree/v0.1.0),
is published. Catalogue coverage does not mean consumer adoption: consumer
migrations are still pending, and each repository upgrades independently.

Each migrated repository uses one `contracts.version` tag pin for all shared
contract views, generating with Buf from that tagged Git input. Migration
removes shared-contract submodules and source copies after equivalence is proved.
Versioned generated Go and Swift packages are separate, later SDK work.

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
