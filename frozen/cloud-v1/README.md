# Frozen Cloud v1 inputs

These are exact source views, not a choice of the live deployment's contract.
Both are recorded by Cloud `legacy` at
`6b0128da9f25b0a78692635ed8b1210d5f33beee`:

- `buf.cloud-v1-dashboard.yaml`: the 33 tracked `dashboard/proto/**/*.proto`
  files. Cloud's README and App Hosting build describe using this tree when
  submodules are unavailable.
- `buf.cloud-v1-submodule.yaml`: the 36 files copied by
  `dashboard/scripts/copy-protos.sh` from the initialized `proto` submodule,
  `c3878f4eb522a709ad9fb6b0e169222da3a4dfe6` of service-protos (root protos
  and `opentelemetry/`).

`notifications.proto`, `schedule.proto` and `tunnel.proto` differ between these
inputs. Only the tracked dashboard has `hackathon_org.proto` and `robots.proto`.
Only the submodule copy has `authorization.proto`, `diagnostics.proto`,
`org_invites.proto`, `public_routing.proto` and `telemetry_query.proto`.
The common files are shared here, including the historical
`personal_access_tokens.proto`. Eight byte-identical OTLP files are reused from
root. Other shared flat files must be collected here because Buf module filters
select directories, and the root also contains conflicting declarations.
Do not combine the views or modernize their fields, packages, options or imports.

The default root module excludes this directory. Each view compiles independently
and preserves the original import basenames. Its minimal lint checks accommodate
historical package layout without changing root lint or breaking rules. CI lints
both views and checks each against master once its baseline exists.

From a checkout at the intended immutable source commit:

```sh
buf lint --config buf.cloud-v1-dashboard.yaml
buf export . --config buf.cloud-v1-dashboard.yaml --output "$scratch/source"
```

For the other input, use `buf.cloud-v1-submodule.yaml`. Export produces the exact
original source bytes and paths, suitable for the existing dashboard generator.
A consumer using a pinned Buf Git input can supply the selected view directly:

```sh
buf export "https://github.com/wendylabsinc/service-protos.git#ref=$source_sha" \
  --config '{"version":"v2","modules":[{"path":".","includes":["opentelemetry"]},{"path":"frozen/cloud-v1/common"},{"path":"frozen/cloud-v1/dashboard"}]}' \
  --output "$scratch/source"
```

Use the full immutable commit for `source_sha`. Select `submodule` instead of
`dashboard` in the final module path only when that input is justified. Git build
instructions do not prove the live build input. The Swift Dockerfile compiles
committed `swift/Sources/Proto` without regeneration, and its standalone generator
also requests files missing from the submodule. Resolve that independently before
changing a legacy consumer. This collection changes no consumer or runtime API.
