# Contract ledger

Cross-service contract changes ship expand → migrate → contract (sem ruling
2026-10-06 14:45): receivers accept old and new first and are live on prod;
then senders switch; the old path is removed one release later at the
earliest. One row per phase that lands here.

| Date | Ticket | Contract | Phase | Change | Next phase when |
|------|--------|----------|-------|--------|-----------------|
| 2026-10-06 | WDY-3508 | `pkicore.v1` audit log (engine ← fabric ← cloud) | expand | Additive: `AuditLogEntry` gains `id` (7), `correlation_id` (8), `actor_principal` (9), `actor_kind` (10, enum `ActorKind`); `GetAuditLogRequest` gains `before_id` (7), `order` (8, enum `AuditLogOrder`, UNSPECIFIED = ASC). `actor` unchanged. Unset values keep today's behaviour. | pki-core engine and fabric fill/accept the fields and are live on prod; then cloud signs `order`/`before_id` and renders `actor_principal`. Nothing is removed: no contract phase planned. |

## Hosted MCP tunnel binding (WDY-3526)

The [hosted MCP descriptor contract](../conformance/tunnel/README.md#hosted-mcp-delegation-binding)
adds an optional, signed `mcp` object for FleetScope v2 credentials. Cloud, PKI and
WendyOS must ship the dedicated authorization path together. The broker's opaque
hash bindings and protobuf messages do not change. Generic tunnel entry points
reject this delegated path, and ordinary operator certificates cannot claim it.

WDY-3527: FleetScope v3 adds explicit time-limited all-app consent while retaining
exact device, owner, key, audience, gateway and RPC constraints. See the
[tunnel contract](../conformance/tunnel/README.md#blanket-app-consent-wdy-3527).
