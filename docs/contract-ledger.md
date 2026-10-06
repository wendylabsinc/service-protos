# Contract ledger

Cross-service contract changes ship expand → migrate → contract (sem ruling
2026-10-06 14:45): receivers accept old and new first and are live on prod;
then senders switch; the old path is removed one release later at the
earliest. One row per phase that lands here.

| Date | Ticket | Contract | Phase | Change | Next phase when |
|------|--------|----------|-------|--------|-----------------|
| 2026-10-06 | WDY-3508 | `pkicore.v1` audit log (engine ← fabric ← cloud) | expand | Additive: `AuditLogEntry` gains `id` (7), `correlation_id` (8), `actor_principal` (9), `actor_kind` (10, enum `ActorKind`); `GetAuditLogRequest` gains `before_id` (7), `order` (8, enum `AuditLogOrder`, UNSPECIFIED = ASC). `actor` unchanged. Unset values keep today's behaviour. | pki-core engine and fabric fill/accept the fields and are live on prod; then cloud signs `order`/`before_id` and renders `actor_principal`. Nothing is removed: no contract phase planned. |
