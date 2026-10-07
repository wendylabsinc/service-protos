# Contract ledger

Cross-service contract changes ship expand → migrate → contract (sem ruling
2026-10-06 14:45): receivers accept old and new first and are live on prod;
then senders switch; the old path is removed one release later at the
earliest. One row per phase that lands here.

| Date | Ticket | Contract | Phase | Change | Next phase when |
|------|--------|----------|-------|--------|-----------------|
| 2026-10-06 | WDY-3508 | `pkicore.v1` audit log (engine ← fabric ← cloud) | expand | Additive: `AuditLogEntry` gains `id` (7), `correlation_id` (8), `actor_principal` (9), `actor_kind` (10, enum `ActorKind`); `GetAuditLogRequest` gains `before_id` (7), `order` (8, enum `AuditLogOrder`, UNSPECIFIED = ASC). `actor` unchanged. Unset values keep today's behaviour. | pki-core engine and fabric fill/accept the fields and are live on prod; then cloud signs `order`/`before_id` and renders `actor_principal`. Nothing is removed: no contract phase planned. |
| 2026-10-08 | WDY-3545 | `wendyauth.v1` member provisioning (auth → cloud) | expand | Additive: `AuthFabric.ListRealmMembers` (+ `ListRealmMembersRequest/Response`, `RealmMember`, `RealmMemberGroup`, enums `RealmMemberStatus`, `RealmMemberKind`, `RealmGroupSource`); new SET event-type `https://schemas.wendy.sh/secevent/membership-changed` (refresh hint, cloud only, grants nothing; vectors in `conformance/set/`). Min peer versions: wendy-auth serving the read needs none; cloud uses the read only when `GetCapabilities` lists it, so no cloud release needs a new wendy-auth. | migrate: wendy-auth turns on `WENDY_AUTH_SET_MEMBERSHIP_CHANGED` only once cloud on prod handles the hint and the read (WDY-3545 phase 3); that wendy-auth tag states the cloud minimum. Nothing is removed from wendy-auth. |
