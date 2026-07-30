# Wendy Cloud API v2 Migration

This checklist coordinates the next global protobuf API generation. `wendycloud.v2`
must be introduced as a new, side-by-side package; it must never be created by
destructively changing `wendycloud.v1`. Buf continues to protect the v1 wire contract
throughout migration. Retire v1 only after every known producer and consumer has
migrated and the exit criteria below are met.

Tracking: [WDY-2053](https://linear.app/wendylabsinc/issue/WDY-2053/plan-wendycloudv2-api-hardening-and-migration)

**Status labels**

- **Approved direction** describes the intended v2 outcome.
- **Confirmation required** identifies design details that are not final and must be
  agreed before their v2 contract is published.

## Notifications

### Approved direction

- [ ] Remove the deprecated legacy `CreateNotification` RPC and
  `CreateNotificationRequest` from the v2 package. Keep them intact in v1 during
  migration.
- [ ] Make the canonical UUID the sole public `Notification` identifier.
- [ ] Treat creation as a strict resource claim: the first use of a canonical UUID may
  succeed, every later use fails with `ALREADY_EXISTS`, and a new UUID creates a distinct
  Notification.
- [ ] Keep per-recipient projection identifiers internal; do not expose their integer
  IDs through the canonical v2 interface.
- [ ] Define List, Get, Delete, Mark, and read-state APIs around canonical Notification
  UUIDs, including UUIDs in list results and mutation inputs.
- [ ] Use Notification UUIDs for APNs payloads and Companion navigation so links do not
  depend on recipient-projection IDs.
- [ ] Remove legacy `related_entities`; use structured `metadata` instead.
- [ ] Extract shared immutable fields into `NotificationContent` rather than duplicating
  them across request and response messages.
- [ ] Represent creator attribution as a structured `oneof` instead of parallel nullable
  creator fields.
- [ ] Adopt one global UUID wire and validation convention across all v2 services.
- [ ] Add declarative validation for UUID v4 values, text sizes and characters,
  `wendy://` URIs, audience selector bounds, and resolved-recipient bounds.
- [ ] Backfill canonical data before removing transitional nullable fields.
- [ ] Dual-serve v1 and v2 until all producers, inbox readers, state mutations, APNs
  navigation, and Companion navigation use v2; retire v1 only afterward.

### Confirmation required

The direction above is approved, but these contract details still require explicit
agreement:

- [ ] Choose the single global UUID protobuf representation and textual rules, including
  canonical casing, accepted input forms, and UUID-version enforcement.
- [ ] Confirm the exact List pagination, bulk Mark, and read-state request/response shapes.
- [ ] Confirm the fields and presence rules in `NotificationContent`.
- [ ] Confirm the creator `oneof` variants and the trusted attribution attached to each.
- [ ] Confirm the APNs payload and Companion navigation transition from integer IDs to
  UUIDs.
- [ ] Select the declarative validation mechanism and stable validation error mapping.
- [ ] Approve the dual-serve observation period and final v1 retirement date.

## Migration sequence

1. Inventory every v1 producer and consumer, including generated clients, Cloud,
   dashboard, MCP, WendyOS, WendyKit, Companion, APNs, tests, and documentation.
2. Resolve all **Confirmation required** items and publish new `wendycloud.v2` files
   beside v1. Keep Buf compatibility checks protecting v1.
3. Implement v2 storage and handlers, backfill canonical UUID/content/creator data, and
   dual-serve v1 and v2 with parity tests and rollback coverage.
4. Migrate producers first, then list/read/state consumers and UUID navigation. Track
   remaining v1 traffic and owners.
5. Stop v1 serving only after the exit criteria are met. Remove v1 contracts only as an
   explicit, separately approved compatibility-policy change.

## Exit criteria

- [ ] Every inventoried producer and consumer has an owner-confirmed v2 migration.
- [ ] Canonical UUID and required-field backfills are complete and verified; transitional
  nullable columns or fields are no longer needed.
- [ ] V2 creation, duplicate rejection, fanout, read-state, and navigation behavior has
  parity coverage.
- [ ] APNs and Companion navigation use UUIDs end to end.
- [ ] Production telemetry shows no v1 Notification traffic for the approved observation
  period.
- [ ] Rollback, support, and retirement plans are approved, and the intentional Buf policy
  change for eventual v1 removal is reviewed separately.

## Other services

Add a section for each service before designing its v2 contract. Use the same labels so
approved direction is not confused with unresolved design:

```markdown
## <Service name>

### Approved direction
- [ ] ...

### Confirmation required
- [ ] ...

### Migration and exit criteria
- [ ] ...
```
