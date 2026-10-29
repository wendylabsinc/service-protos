# API guidelines

These guidelines record the API decisions approved on 2026-10-22 and the
deletion rule settled on 2026-10-28: gone is gone. They describe the target contract for
new and changed APIs. The migration section distinguishes existing behavior from
that target.

## List APIs and pagination

Every new or changed list API uses stable pagination. Do not add offset paging.
A service picks one of two styles per RPC family and documents its choice:

- ID-anchored: one optional exclusive `after_id` with `has_more`, as described
  below.
- Page tokens: an opaque `page_token` with `page_size`, answered with
  `next_page_token`. The merged `AccessService` (`ListBindings`,
  `ListRoleHolders` in `wendycloud/v2/access.proto`) uses page tokens and is a
  valid precedent.

The rest of this section describes the ID-anchored style. An anchor is the ID
of an item the client has seen, and its position is defined by the request's
filter and ordering.

### Linear pages

Use an `optional string after_id` field directly on the request. Unset starts
the first page. To continue, send the last returned item's ID as `after_id`:
it is excluded, and the next batch starts strictly after it in the selected
order. Keep the same filter and ordering on every call. `limit` counts forward
from that position.

To iterate in the other direction, start a traversal with the opposite supported
order. For example, request `ID_ASC` with `after: <anchor>` to get the nearest
higher IDs, then reverse the page on the client for a descending display.

### Validation and limit

- A present `after_id` that is empty or malformed fails with `INVALID_ARGUMENT`.
  An empty string is different from leaving `after_id` unset.
- An anchor is a comparison value, never a lookup. A deleted, unknown or
  inaccessible anchor positions normally and is never an error, so a response
  reveals nothing about whether it exists. AAA applies to the returned items.

Use `optional int32 limit`:

| Value | Behavior |
| --- | --- |
| Unset | Use the API's documented default |
| `0` | Return zero items |
| Negative | Fail with `INVALID_ARGUMENT` |
| Above the API maximum | Clamp to that maximum |

Document the default and maximum for each API. Never lower the maximum within an
API version. There is no global default or maximum specified here.

### Response and continuation

Use a unary RPC: one page per call. Return `repeated` items in result order and
`bool has_more`. The server reads up to the effective limit + 1 matching items
after the anchor, returns at most the limit, and uses the extra item to determine
`has_more`.

An ID-anchored API returns no cursor. Continue with `after: <last returned ID>`,
keeping the same filter and ordering. Do not add `total`; it is legacy-only. If a
screen needs a count, use a separate Count RPC. Do not stream list pages.

For example, this illustrative API puts the continuation anchor directly on the
request. The orders and default below are examples; each API defines its own
supported orders and default.

```proto
syntax = "proto3";

package example.v1;

service ItemService {
  rpc ListItems(ListItemsRequest) returns (ListItemsResponse);
}

message ListItemsRequest {
  // Last returned item's ID, excluded; unset starts the first page.
  optional string after_id = 1;
  // Result order; UNSPECIFIED uses ID_ASC in this example API.
  ItemOrder order = 2;
  // Unset uses this API's documented default; zero returns no items.
  optional int32 limit = 3;
  // Optional filter; keep the same value on every page.
  optional string query = 4;
}

message ListItemsResponse {
  // Visible items in the selected result order.
  repeated Item items = 1;
  // More visible items remain after this page in the selected order.
  bool has_more = 2;
}

message Item {
  // The item's UUIDv4.
  string id = 1;
}

enum ItemOrder {
  // Uses ITEM_ORDER_ID_ASC.
  ITEM_ORDER_UNSPECIFIED = 0;
  ITEM_ORDER_ID_ASC = 1;
  ITEM_ORDER_ID_DESC = 2;
  // Creation time descending, then ID descending for ties.
  ITEM_ORDER_CREATED_AT_DESC = 3;
}
```

Swift SDKs expose the exclusive continuation anchor as `after:`. For example,
with the same filter and order configured on `items`:

```swift
// First page, then continue after its last item.
let firstPage = try await items.list(limit: 20)
if firstPage.hasMore, let last = firstPage.items.last {
    let nextPage = try await items.list(after: last.id, limit: 20)
}
```

These are SDK design examples, not claims about existing generated clients.
The continuation ID is a string on the wire; SDKs can expose their typed item ID.

### Ordering and IDs

Each API has one order enum listing only orders it supports. Put direction in
each value, such as `ID_ASC` or `CREATED_AT_DESC`. The zero value ends in
`_UNSPECIFIED` and means the API's documented default. Do not use a separate
direction field or free-text `order_by` for new APIs.

ID is always the final tie-breaker. For a non-ID order, compare the pair
`(sort value, ID)` both when ordering results and when applying the continuation
anchor. "After" refers to a position in this order, including when it is
descending.
Send the same filter and ordering on every page.

IDs stay random UUIDv4. ID order is stable, but it is not chronological. "Newest
first" means creation-time ordering with ID as the tie-breaker. This is a non-ID
order, so the server looks up the anchor's creation time.

### Deleted anchors and changed sort values

Gone is gone. A deleted row is deleted: no soft deletion, no tombstones, no
retention period. The audit log keeps the ID, and UIs render a dangling ID as
"deleted <kind>", for example "deleted device". A device that re-enrols gets a
new UUID: a new enrolment is a new record.

An anchor is a comparison value, never a lookup. A deleted or unknown anchor
positions normally: the range covers the IDs greater or less than it in result
order. It is never an error. How a deleted anchor positions in a non-ID order,
which needs the anchor's sort value, is not settled yet.

If an item's sort value changes, for example after a rename, use its current
value. Paging may rarely repeat or skip an item as a result; document this
behavior.

### Migration of existing APIs

For APIs adopting ID-anchored linear pages, add one optional exclusive `after_id`
alongside legacy pagination fields, deprecate the old fields, and remove them in
the next API version. Preserve the old fields in the current version. New
ID-anchored APIs use `after_id` directly on the request. The decisions do not
specify precedence or an error when a caller supplies both old and new pagination
fields; that needs to be settled for each migration before implementation.
Existing token-paged RPC families keep their `page_token`, `page_size` and
`next_page_token` contracts.

| API or existing field | Migration |
| --- | --- |
| `ListNotificationsV2.before_notification_id` and `after_notification_id` | Add one exclusive `after_id` alongside them, deprecate both, remove in the next version. Translate by verified behavior below, not by the old names. |
| Postbox `after_entry_id` | When migrated to the shared paging convention, add `after_id` alongside it, deprecate the old field, remove in the next version. |
| PKI `before_id`, including `GetAuditLog` | For an ID-anchored migration, add `after_id` alongside the old anchor, deprecate the old field, remove in the next version. Existing token pagination is unchanged. |
| Assets `order_by` | For ID-anchored pages, use `after_id` and a supported-order enum alongside legacy fields. Deprecate free-text `order_by` and remove it in the next version. |
| `ListOrganizationsV2` in [service-protos #77 — feat(organizations): add stable v2 discovery contract](https://github.com/wendylabsinc/service-protos/pull/77) | Use flat request fields: optional string `after_id = 1`, `order = 2`, optional `limit = 3`, optional `query = 4`. |
| Legacy streamed offset `ListOrganizations` | Deprecated in favour of `ListOrganizationsV2`; no continuation anchor is added to it. |

Postbox `after_entry_id` and audit `before_id` currently use integer IDs. Their
mapping to a string continuation anchor is not specified by these decisions;
this guide does not prescribe an ID conversion or renumbering. Adding an anchor
alone does not migrate existing limit or response semantics to the target
contract. Keep the side-by-side package and compatibility requirements in
[`API_V2_MIGRATION.md`](API_V2_MIGRATION.md).

#### Verified notification behavior

Read-only verification on Cloud `main` at
`5d1c3b59694fac4b551626a12dd9a7b0cbf87f45`:
[`NotificationServiceHandler.swift`](https://github.com/wendylabsinc/cloud/blob/5d1c3b59694fac4b551626a12dd9a7b0cbf87f45/swift/Sources/GRPCServices/NotificationServiceHandler.swift#L266)
and
[`notifications.query.sql`](https://github.com/wendylabsinc/cloud/blob/5d1c3b59694fac4b551626a12dd9a7b0cbf87f45/swift/Sources/GRPCServices/notifications.query.sql#L136).

- The response is newest first, by `(created_at, notification_id)` descending.
- `before_notification_id` selects tuples **less than** the anchor: older items,
  excluding the anchor. The query reads them descending. In that result order,
  this is an exclusive `after_id` continuation.
- `after_notification_id` selects tuples **greater than** the anchor: newer items,
  excluding the anchor. The query reads ascending to select the nearest newer
  items, then the handler reverses the selected page to newest first. A linear
  replacement for this nearest-newer traversal uses the opposite supported
  order with an exclusive `after_id`, then reverses the page for display.
- The handler currently rejects both fields together with `INVALID_ARGUMENT` and
  the message "before_notification_id and after_notification_id are mutually
  exclusive". The linear replacement has only one `after_id` anchor.
- The handler requires limit in `1...100`, looks up anchors within the caller's
  organization and recipient inbox, reads limit + 1, and returns
  `more_available`. Results exclude deleted recipient rows. Anchor lookup does
  not filter on recipient deletion, severity or read status.

Do not silently reinterpret the legacy fields or assume their names match the
new continuation field. The migration must preserve old behavior while
introducing `after_id` and documenting the selected order's traversal rules.

## Authorization

Declare every RPC in Cloud's `GateCatalog`. For Cloud, Auth and PKI boundaries,
follow the governing
[AAA Contract — Authentication, Authorization, Accounting](https://linear.app/wendylabsinc/document/aaa-contract-authentication-authorization-accounting-v024-dff5a8351650).
The guide does not replace that contract or establish new authorization policy.
