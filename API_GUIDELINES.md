# API guidelines

These guidelines record the API decisions approved on 2026-10-22. They describe
the target contract for new and changed APIs. The migration section distinguishes
existing behavior from that target.

## List APIs and pagination

Every new or changed list API uses stable pagination anchored by item IDs. Do not
add offset paging. An anchor is the ID of an item the client has seen, and its
position is defined by the request's filter and ordering.

### One shared range

Import [`wendy/id_range.proto`](wendy/id_range.proto) in every API that uses a
range. Use `wendy.IDRange` rather than defining another range message or flattening
its fields into each request. The shared type evolves append-only and gives SDKs
one value type and a shared validation contract.

Its definition is:

```proto
message IDRange {
  // Unset means from the first item in result order.
  oneof start {
    string from_id = 1;     // Inclusive.
    string after_id = 2;    // Exclusive.
  }
  // Unset means through the last item in result order.
  oneof end {
    string through_id = 3;  // Inclusive.
    string up_to_id = 4;    // Exclusive.
  }
}
```

Start and end are independent. Each `oneof` selects at most one bound at its own
end; it does not prevent using both ends together. A missing bound means no bound
at that end of the filtered, ordered results. `limit` counts from the start of the
range.
To page toward the other end, flip the order: for example, request `ID_ASC` with
`after: <anchor>` to get the nearest higher IDs, then reverse the page on the
client for a descending display.

All nine combinations are valid. In this table, A and B are anchor IDs and
"first" and "last" refer to the request's result order, not numeric ID order.

| Start | End | Range in result order |
| --- | --- | --- |
| Unset | Unset | First item through last item |
| Unset | `through_id = B` | First item through B, including B |
| Unset | `up_to_id = B` | First item up to B, excluding B |
| `from_id = A` | Unset | A through last item, including A |
| `from_id = A` | `through_id = B` | A through B, including both |
| `from_id = A` | `up_to_id = B` | A up to B, including A and excluding B |
| `after_id = A` | Unset | After A through last item, excluding A |
| `after_id = A` | `through_id = B` | After A through B, excluding A and including B |
| `after_id = A` | `up_to_id = B` | After A up to B, excluding both |

### Validation and limit

- A selected anchor that is empty or malformed fails with `INVALID_ARGUMENT`.
  Selecting an empty string is different from leaving a bound unset.
- Anchors in the wrong order produce an empty page.
- If both ends name the same item, the range contains that item only when both
  ends are inclusive. Otherwise it is empty. Filters, deletion and limit still
  determine whether the item is returned.
- In ID order, an unknown anchor works without a lookup: its ID defines the
  boundary. In other orders, an unknown anchor is an error because its sort value
  cannot be resolved.
- An inaccessible anchor gets the same error as a not-found anchor. Do not reveal
  whether an item the caller cannot access exists. AAA applies.

The decisions do not select a specific status code for not-found, inaccessible
or purged anchors. An API must not infer different errors that reveal existence.

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
within the range, returns at most the limit, and uses the extra item to determine
`has_more`. Tombstones are not result items.

Do not return a cursor. Continue with `after: <last returned ID>`, keeping the
same end bound, filter and ordering. Do not add `total`; it is legacy-only. If a
screen needs a count, use a separate Count RPC. Do not stream list pages.

For example, this illustrative API imports the shared range. The orders and
default below are examples; each API defines its own supported orders and default.

```proto
syntax = "proto3";

package example.v1;

import "wendy/id_range.proto";

service ItemService {
  rpc ListItems(ListItemsRequest) returns (ListItemsResponse);
}

message ListItemsRequest {
  // Bounds in the selected result order; unset means the whole range.
  wendy.IDRange range = 1;
  // Result order; UNSPECIFIED uses ID_ASC in this example API.
  ItemOrder order = 2;
  // Unset uses this API's documented default; zero returns no items.
  optional int32 limit = 3;
}

message ListItemsResponse {
  // Visible items in the selected result order.
  repeated Item items = 1;
  // More visible items remain in this range after this page.
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

Swift SDK spelling follows the standard library's range terms: `from` includes
the start, `after` excludes it, `through` includes the end, and `upTo` excludes it.
For example, with the same filter and order configured on `items`:

```swift
// First page, then continue after its last item.
let firstPage = try await items.list(limit: 20)
if firstPage.hasMore, let last = firstPage.items.last {
    let nextPage = try await items.list(after: last.id, limit: 20)
}

// Both ends included; a limit, if supplied, counts from firstID.
let window = try await items.list(from: firstID, through: lastID)
```

These are SDK design examples, not claims about existing generated clients.
Protobuf has no generics, so IDs are `string` on the wire. SDKs use typed ranges:
`IDRange<ID>` in Swift and `IDRange[ID]` in Go.

### Ordering and IDs

Each API has one order enum listing only orders it supports. Put direction in
each value, such as `ID_ASC` or `CREATED_AT_DESC`. The zero value ends in
`_UNSPECIFIED` and means the API's documented default. Do not use a separate
direction field or free-text `order_by` for new APIs.

ID is always the final tie-breaker. For a non-ID order, compare the pair
`(sort value, ID)` both when ordering results and when applying bounds. "After"
and "up to" refer to positions in this order, including when it is descending.
Send the same filter and ordering on every page.

IDs stay random UUIDv4. ID order is stable, but it is not chronological. "Newest
first" means creation-time ordering with ID as the tie-breaker. This is a non-ID
order, so the server looks up the anchor's creation time.

### Deleted anchors and changed sort values

Use soft deletion with tombstones. A tombstone keeps only the ID, owner
(organization or user) and sort-key columns. Erase content on deletion and purge
the tombstone after 30 days. Include tombstones when resolving anchors, but
exclude them from results. They are never returned to clients.

In ID order, anchors work without a lookup. Deletion and purge do not affect
them, and no tombstone is needed for the anchor. In non-ID orders, the server
resolves the anchor's sort value from the tombstone so paging can continue after
deletion. After purge, that anchor errors and the client restarts. An anchor the
caller could not access while it existed gets the same error as not found.

If an item's sort value changes, for example after a rename, use its current
value. Paging may rarely repeat or skip an item as a result; document this
behavior. Apply tombstone handling to new list APIs first and to existing APIs
when they are next changed. This is Cloud deletion work and is subject to AAA.
The guide and shared proto do not implement that storage behavior.

### Migration of existing APIs

Add `IDRange` alongside existing pagination fields, deprecate the old fields, and
remove them in the next API version. Preserve the old fields in the current
version. New APIs use the range directly. The decisions do not specify precedence
or an error when a caller supplies both old and new pagination fields; that needs
to be settled for each migration before implementation.

| API or existing field | Migration |
| --- | --- |
| `ListNotificationsV2.before_notification_id` and `after_notification_id` | Add `IDRange` alongside them, deprecate both, remove in the next version. Translate by verified behavior below, not by the old names. |
| Postbox `after_entry_id` | Add `IDRange` alongside it, deprecate the old field, remove in the next version. |
| PKI `before_id` and `page_token`, including `GetAuditLog` | Add `IDRange` alongside them, deprecate the old fields, remove in the next version. New list APIs use a unary page response. |
| Assets `order_by` | Add `IDRange` and a supported-order enum alongside the legacy fields. Deprecate free-text `order_by` and remove it in the next version. |
| `ListOrganizationsV2` in [service-protos #77 — feat(organizations): add stable v2 discovery contract](https://github.com/wendylabsinc/service-protos/pull/77) | Adopt `IDRange` directly. |
| Legacy offset `ListOrganizations` | Leave it as it is. |

Postbox `after_entry_id` and audit `before_id` currently use integer IDs. Their
mapping to the shared string anchor fields is not specified by these decisions;
this guide does not prescribe an ID conversion or renumbering. Nor does adding a
range alone migrate existing limit or response semantics to the target contract.
Keep the side-by-side package and compatibility requirements in
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
  this is an `after_id` start bound.
- `after_notification_id` selects tuples **greater than** the anchor: newer items,
  excluding the anchor. The query reads ascending to select the nearest newer
  items, then the handler reverses the selected page to newest first. Its bound
  corresponds to `up_to_id`, but its nearest-anchor page selection differs from
  the new rule that limit counts from the start of the range.
- The handler currently rejects both fields together with `INVALID_ARGUMENT` and
  the message "before_notification_id and after_notification_id are mutually
  exclusive". That is legacy behavior; the new start and end bounds combine.
- The handler requires limit in `1...100`, looks up anchors within the caller's
  organization and recipient inbox, reads limit + 1, and returns
  `more_available`. Results exclude deleted recipient rows. Anchor lookup does
  not filter on recipient deletion, severity or read status.

Do not silently reinterpret the legacy fields or assume their names match the
new range terms. The migration must preserve old behavior while introducing the
new range and documenting the changed traversal rules.

## Errors

Use gRPC status codes for the error category. Include a ready-to-show English
sentence in `google.rpc.LocalizedMessage`, with `locale = "en-US"`. This guide
does not define a complete per-RPC error-code mapping.

## Authorization

Declare every RPC in Cloud's `GateCatalog`. For Cloud, Auth and PKI boundaries,
follow the governing
[AAA Contract — Authentication, Authorization, Accounting](https://linear.app/wendylabsinc/document/aaa-contract-authentication-authorization-accounting-v024-dff5a8351650).
The guide does not replace that contract or establish new authorization policy.
