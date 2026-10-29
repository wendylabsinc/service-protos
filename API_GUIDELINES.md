# API guidelines

These guidelines fix the shape and behavior of Wendy APIs. Everything here is a rule, except what is listed under "Recommended", which may be done differently for good reason.

## List APIs

### What we design for

Picture the device list in an app, with a few thousand devices. The screen shows about 20 rows at a time.

- **Opening the screen** shows the first rows right away. The scroll bar already has its final size, because the app knows how many devices there are.
- **Scrolling** is continuous. As the user scrolls, the app loads the next rows a little ahead of time, so they are there before they come into view. Scrolling up works the same way.
- **Jumping**: dragging the scroll bar to the middle of the list shows placeholder rows for a moment, then the devices at that position.
- **Staying current**: while the screen is open, the app refreshes the rows the user is looking at, every few seconds, when the app comes back to the foreground, and on pull to refresh. A renamed device shows its new name, a deleted one disappears, a new one appears in its place.
- **Keeping the place**: rows above the user change without moving what the user is looking at.
- **Refreshing is cheap**: when nothing has changed, the server says so and sends no items.

The app does not need to hold the whole list. It only needs what is on screen plus a little around it, and asks the server for exactly that part. It may keep more, for example as a cache. Efficient support for caching is future work. List APIs are built around this: a request names **which list** (the query), **which part of it** (the range), how many extra items around that part (`preceding`, `following`) and how many items at most (`limit`). A response returns those items with their exact position in the list and the size of the whole list.

This covers apps that are online. Catching up after being offline, with diffs and caching, comes on top later (see Future work).

### Naming and paging

- An RPC that returns part of a list is named `List…`.
- An RPC that returns specific items by ID is named `Get…` and takes a list of IDs, so a client fetches many items in one call. Fetching one item is the same call with one ID.
- A `Get…` response returns the items found, in the order of the requested IDs, plus the IDs that were not found. An item that does not exist and one the caller may not see are reported the same way.
- List APIs page by anchors (positions in the list), never by offset. An offset shifts when items are added or deleted, an anchor does not.

Recommended:

- One plural RPC per item type, for example `GetDevices(ids)`. Document the most IDs a request may carry.

### Request

- A request has these fields: `query`, `range`, `preceding`, `following`, `limit`, and optionally the `etag` of an earlier response (see Unchanged responses).
- The query defines the list: filter, search and sort order. A client sends the same query on every request for the same list.
- Every sort order is total. The item ID is the final tie-breaker, so no two items share a position.
- An API supports only a fixed set of sort orders and documents them.

Recommended:

- One sort order enum per API, listing only the supported orders, with the direction built into each value. The `…_UNSPECIFIED = 0` value is the documented default order.
- Prefer sort orders whose values do not change (creation time). Items sorted by a value that changes (name) move when it changes.

```proto
message ListDevicesRequest {
  DeviceQuery query = 1;
  ListRange range = 2;
  int32 preceding = 3;
  int32 following = 4;
  optional int32 limit = 5;
  string etag = 6;           // optional: etag of the previous response to the same request
}

message DeviceQuery {
  string search = 1;
  optional bool online = 2;
  DeviceSortOrder sort_order = 3;
}
```

### Range

- The range is a part of the list, given by a start and an end.
- Start, one of:
  - unset: the top of the list,
  - `from`: an anchor, inclusive,
  - `after`: an anchor, exclusive,
  - `at`: a position in the list, for jumping to a part the client has not loaded. After a jump, clients continue by anchor.
- End, one of:
  - unset: the bottom of the list,
  - `through`: an anchor, inclusive,
  - `up_to`: an anchor, exclusive.
- A start after the end gives an empty range. A range can also be empty on purpose, for example `from: A, up_to: A`, to fetch only overhang around A.

Recommended:

- One shared `ListRange` message for all APIs.

```proto
message ListRange {
  oneof start {             // unset = the top
    ListAnchor from = 1;    // inclusive
    ListAnchor after = 2;   // exclusive
    int32 at = 3;           // position, for jumps
  }
  oneof end {               // unset = the bottom
    ListAnchor through = 4; // inclusive
    ListAnchor up_to = 5;   // exclusive
  }
}
```

### Overhang and limit

- `preceding` is the number of extra items before the range, counted backwards from its start bound. `following` is the number of extra items after the range, counted on from its end bound. Both are cut off at the edges of the list.
- `limit` is the most items a response contains, overhang included. Unset means the API's default.
- The range is filled first, from its start. An open range takes the whole limit, so it gets overhang only if it runs out first.
- What is left goes to the overhang. If both sides fit, each gets what it asked for. Otherwise the rest is split in proportion to the two requests: `preceding` gets its share rounded up, `following` gets the remainder. Neither side ever gets more than it asked for, and a side that reaches an edge of the list leaves the rest to the other side.
- A response is always one contiguous part of the list, without gaps.

Example: a range of 70 items with `preceding: 10, following: 1`. With `limit: 100` the response has 10 + 70 + 1 items. With `limit: 75` it has 5 + 70 + 0. With `limit: 70` it has the range only.

### Anchors

- An anchor marks a position in the list. It is compared against the items, never used to fetch the item it came from. A bound whose item was deleted still positions correctly, between the items that were around it.
- An API uses one of two anchor variants, depending on whether it keeps deleted items as tombstones. Everything else is the same in both.
  - **With tombstones:** the anchor is the item ID. The server finds the position from the item or its tombstone.
  - **Without tombstones:** the anchor is the item's sort values for the current sort order, plus its ID. It positions correctly no matter how many items around it were deleted.
- The server returns one anchor per item. Clients use those anchors as bounds and treat them as opaque.
- An anchor belongs to the query it was returned for. The server rejects an anchor it can tell came from a different query.

Recommended:

- One shared `ListAnchor` message for all APIs, with typed sort values. SDKs type anchors by item, so a device anchor cannot be passed to the apps API.
- Without tombstones, include a short hash of the API and the normalized query, issued by the server. It is optional and a safeguard against bugs, not a security feature. Without a hash, check that the number and types of sort values match the sort order.
- Keep sort values at full precision, for example timestamps in microseconds, so comparisons match the stored data.

```proto
// With tombstones
message ListAnchor {
  string id = 1;
}

// Without tombstones
message ListAnchor {
  optional bytes query_hash = 1;           // issued by the server
  string id = 2;                           // final tie-breaker
  repeated ListSortValue sort_values = 3;  // in the sort order's column order
}

message ListSortValue {
  oneof value {                            // unset = null
    string string = 1;
    int64 integer = 2;
    google.protobuf.Timestamp timestamp = 3;
    bool boolean = 4;
  }
}
```

### Response

- The response has:
  - the items in list order: preceding, then the range, then following,
  - one anchor per item,
  - `index`: the position of the range's first item in the whole list, exact,
  - `count`: the number of items in the range, exact,
  - `total`: the number of items in the whole list, may be estimated,
  - `preceding` and `following`: how many overhang items were actually returned.
- Items, positions and counts come from one consistent read.
- Every list API returns `index`.
- Edges of the list:
  - The top is reached when `index - preceding == 0`.
  - The bottom is reached when fewer than `limit` items came back and the part running toward the bottom came back short: `following` smaller than asked, or the range itself if its end is open.

Recommended:

- Return an exact `total` where counting is cheap. Estimate it only where an exact count is expensive.
- Make the position counts cheap, for example with database indexes that match each sort order.

```proto
message ListDevicesResponse {
  repeated Device devices = 1;
  repeated ListAnchor anchors = 2;
  int32 index = 3;
  int32 count = 4;
  int32 total = 5;
  int32 preceding = 6;
  int32 following = 7;
  string etag = 8;           // same as the request's etag: unchanged, no items
}
```

### Unchanged responses

Clients refresh often, and usually nothing has changed. A refresh must not send everything again.

- Every response has an `etag` (entity tag, as in HTTP). It is opaque to clients.
- A request may carry the `etag` of an earlier response to the same request. If nothing in that response would change, the server returns the same `etag` and no items and no anchors. The client sees its own `etag` come back and keeps what it has.
- An `etag` is only meaningful for the identical request. Any change in query, range, `preceding`, `following` or `limit` gives a full response.
- A server that does not check `etag`s simply always answers in full.

Recommended:

- Answer unchanged requests without reading the list: keep a change counter per list (for example per organization and item type), raised in the same transaction as every write, and build the `etag` from that counter plus a hash of the request. An unchanged counter means an unchanged response.
- Fields that change constantly, such as presence or last-seen times, raise the counter only when their meaning changes (online to offline), or are delivered another way.
- Where no counter exists, hash the built response as the `etag`. That saves transfer and client work, not server work.
- Keep an estimated `total` stable between refreshes, so small fluctuations do not cause full responses.

### Validation

- A malformed anchor or a negative `preceding`, `following`, `limit` or `at`: `INVALID_ARGUMENT`.
- An anchor from a different query, where the server can tell: `FAILED_PRECONDITION`. The client starts over.
- With tombstones, an anchor ID that is unknown or that the caller may not see: `NOT_FOUND`, the same error in both cases, so the API does not reveal whether an item exists.
- `limit` above the API's maximum is lowered to the maximum. `limit: 0` returns no items.
- `at` beyond the bottom gives an empty range at the bottom.

Recommended:

- Document the default and maximum `limit` per API. Never lower the maximum within a version.

### Deleted items and changed sort values

- A deleted bound still positions correctly (see Anchors).
- An item whose sort value changes moves to its new position. A client that reloads both positions sees it once.

Recommended:

- Clients drop duplicates by ID when two loaded parts overlap, keeping the copy from the newer response.

### Examples

The list is sorted, the screen shows about 20 rows, and `A`, `B` are anchors the server returned.

| Situation | Request | Result |
|---|---|---|
| Open the screen | `limit: 50` | items 0–49 |
| Scroll down | `range: {after: last loaded}, limit: 50` | the next 50 |
| Scroll up | `range: {from: first loaded, up_to: first loaded}, preceding: 50` | the 50 before |
| Refresh what is visible | `range: {from: A, through: B}, preceding: 20, following: 20` | A to B, plus up to 20 on each side |
| Pull to refresh | `range: {through: B}` | from the top through B |
| Jump with the scroll bar | `range: {at: 4980}, limit: 70` | items 4980–5049 |

## Future work

These list APIs are built for apps that are online: they reload what is on screen. Offline use and spotty connections need more, and will be added on top without changing the list APIs:

- **Diffs:** what changed since the client's last sync, so it can catch up without reloading. A "changed since" RPC needs a record of deletions (tombstones or a deletion log). A stateless alternative compares per-section `etag`s sent by the client.
- **Caching:** keeping loaded parts of a list on the device and updating them efficiently when the connection returns.

## Authorization

Declare every RPC in Cloud's `GateCatalog`. For Cloud, Auth and PKI boundaries,
follow the governing
[AAA Contract — Authentication, Authorization, Accounting](https://linear.app/wendylabsinc/document/aaa-contract-authentication-authorization-accounting-v024-dff5a8351650).
The guide does not replace that contract or establish new authorization policy.
