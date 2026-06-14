## 2026-06-14 - Map Lookup Cache

**Learning:** When attempting to cache expensive lookups inside a loop, ensure that the iteration actually contains duplicate keys. In `internal/web/handlers.go`, iterating over the `hostBytes` map means every IP is strictly unique. Caching locally per-request for unique elements only adds map initialization and map lookup overhead, ultimately hurting performance rather than improving it.

**Action:** Before optimizing a loop with a local cache, verify the distribution of elements inside that loop allows for cache hits. If iterating over a map, a local cache mapping the exact same keys is inherently redundant.
