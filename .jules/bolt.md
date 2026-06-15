## 2026-06-14 - Cache GeoIP lookups during flow iteration

**Learning:** `geoLookup.Find(ip)` involves a binary search on IP ranges. When displaying flows in the UI (`handleFlows`), resolving the same source/destination IPs repeatedly adds unnecessary computational overhead.
**Action:** When iterating through lists of flows, always initialize a `map[string]string` cache locally to store previously resolved geo information (like `.Country`) to reduce `O(log N)` lookups to `O(1)`.
