
## 2024-05-18 - Optimize buildMapData IP Processing
**Learning:** Using `net.IP.String()` inside a tight loop parsing network flows causes substantial string allocation overhead and performance degradation (GC pressure, CPU usage). Converting the `net.IP` representation to a `[16]byte` fixed array avoids allocation, allows using the array as a map key directly, and defers string formatting until necessary.
**Action:** When grouping or caching flows by IP, consider casting IP byte slices to fixed-sized byte arrays (`[16]byte` via `To16()`) for map keys instead of using standard string conversion.

## 2024-05-18 - Optimized SQLite Flow Batch Insert Parameter Allocations
**Learning:** In modernc.org/sqlite, bulk dynamic string-based batch inserts (e.g. creating string queries like `INSERT INTO flows VALUES (?), (?)`) can be slower than simply iterating over flows and running `stmt.Exec(args...)` using a prepared statement, due to overhead in string concatenation and statement preparation on large queries.
**Action:** The most effective optimization without modifying the API signature was preallocating the `args` array outside the loop as `make([]interface{}, 29)` and populating its elements manually via indexed assignments inside the loop with `f := &flows[i]` to avoid pointer indirection / struct copying overheads, leading to ~6% CPU time reduction and minimizing GC overhead from 28k allocs to practically minimal allocs inside the loop body.
