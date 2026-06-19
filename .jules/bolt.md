
## 2024-05-18 - Optimize buildMapData IP Processing
**Learning:** Using `net.IP.String()` inside a tight loop parsing network flows causes substantial string allocation overhead and performance degradation (GC pressure, CPU usage). Converting the `net.IP` representation to a `[16]byte` fixed array avoids allocation, allows using the array as a map key directly, and defers string formatting until necessary.
**Action:** When grouping or caching flows by IP, consider casting IP byte slices to fixed-sized byte arrays (`[16]byte` via `To16()`) for map keys instead of using standard string conversion.
## 2026-06-19 - Fixed-size byte array map keys for IP addresses

**Learning:** When using `net.IP` (which is a `[]byte` slice) as a map key in a hot loop (like per-flow processing), calling `ip.String()` or relying on `fmt.Sprintf` causes significant heap allocations (allocating a new string per IP per flow). Even `net.IP.To16()` will allocate a new slice if the IP is 4 bytes.

**Action:** Convert `net.IP` manually to a fixed size `[16]byte` stack-allocated array for map keys in performance-critical code paths. To reconstruct the string later outside the hot loop, slice the array back to `[]byte` and call `net.IP(arr[:]).String()`.
