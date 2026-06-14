
## 2024-05-18 - Optimize buildMapData IP Processing
**Learning:** Using `net.IP.String()` inside a tight loop parsing network flows causes substantial string allocation overhead and performance degradation (GC pressure, CPU usage). Converting the `net.IP` representation to a `[16]byte` fixed array avoids allocation, allows using the array as a map key directly, and defers string formatting until necessary.
**Action:** When grouping or caching flows by IP, consider casting IP byte slices to fixed-sized byte arrays (`[16]byte` via `To16()`) for map keys instead of using standard string conversion.
