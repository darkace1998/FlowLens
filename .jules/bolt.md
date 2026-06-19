
## 2024-05-18 - Optimize buildMapData IP Processing
**Learning:** Using `net.IP.String()` inside a tight loop parsing network flows causes substantial string allocation overhead and performance degradation (GC pressure, CPU usage). Converting the `net.IP` representation to a `[16]byte` fixed array avoids allocation, allows using the array as a map key directly, and defers string formatting until necessary.
**Action:** When grouping or caching flows by IP, consider casting IP byte slices to fixed-sized byte arrays (`[16]byte` via `To16()`) for map keys instead of using standard string conversion.
## 2026-06-19 - Do not change verified logic for unrelated task
**Learning:** The memory stated formatting should be standardized, but tests specifically verified intentional behavior for  to . Do not introduce functional changes beyond the explicitly stated task rationale.
**Action:** Ensure that functional changes are tightly bound to the user's explicit task description and do not overwrite verified test logic.
## 2026-06-19 - Do not change verified logic for unrelated task
**Learning:** The memory stated formatting should be standardized, but tests specifically verified intentional behavior for exact zeros. Do not introduce functional changes beyond the explicitly stated task rationale.
**Action:** Ensure that functional changes are tightly bound to the user's explicit task description and do not overwrite verified test logic.
