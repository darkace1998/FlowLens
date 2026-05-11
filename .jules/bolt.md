## 2023-11-09 - Avoid net.IP string allocations in tight loops
**Learning:** In Go, converting `net.IP` to string using `.String()` or implicit formatting in hot loops (like processing flows) creates a huge amount of short-lived allocations.
**Action:** When using IP addresses as map keys for correlation/aggregation in hot paths, convert them to fixed-size `[16]byte` arrays instead of strings.
