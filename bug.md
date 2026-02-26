# FlowLens — Bug & Issue Report

Full codebase analysis performed against the current `main` branch.  
Last updated: 2026-02-26.

---

## 1. RingBuffer `ring_buffer_duration` config partially ignored

**Severity:** Medium  
**Files:** `cmd/flowlens/main.go:46`, `internal/analysis/*.go`

The ring buffer capacity is still hardcoded at 10,000 records:

```go
// main.go:46 — hardcoded 10,000 records, no config option for capacity
ringBuf := storage.NewRingBuffer(10000)
```

Web handlers now correctly use the `ring_buffer_duration` config for their query window (e.g. `handlers.go:460–463`), but:

1. **Ring buffer capacity** has no config option and remains hardcoded. In high-flow-rate environments, 10,000 records may be consumed in seconds, giving an effective window much shorter than the configured duration.
2. **All 11 analysis modules** still hardcode `10*time.Minute` (see bug #13 below).

The web handler fix is confirmed (the dashboard uses `s.fullCfg.Storage.RingBufferDuration`), but the architectural gap between record-count capacity and time-based duration remains.

---

## 2. Nil-pointer on nil IP addresses in SQLite and web handlers

**Severity:** High  
**Files:** `internal/storage/sqlite.go:185–199`, `internal/web/handlers.go:1323`

The `SQLiteStore.Insert` method now correctly uses `model.SafeIPString()` for `SrcAddr`, `DstAddr`, and `ExporterIP`. The `matchIP` filter function now guards against nil IPs. These fixes prevent the original crash and nil key issues in the storage and web layers.

However, multiple analysis modules still call `.String()` directly on potentially nil IPs — see bug #14 below.

---

## 3. NetFlow v9 padding calculation may skip valid FlowSets

**Severity:** Low  
**File:** `internal/collector/netflowv9.go:139–141`

The decoder now correctly advances by `flowSetLen` only, with a comment documenting that RFC 3954 `flowSetLen` already includes padding:

```go
// RFC 3954: flowSetLen already includes any padding bytes for
// 4-byte alignment, so no additional padding adjustment is needed.
offset += flowSetLen
```

---

## 4. Web server serves static files from a relative path

**Severity:** Medium  
**File:** `cmd/flowlens/main.go:149–157`

The static directory is now resolved relative to the binary's location when the CWD-relative `"static"` path doesn't exist:

```go
staticDir := "static"
if _, err := os.Stat(staticDir); os.IsNotExist(err) {
    if exe, err := os.Executable(); err == nil {
        candidate := filepath.Join(filepath.Dir(exe), "static")
        if _, err := os.Stat(candidate); err == nil {
            staticDir = candidate
        }
    }
}
```

---

## 5. Templates are re-parsed on every HTTP request

**Severity:** Low  
**File:** `internal/web/server.go:62–71`

Templates are now parsed once at startup and stored on the `Server` struct:

```go
s.tmplDashboard = template.Must(template.New("layout.xhtml").Funcs(funcMap).ParseFS(templateFS, ...))
s.tmplFlows = template.Must(...)
// ... (10 templates total)
```

All handlers use the pre-parsed templates via `s.tmplXxx.ExecuteTemplate(w, "layout", data)`.

---

## 6. `RingBuffer.Recent()` assumes chronological insertion order

**Severity:** Medium  
**File:** `internal/storage/ringbuffer.go:56`

`Recent()` now uses `continue` instead of `break`, scanning all valid entries rather than short-circuiting on the first out-of-order timestamp:

```go
if f.Timestamp.Before(cutoff) {
    continue // was: break
}
```

---

## 7. Analysis engine ignores errors from `store.Recent()`

**Severity:** Low  
**Files:** `internal/analysis/*.go` (all 11 analyzers)

All analyzers now check and log errors from `store.Recent()`:

```go
flows, err := store.Recent(10*time.Minute, 0)
if err != nil {
    logging.Default().Error("TopTalkers: failed to query recent flows: %v", err)
    return nil
}
```

---

## 8. `Collector.Stop()` may leave connections in the `conns` slice

**Severity:** Low  
**File:** `internal/collector/collector.go:219–228`

`Stop()` now nils out both connection slices after closing:

```go
func (c *Collector) Stop() {
    for _, conn := range c.conns {
        conn.Close()
    }
    c.conns = nil
    for _, conn := range c.sflowConns {
        conn.Close()
    }
    c.sflowConns = nil
}
```

---

## 9. No input validation on collector config ports

**Severity:** Low  
**File:** `internal/collector/collector.go:48–56`

Port validation was added at the top of `Start()`:

```go
if c.cfg.NetFlowPort < 0 || c.cfg.NetFlowPort > 65535 {
    return fmt.Errorf("invalid NetFlow port: %d (must be 0–65535)", c.cfg.NetFlowPort)
}
// (same for IPFIXPort and SFlowPort)
```

---

## 10. Flow Explorer pagination renders all page links

**Severity:** Low  
**File:** `internal/web/handlers.go:230–252`

Pagination now uses a sliding window of 5 pages via `pageWindow()`:

```go
func pageWindow(currentPage, totalPages int) []int {
    const windowSize = 5
    // Centers 5 pages around the current page with clamping.
    ...
}
```

---

## 11. `SQLiteStore` has no connection pool limits

**Severity:** Low  
**File:** `internal/storage/sqlite.go:146`

Connection pool is now limited:

```go
// SQLite uses file-level locking; limit to one open connection to avoid
// SQLITE_BUSY errors from concurrent writers.
db.SetMaxOpenConns(1)
```

---

## 12. Graceful shutdown race condition

**Severity:** Low  
**File:** `cmd/flowlens/main.go:57–67, 179`

The flow handler now uses a `sync.WaitGroup` to track in-flight calls, and `main()` waits for them to complete before stopping the engine and web server:

```go
var handlerWg sync.WaitGroup
handler := func(flows []model.Flow) {
    handlerWg.Add(1)
    defer handlerWg.Done()
    // ...
}
// ...
coll.Stop()
handlerWg.Wait() // drain in-flight handlers before closing storage
engine.Stop()
srv.Stop()
```

---

## 13. Analysis modules hardcode 10-minute query window

**Severity:** Medium  
**Files:** `internal/analysis/toptalkers.go:29`, `scanner.go:21`, `dns.go:27`, `protocol.go:29`, `anomaly.go:36,48`, `retransmission.go:38`, `asymmetry.go:53`, `portconcentration.go:25`, `unreachable.go:28`, `newtalker.go:32`, `voip.go:27`

All 11 analysis modules still hardcode `10*time.Minute` for their `store.Recent()` calls:

```go
flows, err := store.Recent(10*time.Minute, 0)
```

The web handlers were fixed (bug #1) to use `s.fullCfg.Storage.RingBufferDuration`, but the `Analyzer` interface only receives `config.AnalysisConfig`, which doesn't include the ring buffer duration (that lives in `config.StorageConfig`). There's no way for analyzers to access the configured window without changing the `Analyzer` interface or `AnalysisConfig` struct.

If a user sets `ring_buffer_duration: 30m`, the dashboard shows 30 minutes of data, but all analysis modules still only examine the most recent 10 minutes.

---

## 14. Analysis modules use `.String()` on potentially nil IP addresses

**Severity:** Medium  
**Files:** `internal/analysis/toptalkers.go:43,139`, `scanner.go:43-44`, `retransmission.go:87-88,174-175`, `asymmetry.go:66-67`, `portconcentration.go:53,59`, `unreachable.go:57,64`

Bug #2 fixed nil IP handling in `SQLiteStore.Insert` and `matchIP`, but multiple analysis modules still call `.String()` directly on `f.SrcAddr` / `f.DstAddr` without using `model.SafeIPString()`:

```go
// toptalkers.go:43
src := f.SrcAddr.String()  // returns "<nil>" if SrcAddr is nil

// scanner.go:43-44
src := f.SrcAddr.String()
key := scanKey{DstIP: f.DstAddr.String(), DstPort: f.DstPort}
```

When a flow has nil IPs (e.g. from an IPFIX template missing IP address fields), these produce `"<nil>"` keys in aggregation maps, leading to:
- Corrupted top-talker reports with a `"<nil>"` host entry
- False port scan detections attributed to `"<nil>"`
- Incorrect asymmetry, unreachable, and retransmission analysis

The affected analyzers are: `TopTalkers`, `BuildTopTalkersReport`, `ScanDetector`, `RetransmissionDetector` (both counter and heuristic paths), `FlowAsymmetry`, `PortConcentrationDetector`, and `UnreachableDetector`.

---

## 15. sFlow decoder drops L2 metadata from Ethernet headers

**Severity:** Low  
**Files:** `internal/collector/sflow.go:265–289`

`decodeSFlowEthernet()` parses the Ethernet header but does not extract MAC addresses, VLAN IDs, or EtherType — the decoded `Flow` is missing all L2 fields:

```go
// sflow.go:265-289 — etherType is parsed for protocol dispatch but not stored
func decodeSFlowEthernet(data []byte, ts time.Time, frameLength uint32) (model.Flow, bool) {
    etherType := uint16(data[12])<<8 | uint16(data[13])
    offset := 14
    if etherType == 0x8100 {
        // VLAN tag is skipped — VLAN ID is not extracted
        etherType = uint16(data[16])<<8 | uint16(data[17])
        offset = 18
    }
    // MAC addresses (data[0:6] dst, data[6:12] src) are never read
    // ...
}
```

Compare with the direct capture path (`capture.go:66–107`) which correctly populates `SrcMAC`, `DstMAC`, `VLAN`, and `EtherType`. The sFlow path produces flows with empty L2 fields, so the `/vlans` and `/macs` pages will not show any data from sFlow-sourced flows.

---

## 16. Extra collectors from `interfaces` config are never stopped

**Severity:** Medium  
**File:** `cmd/flowlens/main.go:91–115`

When additional NetFlow/IPFIX collectors are created from the `interfaces` config, they are not tracked for shutdown:

```go
case "netflow", "":
    if ifCfg.Listen != "" {
        extraCfg := cfg.Collector
        // ...
        extraColl := collector.New(extraCfg, handler) // local variable
        go func(name string) {
            if err := extraColl.Start(); err != nil { ... }
        }(ifCfg.Name)
    }
```

The `extraColl` variable is scoped inside the loop body and never stored. During shutdown (main.go:174), only the primary `coll` is stopped — extra collectors' goroutines and UDP connections leak. This means:
- UDP ports remain bound until the process exits
- The flow handler `WaitGroup` may never reach zero if an in-flight handler call races with the `handlerWg.Wait()` call
- The goroutines running `readLoop` keep allocating buffers until process termination

---

## 17. CSV report export doesn't escape special characters

**Severity:** Low  
**File:** `internal/web/handlers.go:1694–1698`

The CSV export writes `GroupKey` values directly without RFC 4180 escaping:

```go
fmt.Fprintf(w, "%s,%d,%d,%d,%.1f\n",
    row.GroupKey, row.TotalBytes, row.TotalPackets, row.FlowCount, row.AvgBytes)
```

If a `GroupKey` contains commas, double quotes, or newlines (unlikely for most group-by columns like `protocol` or `dst_port`, but possible for `src_addr` in edge cases or future group-by options), the CSV output will be malformed. The `encoding/csv` package should be used instead for proper escaping.

---

## 18. `handleCaptureStart` doesn't validate device against allowed interfaces

**Severity:** Medium  
**File:** `internal/web/handlers.go:1848–1856`

The capture start handler accepts any device name from the form input without checking it against the configured `capture.interfaces` list:

```go
device := r.FormValue("device")
bpf := r.FormValue("bpf")
if device == "" {
    http.Error(w, "Device is required", http.StatusBadRequest)
    return
}
_, err := s.captureMgr.Start(device, bpf)
```

A user (or attacker with access to the web UI) could request capture on any network interface the process has access to, not just the ones configured in `capture.interfaces`. While kernel permissions limit the actual risk, the application should validate the device against `s.captureMgr.Interfaces()` before starting a capture.

---

## Summary

| # | Issue | Severity | Category | Status |
|---|-------|----------|----------|--------|
| 1 | `ring_buffer_duration` config partially ignored | Medium | Config | ⚠️ Partially Fixed |
| 2 | Nil-pointer on nil IP addresses (SQLite + web) | High | Crash | ✅ Fixed |
| 3 | NFv9 FlowSet padding over-skip | Low | Protocol | ✅ Fixed |
| 4 | Relative static file path | Medium | Deployment | ✅ Fixed |
| 5 | Templates re-parsed every request | Low | Performance | ✅ Fixed |
| 6 | RingBuffer early-break on out-of-order data | Medium | Correctness | ✅ Fixed |
| 7 | Analyzer errors silently discarded | Low | Error handling | ✅ Fixed |
| 8 | `Stop()` doesn't reset `conns` slice | Low | Lifecycle | ✅ Fixed |
| 9 | No port range validation | Low | Config | ✅ Fixed |
| 10 | Pagination renders all page links | Low | UI/UX | ✅ Fixed |
| 11 | No SQLite connection pool limits | Low | Database | ✅ Fixed |
| 12 | Shutdown race condition | Low | Concurrency | ✅ Fixed |
| 13 | Analysis modules hardcode 10-min window | Medium | Config | ❌ Open |
| 14 | Analysis modules nil-unsafe IP `.String()` calls | Medium | Correctness | ❌ Open |
| 15 | sFlow decoder drops L2 metadata | Low | Protocol | ❌ Open |
| 16 | Extra collectors never stopped on shutdown | Medium | Lifecycle | ❌ Open |
| 17 | CSV export doesn't escape special chars | Low | Data Export | ❌ Open |
| 18 | Capture start doesn't validate device name | Medium | Security | ❌ Open |
