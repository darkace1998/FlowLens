# FlowLens — Bug & Issue Report

Full codebase analysis performed against the current `main` branch.  
Last updated: 2026-02-26.

---

## 1. RingBuffer `ring_buffer_duration` config partially ignored

**Severity:** Medium  
**Files:** `cmd/flowlens/main.go:46`, `internal/analysis/*.go`

**Fixed:** Added `ring_buffer_capacity` config option to `StorageConfig` (default: 10000). `main.go` now reads `cfg.Storage.RingBufferCapacity` instead of hardcoding 10000. Added `query_window` to `AnalysisConfig` which defaults to `ring_buffer_duration` — all 11 analysis modules now use `queryWindow(cfg)` instead of `10*time.Minute`.

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

**Fixed:** Added `QueryWindow` field to `config.AnalysisConfig`. Added `queryWindow(cfg)` helper in `engine.go` that returns `cfg.QueryWindow` (falling back to 10 min). All 11 analyzers now call `store.Recent(queryWindow(cfg), 0)`. In `main.go`, `cfg.Analysis.QueryWindow` is auto-set from `cfg.Storage.RingBufferDuration` when not explicitly configured.

---

## 14. Analysis modules use `.String()` on potentially nil IP addresses

**Severity:** Medium  
**Files:** `internal/analysis/toptalkers.go:43,139`, `scanner.go:43-44`, `retransmission.go:87-88,174-175`, `asymmetry.go:66-67`, `portconcentration.go:53,59`, `unreachable.go:57,64`

**Fixed:** All `.String()` calls on `f.SrcAddr` and `f.DstAddr` in analysis modules replaced with `model.SafeIPString()`. Affected: `TopTalkers`, `BuildTopTalkersReport`, `ScanDetector`, `RetransmissionDetector` (both counter and heuristic paths), `FlowAsymmetry`, `PortConcentrationDetector`, `UnreachableDetector`, and `NewTalkerDetector`.

---

## 15. sFlow decoder drops L2 metadata from Ethernet headers

**Severity:** Low  
**Files:** `internal/collector/sflow.go:265–289`

**Fixed:** `decodeSFlowEthernet()` now extracts MAC addresses (`data[0:6]` dst, `data[6:12]` src), VLAN ID (from 802.1Q tag `& 0x0FFF`), and EtherType, storing them in the decoded `Flow`. Matches the pattern used in `capture.go:66–107`.

---

## 16. Extra collectors from `interfaces` config are never stopped

**Severity:** Medium  
**File:** `cmd/flowlens/main.go:91–115`

**Fixed:** Extra collectors are now tracked in an `extraCollectors` slice and stopped during shutdown alongside the primary collector, before `handlerWg.Wait()`.

---

## 17. CSV report export doesn't escape special characters

**Severity:** Low  
**File:** `internal/web/handlers.go:1694–1698`

**Fixed:** CSV export now uses `encoding/csv.Writer` for proper RFC 4180 escaping instead of raw `fmt.Fprintf`.

---

## 18. `handleCaptureStart` doesn't validate device against allowed interfaces

**Severity:** Medium  
**File:** `internal/web/handlers.go:1848–1856`

**Fixed:** `handleCaptureStart` now validates the requested device against `s.captureMgr.Interfaces()`. If the allowed interfaces list is non-empty and the device is not in it, a 403 Forbidden response is returned.

---

## Summary

| # | Issue | Severity | Category | Status |
|---|-------|----------|----------|--------|
| 1 | `ring_buffer_duration` config partially ignored | Medium | Config | ✅ Fixed |
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
| 13 | Analysis modules hardcode 10-min window | Medium | Config | ✅ Fixed |
| 14 | Analysis modules nil-unsafe IP `.String()` calls | Medium | Correctness | ✅ Fixed |
| 15 | sFlow decoder drops L2 metadata | Low | Protocol | ✅ Fixed |
| 16 | Extra collectors never stopped on shutdown | Medium | Lifecycle | ✅ Fixed |
| 17 | CSV export doesn't escape special chars | Low | Data Export | ✅ Fixed |
| 18 | Capture start doesn't validate device name | Medium | Security | ✅ Fixed |
