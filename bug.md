# FlowLens — Bug & Issue Report

Full codebase analysis performed against the current `main` branch plus the dual-port collector fix.

---

## 1. RingBuffer `ring_buffer_duration` config is ignored

**Severity:** Medium  
**File:** `cmd/flowlens/main.go:41`, `internal/config/config.go:28`

The config has a `ring_buffer_duration` setting (default 10 min), but `NewRingBuffer` only takes a `capacity` (number of records). The duration from config is never passed to the ring buffer:

```go
// main.go:41 — hardcoded 10,000 records, duration config ignored
ringBuf := storage.NewRingBuffer(10000)
```

Additionally, the dashboard and flow explorer both hardcode a 10-minute window:

```go
// handlers.go:177
flows, err := s.ringBuf.Recent(10*time.Minute, 0)

// handlers.go:333
allFlows, err := s.ringBuf.Recent(10*time.Minute, 0)
```

The `ring_buffer_duration` config value has no effect anywhere — neither on the ring buffer size nor on the query window.

---

## 2. Nil-pointer panic on flows with nil SrcAddr or DstAddr

**Severity:** High  
**Files:** `internal/web/handlers.go:209,219`, `internal/analysis/toptalkers.go:39`, `internal/analysis/scanner.go:39`, and many others

If a decoded flow has a `nil` `SrcAddr` or `DstAddr` (e.g. the template didn't include an IP address field), calling `.String()` on a nil `net.IP` returns `"<nil>"`. While this won't panic, it will produce misleading dashboard entries and corrupt aggregation maps with a `"<nil>"` key. The `matchIP` filter function also doesn't guard against nil IPs.

More critically, in `SQLiteStore.Insert`, calling `f.SrcAddr.String()` or `f.ExporterIP.String()` on a nil IP **will panic**:

```go
// sqlite.go:105-106
f.SrcAddr.String(), // panics if SrcAddr is nil
f.DstAddr.String(), // panics if DstAddr is nil
```

This can happen with NetFlow v9/IPFIX templates that omit IP address fields.

---

## 3. NetFlow v9 padding calculation may skip valid FlowSets

**Severity:** Low  
**File:** `internal/collector/netflowv9.go:136-138`

After processing each FlowSet, the decoder aligns to a 4-byte boundary:

```go
offset += flowSetLen
if offset%4 != 0 {
    offset += 4 - (offset % 4)
}
```

However, according to RFC 3954, the `flowSetLen` field already includes any padding bytes needed for 4-byte alignment. This means the code may over-skip bytes when `flowSetLen` is already properly aligned but the manual padding calculation adds extra bytes. In practice this rarely causes issues because most implementations align FlowSet lengths, but it deviates from the RFC.

---

## 4. Web server serves static files from a relative path

**Severity:** Medium  
**File:** `cmd/flowlens/main.go:84`

```go
srv := web.NewServer(cfg.Web, ringBuf, sqlStore, "static", engine)
```

The static directory is hardcoded as a relative path `"static"`. If the binary is run from a different working directory, the static files (CSS) won't be found, and the web UI will render without styles. The Dockerfile handles this by setting `WORKDIR /app`, but running the binary directly from a different directory will break styling.

---

## 5. Templates are re-parsed on every HTTP request

**Severity:** Low  
**File:** `internal/web/handlers.go:186-191,388-393,472-477,546-551`

Every dashboard, flows, advisories, and about request re-parses templates from the embedded filesystem:

```go
tmpl, err := template.New("layout.xhtml").Funcs(funcMap).ParseFS(templateFS, ...)
```

While the templates are embedded (so no disk I/O), parsing and compiling templates on every request wastes CPU. Templates should be parsed once at server startup and reused.

---

## 6. `RingBuffer.Recent()` assumes chronological insertion order

**Severity:** Medium  
**File:** `internal/storage/ringbuffer.go:52-66`

`Recent()` walks backwards from the head and **breaks** as soon as it finds a flow with a timestamp before the cutoff:

```go
if f.Timestamp.Before(cutoff) {
    break  // stops scanning entirely
}
```

If flows arrive out of chronological order (e.g., delayed NetFlow exports, template-cached v9 records decoded later), this early-break may miss valid recent flows that were inserted earlier in the buffer but have more recent timestamps. The ring buffer is insertion-ordered, not timestamp-ordered, so the early-break optimization is incorrect for out-of-order data.

---

## 7. Analysis engine ignores errors from `store.Recent()`

**Severity:** Low  
**Files:** `internal/analysis/toptalkers.go:28`, `scanner.go:20`, `protocol.go:29`, `anomaly.go:35`, `dns.go:26`, `asymmetry.go:53`, `retransmission.go:28`, `unreachable.go:28`, `newtalker.go:31`, `portconcentration.go:25`

Every analyzer discards the error from `store.Recent()`:

```go
flows, _ := store.Recent(10*time.Minute, 0)
```

While `RingBuffer.Recent()` currently always returns nil error, the `Storage` interface contract allows errors. If the storage backend changes (or a future refactor introduces error conditions), these silent drops would mask failures.

---

## 8. `Collector.Stop()` may leave connections in the `conns` slice

**Severity:** Low  
**File:** `internal/collector/collector.go:137-141`

`Stop()` closes all connections but doesn't nil out the `conns` slice. If `Start()` is called again on the same `Collector` instance, the old (closed) connections would still be in the slice, and new connections would be appended. While re-starting a collector is unlikely in normal usage, it could cause issues in tests or edge cases.

---

## 9. No input validation on collector config ports

**Severity:** Low  
**File:** `internal/collector/collector.go:40-44`

The collector doesn't validate that port numbers are in the valid range (1–65535). A config with `netflow_port: 0` would cause the OS to assign a random port (useful for tests, but surprising in production). Negative or >65535 values would cause a runtime error from `net.ListenUDP`.

---

## 10. Flow Explorer pagination renders all page links

**Severity:** Low  
**File:** `internal/web/templates/flows.xhtml:55-61`

The pagination template renders a link for every page:

```html
{{range seq 1 .TotalPages}}
```

With a large number of flows and a small page size, this could render thousands of page links, making the UI unusable. A sliding window (e.g., show 5 pages around the current page) would be more practical.

---

## 11. `SQLiteStore` has no connection pool limits

**Severity:** Low  
**File:** `internal/storage/sqlite.go:29`

The SQLite connection is opened with `sql.Open()` without setting `MaxOpenConns` or `MaxIdleConns`. For SQLite (which uses file-level locking), having multiple concurrent connections can cause `SQLITE_BUSY` errors. Setting `db.SetMaxOpenConns(1)` is a common best practice for SQLite.

---

## 12. Graceful shutdown race condition

**Severity:** Low  
**File:** `cmd/flowlens/main.go:99-106`

During shutdown, `coll.Stop()` is called first (which closes UDP connections), then `engine.Stop()`, then `srv.Stop()`. However, the collector's flow handler writes to both `ringBuf` and `sqlStore`. If a flow is being processed while shutdown begins, the handler could attempt to write to storage after `srv.Stop()` returns but before the function exits. There's no synchronization to ensure in-flight flow handler calls complete before storage is closed.

---

## Summary

| # | Issue | Severity | Category | Status |
|---|-------|----------|----------|--------|
| 1 | `ring_buffer_duration` config ignored | Medium | Config | ✅ Fixed |
| 2 | Nil-pointer panic on nil IP addresses | High | Crash | ✅ Fixed |
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
