# Copilot Instructions for FlowLens

## Build, test, and lint commands

Use the same commands CI uses unless you need a narrower target:

```bash
# Build binary
go build -o flowlens ./cmd/flowlens/

# Run with default config
./flowlens

# Run with explicit config file
./flowlens configs/flowlens.yaml

# Full test suite (fast local)
go test ./...

# CI-equivalent test run
go test -race -count=1 -coverprofile=coverage.out ./...

# Run one package
go test ./internal/collector -count=1

# Run one test
go test ./internal/collector -run '^TestDecodeIPFIX_TemplateAndData$' -count=1

# Linting
go vet ./...
golangci-lint run
```

## High-level architecture

FlowLens is a single-process pipeline wired in `cmd/flowlens/main.go`:

1. `internal/collector` listens on UDP (NetFlow v5/v9, IPFIX, sFlow), decodes records, and emits unified `model.Flow` objects.
2. The collector callback fans out each flow batch to **both** storages:
   - `internal/storage/ringbuffer.go` for short-window, in-memory reads used by most pages/APIs.
   - `internal/storage/sqlite.go` for persisted history, pruning, and report/time-series queries.
3. `internal/analysis/engine.go` runs analyzers on a schedule against the ring buffer and maintains advisory history (active/resolved).
4. `internal/web/server.go` serves XHTML templates and JSON APIs, using:
   - `FlowService` (ring buffer) for real-time endpoints.
   - `ReportService` (SQLite) for historical reports.
   - middleware chain: recovery → request logging → timeout → CSP → basic auth (with `/healthz` exempted).

Data model center: `internal/model/flow.go` is the shared contract across decoders, storage, analysis, and web rendering.

## Key conventions in this repo

- **Decoder output convention:** protocol decoders call `f.Classify()` before appending flows (`internal/collector/*`), so app/category/throughput fields are populated at ingest time.
- **Variable-length counter parsing:** decoders use `readUintN` for flow counter fields instead of assuming fixed widths.
- **Ring vs SQLite responsibility split:** do not move dashboard/flows/hosts/session queries to SQLite; only report-style historical aggregations should use `SQLiteStore` query methods.
- **Advisory identity rule:** advisory lifecycle in `analysis.Engine` is keyed by `Advisory.Title`. New analyzer titles must be stable/deterministic so resolution tracking works correctly.
- **Web error handling:** handlers use `httpError(...)` from `internal/web/middleware.go` for consistent logging + HTTP responses.
- **Flow stitching before presentation:** handlers/APIs that expose RTT/throughput/session semantics call `model.StitchFlows(...)` before aggregation/rendering.
- **State-changing routes require CSRF protection:** register POST handlers through `csrf.csrfProtect(...)` and include `{{csrfToken}}` in forms.
- **Template/static layout:** templates are embedded from `internal/web/templates/*.xhtml`; static assets are embedded from `internal/web/static` (with optional on-disk override in development).
- **Config defaults source of truth:** if adding a config key, update `internal/config/config.go` defaults and `configs/flowlens.yaml` docs together.
