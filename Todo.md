# FlowLens — Project Todo

> Phased task list derived from [idea.md](idea.md).

---

## Phase 1 — Project Setup & Core Infrastructure

- [x] Initialize Go module (`go.mod`)
- [x] Create project directory structure (`cmd/`, `internal/`, `configs/`, `static/`)
- [x] Define the unified `Flow` struct in `internal/model/flow.go`
- [x] Create YAML config struct and loader in `internal/config/config.go`
- [x] Write default `configs/flowlens.yaml` with all config options
- [x] Write `cmd/flowlens/main.go` entry point that loads config and wires components

---

## Phase 2 — Collector (NetFlow v5)

- [x] Implement UDP listener in `internal/collector/collector.go`
- [x] Decode NetFlow v5 packets into unified `Flow` records (`netflowv5.go`)
- [x] Unit tests for NetFlow v5 decoding
- [x] Verify collector receives and parses live NetFlow v5 data

---

## Phase 3 — Storage Layer

- [x] Define `Storage` interface in `internal/storage/storage.go`
- [x] Implement fixed-capacity in-memory ring buffer (`ringbuffer.go`)
  - [x] Configurable duration / record cap
  - [x] Thread-safe read/write
- [x] Implement SQLite backend (`sqlite.go`)
  - [x] WAL mode enabled
  - [x] Insert flow records
  - [x] TTL-based pruning on a configurable schedule
- [x] Unit tests for ring buffer and SQLite storage
- [x] Wire storage into `main.go` (collector → ring buffer + SQLite)

---

## Phase 4 — Web Interface

- [x] Set up HTTP server with `net/http` in `internal/web/server.go`
- [x] Create XHTML base layout template (`templates/layout.xhtml`)
- [x] Create minimal CSS stylesheet (`static/style.css`)
- [x] **Dashboard page** (`/`)
  - [x] Total throughput (bps / pps) over last 10 minutes
  - [x] Top 10 talkers (source + destination)
  - [x] Protocol breakdown (CSS-only bar/chart)
  - [x] Active advisory count by severity
- [x] **Flow Explorer page** (`/flows`)
  - [x] Searchable, filterable table of recent flow records
  - [x] Filters: source IP, destination IP, port, protocol, time range
  - [x] Server-side pagination
- [x] Route handlers in `internal/web/handlers.go`
- [x] Wire web server into `main.go`

---

## Phase 5 — Analysis Engine

- [x] Build analysis runner with configurable interval (`internal/analysis/engine.go`)
- [x] Define advisory model with severity levels (`advisory.go`)
  - [x] CRITICAL / WARNING / INFO levels
- [x] Implement **Top Talkers** analyzer (`toptalkers.go`)
- [x] Implement **Protocol Distribution** analyzer (`protocol.go`)
- [x] Implement **Port Scan / Sweep Detector** (`scanner.go`)
- [x] Unit tests for each analyzer
- [x] **Advisories page** (`/advisories`)
  - [x] List advisories sorted by severity
  - [x] Severity badge, timestamp, description, suggested action
- [x] Wire analysis engine into `main.go`

---

## Phase 6 — Advanced Analyzers

- [x] Implement **Anomaly Detection** — baseline deviation (`anomaly.go`)
  - [x] Configurable baseline window (e.g., 7 days)
  - [x] Detect traffic spikes and drops vs. baseline
- [x] Implement **DNS Volume** analyzer
  - [x] Detect excessive DNS query rates
- [x] Implement **Flow Asymmetry** analyzer
  - [x] Detect asymmetric routing patterns
- [x] Unit tests for advanced analyzers

---

## Phase 7 — Extended Protocol Support

- [x] Implement NetFlow v9 decoder with template handling (`netflowv9.go`)
- [x] Implement IPFIX (v10) decoder with template handling (`ipfix.go`)
- [x] Unit tests for v9 and IPFIX decoding
- [x] Verify collector handles mixed v5/v9/IPFIX traffic

---

## Phase 8 — Polish & Hardening

- [x] **About / Status page** (`/about`)
  - [x] Show current config (listen ports, retention, thresholds)
  - [x] System resource usage (memory, goroutines, flow rate)
  - [x] Uptime and version info
- [x] Graceful shutdown (signal handling, drain connections)
- [x] Structured, leveled logging throughout the codebase
- [x] Resource budget enforcement
  - [x] Validate ring buffer stays within memory targets
  - [x] Cap goroutine pool for analysis workers to CPU core count
- [x] Dockerfile (multi-stage build, scratch/alpine base)
- [x] Update `README.md` with full setup and usage instructions

---

## Future Ideas (Out of Scope)

> These are noted for future consideration and are **not** part of the current roadmap.

- [ ] sFlow support
- [ ] SNMP enrichment (interface names, device hostnames)
- [ ] GeoIP mapping
- [ ] Webhook / email alerting
- [ ] LLM-powered advisory explanations
- [ ] Dark mode
- [ ] Horizontal scaling (multiple collectors → shared database)
