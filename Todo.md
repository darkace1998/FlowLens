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

- [ ] Implement UDP listener in `internal/collector/collector.go`
- [ ] Decode NetFlow v5 packets into unified `Flow` records (`netflowv5.go`)
- [ ] Unit tests for NetFlow v5 decoding
- [ ] Verify collector receives and parses live NetFlow v5 data

---

## Phase 3 — Storage Layer

- [ ] Define `Storage` interface in `internal/storage/storage.go`
- [ ] Implement fixed-capacity in-memory ring buffer (`ringbuffer.go`)
  - [ ] Configurable duration / record cap
  - [ ] Thread-safe read/write
- [ ] Implement SQLite backend (`sqlite.go`)
  - [ ] WAL mode enabled
  - [ ] Insert flow records
  - [ ] TTL-based pruning on a configurable schedule
- [ ] Unit tests for ring buffer and SQLite storage
- [ ] Wire storage into `main.go` (collector → ring buffer + SQLite)

---

## Phase 4 — Web Interface

- [ ] Set up HTTP server with `net/http` in `internal/web/server.go`
- [ ] Create XHTML base layout template (`templates/layout.xhtml`)
- [ ] Create minimal CSS stylesheet (`static/style.css`)
- [ ] **Dashboard page** (`/`)
  - [ ] Total throughput (bps / pps) over last 10 minutes
  - [ ] Top 10 talkers (source + destination)
  - [ ] Protocol breakdown (CSS-only bar/chart)
  - [ ] Active advisory count by severity
- [ ] **Flow Explorer page** (`/flows`)
  - [ ] Searchable, filterable table of recent flow records
  - [ ] Filters: source IP, destination IP, port, protocol, time range
  - [ ] Server-side pagination
- [ ] Route handlers in `internal/web/handlers.go`
- [ ] Wire web server into `main.go`

---

## Phase 5 — Analysis Engine

- [ ] Build analysis runner with configurable interval (`internal/analysis/engine.go`)
- [ ] Define advisory model with severity levels (`advisory.go`)
  - [ ] CRITICAL / WARNING / INFO levels
- [ ] Implement **Top Talkers** analyzer (`toptalkers.go`)
- [ ] Implement **Protocol Distribution** analyzer (`protocol.go`)
- [ ] Implement **Port Scan / Sweep Detector** (`scanner.go`)
- [ ] Unit tests for each analyzer
- [ ] **Advisories page** (`/advisories`)
  - [ ] List advisories sorted by severity
  - [ ] Severity badge, timestamp, description, suggested action
- [ ] Wire analysis engine into `main.go`

---

## Phase 6 — Advanced Analyzers

- [ ] Implement **Anomaly Detection** — baseline deviation (`anomaly.go`)
  - [ ] Configurable baseline window (e.g., 7 days)
  - [ ] Detect traffic spikes and drops vs. baseline
- [ ] Implement **DNS Volume** analyzer
  - [ ] Detect excessive DNS query rates
- [ ] Implement **Flow Asymmetry** analyzer
  - [ ] Detect asymmetric routing patterns
- [ ] Unit tests for advanced analyzers

---

## Phase 7 — Extended Protocol Support

- [ ] Implement NetFlow v9 decoder with template handling (`netflowv9.go`)
- [ ] Implement IPFIX (v10) decoder with template handling (`ipfix.go`)
- [ ] Unit tests for v9 and IPFIX decoding
- [ ] Verify collector handles mixed v5/v9/IPFIX traffic

---

## Phase 8 — Polish & Hardening

- [ ] **About / Status page** (`/about`)
  - [ ] Show current config (listen ports, retention, thresholds)
  - [ ] System resource usage (memory, goroutines, flow rate)
  - [ ] Uptime and version info
- [ ] Graceful shutdown (signal handling, drain connections)
- [ ] Structured, leveled logging throughout the codebase
- [ ] Resource budget enforcement
  - [ ] Validate ring buffer stays within memory targets
  - [ ] Cap goroutine pool for analysis workers to CPU core count
- [ ] Dockerfile (multi-stage build, scratch/alpine base)
- [ ] Update `README.md` with full setup and usage instructions

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
