# FlowLens — Project TODO

> Deep-dive roadmap generated from a full code audit.
> Items are grouped by subsystem and ranked **P0** (critical) → **P3** (nice-to-have).

---

## Table of Contents

1. [Collector — Protocol & Ingestion](#1-collector--protocol--ingestion)
2. [Storage — Ring Buffer & SQLite](#2-storage--ring-buffer--sqlite)
3. [Analysis Engine & Advisories](#3-analysis-engine--advisories)
4. [Web Interface & Dashboard](#4-web-interface--dashboard)
5. [REST / Programmatic API](#5-rest--programmatic-api)
6. [Model & Flow Processing](#6-model--flow-processing)
7. [Packet Capture (Mirror / TAP)](#7-packet-capture-mirror--tap)
8. [GeoIP & Enrichment](#8-geoip--enrichment)
9. [Configuration & Operations](#9-configuration--operations)
10. [Security & Hardening](#10-security--hardening)
11. [Testing & CI/CD](#11-testing--cicd)
12. [Documentation](#12-documentation)
13. [Performance & Scalability](#13-performance--scalability)

---

## 1. Collector — Protocol & Ingestion

### Currently Implemented
- [x] NetFlow v5 decoder (fixed 48-byte records, sysUptime timestamps)
- [x] NetFlow v9 decoder (template-based, cached by sourceID + templateID)
- [x] IPFIX / v10 decoder (template-based, variable-length fields, enterprise elements skipped)
- [x] sFlow v5 decoder (standard + expanded flow/counter samples, raw Ethernet header parsing)
- [x] UDP multi-listener architecture (separate ports for NetFlow/IPFIX and sFlow)
- [x] Auto-detection of protocol version from first two bytes
- [x] Template caching with RWMutex thread safety
- [x] TCP quality metrics extraction (IPFIX IEs 321, 227, 233, 387)
- [x] L2 field extraction (MAC addresses IE 56/80, VLAN IE 58, EtherType)
- [x] Additional collector instances from config (`interfaces` list)

### TODO
- [ ] **P0** — Add template cache TTL / expiration (stale templates can cause silent data corruption)
- [ ] **P1** — Support IPFIX Options Templates (v9 / IPFIX) for sampler-table and interface-name resolution
- [ ] **P1** — Account for sampling rate in NetFlow v5 header (currently ignored — byte/packet counts may be under-reported)
- [ ] **P1** — Track and expose ingestion metrics (packets received, decoded, errors, drops per protocol)
- [ ] **P2** — Handle IPFIX variable-length fields > 254 bytes (3-byte length encoding per RFC 7011 §7)
- [ ] **P2** — Parse enterprise-specific Information Elements instead of silently skipping them
- [ ] **P2** — sFlow: decode inner GRE / MPLS / VXLAN tunnel headers for encapsulated traffic
- [ ] **P2** — sFlow: use agent sysUptime for timestamps instead of `time.Now()` (clock-skew resilient)
- [ ] **P2** — sFlow: extract and expose counter-sample data (interface utilization, error counts)
- [ ] **P3** — Extract IPv6 flow label from v9 / IPFIX
- [ ] **P3** — Implement NetFlow v1 support (legacy Cisco devices)
- [ ] **P3** — Support IPFIX SCTP transport (RFC 7011 §10)

---

## 2. Storage — Ring Buffer & SQLite

### Currently Implemented
- [x] In-memory ring buffer with configurable capacity (`ring_buffer_capacity`)
- [x] RWMutex-protected concurrent reads/writes
- [x] `Recent(duration, limit)` queries walking backward from head
- [x] SQLite persistent store with WAL mode and auto-migration for new columns
- [x] Background pruning loop (configurable interval + retention TTL)
- [x] 29-column schema covering 5-tuple, counters, L2, quality metrics
- [x] `QueryReport()` for grouped aggregation (by app_proto, country, port, AS, etc.)
- [x] `QueryTimeSeries()` for bucketed time-series data
- [x] Dual fan-out handler writing each flow to both ring buffer and SQLite

### TODO
- [ ] **P0** — Add composite SQLite indexes (`src_addr, timestamp`; `dst_addr, timestamp`; `protocol, timestamp`) — current single index on `timestamp` is insufficient for filtered queries
- [ ] **P1** — Connection pooling or write batching for SQLite (single `SetMaxOpenConns(1)` serializes all writes — bottleneck above ~10K flows/sec)
- [ ] **P1** — Ring buffer snapshot / persistence — crash loses all in-memory data
- [ ] **P2** — Expose storage metrics (inserts/sec, query latency, buffer utilization %)
- [ ] **P2** — Add hot/cold storage tiering — compress and archive old SQLite data beyond retention window
- [ ] **P2** — Support alternative backends (PostgreSQL, ClickHouse) for high-volume deployments
- [ ] **P3** — Add flow deduplication at the storage layer (same 5-tuple + timestamp within window)
- [ ] **P3** — VACUUM / ANALYZE scheduling for SQLite health

---

## 3. Analysis Engine & Advisories

### Currently Implemented
- [x] Engine runs registered analyzers on configurable interval (default 60 s)
- [x] Advisory deduplication (active title tracking prevents re-reporting)
- [x] Advisory auto-resolution (advisories marked resolved when issue stops appearing)
- [x] Severity levels: INFO → WARNING → CRITICAL
- [x] Rolling advisory history (max 100 entries, sorted: active before resolved, severity, time)
- [x] Configurable `QueryWindow` via `AnalysisConfig` (defaults to 10 min)
- [x] 12 analyzer modules:
  - [x] TopTalkers (>25% bandwidth → WARNING, >50% → CRITICAL)
  - [x] ScanDetector (>500 unique dst ports → WARNING, >1500 → CRITICAL)
  - [x] DNSVolume (>100 flows/min or >30% ratio)
  - [x] ProtocolDistribution (non-TCP/UDP/ICMP >5%, ICMP >10%)
  - [x] AnomalyDetector (statistical: mean ± 2σ spike, mean/4 drop)
  - [x] RetransmissionDetector (≥1% retransmission rate, heuristic fallback)
  - [x] FlowAsymmetry (≥10:1 byte ratio, ≥100 KB threshold)
  - [x] PortConcentration (≥20 unique sources per dst port)
  - [x] UnreachableDetector (≥20 tiny flows, ≥70% tiny ratio)
  - [x] NewTalkerDetector (new IPs > 10 KB in recent window)
  - [x] VoIPQuality (MOS < 3.5 WARNING, < 3.0 CRITICAL)

### TODO
- [ ] **P1** — Make all hardcoded thresholds configurable via YAML (currently only `scan_threshold` and `top_talkers_count` are configurable; the remaining ~20 thresholds are hardcoded constants)
- [ ] **P1** — Add a lateral-movement / east-west traffic analyzer (detect internal host-to-host scanning)
- [ ] **P2** — Add advisory webhook / notification support (Slack, email, syslog, PagerDuty)
- [ ] **P2** — Advisory persistence in SQLite (currently in-memory only — lost on restart)
- [ ] **P2** — Add a beaconing detector (periodic outbound connections at regular intervals → C2 indicator)
- [ ] **P2** — Add a data-exfiltration detector (large outbound transfers to uncommon destinations)
- [ ] **P2** — Increase advisory history beyond 100 entries (configurable cap)
- [ ] **P3** — Add machine-learning baseline (replace simple mean ± σ with seasonal decomposition or EWMA)
- [ ] **P3** — User-defined custom analysis rules (YAML-based threshold expressions)

---

## 4. Web Interface & Dashboard

### Currently Implemented
- [x] Server-rendered XHTML templates with `go:embed`
- [x] Dark mode toggle (CSS custom properties + `localStorage`)
- [x] Auto-refresh with countdown timer (30 s) and scroll-position preservation
- [x] Responsive design with hamburger menu (768 px breakpoint)
- [x] Chart.js visualizations (doughnut, bar, line charts)
- [x] 11 pages: Dashboard, Flows, Hosts, Map, Reports, Advisories, About, Capture, VLANs, MACs
- [x] Flow explorer with src/dst/port/protocol filters and pagination (5-page window)
- [x] CSV and JSON export from Reports page
- [x] Leaflet.js geographic map with IP markers
- [x] Latency percentiles (P50/P95/P99 RTT and throughput)
- [x] TCP health dashboard (retransmission, OOO, packet-loss rates)
- [x] VoIP quality metrics (MOS, jitter, call count)
- [x] PCAP capture start/stop/download from web UI

### TODO
- [ ] **P1** — Add WebSocket or SSE for real-time flow streaming (replace polling-based auto-refresh)
- [ ] **P1** — Add flow detail / drill-down page (click a flow row → full metadata + related flows)
- [ ] **P2** — Add search / full-text filter across all flow fields
- [ ] **P2** — Add time-range selector to Dashboard (currently shows only the ring buffer window)
- [ ] **P2** — Column sort on Flows / Hosts / VLANs / MACs tables (currently fixed sort order)
- [ ] **P2** — Export flows page results as CSV/JSON (currently only Reports has export)
- [ ] **P2** — Add per-host detail page (traffic history, top peers, advisory timeline)
- [ ] **P2** — Keyboard shortcuts (n = next page, p = previous, / = focus filter)
- [ ] **P3** — Themeable UI (user-selectable accent colors beyond dark/light)
- [ ] **P3** — Configurable auto-refresh interval (currently hardcoded 30 s)
- [ ] **P3** — Add Sankey / chord diagram for inter-host traffic visualization

---

## 5. REST / Programmatic API

### Currently Implemented
- _Nothing — all routes return HTML._

### TODO
- [ ] **P1** — JSON API endpoints mirroring each page (`/api/v1/flows`, `/api/v1/dashboard`, `/api/v1/advisories`, etc.)
- [ ] **P1** — Pagination via `?page=N&limit=M` query params with `Link` headers
- [ ] **P2** — OpenAPI / Swagger spec generation
- [ ] **P2** — API key or JWT authentication for programmatic access
- [ ] **P3** — gRPC streaming endpoint for real-time flow export
- [ ] **P3** — Prometheus `/metrics` endpoint for scraping (flows/sec, advisory counts, storage utilization)

---

## 6. Model & Flow Processing

### Currently Implemented
- [x] Unified `Flow` struct with 42 fields (5-tuple, counters, L2, L7, quality metrics)
- [x] Port-based L7 classification (`Classify()` → AppProto / AppCat)
- [x] VoIP detection via port heuristics (SIP 5060/5061, RTP 10000–20000)
- [x] MOS calculation using ITU-T G.107 E-model (R-value → MOS 1.0–4.41)
- [x] Bidirectional flow stitching (`StitchFlows()` → RTT estimation)
- [x] Canonical `FlowKey()` for correlation (lower IP sorted first)
- [x] Safe helpers: `SafeIPString()`, `FormatMAC()`, `FormatEtherType()`, `ProtocolName()`
- [x] ASN-to-name mapping for ~80 well-known networks

### TODO
- [ ] **P1** — Add DNS / TLS SNI payload-based classification (port-based alone misses >85% of encrypted traffic)
- [ ] **P1** — Support IPv6 extension header parsing (currently assumes no headers between IPv6 and L4)
- [ ] **P2** — Expand ASN database beyond the hardcoded ~80 entries (load from MRT/RIB dump or BGP feed)
- [ ] **P2** — Add DSCP / QoS field extraction and classification (currently only raw ToS byte)
- [ ] **P2** — Add MPLS label stack extraction
- [ ] **P3** — MOS model selection beyond G.711 (Opus, G.729, AMR codecs have different impairment curves)
- [ ] **P3** — Add IP fragmentation reassembly tracking

---

## 7. Packet Capture (Mirror / TAP)

### Currently Implemented
- [x] Linux raw-socket capture via `AF_PACKET`
- [x] Ethernet → IPv4/IPv6 → TCP/UDP decoding pipeline
- [x] 802.1Q VLAN tag parsing
- [x] PCAP file writer (libpcap-compatible, magic 0xa1b2c3d4)
- [x] File rotation by size (`max_size_mb`, default 100 MB)
- [x] Oldest-file cleanup (`max_files`, default 10)
- [x] Session manager with unique IDs (cap-1, cap-2, …)
- [x] Web UI start/stop/download controls

### TODO
- [ ] **P1** — Implement BPF filter application at the kernel level (config field exists but filters are not applied)
- [ ] **P1** — Add pcap-ng format support (richer metadata: interface info, comments, name resolution)
- [ ] **P2** — Add PCAP rotation by time (e.g., hourly files) in addition to size-based rotation
- [ ] **P2** — Compress rotated PCAP files (gzip/zstd) to reduce disk usage
- [ ] **P2** — Add PCAP indexing / metadata catalog (session start/end time, packet count, filter used)
- [ ] **P2** — Cross-platform capture support (currently Linux-only; consider `gopacket/pcap` for macOS/Windows)
- [ ] **P2** — Track and report capture statistics (packets captured vs. dropped by kernel)
- [ ] **P3** — Add GRE / MPLS / VXLAN tunnel decapsulation
- [ ] **P3** — Add Netmap / AF_XDP support for 10 Gbps+ capture

---

## 8. GeoIP & Enrichment

### Currently Implemented
- [x] Binary-search lookup on sorted IP ranges (IPv4 only)
- [x] Private-IP detection (10/8, 172.16/12, 192.168/16, 127/8 → "LAN / Private")
- [x] ~25 built-in well-known ranges (Google, Cloudflare, AWS, Azure, GCP, CDNs)
- [x] CSV loading for IP2Location LITE DB5 format
- [x] Thread-safe `RWMutex`-protected concurrent lookups
- [x] Web map page with Leaflet.js markers

### TODO
- [ ] **P1** — Add IPv6 GeoIP support (currently returns empty for all IPv6 addresses)
- [ ] **P2** — Support MaxMind GeoLite2 `.mmdb` format (industry standard, auto-updatable)
- [ ] **P2** — Periodic GeoIP database refresh without restart
- [ ] **P2** — Add reverse-DNS enrichment (PTR lookups for IP → hostname)
- [ ] **P3** — Add threat-intelligence feed integration (blocklists, Tor exit nodes, known C2 IPs)
- [ ] **P3** — Add WHOIS / RDAP lookup for unknown ASNs

---

## 9. Configuration & Operations

### Currently Implemented
- [x] YAML config loading with sensible defaults
- [x] Graceful shutdown on SIGINT / SIGTERM
- [x] Multi-stage Docker build (alpine runtime, ~20 MB image)
- [x] GitHub Actions release workflow (multi-arch Docker push to GHCR)
- [x] Version injection via `-ldflags` at build time

### TODO
- [ ] **P1** — Add config validation at startup (port ranges, file paths, conflicting settings)
- [ ] **P1** — Add log-level configuration in YAML (currently hardcoded INFO)
- [ ] **P1** — Add structured JSON logging option (for log aggregators like ELK / Loki)
- [ ] **P2** — Hot-reload config on SIGHUP without restarting the process
- [ ] **P2** — Add systemd unit file and install documentation
- [ ] **P2** — Add health-check endpoint (`/healthz`) for container orchestration
- [ ] **P2** — Add environment-variable overrides for config values (12-factor app)
- [ ] **P3** — Add CLI flags (`--config`, `--version`, `--debug`) in addition to positional args
- [ ] **P3** — Add log file rotation (currently stderr-only)

---

## 10. Security & Hardening

### Currently Implemented
- [x] PCAP download path-traversal prevention (filepath security check)
- [x] CSV export uses `encoding/csv` for RFC 4180 compliance (injection-safe)
- [x] SQLite parameterized queries (SQL-injection safe)
- [x] Embedded templates (no file-system template injection)

### TODO
- [ ] **P0** — Add source-IP allowlist for NetFlow/IPFIX/sFlow UDP exporters (anyone on the network can currently inject fake flow data)
- [ ] **P1** — Add TLS support for the web server (HTTPS with certificate configuration)
- [ ] **P1** — Add authentication for the web UI (at minimum HTTP Basic Auth, ideally session-based)
- [ ] **P1** — Add CSRF protection on POST routes (`/capture/start`, `/capture/stop`)
- [ ] **P2** — Rate-limit the web interface to prevent resource exhaustion
- [ ] **P2** — Add Content-Security-Policy, X-Frame-Options, and other security headers
- [ ] **P2** — Audit and restrict UDP buffer sizes to prevent memory exhaustion from crafted packets
- [ ] **P3** — Add RBAC (role-based access control) for multi-user deployments
- [ ] **P3** — Add audit logging for capture start/stop and configuration changes

---

## 11. Testing & CI/CD

### Currently Implemented
- [x] 16 test files covering all major packages
- [x] Model tests (flow struct, protocol names, MOS, throughput, VoIP detection)
- [x] Collector tests (v5, v9, IPFIX, sFlow packet construction and parsing)
- [x] Storage tests (ring buffer operations, SQLite insert/query/prune)
- [x] Analysis tests (all 12 analyzers, engine scheduling, advisory lifecycle)
- [x] Web handler tests (HTTP response codes, page rendering)
- [x] Capture tests (packet parsing, PCAP writing, session management)
- [x] Config tests (default values)
- [x] Geo tests (lookups, CSV loading, private IPs)
- [x] GitHub Actions release pipeline (multi-arch Docker)

### TODO
- [ ] **P1** — Add CI workflow for PRs (run `go vet`, `go test -race`, `golangci-lint` on every push)
- [ ] **P1** — Add code coverage reporting and enforce minimum threshold (e.g., 80%)
- [ ] **P2** — Add integration tests (spin up collector + storage + web, send real flow packets, verify end-to-end)
- [ ] **P2** — Add benchmark tests for hot paths (`storage.Insert`, `RingBuffer.Recent`, `buildDashboardData`)
- [ ] **P2** — Add fuzz tests for protocol decoders (`DecodeNetFlowV5`, `DecodeNetFlowV9`, `DecodeIPFIX`, `DecodeSFlow`)
- [ ] **P3** — Add load / stress tests simulating high flow rates (10K+ flows/sec)
- [ ] **P3** — Add Makefile or Taskfile with standard targets (`build`, `test`, `lint`, `docker`, `release`)

---

## 12. Documentation

### Currently Implemented
- [x] README.md with feature overview, quick-start, and configuration reference
- [x] idea.md with original design document and architecture diagram
- [x] Inline code comments on key functions

### TODO
- [ ] **P1** — Add CONTRIBUTING.md (dev setup, code style, PR process, testing requirements)
- [ ] **P1** — Add architecture diagram (ASCII or Mermaid) showing data flow: Exporter → Collector → Storage → Analysis → Web
- [ ] **P2** — Add deployment guide (bare-metal, Docker Compose, Kubernetes Helm chart)
- [ ] **P2** — Add CHANGELOG.md tracking releases and notable changes
- [ ] **P2** — Document all analyzer modules (thresholds, what they detect, remediation guidance)
- [ ] **P2** — Add network-device configuration examples (Cisco, Juniper, MikroTik NetFlow/IPFIX export setup)
- [ ] **P3** — Add troubleshooting / FAQ page (common issues: no flows received, high memory, template errors)

---

## 13. Performance & Scalability

### Currently Implemented
- [x] Ring buffer O(1) insert, O(n) recent query (bounded by capacity)
- [x] SQLite WAL mode for concurrent reads during writes
- [x] Geo lookup O(log n) binary search
- [x] Template caching to avoid re-parsing on every packet
- [x] Minimal memory footprint (targets < 350 MB on 512 MB system)

### TODO
- [ ] **P1** — Profile and optimize `buildDashboardData()` — it iterates all recent flows multiple times for different aggregations
- [ ] **P1** — Batch SQLite inserts (currently one `INSERT` per flow in a transaction; batch 100–1000 flows per transaction)
- [ ] **P2** — Add connection pooling or switch to `database/sql` connection pool (currently `MaxOpenConns(1)`)
- [ ] **P2** — Pre-aggregate dashboard counters incrementally (avoid full re-scan on every page load)
- [ ] **P2** — Add memory budget / back-pressure (drop oldest flows or slow down ingestion when memory limit is hit)
- [ ] **P3** — Explore ClickHouse or TimescaleDB for deployments ingesting >50K flows/sec
- [ ] **P3** — Add horizontal scaling via flow sharding (hash on exporter IP or src/dst subnet)

---

## Cross-Cutting Concerns

| Concern | Status | Notes |
|---------|--------|-------|
| Graceful shutdown | ✅ | Signal handling, WaitGroup for in-flight handlers |
| Thread safety | ✅ | RWMutex on ring buffer, template caches, geo DB |
| Error handling | ⚠️ | Most errors logged but not surfaced to the user |
| Observability | ❌ | No Prometheus metrics, no structured logging, no tracing |
| IPv6 support | ⚠️ | Flow struct supports it, but GeoIP and some decoders do not |
| Multi-tenancy | ❌ | Single-tenant only; no per-exporter or per-user isolation |
| Clustering | ❌ | Single-instance only; no distributed state or coordination |

---

_Last updated: 2026-03-01_
