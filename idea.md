# FlowLens — Lightweight NetFlow/IPFIX Analyzer

> A small, resource-efficient NetFlow/IPFIX collector and analyzer with a web interface that gives network engineers actionable troubleshooting advice.

---

## Goals

- Ingest NetFlow v5, v9, and IPFIX (v10) data
- Store and analyze flow data efficiently
- Present everything through a simple XHTML web interface
- Run comfortably on 512 MB RAM / 2 CPU cores
- Give engineers plain-language advice about what is happening on the network

---

## Tech Stack

| Component       | Choice                          | Rationale                                      |
| --------------- | ------------------------------- | ---------------------------------------------- |
| Language        | Go                              | Low memory, single binary, great concurrency   |
| Frontend        | XHTML (server-rendered via Go)  | No JS frameworks, minimal footprint, fast       |
| Storage (hot)   | In-memory ring buffer           | Sub-second queries on recent flows              |
| Storage (warm)  | SQLite (WAL mode)               | Zero-config, embedded, proven reliability       |
| Config          | YAML file                       | Simple, human-readable                          |
| Deployment      | Single binary + Dockerfile      | Drop it on a box and run it                     |

---

## Architecture

```
Network Devices (routers, switches, firewalls)
        │
        │ NetFlow/IPFIX (UDP)
        ▼
┌────────────────┐
│   Collector    │  ← UDP listener on port 2055 (NetFlow) / 4739 (IPFIX)
���   (decoder)    │
└───────┬────────┘
        │ parsed flow records
        ▼
┌────────────────┐
│   Storage      │  ← In-memory ring buffer (last 10 min)
│                │  ← SQLite (last 24-72 hrs, TTL pruned)
└───────┬────────┘
        │
        ▼
┌────────────────┐
│   Analysis     │  ← Rule-based heuristics
│   Engine       │  ← Generates advisories
└───────┬────────┘
        │
        ▼
┌────────────────┐
│   Web Server   │  ← Go net/http + html/template
│   (XHTML)      │  ← Serves pages + handles API
└────────────────┘
```

---

## Project Structure

```
flowlens/
├── cmd/
│   └── flowlens/
│       └── main.go              # entry point, wires everything together
├── internal/
│   ├── collector/
│   │   ├── collector.go         # UDP listener, dispatches raw packets
│   │   ├── netflowv5.go         # NetFlow v5 decoder
│   │   ├── netflowv9.go         # NetFlow v9 decoder (template-based)
│   │   └── ipfix.go             # IPFIX decoder (template-based)
│   ├── model/
│   │   └── flow.go              # Flow record struct (unified format)
│   ├── storage/
│   │   ├── storage.go           # Storage interface
│   │   ├── ringbuffer.go        # In-memory ring buffer (hot tier)
│   │   └── sqlite.go            # SQLite backend (warm tier)
│   ├── analysis/
│   │   ├── engine.go            # Runs all analyzers on a schedule
│   │   ├── toptalkers.go        # Top talkers by bytes/packets
│   │   ├── anomaly.go           # Baseline deviation detection
│   │   ├── protocol.go          # Protocol distribution analysis
│   │   ├── scanner.go           # Port scan / recon detection
│   │   └── advisory.go          # Advisory model + severity levels
│   ├── web/
│   │   ├── server.go            # HTTP server setup, routes
│   │   ├── handlers.go          # Page handlers (dashboard, flows, advisories)
│   │   └── templates/
│   │       ├── layout.xhtml     # Base layout (head, nav, footer)
│   │       ├── dashboard.xhtml  # Overview page
│   │       ├── flows.xhtml      # Flow explorer table
│   │       └── advisories.xhtml # Advisory list
│   └── config/
│       └── config.go            # YAML config loader
├── configs/
│   └── flowlens.yaml            # Default configuration file
├── static/
│   └── style.css                # Minimal stylesheet
├── Dockerfile
├── go.mod
├── LICENSE
└── README.md
```

---

## Unified Flow Record

All NetFlow/IPFIX versions get decoded into one common struct:

```go
type Flow struct {
    Timestamp   time.Time
    SrcAddr     net.IP
    DstAddr     net.IP
    SrcPort     uint16
    DstPort     uint16
    Protocol    uint8       // TCP=6, UDP=17, ICMP=1, etc.
    Bytes       uint64
    Packets     uint64
    TCPFlags    uint8
    ToS         uint8
    InputIface  uint32
    OutputIface uint32
    SrcAS       uint32
    DstAS       uint32
    Duration    time.Duration
    ExporterIP  net.IP      // which device sent this flow
}
```

---

## Analysis & Advisories

The analysis engine runs periodically (e.g., every 60 seconds) against recent flow data and produces advisories.

### Analyzers

| Analyzer              | What It Detects                     | Example Advisory                                                                                     |
| --------------------- | ----------------------------------- | ---------------------------------------------------------------------------------------------------- |
| **Top Talkers**       | Bandwidth-heavy hosts               | `"10.0.1.50 is using 73% of total bandwidth (8.2 Gbps), primarily HTTPS to 52.94.x.x (AWS)"`        |
| **Anomaly Detection** | Spikes or drops vs. baseline        | `"Traffic to 192.168.5.0/24 dropped 95% at 14:32 — possible link failure"`                           |
| **Protocol Mix**      | Unusual or insecure protocols       | `"Telnet traffic (port 23) detected from 10.0.2.15 — consider migrating to SSH"`                     |
| **Scan Detection**    | Port scans, host sweeps             | `"172.16.0.55 contacted 2,847 unique ports in 60s — likely a port scan"`                              |
| **DNS Volume**        | Excessive DNS queries               | `"10.0.1.100 is generating 12,000 DNS queries/sec — possible loop or misconfigured resolver"`         |
| **Flow Asymmetry**    | Asymmetric routing hints            | `"Traffic to 10.1.0.0/16 exits via GW-A but returns via GW-B — check routing tables"`                |

### Advisory Severity Levels

```
CRITICAL  — immediate action needed (e.g., scan detected, link down)
WARNING   — something unusual, investigate soon
INFO      — informational insight (e.g., top talker shift)
```

---

## Web Interface Pages

All pages are **server-rendered XHTML** using Go's `html/template`. No JavaScript frameworks. Minimal CSS.

### 1. Dashboard (`/`)

- Total throughput (bps / pps) over the last 10 minutes
- Top 10 talkers (source + destination)
- Protocol breakdown (pie chart or simple bar — CSS-only if possible)
- Active advisory count by severity

### 2. Flow Explorer (`/flows`)

- Searchable, filterable table of recent flow records
- Filter by: source IP, destination IP, port, protocol, time range
- Pagination (server-side)

### 3. Advisories (`/advisories`)

- List of current advisories sorted by severity
- Each advisory includes:
  - Severity badge
  - Timestamp
  - Plain-language description
  - Suggested action

### 4. About / Config (`/about`)

- Show current config (listen ports, retention, thresholds)
- System resource usage (memory, goroutines, flow rate)
- Uptime and version info

---

## Configuration (`flowlens.yaml`)

```yaml
collector:
  netflow_port: 2055          # UDP port for NetFlow v5/v9
  ipfix_port: 4739            # UDP port for IPFIX
  buffer_size: 65535          # UDP read buffer size in bytes

storage:
  ring_buffer_duration: 10m   # how long to keep flows in memory
  sqlite_path: "./flowlens.db"
  sqlite_retention: 72h       # auto-prune flows older than this
  prune_interval: 15m         # how often to run TTL cleanup

analysis:
  interval: 60s               # how often to run analyzers
  top_talkers_count: 10       # number of top talkers to track
  anomaly_baseline_window: 7d # baseline period for anomaly detection
  scan_threshold: 500         # unique ports in 60s = scan

web:
  listen: ":8080"             # HTTP listen address
  page_size: 50               # rows per page in flow explorer
```

---

## Resource Budget

| State          | Target RAM | Notes                                       |
| -------------- | ---------- | ------------------------------------------- |
| Idle           | ~30 MB     | Collector listening, no active flows         |
| Normal load    | ~80-150 MB | Ring buffer populated, periodic analysis     |
| Peak           | <350 MB    | Full ring buffer, SQLite queries, web traffic|
| **Hard limit** | 450 MB     | Leave headroom for OS on a 512 MB system     |

### Techniques

- Fixed-size ring buffer (capped by record count, not unbounded)
- SQLite WAL mode (concurrent reads during writes)
- Aggressive TTL pruning on a schedule
- Server-rendered pages (no large API payloads)
- Goroutine pool for analysis workers (cap at number of CPU cores)

---

## MVP Roadmap

### Phase 1 — Collector & Storage

- [ ] UDP listener for NetFlow v5
- [ ] Decode NetFlow v5 into unified `Flow` struct
- [ ] In-memory ring buffer with fixed capacity
- [ ] SQLite storage with insert and TTL-based pruning
- [ ] YAML config loader
- [ ] Basic `main.go` that wires it all together and runs

### Phase 2 — Web Interface

- [ ] HTTP server with Go `net/http`
- [ ] XHTML layout template (header, nav, footer)
- [ ] Dashboard page: throughput, top talkers, protocol breakdown
- [ ] Flow explorer page: table with server-side filtering + pagination
- [ ] Minimal CSS stylesheet

### Phase 3 — Analysis Engine

- [ ] Analysis runner (periodic, configurable interval)
- [ ] Top talkers analyzer
- [ ] Protocol distribution analyzer
- [ ] Port scan / sweep detector
- [ ] Advisory model with severity levels
- [ ] Advisories page in web UI

### Phase 4 — Polish & Harden

- [ ] NetFlow v9 decoder (template handling)
- [ ] IPFIX decoder (template handling)
- [ ] Anomaly detection (baseline deviation)
- [ ] About / status page (config, memory, uptime)
- [ ] Dockerfile (multi-stage build, scratch/alpine base)
- [ ] Graceful shutdown
- [ ] Logging (structured, leveled)
- [ ] README with setup instructions

---

## Running

```bash
# Build
go build -o flowlens ./cmd/flowlens/

# Run
./flowlens --config configs/flowlens.yaml

# Open browser
# http://localhost:8080
```

---

## Future Ideas (Out of Scope for Now)

- sFlow support
- SNMP enrichment (interface names, device hostnames)
- GeoIP mapping
- Webhook / email alerting
- LLM-powered advisory explanations
- Dark mode
- Horizontal scaling (multiple collectors → shared database)