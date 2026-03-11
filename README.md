# FlowLens

Lightweight NetFlow/IPFIX/sFlow Analyzer — a single-binary network flow collector, storage engine, analysis platform, and web dashboard.

## Features

- **Multi-protocol collector** — NetFlow v5, v9, IPFIX (v10), and sFlow v5 with template handling
- **Dual storage** — In-memory ring buffer for real-time queries + SQLite for persistence
- **12 built-in analyzers** — Top talkers, protocol distribution, port scans, anomaly detection, DNS volume, flow asymmetry, retransmissions, unreachable hosts, new talkers, port concentration, VoIP quality
- **Rolling advisory history** — Advisories are preserved with resolved/active status
- **Web dashboard** — 13 pages including dashboard, flow explorer, hosts, sessions, advisories, reports, map, VLANs, MACs, counters, exporters, capture, and about
- **JSON REST API** — Programmatic access to flows, hosts, sessions, advisories, and dashboard data
- **Security** — HTTP Basic Auth, CSRF tokens, Content-Security-Policy headers, TLS support
- **Zero dependencies** — Pure Go, no CGO required (uses `modernc.org/sqlite`)

## Architecture

```
Network Devices (routers, switches, firewalls)
        │
        │ NetFlow v5/v9 (UDP:2055)
        │ IPFIX (UDP:4739)
        │ sFlow v5 (UDP:6343)
        ▼
┌─────────────────┐
│    Collector     │  ← UDP listeners with per-source-IP rate limiting
│    (decoders)    │  ← Protocol decoders: netflowv5, netflowv9, ipfix, sflow
└────────┬────────┘
         │ unified Flow records
         ▼
┌─────────────────┐
│    Storage       │  ← Ring buffer (in-memory, last 10 min, sub-ms queries)
│                  │  ← SQLite WAL (last 24–72 h, TTL-pruned, concurrent R/W)
└────────┬────────┘
         │
    ┌────┴─────┐
    ▼          ▼
┌────────┐ ┌────────────┐
│Analysis│ │  Web Server │  ← Go net/http with middleware chain:
│ Engine │ │  (XHTML +   │     Recovery → Logging → Timeout → CSP → Auth → Mux
│        │ │   JSON API) │
└────┬───┘ └─────────────┘
     │
     ▼
┌─────────────────┐
│   Advisories    │  ← Rule-based heuristics + optional webhook notifications
│   (in-memory)   │
└─────────────────┘
```

### Component Overview

| Component | Package | Responsibility |
|-----------|---------|----------------|
| Collector | `internal/collector/` | UDP listeners, NetFlow v5/v9, IPFIX, sFlow v5 decoders, rate limiting |
| Model | `internal/model/` | Unified `Flow` struct, protocol helpers, TCP flag formatting, flow stitching, retransmission detection |
| Storage | `internal/storage/` | Ring buffer (hot tier), SQLite WAL (warm tier), TTL pruning |
| Analysis | `internal/analysis/` | Periodic advisory engine, 12 analyzer modules, webhook dispatch |
| Web | `internal/web/` | HTTP server, 13 page handlers, JSON API, middleware (auth, CSRF, CSP, logging, timeout, recovery) |
| Config | `internal/config/` | YAML config loader with sensible defaults |
| Capture | `internal/capture/` | Raw packet capture (AF_PACKET), PCAP reader (LE/BE, micro/nano) |
| GeoIP | `internal/geo/` | IP geolocation (built-in ranges + CSV loader) |
| Logging | `internal/logging/` | Structured leveled logger |
| Tracing | `internal/tracing/` | Tracer interface (no-op default, wirable to OpenTelemetry) |

## Quick Start

### From Source

```bash
# Clone and build
git clone https://github.com/darkace1998/FlowLens.git
cd FlowLens
go build -o flowlens ./cmd/flowlens/

# Run with default config
./flowlens

# Or specify a config file
./flowlens configs/flowlens.yaml
```

### With Docker

```bash
# Build the image
docker build -t flowlens .

# Run with default config
docker run -d \
  -p 2055:2055/udp \
  -p 4739:4739/udp \
  -p 6343:6343/udp \
  -p 8080:8080 \
  --name flowlens \
  flowlens

# Run with a custom config
docker run -d \
  -p 2055:2055/udp \
  -p 4739:4739/udp \
  -p 6343:6343/udp \
  -p 8080:8080 \
  -v /path/to/flowlens.yaml:/app/configs/flowlens.yaml \
  --name flowlens \
  flowlens
```

### With Docker Compose

A ready-to-use [`docker-compose.yml`](docker-compose.yml) is included with persistent volumes for the database and captures:

```bash
docker compose up -d
```

### With Kubernetes (Helm)

A Helm chart is available in [`deploy/helm/flowlens/`](deploy/helm/flowlens/):

```bash
helm install flowlens deploy/helm/flowlens/
```

See the chart's [`values.yaml`](deploy/helm/flowlens/values.yaml) for all configurable options including ingress, persistence, and resource limits.

### Recommended Resource Limits

FlowLens is lightweight but resource needs scale with traffic volume. The following limits are recommended starting points:

| Environment | CPUs | Memory | Notes |
|-------------|------|--------|-------|
| Low traffic (<1K flows/s) | 0.5 | 128 MB | Suitable for home lab / small office |
| Medium traffic (1K–10K flows/s) | 1 | 256 MB | Typical enterprise branch |
| High traffic (10K–50K flows/s) | 2 | 512 MB | Data center / core router |
| Very high traffic (>50K flows/s) | 4 | 1 GB | Consider dedicated host |

Apply limits with Docker:

```bash
docker run -d --memory=512m --cpus=2 \
  -p 2055:2055/udp -p 4739:4739/udp -p 6343:6343/udp -p 8080:8080 \
  --name flowlens flowlens
```

The SQLite database and PCAP capture files are the primary disk consumers. Mount volumes for `/app/data` and `/app/captures` to persist data across container restarts.

## Configuration

FlowLens is configured via a YAML file. See [`configs/flowlens.yaml`](configs/flowlens.yaml) for the default configuration with all options documented.

| Section | Key | Default | Description |
|---------|-----|---------|-------------|
| `collector` | `netflow_port` | `2055` | UDP port for NetFlow v5/v9 |
| `collector` | `ipfix_port` | `4739` | UDP port for IPFIX |
| `collector` | `sflow_port` | `6343` | UDP port for sFlow v5 |
| `collector` | `buffer_size` | `65535` | UDP read buffer size (bytes) |
| `collector` | `rate_limit` | `0` | Max packets/sec per source IP (0 = unlimited) |
| `storage` | `ring_buffer_duration` | `10m` | In-memory flow retention window |
| `storage` | `sqlite_path` | `./flowlens.db` | SQLite database file path |
| `storage` | `sqlite_retention` | `72h` | Auto-prune flows older than this |
| `storage` | `prune_interval` | `15m` | How often to run TTL cleanup |
| `analysis` | `interval` | `60s` | How often to run analyzers |
| `analysis` | `top_talkers_count` | `10` | Number of top talkers to track |
| `analysis` | `anomaly_baseline_window` | `168h` | Baseline period for anomaly detection |
| `analysis` | `scan_threshold` | `500` | Unique ports in 60s = scan |
| `analysis` | `webhook_url` | _(empty)_ | URL to POST new advisories as JSON |
| `web` | `listen` | `:8080` | HTTP listen address |
| `web` | `page_size` | `50` | Rows per page in flow explorer |
| `web` | `tls_cert` | _(empty)_ | Path to TLS certificate (enables HTTPS) |
| `web` | `tls_key` | _(empty)_ | Path to TLS private key |
| `web` | `username` | _(empty)_ | HTTP Basic Auth username (disabled when empty) |
| `web` | `password` | _(empty)_ | HTTP Basic Auth password |

## Security Considerations

### Authentication

FlowLens supports HTTP Basic Auth. Enable it by setting `username` and `password` in the web config:

```yaml
web:
  username: "admin"
  password: "changeme"
```

Credentials are compared using constant-time comparison to prevent timing attacks. When both fields are empty, authentication is disabled.

### TLS / HTTPS

FlowLens has built-in TLS support. Provide certificate and key files:

```yaml
web:
  tls_cert: "/path/to/cert.pem"
  tls_key: "/path/to/key.pem"
```

The server enforces TLS 1.2 as the minimum version. For production deployments, consider using a reverse proxy (nginx, Caddy) for TLS termination — see [Reverse Proxy Examples](docs/reverse-proxy.md).

### CSRF Protection

All state-changing POST endpoints (`/capture/start`, `/capture/stop`, `/pcap/import`) are protected with single-use CSRF tokens embedded in forms.

### Content Security Policy

Every response includes a `Content-Security-Policy` header restricting resource origins:

```
default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';
img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'
```

### Firewall Rules

The collector UDP ports receive untrusted network data. Restrict source IPs with firewall rules:

```bash
# iptables example: allow NetFlow only from known exporters
iptables -A INPUT -p udp --dport 2055 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p udp --dport 2055 -j DROP

# Similar for IPFIX (4739) and sFlow (6343)
```

The collector includes per-source-IP rate limiting (`collector.rate_limit`) to mitigate UDP amplification and DoS attacks.

### Container Security

The Docker image runs as a non-root user (`flowlens`), base images are pinned by digest for reproducible builds, and a `HEALTHCHECK` directive monitors the `/healthz` endpoint.

## Web Interface

Open `http://localhost:8080` in your browser after starting FlowLens.

| Page | Path | Description |
|------|------|-------------|
| Dashboard | `/` | Throughput, top talkers, protocol breakdown (with time-range selector) |
| Flow Explorer | `/flows` | Searchable flow table with filtering, pagination, and CSV/JSON export |
| Hosts | `/hosts` | Host inventory with traffic statistics and GeoIP |
| Sessions | `/sessions` | Bidirectional session aggregation with TCP flags and quality metrics |
| Advisories | `/advisories` | Active and resolved advisories sorted by severity |
| Reports | `/reports` | SQLite-backed historical reports with time-series charts |
| Map | `/map` | Geographic flow visualization |
| Capture | `/capture` | Start/stop raw packet capture, download PCAPs |
| VLANs | `/vlans` | VLAN traffic breakdown |
| MACs | `/macs` | MAC address traffic statistics |
| Counters | `/counters` | sFlow counter samples (interface utilization, errors, drops) |
| Exporters | `/exporters` | Per-exporter flow aggregation and comparison |
| About | `/about` | System status, resource usage, and configuration |

## JSON REST API

All API endpoints return `application/json`. When Basic Auth is enabled, API requests must include credentials.

### `GET /api/flows`

Paginated flow records from the in-memory ring buffer.

| Parameter | Type | Description |
|-----------|------|-------------|
| `page` | int | Page number (default: 1) |
| `src_ip` | string | Filter by source IP |
| `dst_ip` | string | Filter by destination IP |
| `port` | string | Filter by source or destination port |
| `protocol` | string | Filter by protocol name (e.g. `TCP`, `UDP`) |
| `ip` | string | Filter by either source or destination IP |

**Response:**

```json
{
  "page": 1,
  "total_pages": 5,
  "total_flows": 234,
  "flows": [
    {
      "timestamp": "2025-01-15T10:30:00Z",
      "src_addr": "10.0.1.50",
      "dst_addr": "192.168.1.1",
      "src_port": 443,
      "dst_port": 52341,
      "protocol": "TCP",
      "bytes": 1048576,
      "packets": 720,
      "duration": "5.2s",
      "app_proto": "HTTPS",
      "app_category": "Web"
    }
  ]
}
```

### `GET /api/hosts`

Aggregated host statistics.

**Response:**

```json
{
  "total_hosts": 42,
  "total_bytes": 5368709120,
  "hosts": [
    {
      "ip": "10.0.1.50",
      "bytes": 1073741824,
      "packets": 524288,
      "flow_count": 150,
      "first_seen": "2025-01-15T10:00:00Z",
      "last_seen": "2025-01-15T10:30:00Z",
      "pct": 20.0,
      "country": "US"
    }
  ]
}
```

### `GET /api/sessions`

Bidirectional session aggregation.

**Response:**

```json
{
  "total_sessions": 18,
  "total_bytes": 2147483648,
  "total_packets": 1048576,
  "sessions": [
    {
      "src_addr": "10.0.1.50",
      "dst_addr": "192.168.1.1",
      "src_port": 443,
      "dst_port": 52341,
      "protocol": "TCP",
      "bytes": 1048576,
      "packets": 720,
      "flow_count": 3,
      "first_seen": "2025-01-15T10:00:00Z",
      "last_seen": "2025-01-15T10:30:00Z",
      "duration": "30m0s",
      "throughput": "4.7 Mbps",
      "app_proto": "HTTPS",
      "retrans": 0,
      "ooo": 0,
      "loss": 0,
      "tcp_flags": "SYN ACK PSH FIN"
    }
  ]
}
```

### `GET /api/advisories`

All active and resolved advisories.

**Response:**

```json
{
  "advisories": [
    {
      "severity": "WARNING",
      "timestamp": "2025-01-15T10:25:00Z",
      "title": "Top Talker Detected",
      "description": "10.0.1.50 is using 35% of total bandwidth",
      "action": "Investigate traffic from this host",
      "resolved": false
    }
  ]
}
```

### `GET /api/dashboard`

Dashboard summary data.

**Response:**

```json
{
  "total_bytes": 5368709120,
  "total_packets": 2621440,
  "bps": "71.6 Mbps",
  "pps": "4.4 Kpps",
  "flow_count": 1500,
  "active_flows": 234,
  "active_hosts": 42,
  "window": "10m0s",
  "top_src": [{"ip": "10.0.1.50", "bytes": 1073741824, "packets": 524288, "pct": 20.0}],
  "top_dst": [{"ip": "192.168.1.1", "bytes": 536870912, "packets": 262144, "pct": 10.0}],
  "protocols": [{"name": "TCP", "bytes": 4294967296, "packets": 2097152, "pct": 80.0}]
}
```

### `GET /healthz`

Liveness probe endpoint for container orchestration.

**Response:** `200 OK`

```json
{
  "status": "ok",
  "uptime": "2h15m30s"
}
```

## Analyzers

FlowLens includes 12 built-in analyzers that run periodically (configurable via `analysis.interval`):

| Analyzer | Description |
|----------|-------------|
| **Top Talkers** | Alerts when a single host exceeds the configured bandwidth percentage |
| **Protocol Distribution** | Detects ICMP floods and unusual/insecure protocols |
| **Scan Detector** | Detects port scans and sweeps by unique port count |
| **Anomaly Detector** | Statistical deviation from baseline (spikes and drops) |
| **DNS Volume** | Detects excessive DNS query rates and ratios |
| **Flow Asymmetry** | Detects asymmetric routing patterns between IP pairs |
| **Retransmission Detector** | High retransmission rates suggesting TCP issues |
| **Unreachable Detector** | Many tiny flows to same destination (host/service down) |
| **New Talker Detector** | Previously unseen hosts suddenly active |
| **Port Concentration** | Many sources hitting the same destination port |
| **VoIP Quality** | MOS score estimation for voice/video traffic |

Analyzer thresholds are configurable in the `analysis` config section. Advisories can be forwarded to an external system via the `webhook_url` setting.

## Project Structure

```
FlowLens/
├── cmd/flowlens/          # Application entry point
│   └── main.go
├── configs/               # Default configuration
│   └── flowlens.yaml
├── deploy/
│   └── helm/flowlens/     # Kubernetes Helm chart
├── docs/                  # Additional documentation
│   └── reverse-proxy.md   # nginx / Caddy reverse-proxy examples
├── internal/
│   ├── analysis/          # Advisory engine and 12 analyzers
│   ├── capture/           # Raw packet capture, PCAP reader
│   ├── collector/         # UDP listeners, NetFlow v5/v9/IPFIX/sFlow decoders
│   ├── config/            # YAML configuration loader
│   ├── geo/               # GeoIP lookup (built-in ranges + CSV)
│   ├── logging/           # Structured leveled logger
│   ├── model/             # Unified Flow struct, helpers
│   ├── storage/           # Ring buffer and SQLite backends
│   ├── tracing/           # Tracer interface (OpenTelemetry-ready)
│   └── web/               # HTTP server, handlers, templates, JSON API
├── static/                # CSS stylesheet and Chart.js
├── docker-compose.yml     # Docker Compose example
├── Dockerfile             # Multi-stage Docker build
├── CONTRIBUTING.md        # Contributor guide
└── README.md
```

## Development Guide

### Prerequisites

- **Go 1.24+** — [install instructions](https://go.dev/doc/install)
- **golangci-lint** _(optional, for linting)_ — [install instructions](https://golangci-lint.run/welcome/install/)

### Build

```bash
go build -o flowlens ./cmd/flowlens/
```

Build with version information (matches the Docker build):

```bash
go build -ldflags="-s -w -X main.Version=$(git describe --tags --always --dirty)" \
  -o flowlens ./cmd/flowlens/
```

### Run Locally

```bash
# Start with default config (listens on :2055/udp, :4739/udp, :6343/udp, :8080/tcp)
./flowlens

# Start with a custom config
./flowlens configs/flowlens.yaml
```

Open `http://localhost:8080` in your browser.

### Test

```bash
# Run all tests
go test ./...

# Run tests with race detector (used in CI)
go test -race -count=1 ./...

# Run tests with coverage
go test -race -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Run benchmarks
go test -bench=. -benchmem ./...

# Run fuzz tests (30-second budget)
go test -fuzz=FuzzDecodeNetFlowV5 -fuzztime=30s ./internal/collector/
go test -fuzz=FuzzDecodeNetFlowV9 -fuzztime=30s ./internal/collector/
go test -fuzz=FuzzDecodeIPFIX      -fuzztime=30s ./internal/collector/
go test -fuzz=FuzzDecodeSFlow      -fuzztime=30s ./internal/collector/
go test -fuzz=FuzzReadPcapFlows    -fuzztime=30s ./internal/capture/
```

### Lint

```bash
# Run go vet
go vet ./...

# Run golangci-lint (16 linters configured in .golangci.yml)
golangci-lint run
```

### Docker

```bash
# Build the image
docker build -t flowlens .

# Run the container
docker run -d -p 2055:2055/udp -p 4739:4739/udp -p 6343:6343/udp -p 8080:8080 flowlens
```

### CI Pipeline

The project uses GitHub Actions with two workflows:

- **CI** (`.github/workflows/ci.yml`) — runs on every push/PR to `main`:
  - `go vet ./...`
  - `golangci-lint run`
  - `go test -race -count=1 -coverprofile=coverage.out ./...`
- **Release** (`.github/workflows/release.yml`) — runs on `v*` tags:
  - Test gate (race detector)
  - Multi-platform Docker image build (amd64/arm64)
  - Push to `ghcr.io`

## License

See [LICENSE](LICENSE) for details.
