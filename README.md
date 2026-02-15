# FlowLens

Lightweight NetFlow/IPFIX Analyzer — a single-binary network flow collector, storage engine, analysis platform, and web dashboard.

## Features

- **Multi-protocol collector** — NetFlow v5, v9, and IPFIX (v10) with template handling
- **Dual storage** — In-memory ring buffer for real-time queries + SQLite for persistence
- **10 built-in analyzers** — Top talkers, protocol distribution, port scans, anomaly detection, DNS volume, flow asymmetry, retransmissions, unreachable hosts, new talkers, port concentration
- **Rolling advisory history** — Advisories are preserved with resolved/active status
- **Web dashboard** — Dashboard, flow explorer, advisories, and system status pages
- **Zero dependencies** — Pure Go, no CGO required (uses `modernc.org/sqlite`)

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
  -p 8080:8080 \
  --name flowlens \
  flowlens

# Run with a custom config
docker run -d \
  -p 2055:2055/udp \
  -p 4739:4739/udp \
  -p 8080:8080 \
  -v /path/to/flowlens.yaml:/app/configs/flowlens.yaml \
  --name flowlens \
  flowlens
```

## Configuration

FlowLens is configured via a YAML file. See [`configs/flowlens.yaml`](configs/flowlens.yaml) for the default configuration with all options documented.

| Section | Key | Default | Description |
|---------|-----|---------|-------------|
| `collector` | `netflow_port` | `2055` | UDP port for NetFlow v5/v9 |
| `collector` | `ipfix_port` | `4739` | UDP port for IPFIX |
| `collector` | `buffer_size` | `65535` | UDP read buffer size (bytes) |
| `storage` | `ring_buffer_duration` | `10m` | In-memory flow retention window |
| `storage` | `sqlite_path` | `./flowlens.db` | SQLite database file path |
| `storage` | `sqlite_retention` | `72h` | Auto-prune flows older than this |
| `storage` | `prune_interval` | `15m` | How often to run TTL cleanup |
| `analysis` | `interval` | `60s` | How often to run analyzers |
| `analysis` | `top_talkers_count` | `10` | Number of top talkers to track |
| `analysis` | `anomaly_baseline_window` | `168h` | Baseline period for anomaly detection |
| `analysis` | `scan_threshold` | `500` | Unique ports in 60s = scan |
| `web` | `listen` | `:8080` | HTTP listen address |
| `web` | `page_size` | `50` | Rows per page in flow explorer |

## Web Interface

Open `http://localhost:8080` in your browser after starting FlowLens.

| Page | Path | Description |
|------|------|-------------|
| Dashboard | `/` | Throughput, top talkers, protocol breakdown |
| Flow Explorer | `/flows` | Searchable flow table with filtering and pagination |
| Advisories | `/advisories` | Active and resolved advisories sorted by severity |
| About | `/about` | System status, resource usage, and configuration |

## Analyzers

FlowLens includes 10 built-in analyzers:

| Analyzer | Description |
|----------|-------------|
| **Top Talkers** | Alerts when a single host exceeds 25% of total traffic |
| **Protocol Distribution** | Detects ICMP floods and unusual/insecure protocols |
| **Scan Detector** | Detects port scans and sweeps by unique port count |
| **Anomaly Detector** | Statistical deviation from baseline (spikes and drops) |
| **DNS Volume** | Detects excessive DNS query rates and ratios |
| **Flow Asymmetry** | Detects asymmetric routing patterns between IP pairs |
| **Retransmission Detector** | High packet-to-byte ratio suggesting TCP issues |
| **Unreachable Detector** | Many tiny flows to same destination (host/service down) |
| **New Talker Detector** | Previously unseen hosts suddenly active |
| **Port Concentration** | Many sources hitting the same destination port |

## Project Structure

```
FlowLens/
├── cmd/flowlens/          # Application entry point
│   └── main.go
├── configs/               # Default configuration
│   └── flowlens.yaml
├── internal/
│   ├── analysis/          # Advisory engine and analyzers
│   ├── collector/         # UDP listener, NetFlow v5/v9/IPFIX decoders
│   ├── config/            # YAML configuration loader
│   ├── logging/           # Structured leveled logger
│   ├── model/             # Unified Flow struct
│   ├── storage/           # Ring buffer and SQLite backends
│   └── web/               # HTTP server, handlers, and templates
├── static/                # CSS stylesheet
├── Dockerfile             # Multi-stage Docker build
└── README.md
```

## Running Tests

```bash
go test ./...
```

## License

See [LICENSE](LICENSE) for details.
