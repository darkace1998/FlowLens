# Architecture

## High-level Flow

```text
Network Devices (routers, switches, firewalls)
        |
        | NetFlow v5/v9 (UDP:2055)
        | IPFIX (UDP:4739)
        | sFlow v5 (UDP:6343)
        v
Collector (decoders + rate limiting)
        |
        | unified Flow records
        v
Storage (ring buffer + SQLite WAL)
        |
   +----+----+
   v         v
Analysis   Web/API
Engine     Server
   |
   v
Advisories
```

## Components

| Component | Package | Responsibility |
|---|---|---|
| Collector | `internal/collector/` | UDP listeners, NetFlow/IPFIX/sFlow decoders, per-source rate limiting |
| Model | `internal/model/` | Unified flow model and protocol helpers |
| Storage | `internal/storage/` | Hot ring buffer + warm SQLite persistence with retention pruning |
| Analysis | `internal/analysis/` | Advisory engine and analyzer modules |
| Web | `internal/web/` | HTTP server, templates, JSON API, middleware chain |
| Config | `internal/config/` | YAML configuration loading and defaults |
| Capture | `internal/capture/` | Raw capture and PCAP ingestion |
| GeoIP | `internal/geo/` | Built-in + CSV geolocation support |
| Logging | `internal/logging/` | Structured logging |
| Tracing | `internal/tracing/` | Tracer interface (no-op default) |

## Storage Model

- **In-memory ring buffer** for recent, low-latency reads
- **SQLite WAL** for historical reporting and persistence
- **TTL pruning** to cap retention and disk growth

## Middleware Chain

Recovery → Logging → Timeout → CSP → Auth → Router

## Repository Layout

```text
FlowLens/
├── cmd/flowlens/          # Application entry point
├── configs/               # Default YAML configuration
├── deploy/helm/flowlens/  # Helm chart
├── docs/                  # Documentation
├── internal/              # Application packages
├── Dockerfile             # Container build
└── docker-compose.yml     # Local compose run
```
