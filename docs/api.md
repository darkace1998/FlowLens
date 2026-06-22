# API Reference

All endpoints return JSON (`application/json`).

When Basic Auth is enabled, include credentials in API requests.

## Endpoints

### `GET /api/flows`

Paginated flows from the in-memory ring buffer.

Query params:

| Param | Type | Description |
|---|---|---|
| `page` | int | Page number (default: `1`) |
| `src_ip` | string | Source IP filter |
| `dst_ip` | string | Destination IP filter |
| `ip` | string | Source-or-destination IP filter |
| `port` | string | Source-or-destination port filter |
| `protocol` | string | Protocol filter (for example `TCP`, `UDP`) |

**Example Response:**

```json
{
  "page": 1,
  "total_pages": 1,
  "total_flows": 12,
  "flows": [
    {
      "timestamp": "2023-10-25T10:00:00Z",
      "src_addr": "192.168.1.5",
      "dst_addr": "8.8.8.8",
      "src_port": 53535,
      "dst_port": 53,
      "protocol": "UDP",
      "bytes": 512,
      "packets": 4,
      "duration": "15ms",
      "app_proto": "DNS",
      "app_category": "Network Services"
    }
  ]
}
```

### `GET /api/hosts`

Aggregated host-level traffic statistics.

This endpoint does not accept any query parameters.

**Example Response:**

```json
{
  "total_hosts": 3,
  "total_bytes": 1024000,
  "hosts": [
    {
      "ip": "192.168.1.5",
      "bytes": 512000,
      "packets": 1500,
      "flow_count": 45,
      "first_seen": "2023-10-25T09:50:00Z",
      "last_seen": "2023-10-25T10:00:00Z",
      "pct": 50.0,
      "country": "Local"
    }
  ]
}
```

### `GET /api/sessions`

Bidirectional session aggregation with packet/byte stats and quality fields.

This endpoint does not accept any query parameters.

**Example Response:**

```json
{
  "total_sessions": 15,
  "total_bytes": 2048000,
  "total_packets": 3500,
  "sessions": [
    {
      "src_addr": "192.168.1.10",
      "dst_addr": "10.0.0.5",
      "src_port": 44444,
      "dst_port": 443,
      "protocol": "TCP",
      "bytes": 10240,
      "packets": 50,
      "flow_count": 2,
      "first_seen": "2023-10-25T09:55:00Z",
      "last_seen": "2023-10-25T10:00:00Z",
      "duration": "5m0s",
      "throughput": "34.13 bps",
      "app_proto": "HTTPS",
      "retrans": 1,
      "ooo": 0,
      "loss": 0,
      "tcp_flags": "S,A,P,F"
    }
  ]
}
```

### `GET /api/advisories`

Active and resolved advisories with severity, context, and action guidance.

This endpoint does not accept any query parameters.

**Example Response:**

```json
{
  "advisories": [
    {
      "severity": "high",
      "timestamp": "2023-10-25T09:58:00Z",
      "title": "Port Scan Detected",
      "description": "Host 192.168.1.100 is scanning multiple ports on 10.0.0.5.",
      "action": "Investigate host 192.168.1.100 for compromise.",
      "resolved": false
    }
  ]
}
```

### `GET /api/dashboard`

Dashboard summary payload:

- totals (`bytes`, `packets`, `flow_count`)
- live rates (`bps`, `pps`)
- active host/flow counts
- top source/destination lists
- protocol distribution

This endpoint does not accept any query parameters.

**Example Response:**

```json
{
  "total_bytes": 5000000,
  "total_packets": 15000,
  "bps": "10.50 Mbps",
  "pps": "3500.00 pps",
  "flow_count": 120,
  "active_flows": 45,
  "active_hosts": 10,
  "window": "10m0s",
  "top_src": [
    {
      "ip": "192.168.1.10",
      "bytes": 2500000,
      "packets": 7000,
      "pct": 50.0
    }
  ],
  "top_dst": [
    {
      "ip": "8.8.8.8",
      "bytes": 100000,
      "packets": 500,
      "pct": 2.0
    }
  ],
  "protocols": [
    {
      "name": "TCP",
      "bytes": 4500000,
      "packets": 14000,
      "pct": 90.0
    }
  ]
}
```


### `GET /flows/export`

Export filtered flow data in CSV or JSON format.

Query params:

| Param | Type | Description |
|---|---|---|
| `format` | string | Output format: `csv` or `json` (default: `csv`) |
| `src_ip` | string | Source IP filter |
| `dst_ip` | string | Destination IP filter |
| `port` | string | Source-or-destination port filter |
| `protocol` | string | Protocol filter (for example `TCP`, `UDP`) |
| `ip` | string | Source-or-destination IP filter |
| `app_proto` | string | Application protocol filter (for example `HTTP`, `DNS`) |
| `app_cat` | string | Application category filter |
| `start` | string | Start time filter (RFC3339) |
| `end` | string | End time filter (RFC3339) |
| `bytes_min` | uint64 | Minimum bytes filter |
| `bytes_max` | uint64 | Maximum bytes filter |
| `tcp_flags` | string | TCP flags filter (for example `S,A`) |
| `tos` | uint8 | Type of Service (ToS) filter |
| `in_iface` | string | Ingress interface filter |
| `out_iface` | string | Egress interface filter |
| `src_as` | uint32 | Source AS number filter |
| `dst_as` | uint32 | Destination AS number filter |
| `src_mac` | string | Source MAC address filter |
| `dst_mac` | string | Destination MAC address filter |
| `vlan` | uint16 | VLAN ID filter |
| `ether_type` | string | EtherType filter (hex or decimal) |
| `exporter` | string | Exporter IP filter |
| `rtt_min` | int64 | Minimum RTT (microseconds) filter |
| `rtt_max` | int64 | Maximum RTT (microseconds) filter |
| `retrans_min` | uint32 | Minimum retransmissions filter |
| `ooo_min` | uint32 | Minimum out-of-order packets filter |
| `loss_min` | uint32 | Minimum packet loss filter |
| `jitter_min` | int64 | Minimum jitter (microseconds) filter |
| `jitter_max` | int64 | Maximum jitter (microseconds) filter |
| `mos_min` | float32 | Minimum MOS filter |

### `GET /reports/export`

Export historical reporting data from SQLite in CSV or JSON format.

Query params:

| Param | Type | Description |
|---|---|---|
| `format` | string | Output format: `csv` or `json` (default: `csv`) |
| `start` | string | Start time filter (`YYYY-MM-DDTHH:MM`) (required) |
| `end` | string | End time filter (`YYYY-MM-DDTHH:MM`) (required) |
| `group_by` | string | Dimension to group by (default: `app_proto`) |

### `GET /healthz`

Liveness endpoint used by health checks and orchestration.

*Note: This endpoint does not require authentication even if Basic Auth is enabled.*

Example response:

```json
{
  "status": "ok",
  "uptime": "2h15m30s"
}
```

### `GET /ping`

Simple ping endpoint to check if the server is running. Returns `pong`.

*Note: This endpoint does not require authentication even if Basic Auth is enabled.*

## Webhooks

When `analysis.webhook_url` is configured, FlowLens will send new advisories to the configured URL via HTTP POST. The payload is sent as `application/json`.

**Example Payload:**

```json
{
  "timestamp": "2023-10-25T10:00:00Z",
  "advisories": [
    {
      "severity": "high",
      "title": "Port Scan Detected",
      "description": "Host 192.168.1.100 is scanning multiple ports on 10.0.0.5.",
      "action": "Investigate host 192.168.1.100 for compromise."
    }
  ]
}
```
