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

### `GET /api/exporters`

Aggregated exporter-level traffic statistics.

This endpoint does not accept any query parameters.

**Example Response:**

```json
{
  "total_exporters": 1,
  "total_bytes": 1024000,
  "exporters": [
    {
      "ip": "10.0.0.1",
      "bytes": 1024000,
      "packets": 1500,
      "flow_count": 45,
      "pct": 100.0,
      "top_proto": "TCP",
      "first_seen": "2023-10-25T09:50:00Z",
      "last_seen": "2023-10-25T10:00:00Z"
    }
  ]
}
```

### `GET /api/vlans`

Aggregated VLAN-level traffic statistics.

This endpoint does not accept any query parameters.

**Example Response:**

```json
{
  "total_vlans": 2,
  "total_bytes": 1024000,
  "vlans": [
    {
      "id": 100,
      "bytes": 1024000,
      "packets": 1500,
      "flows": 45
    }
  ]
}
```

### `GET /api/macs`

Aggregated MAC-level traffic statistics.

This endpoint does not accept any query parameters.

**Example Response:**

```json
{
  "total_macs": 2,
  "total_bytes": 1024000,
  "macs": [
    {
      "mac": "aa:bb:cc:dd:ee:ff",
      "bytes": 512000,
      "packets": 750,
      "vlan": 100
    }
  ]
}
```

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
