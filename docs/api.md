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
| `app_proto` | string | Application protocol filter (e.g., `DNS`, `HTTPS`) |
| `app_cat` | string | Application category filter (e.g., `Network Services`) |
| `start` | string | Start timestamp filter (RFC3339) |
| `end` | string | End timestamp filter (RFC3339) |
| `bytes_min` | int | Minimum bytes filter |
| `bytes_max` | int | Maximum bytes filter |
| `tcp_flags` | string | TCP flags filter |
| `tos` | int | Type of Service (ToS) / DSCP filter |
| `in_iface` | string | Input interface index filter |
| `out_iface` | string | Output interface index filter |
| `src_as` | int | Source ASN filter |
| `dst_as` | int | Destination ASN filter |
| `src_mac` | string | Source MAC address filter |
| `dst_mac` | string | Destination MAC address filter |
| `vlan` | int | VLAN ID filter |
| `ether_type` | string | EtherType filter (e.g., `IPv4`, `IPv6`) |
| `exporter` | string | Exporter IP filter |
| `rtt_min` | int | Minimum RTT filter (microseconds) |
| `rtt_max` | int | Maximum RTT filter (microseconds) |
| `retrans_min` | int | Minimum retransmissions filter |
| `ooo_min` | int | Minimum out-of-order packets filter |
| `loss_min` | int | Minimum packet loss filter |
| `jitter_min` | int | Minimum jitter filter (microseconds) |
| `jitter_max` | int | Maximum jitter filter (microseconds) |
| `mos_min` | float | Minimum MOS (Mean Opinion Score) filter |

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

### `GET /flows/export`

Exports filtered flows in CSV or JSON format.

Query params:

| Param | Type | Description |
|---|---|---|
| `format` | string | Output format: `csv` or `json` (default: `csv`) |

*Note: This endpoint also accepts all the flow filtering parameters available on `GET /api/flows` (e.g., `src_ip`, `dst_ip`, `protocol`, `bytes_min`, etc.).*

### `GET /reports/export`

Exports filtered reports in CSV or JSON format.

Query params:

| Param | Type | Description |
|---|---|---|
| `format` | string | Output format: `csv` or `json` (default: `csv`) |
| `start` | string | Start timestamp (RFC3339) |
| `end` | string | End timestamp (RFC3339) |
| `src_ip` | string | Source IP filter |
| `dst_ip` | string | Destination IP filter |
| `protocol` | string | Protocol filter |
| `group_by` | string | Grouping field (e.g. `app_proto`, `src_ip`) (default: `app_proto`) |

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
      "severity": "WARNING",
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
  ],
  "top_as": [
    {
      "asn": 15169,
      "name": "Google",
      "bytes": 2500000,
      "packets": 7000,
      "pct": 50.0
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



### `POST /flows/filter-preset/save`

Saves a new filter preset or overwrites an existing one. This endpoint is meant to be called from the web UI and uses form submissions.

Form values:

| Param | Type | Description |
|---|---|---|
| `name` | string | **Required**. The name of the preset. |
| `description` | string | Optional description of the preset. |
| `csrf_token` | string | **Required**. Anti-CSRF token. |

*Note: All query parameters present in the request URL (except `preset_err`, `save_preset`, `load_preset`, and `delete_preset`) are saved as the filter string for the preset.*

Returns a redirect to `/flows` with an optional `preset_err` query parameter indicating success or failure.

### `GET /flows/filter-preset/load`

Loads a saved filter preset and redirects to the flows explorer with the preset's filters applied.

Query params:

| Param | Type | Description |
|---|---|---|
| `name` | string | **Required**. The name of the preset to load. |

Returns an HTTP 303 See Other redirect to `/flows?{preset_filters}`. If the preset is not found or an error occurs, it redirects to `/flows` with a `preset_err` query parameter.

### `POST /flows/filter-preset/delete`

Deletes a saved filter preset. This endpoint is meant to be called from the web UI and uses form submissions.

Form values:

| Param | Type | Description |
|---|---|---|
| `name` | string | **Required**. The name of the preset to delete. |
| `csrf_token` | string | **Required**. Anti-CSRF token. |

Returns an HTTP 303 See Other redirect to `/flows` with an optional `preset_err` query parameter indicating success or failure.

### `POST /capture/start`

Starts a new packet capture session on the specified interface. This endpoint is meant to be called from the web UI and uses form submissions.

Form values:

| Param | Type | Description |
|---|---|---|
| `device` | string | **Required**. The network device to capture from. |
| `bpf` | string | Optional BPF filter. |
| `csrf_token` | string | **Required**. Anti-CSRF token. |

Returns a redirect to `/capture` or an HTTP error on failure.

### `POST /capture/stop`

Stops an active packet capture session. This endpoint is meant to be called from the web UI and uses form submissions.

Form values:

| Param | Type | Description |
|---|---|---|
| `id` | string | **Required**. The session ID to stop. |
| `csrf_token` | string | **Required**. Anti-CSRF token. |

Returns a redirect to `/capture` or an HTTP error on failure.

### `GET /capture/download`

Downloads a generated PCAP file.

Query params:

| Param | Type | Description |
|---|---|---|
| `file` | string | **Required**. The filename of the PCAP to download. |

Returns the requested PCAP file or an HTTP error if the file is not found.

### `POST /pcap/import`

Uploads and imports a PCAP file for analysis. This endpoint is meant to be called from the web UI and accepts `multipart/form-data`.

Form values:

| Param | Type | Description |
|---|---|---|
| `pcap` | file | **Required**. The PCAP file to import. |
| `csrf_token` | string | **Required**. Anti-CSRF token. |

Returns a redirect to `/sessions` or an HTTP error on failure.

## Webhooks

When `analysis.webhook_url` is configured, FlowLens will send new advisories to the configured URL via HTTP POST. The payload is sent as `application/json`.

**Example Payload:**

```json
{
  "timestamp": "2023-10-25T10:00:00Z",
  "advisories": [
    {
      "severity": "WARNING",
      "title": "Port Scan Detected",
      "description": "Host 192.168.1.100 is scanning multiple ports on 10.0.0.5.",
      "action": "Investigate host 192.168.1.100 for compromise."
    }
  ]
}
```
