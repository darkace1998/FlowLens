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

### `GET /api/hosts`

Aggregated host-level traffic statistics.

### `GET /api/sessions`

Bidirectional session aggregation with packet/byte stats and quality fields.

### `GET /api/advisories`

Active and resolved advisories with severity, context, and action guidance.

### `GET /api/dashboard`

Dashboard summary payload:

- totals (`bytes`, `packets`, `flow_count`)
- live rates (`bps`, `pps`)
- active host/flow counts
- top source/destination lists
- protocol distribution

### `GET /healthz`

Liveness endpoint used by health checks and orchestration.

Example response:

```json
{
  "status": "ok",
  "uptime": "2h15m30s"
}
```
