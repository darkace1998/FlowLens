# Configuration Reference

FlowLens is configured through YAML. Start from `configs/flowlens.yaml`.

## Core Options

| Section | Key | Default | Description |
|---|---|---|---|
| `collector` | `netflow_port` | `2055` | UDP port for NetFlow v5/v9 |
| `collector` | `ipfix_port` | `4739` | UDP port for IPFIX |
| `collector` | `sflow_port` | `6343` | UDP port for sFlow v5 |
| `collector` | `buffer_size` | `65535` | UDP read buffer size (bytes) |
| `collector` | `rate_limit` | `0` | Max packets/sec per exporter IP (`0` = unlimited) |
| `storage` | `ring_buffer_duration` | `10m` | In-memory retention window |
| `storage` | `sqlite_path` | `./flowlens.db` | SQLite file path |
| `storage` | `sqlite_retention` | `72h` | TTL retention window for persisted flows |
| `storage` | `prune_interval` | `15m` | TTL cleanup interval |
| `analysis` | `interval` | `60s` | Analyzer execution interval |
| `analysis` | `top_talkers_count` | `10` | Top talkers tracked |
| `analysis` | `anomaly_baseline_window` | `168h` | Baseline window for anomaly detection |
| `analysis` | `scan_threshold` | `500` | Unique ports in window to flag scan behavior |
| `analysis` | `webhook_url` | _(empty)_ | Advisory webhook endpoint |
| `web` | `listen` | `:8080` | HTTP listen address |
| `web` | `page_size` | `50` | Rows per page in flow explorer |
| `web` | `tls_cert` | _(empty)_ | TLS certificate path |
| `web` | `tls_key` | _(empty)_ | TLS private key path |
| `web` | `username` | _(empty)_ | Basic Auth username |
| `web` | `password` | _(empty)_ | Basic Auth password |

## Example

```yaml
collector:
  netflow_port: 2055
  ipfix_port: 4739
  sflow_port: 6343
  rate_limit: 0

storage:
  ring_buffer_duration: 10m
  sqlite_path: "./flowlens.db"
  sqlite_retention: 72h
  prune_interval: 15m

analysis:
  interval: 60s
  top_talkers_count: 10
  anomaly_baseline_window: 168h
  scan_threshold: 500
  webhook_url: ""

web:
  listen: ":8080"
  page_size: 50
  tls_cert: ""
  tls_key: ""
  username: ""
  password: ""
```
