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
| `collector` | `interface_names` | `{}` | Map of ifIndex to human-readable name (e.g. `{"1": "eth0"}`) |
| `collector` | `interfaces` | `[]` | List of multiple collector instances bound to different addresses (see Interface Options) |
| `storage` | `ring_buffer_duration` | `10m` | In-memory retention window |
| `storage` | `ring_buffer_capacity` | `10000` | Max records in ring buffer |
| `storage` | `sqlite_path` | `./flowlens.db` | SQLite file path |
| `storage` | `sqlite_retention` | `72h` | TTL retention window for persisted flows |
| `storage` | `prune_interval` | `15m` | TTL cleanup interval |
| `storage` | `geoip_path` | _(empty)_ | Path to CSV GeoIP database (e.g. IP2Location LITE) |
| `analysis` | `interval` | `60s` | Analyzer execution interval |
| `analysis` | `top_talkers_count` | `10` | Top talkers tracked |
| `analysis` | `anomaly_baseline_window` | `168h` | Baseline window for anomaly detection |
| `analysis` | `scan_threshold` | `500` | Unique ports in window to flag scan behavior |
| `analysis` | `sweep_threshold` | `250` | Unique target IPs in window to flag network sweep behavior |
| `analysis` | `query_window` | _(varies)_ | Analysis query window (defaults to `ring_buffer_duration`) |
| `analysis` | `dns_rate_threshold` | `100` | DNS flows/min to trigger advisory |
| `analysis` | `dns_ratio_threshold` | `30` | DNS flow percentage to trigger advisory |
| `analysis` | `retrans_rate_threshold`| `1.0` | Retransmission % to trigger advisory |
| `analysis` | `retrans_critical_threshold`| `5.0` | Critical retransmission % |
| `analysis` | `asymmetry_threshold` | `10.0` | Traffic ratio imbalance to trigger advisory |
| `analysis` | `mos_warning_threshold` | `3.5` | MOS below this triggers warning |
| `analysis` | `mos_critical_threshold` | `3.0` | MOS below this triggers critical |
| `analysis` | `top_talker_percent` | `25` | Bandwidth % above which top talker triggers advisory |
| `analysis` | `long_connection_threshold` | `1h` | Threshold duration to flag long connections |
| `analysis` | `webhook_url` | _(empty)_ | Advisory webhook endpoint |
| `web` | `listen` | `:8080` | HTTP listen address |
| `web` | `page_size` | `50` | Rows per page in flow explorer |
| `web` | `tls_cert` | _(empty)_ | TLS certificate path |
| `web` | `tls_key` | _(empty)_ | TLS private key path |
| `web` | `username` | _(empty)_ | Basic Auth username |
| `web` | `password` | _(empty)_ | Basic Auth password |
| `capture` | `interfaces` | `[]` | Network interfaces available for capture (e.g. `["eth0", "eth1"]`) |
| `capture` | `snaplen` | `65535` | Packet snapshot length |
| `capture` | `dir` | `./captures` | Directory to store PCAP files |
| `capture` | `max_size_mb` | `100` | Max PCAP file size in MB before rotation |
| `capture` | `max_files` | `10` | Max number of PCAP files to keep |

## Interface Options (Collector `interfaces` items)

| Key | Default | Description |
|---|---|---|
| `name` | _(empty)_ | Human-readable name (e.g. "WAN", "LAN") |
| `listen` | _(empty)_ | Bind address (e.g. ":2055") |
| `type` | `netflow` | Type of listener: `netflow`, `mirror`, or `tap` |
| `device` | _(empty)_ | Network device for mirror/tap mode (e.g. "eth1") |
| `bpf` | _(empty)_ | Optional BPF filter for mirror/tap capture |
| `snaplen` | `65535` | Packet snapshot length for mirror/tap |

## Example

```yaml
collector:
  netflow_port: 2055
  ipfix_port: 4739
  sflow_port: 6343
  rate_limit: 0
  interface_names:
    "1": "eth0"
    "2": "eth1"
  interfaces:
    - name: "WAN Mirror"
      type: "mirror"
      device: "eth1"
      snaplen: 65535

storage:
  ring_buffer_duration: 10m
  ring_buffer_capacity: 10000
  sqlite_path: "./flowlens.db"
  sqlite_retention: 72h
  prune_interval: 15m
  geoip_path: ""

analysis:
  interval: 60s
  top_talkers_count: 10
  anomaly_baseline_window: 168h
  scan_threshold: 500
  sweep_threshold: 250
  dns_rate_threshold: 100
  dns_ratio_threshold: 30
  retrans_rate_threshold: 1.0
  retrans_critical_threshold: 5.0
  asymmetry_threshold: 10.0
  mos_warning_threshold: 3.5
  mos_critical_threshold: 3.0
  top_talker_percent: 25
  long_connection_threshold: 1h
  webhook_url: ""

web:
  listen: ":8080"
  page_size: 50
  tls_cert: ""
  tls_key: ""
  username: ""
  password: ""

capture:
  interfaces: ["eth0", "eth1"]
  snaplen: 65535
  dir: "./captures"
  max_size_mb: 100
  max_files: 10
```
