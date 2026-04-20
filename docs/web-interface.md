# Web Interface

After startup, open `http://localhost:8080`.

## Pages

| Page | Path | Description |
|---|---|---|
| Dashboard | `/` | Throughput, top talkers, protocol breakdown, advisory overview |
| Flow Explorer | `/flows` | Search/filter flows, paginate, export |
| Hosts | `/hosts` | Host inventory with traffic and GeoIP context |
| Sessions | `/sessions` | Bidirectional session views with quality metrics |
| Advisories | `/advisories` | Active and resolved advisories |
| Reports | `/reports` | Historical reporting from SQLite data |
| Map | `/map` | Geographic flow visualization |
| Capture | `/capture` | Start/stop capture and download PCAP files |
| VLANs | `/vlans` | VLAN traffic breakdown |
| MACs | `/macs` | MAC-level traffic statistics |
| Counters | `/counters` | sFlow counter summaries |
| Exporters | `/exporters` | Per-exporter comparisons and activity |
| About | `/about` | Runtime status and configuration summary |
