# FlowLens — Feature Implementation TODO

> This document maps each requested feature to concrete implementation tasks.
> Features already implemented are marked ✅; remaining work is broken into
> actionable items grouped by feature area.

---

## Legend

- ✅ Already implemented
- 🔧 Partially implemented — needs enhancement
- ❌ Not yet implemented

---

## 1. Realtime Network Traffic, Active Flows and Hosts

| Status | Task |
|--------|------|
| ✅ | Collect flows in real time via UDP (NetFlow v5/v9, IPFIX) |
| ✅ | In-memory ring buffer for recent flows (~10 min window) |
| ✅ | Dashboard shows total throughput (bytes/s, packets/s) |
| ✅ | Add an **Active Hosts** view listing unique src/dst IPs currently communicating |
| ✅ | Add an **Active Flows** counter and table showing live (not yet expired) flows |
| ✅ | Add **auto-refresh / WebSocket push** so the dashboard updates without manual reload |
| ✅ | Show per-host bandwidth, packet count, first-seen/last-seen timestamps |

---

## 2. Top Talkers, AS, L7 Application Protocols, Categories

| Status | Task |
|--------|------|
| ✅ | Top 10 talkers by bytes (source and destination) on dashboard |
| ✅ | AS numbers stored in Flow struct (`SrcAS`, `DstAS`) |
| ✅ | Display **Autonomous System** names alongside AS numbers (integrate an AS-name database, e.g. `iptoasn` or Team Cymru bulk lookup) |
| ✅ | Add a **Top AS** view ranked by traffic volume |
| ✅ | Integrate **nDPI** or a port/heuristic-based classifier for **Layer-7 application protocol detection** (HTTP, HTTPS, DNS, SSH, SMTP, etc.) |
| ✅ | Add an **L7 Protocols** dashboard widget showing top application protocols by traffic |
| ✅ | Define a **traffic category taxonomy** (Web, Streaming, Gaming, Social, Cloud, etc.) and map L7 protocols to categories |
| ✅ | Add a **Categories** dashboard widget with per-category byte/packet totals |

---

## 3. Protocol and Application Detection

| Status | Task |
|--------|------|
| ✅ | L3/L4 protocol identification (TCP, UDP, ICMP, GRE, ESP, ICMPv6) |
| ✅ | Protocol distribution analysis in the analysis engine |
| ✅ | Pure-Go heuristic engine for **application protocol detection** via `AppProtocol()` (port-based, 20+ protocols) and `Classify()` method |
| ✅ | Map well-known destination ports to application names (port 443→HTTPS, 53→DNS, 22→SSH, 80→HTTP, 25→SMTP, etc.) |
| ✅ | Extend the `Flow` struct with `AppProto string` and `AppCat string` fields, auto-populated by `Classify()` |
| ✅ | Store and query application protocol data in SQLite (`app_proto`, `app_category` columns with migration) |
| ✅ | Add protocol/application columns to the Flow Explorer table |

---

## 4. Custom Reports on Historical Data with Metrics and Trends

| Status | Task |
|--------|------|
| ✅ | SQLite stores historical flows with configurable retention (default 72 h) |
| ✅ | Flow Explorer supports filtering by src IP, dst IP, port, protocol |
| ✅ | **Reports** page with configurable date range, group-by (8 dimensions), and aggregation (sum bytes, avg throughput, count flows) |
| ✅ | **Trend lines** — CSS bar chart showing time-series traffic over selected period with auto-bucketing |
| ✅ | **CSV / JSON export** via `/reports/export` endpoint with Content-Disposition headers |
| ❌ | Support **scheduled reports** (e.g., daily/weekly email or file dump) |
| ❌ | Add **comparison mode** (compare two time ranges side-by-side) |

---

## 5. Application Latencies, Round Trip Time (RTT), Throughput

| Status | Task |
|--------|------|
| ✅ | Per-flow throughput computed and stored via `CalcThroughput()` (Bytes×8 / Duration) |
| ✅ | Parse **RTT** from NetFlow v9 / IPFIX option templates — `RTTMicros` field on Flow struct, stored in SQLite `rtt_us` column |
| ✅ | Compute **application response time** via bidirectional flow correlation (`StitchFlows`) |
| ✅ | **Flow stitching** correlates bidirectional flows by canonical 5-tuple reversal (`FlowKey`) |
| ✅ | Store and display RTT and throughput metrics in Flow Explorer (Throughput/RTT columns) and Dashboard |
| ✅ | **Throughput & RTT Percentiles** dashboard widget with p50, p95, p99 breakdowns |

---

## 6. TCP Metrics: Retransmissions, Out of Order, Packet Loss

| Status | Task |
|--------|------|
| 🔧 | Retransmission detector exists (heuristic based on packet-to-byte ratio) |
| ❌ | Parse **TCP retransmission counters** from IPFIX IEs (IE 321 `tcpRetransmissionCount`, IE 322 `tcpSynTotalCount`, etc.) when exported by the device |
| ❌ | Parse **out-of-order** and **packet-loss** counters from IPFIX performance IEs |
| ❌ | Add a **TCP Health** dashboard widget summarizing retransmission rates, OOO, and loss across top flows |
| ❌ | Store TCP quality metrics per flow in SQLite |
| ❌ | Generate advisories when retransmission or loss rates exceed configurable thresholds |

---

## 7. Multimedia and VoIP Metrics: Jitter, MOS

| Status | Task |
|--------|------|
| ❌ | Identify **VoIP / RTP flows** (by port range 10000–20000, or SIP signaling on 5060/5061, or DPI) |
| ❌ | Parse **jitter** from IPFIX IEs (e.g., IE 387 `rtp_jitter`) if exported |
| ❌ | Compute **estimated MOS** from jitter, latency, and packet loss using the E-model (ITU-T G.107) |
| ❌ | Add a **VoIP Quality** dashboard page showing active calls, jitter, MOS, packet loss |
| ❌ | Generate advisories when MOS drops below configurable thresholds (e.g., < 3.5) |

---

## 8. Hosts Geolocalisation

| Status | Task |
|--------|------|
| ❌ | Integrate a **GeoIP database** (MaxMind GeoLite2 or ip2location-lite) |
| ❌ | Add `Country`, `City`, `Latitude`, `Longitude` to enriched flow/host metadata |
| ❌ | Add a **Geo Map** page rendering host locations on a world map (e.g., Leaflet.js with OpenStreetMap tiles) |
| ❌ | Show country flags or codes in the Flow Explorer and Top Talkers tables |
| ❌ | Add a config option for the GeoIP database path and auto-update schedule |

---

## 9. Multi-Interface Support: Mirror, TAP, Flow Collection

| Status | Task |
|--------|------|
| ✅ | `InputIface` and `OutputIface` stored per flow |
| ✅ | Dual-port listening (NetFlow + IPFIX simultaneously) |
| ❌ | Add **interface name resolution** via SNMP (map ifIndex → interface name/description) |
| ❌ | Add per-interface traffic views on the dashboard (filter/group by interface) |
| ❌ | Support **mirror/SPAN port** ingestion via raw packet capture (libpcap/gopacket) |
| ❌ | Support **TAP** interfaces as packet sources alongside flow collection |
| ❌ | Allow multiple collector instances bound to different interfaces in config |

---

## 10. Packet Capture

| Status | Task |
|--------|------|
| ❌ | Integrate **gopacket / libpcap** for raw packet capture on configurable interfaces |
| ❌ | Decode Ethernet → IP → TCP/UDP headers to produce flow-like records from packets |
| ❌ | Add a **Capture** page where users can start/stop captures with BPF filter expressions |
| ❌ | Store captured packets in **PCAP files** (ring-buffer of files with size/time rotation) |
| ❌ | Allow **download of PCAP** files from the web UI |
| ❌ | Add config section for capture interfaces, snap length, and BPF filters |

---

## 11. Flow Collection from NetFlow and sFlow Exporters

| Status | Task |
|--------|------|
| ✅ | NetFlow v5 decoder |
| ✅ | NetFlow v9 decoder (template-based) |
| ✅ | IPFIX (v10) decoder (template-based) |
| ❌ | Implement **sFlow v5** decoder (RFC 3176) — sample-based flow records |
| ❌ | Add config for sFlow listen port (default 6343) |
| ❌ | Support **sFlow counter samples** for interface utilization |
| ❌ | Show exporter source in Flow Explorer (which device/interface exported each flow) |

---

## 12. HTML5 Web User Interface

| Status | Task |
|--------|------|
| ✅ | Server-rendered XHTML templates (layout, dashboard, flows, advisories, about) |
| ✅ | Minimal CSS stylesheet |
| ❌ | Migrate templates from XHTML to **HTML5** with semantic elements (`<section>`, `<nav>`, `<main>`, `<article>`) |
| ❌ | Add **interactive charts** (throughput over time, protocol pie, top talkers bar) using a lightweight JS charting library (e.g., Chart.js or uPlot) |
| ❌ | Add **auto-refresh** via JavaScript `fetch()` polling or WebSocket for live dashboard updates |
| ❌ | Add **dark mode** toggle with CSS custom properties |
| ❌ | Improve **responsive design** for mobile and tablet viewports |
| ❌ | Add **favicon** and proper meta tags |

---

## 13. REST API for Third-Party Integration

| Status | Task |
|--------|------|
| ❌ | Create `/api/v1/flows` — list/search flows (JSON, with pagination, filtering, sorting) |
| ❌ | Create `/api/v1/flows/{id}` — get a single flow by ID |
| ❌ | Create `/api/v1/stats` — current throughput, active hosts, flow counts |
| ❌ | Create `/api/v1/top-talkers` — top N talkers (configurable) |
| ❌ | Create `/api/v1/protocols` — protocol distribution |
| ❌ | Create `/api/v1/advisories` — list advisories (filter by severity, status) |
| ❌ | Create `/api/v1/hosts` — host list with aggregate stats |
| ❌ | Create `/api/v1/interfaces` — per-interface statistics |
| ❌ | Add **API key authentication** (Bearer token in config) |
| ❌ | Add **CORS** headers for cross-origin access |
| ❌ | Add **OpenAPI / Swagger** spec for the REST API |

---

## 14. Full Layer-2 Support and Statistics

| Status | Task |
|--------|------|
| ❌ | Extend `Flow` struct with **L2 fields**: `SrcMAC`, `DstMAC`, `VLAN`, `EtherType` |
| ❌ | Parse L2 fields from IPFIX IEs (IE 56 `sourceMacAddress`, IE 80 `destinationMacAddress`, IE 58 `vlanId`) |
| ❌ | Parse L2 from raw packet captures (gopacket Ethernet layer) |
| ❌ | Add **VLAN statistics** view (traffic per VLAN, top hosts per VLAN) |
| ❌ | Add MAC address tables and L2 topology awareness |
| ❌ | Store L2 metadata in SQLite |

---

## 15. Tunnel Decapsulation (GTP and GRE)

| Status | Task |
|--------|------|
| 🔧 | GRE (protocol 47) recognized as a protocol type |
| ❌ | Implement **GRE decapsulation** — parse inner IP/TCP/UDP headers from GRE-encapsulated packets |
| ❌ | Implement **GTP-U decapsulation** (UDP port 2152) — parse inner IP from GPRS tunnels |
| ❌ | Implement **GTP-C** parsing for session correlation (TEID mapping) |
| ❌ | Add `TunnelType`, `InnerSrcAddr`, `InnerDstAddr` fields to `Flow` |
| ❌ | Show both inner and outer flow data in the Flow Explorer |
| ❌ | Support **VXLAN** and **MPLS** decapsulation |

---

## 16. Export to ElasticSearch and Big Data Systems

| Status | Task |
|--------|------|
| ❌ | Add an **Elasticsearch exporter** (bulk index flows to ES using the REST API) |
| ❌ | Add config for ES endpoint, index pattern, bulk size, flush interval |
| ❌ | Add a **Kafka producer** for streaming flows to big data pipelines |
| ❌ | Add a **syslog exporter** (RFC 5424) for SIEM integration |
| ❌ | Add a **CSV file exporter** with rotation |
| ❌ | Implement a pluggable **exporter interface** so new backends can be added easily |

---

## 17. Interactive Exploration of Historical Data (ClickHouse)

| Status | Task |
|--------|------|
| ❌ | Add a **ClickHouse storage backend** (insert flows into ClickHouse for long-term analytics) |
| ❌ | Define ClickHouse schema (MergeTree engine, partition by day, order by timestamp + src + dst) |
| ❌ | Add config for ClickHouse DSN, table name, batch size, flush interval |
| ❌ | Add a **Historical Explorer** page with time-range queries, drill-down, and aggregation powered by ClickHouse |
| ❌ | Support **Grafana** integration via ClickHouse data source |

---

## 18. Behavioural Checks and Alert Notifications

| Status | Task |
|--------|------|
| ✅ | 10 analyzers producing advisories (top talkers, scans, anomalies, DNS, asymmetry, retransmissions, unreachable, new talkers, port concentration, protocol mix) |
| ✅ | Advisory model with severity levels (CRITICAL, WARNING, INFO) |
| ✅ | Advisories page in web UI |
| ❌ | Add **webhook notifications** (POST advisory JSON to configurable URLs) |
| ❌ | Add **email notifications** (SMTP config, per-severity subscription) |
| ❌ | Add **Slack / Microsoft Teams** integration |
| ❌ | Add **syslog alert forwarding** |
| ❌ | Add **alert rules engine** — user-defined threshold rules (e.g., "alert if host X exceeds 1 Gbps") |
| ❌ | Add **alert suppression / deduplication** (don't re-alert for same condition within cooldown window) |
| ❌ | Add **alert history / audit log** persisted in SQLite |

---

## 19. SNMP v1/v2c/v3 Support

| Status | Task |
|--------|------|
| ❌ | Integrate a Go SNMP library (e.g., `github.com/gosnmp/gosnmp`) |
| ❌ | Implement **SNMP polling** for interface counters (ifInOctets, ifOutOctets, ifSpeed, ifOperStatus) |
| ❌ | Implement **SNMP interface table walk** to resolve ifIndex → interface name/description/alias |
| ❌ | Support **SNMPv1**, **SNMPv2c**, and **SNMPv3** (auth + priv) |
| ❌ | Add device inventory config (IP, community/credentials, poll interval) |
| ❌ | Correlate SNMP interface data with flow `InputIface`/`OutputIface` |
| ❌ | Add a **Devices** page showing polled device status, interface utilization, and errors |
| ❌ | Support **SNMP traps** (v1/v2c/v3) for event-driven alerts |

---

## 20. Identity Management and VPN Correlation

| Status | Task |
|--------|------|
| ❌ | Add **user authentication** to the web UI (login page, session cookies, bcrypt passwords) |
| ❌ | Add **role-based access control** (admin, operator, viewer) |
| ❌ | Support **LDAP / Active Directory** authentication |
| ❌ | Support **RADIUS** accounting integration (map IP → username from RADIUS Start/Stop records) |
| ❌ | Support **VPN session correlation** (import VPN session logs to map tunnel IPs to user identities) |
| ❌ | Add an **Identity** column in the Flow Explorer (show username instead of / alongside IP) |
| ❌ | Add config for identity sources (LDAP server, RADIUS server, VPN log path) |

---

## 21. Active Monitoring and SLA Reporting

| Status | Task |
|--------|------|
| ❌ | Implement **ICMP ping probes** to configurable targets (latency, jitter, packet loss) |
| ❌ | Implement **TCP connect probes** (measure connection establishment time to critical services) |
| ❌ | Implement **HTTP(S) probes** (response time, status code, certificate expiry) |
| ❌ | Define **SLA targets** in config (e.g., "target X must respond in < 100 ms, 99.9% uptime") |
| ❌ | Add an **SLA Dashboard** page showing current compliance, violation history, and uptime percentage |
| ❌ | Generate **SLA reports** (daily/weekly/monthly) with availability and latency statistics |
| ❌ | Trigger alerts when SLA thresholds are breached |

---

## Cross-Cutting Concerns

These items support multiple features above:

| Status | Task |
|--------|------|
| ✅ | Structured leveled logging |
| ✅ | YAML configuration |
| ✅ | Graceful shutdown |
| ✅ | Docker support |
| ❌ | Add **configuration hot-reload** (watch YAML file for changes) |
| ❌ | Add **Prometheus metrics endpoint** (`/metrics`) for external monitoring |
| ❌ | Add **health check endpoint** (`/healthz`) |
| ❌ | Add **TLS support** for the web server (HTTPS) |
| ❌ | Add **rate limiting** on API endpoints |
| ❌ | Add **database migrations** for schema evolution |
| ❌ | Add **CI/CD pipeline** (GitHub Actions: build, test, lint, release) |
| ❌ | Add **integration tests** with mock NetFlow/sFlow exporters |

---

## Suggested Implementation Order

A recommended sequence that builds on existing capabilities incrementally:

1. **REST API** (§13) — unlocks third-party integration and decouples frontend
2. **HTML5 Web UI upgrade** (§12) — interactive charts, auto-refresh
3. **L7 Application & Protocol Detection** (§2, §3) — port-based first, DPI later
4. **Custom Reports & Trends** (§4) — leverages existing SQLite data
5. **sFlow support** (§11) — broadens collector input sources
6. **GeoIP mapping** (§8) — enriches existing flow data
7. **TCP metrics** (§6) — extends IPFIX field parsing
8. **Behavioural alerts & notifications** (§18) — extends existing analysis engine
9. **SNMP** (§19) — interface enrichment and device monitoring
10. **Elasticsearch / ClickHouse export** (§16, §17) — long-term storage
11. **Latency & RTT** (§5) — requires flow stitching
12. **Packet capture** (§10) — new subsystem, gopacket dependency
13. **Layer-2 support** (§14) — extends flow model
14. **Tunnel decapsulation** (§15) — GRE/GTP parsing
15. **VoIP / MOS** (§7) — niche, depends on DPI and latency
16. **Active monitoring & SLA** (§21) — new probe subsystem
17. **Identity & VPN** (§20) — requires external system integration
18. **Multi-interface & TAP** (§9) — depends on packet capture
