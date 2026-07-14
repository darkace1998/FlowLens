# Analyzer Reference

FlowLens runs analyzers on a configurable interval (`analysis.interval`) and generates advisories.

| Analyzer | Description |
|---|---|
| Amplification Attack Detector | Detects potential DDoS reflection/amplification attacks by monitoring UDP traffic from common amplification ports |
| Top Talkers | Flags hosts consuming disproportionate bandwidth |
| Protocol Distribution | Detects unusual protocol ratios and insecure protocols |
| Port Scan Detector | Detects reconnaissance patterns by unique-port fanout |
| Network Sweep Detector | Detects hosts connecting to many unique destination IPs |
| ICMP Flood Detector | Detects hosts receiving a large number of ICMP packets |
| SYN Flood Detector | Detects targets receiving excessive TCP SYN packets (potential SYN flood) |
| UDP Flood Detector | Detects targets receiving excessive UDP packets (potential UDP flood) |
| TCP RST Flood Detector | Detects targets receiving excessive TCP RST packets (potential RST flood or backscatter) |
| Brute Force Detector | Detects potential login brute-force attempts based on many distinct connections to common login ports |
| Suspicious TCP Flags Detector | Detects potential stealth port scanning or OS fingerprinting by identifying abnormal TCP flag combinations (e.g. SYN-FIN, XMAS) |
| DNS Tunneling Detector | Detects data exfiltration or malware C2 over DNS by identifying unusually large outbound DNS queries from a single host |
| ICMP Tunneling Detector | Detects data exfiltration or malware C2 over ICMP by identifying unusually large outbound ICMP/ICMPv6 packets from a single host |
| Anomaly Detection | Detects spikes/drops against historical baseline |
| DNS Volume | Flags unusual DNS rates and ratios |
| Flow Asymmetry | Detects directional imbalances between peers |
| Retransmission Detector | Flags elevated TCP retransmission behavior |
| Unreachable Host Detector | Detects repeated tiny flows to unavailable targets |
| New Talker Detector | Identifies newly active hosts |
| Port Concentration | Flags many sources converging on one destination port |
| VoIP Quality Detector | Estimates MOS-like quality for voice/video sessions |
| Long Connection Detector | Flags TCP/UDP connections exceeding a configured duration |
| Beaconing Detector | Detects periodic connection attempts typical of malware C2 beaconing or automated telemetry |
| Broadcast Storm Detector | Detects abnormally high volumes of broadcast or multicast traffic originating from a single source |
| LAND Attack Detector | Identifies spoofed traffic where the source and destination IP addresses are identical |
| Lateral Movement Detector | Identifies hosts connecting to many distinct destination IPs on common administrative and lateral movement ports (e.g. SMB, RDP) |
| Mass Email Detector | Identifies a single source IP connecting to many distinct destination IPs on SMTP ports (potential spam botnet) |

Use `analysis.webhook_url` to forward advisories to external systems.
| Elephant Flow Detector | Identifies single network connections that consume a massive amount of bandwidth, which can cause network congestion and degrade the performance of other flows |
