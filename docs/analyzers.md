# Analyzer Reference

FlowLens runs analyzers on a configurable interval (`analysis.interval`) and generates advisories.

| Analyzer | Description |
|---|---|
| Amplification Attack Detector | Detects potential DDoS reflection/amplification attacks by monitoring UDP traffic from common amplification ports |
| Top Talkers | Flags hosts consuming disproportionate bandwidth |
| Protocol Distribution | Detects unusual protocol ratios and insecure protocols |
| Scan Detector | Detects reconnaissance patterns by unique-port fanout |
| Network Sweep Detector | Detects hosts connecting to many unique destination IPs |
| ICMP Flood Detector | Detects hosts receiving a large number of ICMP packets |
| SYN Flood Detector | Detects targets receiving excessive TCP SYN packets (potential SYN flood) |
| Brute Force Detector | Detects potential login brute-force attempts based on many distinct connections to common login ports |
| Anomaly Detector | Detects spikes/drops against historical baseline |
| DNS Volume | Flags unusual DNS rates and ratios |
| Flow Asymmetry | Detects directional imbalances between peers |
| Retransmission Detector | Flags elevated TCP retransmission behavior |
| Unreachable Detector | Detects repeated tiny flows to unavailable targets |
| New Talker Detector | Identifies newly active hosts |
| Port Concentration | Flags many sources converging on one destination port |
| VoIP Quality | Estimates MOS-like quality for voice/video sessions |
| Long Connection Detector | Flags TCP/UDP connections exceeding a configured duration |

Use `analysis.webhook_url` to forward advisories to external systems.
