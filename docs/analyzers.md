# Analyzer Reference

FlowLens runs analyzers on a configurable interval (`analysis.interval`) and generates advisories.

| Analyzer | Description |
|---|---|
| Top Talkers | Flags hosts consuming disproportionate bandwidth |
| Protocol Distribution | Detects unusual protocol ratios and insecure protocols |
| Scan Detector | Detects reconnaissance patterns by unique-port fanout |
| Anomaly Detector | Detects spikes/drops against historical baseline |
| DNS Volume | Flags unusual DNS rates and ratios |
| Flow Asymmetry | Detects directional imbalances between peers |
| Retransmission Detector | Flags elevated TCP retransmission behavior |
| Unreachable Detector | Detects repeated tiny flows to unavailable targets |
| New Talker Detector | Identifies newly active hosts |
| Port Concentration | Flags many sources converging on one destination port |
| VoIP Quality | Estimates MOS-like quality for voice/video sessions |

Use `analysis.webhook_url` to forward advisories to external systems.
