# Packet Capture and PCAP Import

FlowLens includes built-in capabilities for raw packet capture and manual PCAP ingestion. This allows you to augment standard NetFlow/IPFIX analysis with deep-packet inspection or historical analysis of raw traffic.

## Packet Capture

FlowLens can capture packets directly from network interfaces (mirror ports or taps) and store them as rotating PCAP files on disk. Captured packets are not automatically ingested into the FlowLens flow storage; they are saved for external analysis or manual import.

### Configuration

To enable packet capture, configure the `capture` section in your `flowlens.yaml` file:

```yaml
capture:
  interfaces: ["eth0", "eth1"]  # Interfaces the web UI is allowed to capture on
  snaplen: 65535                # Maximum bytes to capture per packet
  dir: "./captures"             # Directory to store generated PCAP files
  max_size_mb: 100              # Maximum file size (MB) before rotation
  max_files: 10                 # Maximum number of rotated files to retain
```

### Web Interface Usage

1. Navigate to the **Capture** page (`/capture`) in the web interface.
2. Select a target interface (must be one of the `capture.interfaces` defined in the config).
3. (Optional) Provide a BPF (Berkeley Packet Filter) string (e.g., `tcp port 80`) to limit the captured traffic.
4. Click **Start Capture**. A new background capture session will begin.
5. Active sessions will appear in the "Active Sessions" table.
6. Click **Stop** to terminate a running capture.
7. Generated `.pcap` files appear in the "Available Files" table and can be downloaded directly from the dashboard.

## PCAP Import

If you have existing `.pcap` files (e.g., from `tcpdump` or Wireshark) and want FlowLens to analyze them, you can import them. FlowLens will read the packets, assemble them into flows, and insert them into the standard in-memory storage (and SQLite if enabled), just as if they had arrived via NetFlow/IPFIX.

### Web Interface Usage

1. Navigate to the **Sessions** page (`/sessions`).
2. At the top of the page, locate the **Import PCAP** section.
3. Select a `.pcap` file from your local machine.
4. Click **Upload & Analyze**.
5. FlowLens will stream the file directly from the browser, process the packets, and populate the Flow Explorer and dashboards with the resulting flow records.

*Note: Imported PCAP traffic is timestamped based on the original packet capture times. Depending on your `storage.ring_buffer_duration` and `storage.sqlite_retention` settings, very old PCAP data may be immediately pruned upon import.*
