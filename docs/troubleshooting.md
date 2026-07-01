# Troubleshooting

If you encounter issues while running FlowLens, check the common problems and solutions below.

## No Flows Are Visible

**Symptoms:** The web dashboard shows zero flows, and the `/api/flows` endpoint returns an empty array.

**Solutions:**
1. **Check Exporter Configuration:** Ensure your network devices are actively sending NetFlow, IPFIX, or sFlow traffic to the correct IP address and port that FlowLens is listening on (default: `2055` for NetFlow, `4739` for IPFIX, `6343` for sFlow).
2. **Firewall Rules:** Verify that the host running FlowLens allows incoming UDP traffic on the configured collector ports.
   ```bash
   # Example: Check if port 2055 is open (Linux)
   sudo iptables -L -n | grep 2055
   ```
3. **Docker Port Mapping:** If running via Docker, ensure you have published the UDP ports using `-p 2055:2055/udp -p 4739:4739/udp -p 6343:6343/udp`. Note the `/udp` is critical.
4. **Packet Capture:** Use `tcpdump` on the host to verify UDP packets are actually arriving:
   ```bash
   sudo tcpdump -i any udp port 2055
   ```

## High Memory Usage

**Symptoms:** The FlowLens process consumes more memory than expected, potentially triggering OOM (Out Of Memory) kills.

**Solutions:**
1. **Reduce Ring Buffer Capacity:** The in-memory ring buffer stores recent flows. Decrease `storage.ring_buffer_capacity` (default: `10000`) in your configuration to retain fewer flows in RAM.
2. **Reduce Ring Buffer Duration:** Decrease `storage.ring_buffer_duration` (default: `10m`) to keep flows in memory for a shorter time.
3. **Check Traffic Volume:** Very high flow rates will naturally consume more memory. Refer to the Resource Sizing Guidance in [`getting-started.md`](getting-started.md).

## Missing or Empty GeoIP Data

**Symptoms:** IP addresses do not show country or city information, or always display as "Local" or "Unknown".

**Solutions:**
1. **Built-in Ranges:** FlowLens includes a small set of well-known IP ranges built-in. If you rely on this, most traffic will not be geolocated.
2. **Download a GeoIP Database:** For full geolocation, download a compatible CSV database (like IP2Location LITE DB5). Make sure to extract the downloaded ZIP file to get the underlying CSV file.
3. **Configure the Path:** Set `storage.geoip_path` in `flowlens.yaml` to point to the CSV file.
4. **Docker Mount:** If using Docker, ensure you mount the CSV file into the container and update `geoip_path` accordingly (e.g., `-v /path/to/db.csv:/app/db.csv` and set `geoip_path: "/app/db.csv"`).

## Cannot Access Web Interface

**Symptoms:** Connecting to `http://localhost:8080` times out or fails.

**Solutions:**
1. **Listen Address:** Check `web.listen` in your config. If it is set to `localhost:8080` or `127.0.0.1:8080`, it will only be accessible from the machine itself. Change it to `:8080` to listen on all interfaces.
2. **Docker Port Mapping:** Verify `-p 8080:8080` was included in your `docker run` command (TCP is the default, which is correct).
3. **Firewall:** Ensure the host firewall allows incoming TCP connections on port 8080.
4. **Basic Auth:** If Basic Auth is enabled but you forgot the credentials, check `web.username` and `web.password` in the configuration.
5. **TLS Configuration:** If `web.tls_cert` and `web.tls_key` are configured, you must access the dashboard via `https://`.

## Advisories Webhook Not Firing

**Symptoms:** Advisories appear in the dashboard, but external systems are not receiving webhook POST requests.

**Solutions:**
1. **Check Webhook URL:** Ensure `analysis.webhook_url` is configured and properly formatted (e.g., `https://example.com/webhook`).
2. **Network Reachability:** Verify that the FlowLens host can reach the webhook URL.
3. **HTTP Status Codes:** FlowLens logs warnings if the webhook server returns a status code >= 300. Check the FlowLens console output or logs.
4. **Timeouts:** The webhook client has a 10-second timeout. If the receiving server is slow to respond, the request will fail.

## Log Output

Reviewing the application logs is often the fastest way to diagnose issues. Run FlowLens directly or check Docker logs:
```bash
docker logs -f flowlens
```
Look for `ERROR` or `WARN` level messages that might indicate configuration parsing issues, database connection failures, or bind address conflicts.
