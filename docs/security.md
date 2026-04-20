# Security

## Authentication

FlowLens supports HTTP Basic Auth. Configure `web.username` and `web.password`:

```yaml
web:
  username: "admin"
  password: "change-me"
```

If both values are empty, auth is disabled.

## TLS

Built-in TLS is enabled when both `web.tls_cert` and `web.tls_key` are set:

```yaml
web:
  tls_cert: "/path/to/cert.pem"
  tls_key: "/path/to/key.pem"
```

Minimum TLS version is 1.2.

For production TLS termination and certificate lifecycle management, see [`reverse-proxy.md`](reverse-proxy.md).

## CSRF Protection

State-changing POST endpoints use single-use CSRF tokens (for example `/capture/start`, `/capture/stop`, `/pcap/import`).

## Content Security Policy

Responses include CSP headers restricting resource origins:

```text
default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';
img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'
```

## Network Hardening

Collector UDP ports process untrusted input. Restrict source IPs at the firewall where possible:

```bash
iptables -A INPUT -p udp --dport 2055 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p udp --dport 2055 -j DROP
```

Apply equivalent rules for IPFIX (`4739`) and sFlow (`6343`).

## Runtime Hardening

- Use `collector.rate_limit` to reduce abuse from noisy or malicious exporters
- Run behind a reverse proxy for TLS, auth layering, and request controls
- Keep storage retention bounded to avoid uncontrolled disk growth
