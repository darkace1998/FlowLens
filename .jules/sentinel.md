## 2024-05-11 - Missing Security Headers in Web Server
**Vulnerability:** The custom Go web server in FlowLens was missing standard defense-in-depth security headers like `X-Frame-Options`, `X-Content-Type-Options`, and `Strict-Transport-Security`.
**Learning:** Even internal or admin-focused web interfaces need robust HTTP response headers to prevent clickjacking, MIME sniffing, and to enforce HTTPS for subsequent visits. Custom middleware chains must explicitly include these headers.
**Prevention:** Always verify standard security headers (HSTS, X-Frame-Options, X-Content-Type-Options) are included when configuring a raw `http.Server` and middleware chain in Go, or use an established middleware library like `secure`.
