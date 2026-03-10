# FlowLens — Project TODO

> A prioritized backlog generated from a full codebase deep-dive.
> Items are grouped by area and tagged **P0** (critical / blocking),
> **P1** (high-value), **P2** (nice-to-have), or **P3** (future / research).

---

## 🔒 Security & Hardening

- [ ] **P0** — Add authentication / authorization layer (even basic HTTP Basic Auth or token-based)
  — Currently anyone with network access to port 8080 can view all flow data and control captures.
- [ ] **P1** — Add CSRF tokens to state-changing endpoints (`/capture/start`, `/capture/stop`, `/pcap/import`)
- [ ] **P1** — Bundle Chart.js as a local static asset instead of loading from `cdn.jsdelivr.net`
  — Eliminates CDN availability risk and supply-chain attack surface (see `bug.md` #7).
- [ ] **P1** — Add TLS support (built-in or document reverse-proxy setup with example configs)
- [ ] **P2** — Add rate-limiting on the UDP collector ports to mitigate amplification / DoS
- [ ] **P2** — Run the container as a non-root user
  ```dockerfile
  RUN addgroup -S flowlens && adduser -S flowlens -G flowlens
  USER flowlens
  ```
- [ ] **P2** — Pin Docker base images by digest for reproducible builds
- [ ] **P3** — Add Content-Security-Policy headers to the web server

---

## 🧪 Testing & Quality

- [ ] **P0** — Add `go test ./...` step to the GitHub Actions release workflow — currently Docker images ship without any test gate
- [ ] **P1** — Add a `golangci-lint` configuration (`.golangci.yml`) and integrate it into CI
- [ ] **P1** — Add integration / end-to-end tests (collector → storage → web handler round-trip)
- [ ] **P2** — Add Go benchmark tests (`Benchmark*`) for hot paths: ring buffer insert/query, flow stitching, protocol decoders
- [ ] **P2** — Add fuzz tests (`Fuzz*`) for protocol decoders (`netflowv5.go`, `netflowv9.go`, `ipfix.go`, `sflow.go`, `pcap.go`) — these parse untrusted network input
- [ ] **P2** — Set up code coverage reporting (e.g. Codecov) in CI
- [ ] **P3** — Add error-injection / chaos tests for storage failures (SQLite disk full, corrupt WAL)

---

## 🚀 CI / CD

- [ ] **P1** — Add a CI workflow that runs on every push / PR (not only on `v*` tags):
  - `go vet ./...`
  - `go test -race ./...`
  - `golangci-lint run`
- [ ] **P1** — Produce cross-compiled binary artifacts (Linux amd64/arm64, macOS, Windows) as GitHub Release assets alongside the Docker image
- [ ] **P2** — Add SBOM generation and vulnerability scanning (e.g. Trivy, Grype) to the Docker build
- [ ] **P2** — Sign container images with `cosign`
- [ ] **P2** — Auto-generate release notes / changelog from commit history
- [ ] **P3** — Add a scheduled dependency-update workflow (Dependabot or Renovate)

---

## 🌐 Web UI & Accessibility

- [ ] **P1** — Add keyboard-focus indicators to all interactive elements (links, buttons, inputs)
  ```css
  a:focus, button:focus, input:focus, select:focus {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
  }
  ```
- [ ] **P1** — Add icons or text prefixes to severity badges so color is not the only differentiator (accessibility for colorblind users)
- [ ] **P2** — Add request timeouts / context deadlines to web handlers to prevent hung requests on slow storage queries
- [ ] **P2** — Make chart container heights responsive (percentage / `clamp()`) instead of fixed `280px` / `220px`
- [ ] **P2** — Improve dark-mode contrast for muted text (`--muted: #8b949e` → `#a8b3ba` or similar to meet WCAG AA 4.5:1 contrast ratio against `--bg: #0d1117`)
- [ ] **P3** — Add a loading spinner / skeleton screen for pages that query large datasets
- [ ] **P3** — Add `aria-label` attributes to the hamburger menu toggle and other icon-only controls

---

## 📊 Features & Functionality

- [ ] **P1** — JSON REST API for programmatic access to flows, hosts, sessions, and advisories
- [ ] **P1** — Alerting integrations — send advisories to webhook, email, Slack, or PagerDuty
- [ ] **P1** — sFlow counter sample support (already decoded but not surfaced in the UI — show interface utilisation from sFlow counters)
- [ ] **P2** — Flow export — allow downloading filtered flow data as CSV or JSON from the flow explorer
- [ ] **P2** — Configurable analyzer thresholds via the config file (top-talker %, scan port count, DNS volume, etc. are currently hardcoded)
- [ ] **P2** — SNMP enrichment — resolve ifIndex to interface name and device hostname
- [ ] **P2** — Streaming PCAP import progress (currently blocks until the entire file is parsed)
- [ ] **P2** — Dashboard time-range selector (last 5m / 15m / 1h / 6h / 24h)
- [ ] **P3** — Multi-exporter view — group and compare flows by exporter IP
- [ ] **P3** — Historical trending — store hourly/daily aggregates for long-term traffic graphs
- [ ] **P3** — Horizontal scaling — multiple collector instances writing to a shared database
- [ ] **P3** — LLM-powered advisory explanations ("Why am I seeing this scan?")

---

## 🏗️ Architecture & Code Health

- [ ] **P1** — Extract hardcoded magic numbers in packet parsing to named constants (e.g. TCP header size `20`, IPv6 header `40`)
- [ ] **P1** — Standardize error handling — some handlers log + return, others silently fall through; adopt a consistent middleware pattern
- [ ] **P2** — Add structured request logging middleware (method, path, status, duration)
- [ ] **P2** — Add a `/healthz` endpoint for container orchestration liveness probes
- [ ] **P2** — Decouple the web handler layer from direct storage calls — introduce a service / use-case layer
- [ ] **P2** — Move template helper functions (`formatBytes`, `formatPkts`, `pctOf`, etc.) into a dedicated `internal/web/helpers.go` file
- [ ] **P3** — Consider replacing SQLite with an embeddable time-series store for >10 M flow scalability
- [ ] **P3** — Add OpenTelemetry tracing for request/query observability

---

## 🐳 Docker & Deployment

- [ ] **P1** — Add a `HEALTHCHECK` directive to the Dockerfile
  ```dockerfile
  HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:8080/about || exit 1
  ```
- [ ] **P2** — Add OCI image labels (`org.opencontainers.image.title`, `.version`, `.source`, `.description`)
- [ ] **P2** — Provide a `docker-compose.yml` example with volume mounts for the database and captures directory
- [ ] **P2** — Document recommended resource limits (`--memory 512m --cpus 2`) in README
- [ ] **P3** — Helm chart for Kubernetes deployment

---

## 📖 Documentation

- [ ] **P1** — Add a **Development Guide** section to the README (build, test, lint, run locally)
- [ ] **P1** — Add a **Security Considerations** section to the README (authentication, TLS, firewall rules)
- [ ] **P1** — Update `idea.md` roadmap checkboxes — all MVP phases are implemented but checkboxes are still empty
- [ ] **P2** — Add architecture diagrams (data-flow, component diagram) to the README or a `docs/` folder
- [ ] **P2** — Document the JSON API once implemented
- [ ] **P2** — Add example `nginx` / `Caddy` reverse-proxy configs for TLS termination + auth
- [ ] **P3** — Add a CONTRIBUTING.md with coding standards, PR process, and issue templates

---

## 🐛 Known Limitations (from `bug.md`)

- [ ] **P2** — `formatPPS()` rounds rates < 0.5 pps to "0 pps" — show `<1 pps` or use one decimal place instead (`bug.md` #8)
- [ ] **P1** — Chart.js loaded from external CDN (`bug.md` #7) — see Security section above

---

## ✅ Recently Completed (reference)

> Tracked here for context; no action needed.

- [x] NetFlow v5, v9, IPFIX, sFlow v5 decoders
- [x] Dual-tier storage (ring buffer + SQLite WAL)
- [x] 12 analysis advisors with severity levels
- [x] Full web dashboard with 12 pages
- [x] PCAP import with retransmission detection and flow stitching
- [x] Dark mode support
- [x] GeoIP enrichment (built-in ranges + CSV loader)
- [x] Raw packet capture (Linux AF_PACKET)
- [x] Responsive CSS with mobile breakpoints
- [x] Comprehensive test suite (258 tests, ~46% test-to-code ratio)
- [x] Multi-stage Docker build (Alpine, ~50 MB image)
- [x] Graceful shutdown with in-flight request draining
- [x] All 8 documented bugs resolved or acknowledged
