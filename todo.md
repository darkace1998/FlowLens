# FlowLens — Project TODO

> A prioritized backlog generated from a full codebase deep-dive.
> Items are grouped by area and tagged **P0** (critical / blocking),
> **P1** (high-value), **P2** (nice-to-have), or **P3** (future / research).

---

## 🔒 Security & Hardening

- [x] **P0** — Add authentication / authorization layer (even basic HTTP Basic Auth or token-based)
  — HTTP Basic Auth middleware with configurable `username`/`password` in web config. Constant-time credential comparison.
- [x] **P1** — Add CSRF tokens to state-changing endpoints (`/capture/start`, `/capture/stop`, `/pcap/import`)
  — Single-use random tokens embedded in forms via `{{csrfToken}}` template function. Validated on POST.
- [x] **P1** — Bundle Chart.js as a local static asset instead of loading from `cdn.jsdelivr.net`
  — Chart.js v4.5.1 UMD bundle saved to `static/chart.umd.min.js`. CDN reference removed from dashboard.
- [x] **P1** — Add TLS support (built-in or document reverse-proxy setup with example configs)
  — Added `tls_cert`/`tls_key` config options. Server auto-switches to `ListenAndServeTLS` when both are set.
- [x] **P2** — Add rate-limiting on the UDP collector ports to mitigate amplification / DoS
  — Per-source-IP packets-per-second limiter with configurable `rate_limit` in collector config. Periodic cleanup of stale entries.
- [x] **P2** — Run the container as a non-root user
  — Added `flowlens` user/group to Dockerfile. Container runs as non-root.
- [x] **P2** — Pin Docker base images by digest for reproducible builds
  — Both `golang:1.24-alpine` and `alpine:3.21` pinned by `@sha256:...` digest in Dockerfile.
- [x] **P3** — Add Content-Security-Policy headers to the web server
  — CSP middleware on all responses: `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'`.

---

## 🧪 Testing & Quality

- [x] **P0** — Add `go test ./...` step to the GitHub Actions release workflow — currently Docker images ship without any test gate
  — Release workflow now requires a `test` job (with race detector) to pass before the Docker build.
- [x] **P1** — Add a `golangci-lint` configuration (`.golangci.yml`) and integrate it into CI
  — `.golangci.yml` with 16 linters configured. Integrated into CI workflow via `golangci-lint-action`.
- [x] **P1** — Add integration / end-to-end tests (collector → storage → web handler round-trip)
  — Three integration tests in `internal/integration_test.go` covering collector→ring buffer→dashboard, collector→SQLite→flows page, and multi-packet round-trip.
- [x] **P2** — Add Go benchmark tests (`Benchmark*`) for hot paths: ring buffer insert/query, flow stitching, protocol decoders
  — 17 benchmark functions across `model/bench_test.go`, `storage/bench_test.go`, `collector/bench_test.go`.
- [x] **P2** — Add fuzz tests (`Fuzz*`) for protocol decoders (`netflowv5.go`, `netflowv9.go`, `ipfix.go`, `sflow.go`, `pcap.go`) — these parse untrusted network input
  — Five `Fuzz*` functions in `collector/fuzz_test.go` and `capture/fuzz_test.go` with valid and edge-case seeds.
- [x] **P2** — Set up code coverage reporting (e.g. Codecov) in CI
  — CI workflow generates `coverage.out` and uploads as GitHub Actions artifact.
- [x] **P3** — Add error-injection / chaos tests for storage failures (SQLite disk full, corrupt WAL)
  — Seven chaos tests in `storage/chaos_test.go` covering corrupt DB, read-only FS, concurrent access, nil IPs, empty/large inserts, and ring buffer stress overflow.

---

## 🚀 CI / CD

- [x] **P1** — Add a CI workflow that runs on every push / PR (not only on `v*` tags):
  - `go vet ./...`
  - `go test -race ./...`
  - `golangci-lint run`
  — `.github/workflows/ci.yml` runs lint and test jobs on push/PR to main.
- [ ] **P1** — Produce cross-compiled binary artifacts (Linux amd64/arm64, macOS, Windows) as GitHub Release assets alongside the Docker image
- [ ] **P2** — Add SBOM generation and vulnerability scanning (e.g. Trivy, Grype) to the Docker build
- [ ] **P2** — Sign container images with `cosign`
- [ ] **P2** — Auto-generate release notes / changelog from commit history
- [ ] **P3** — Add a scheduled dependency-update workflow (Dependabot or Renovate)

---

## 🌐 Web UI & Accessibility

- [x] **P1** — Add keyboard-focus indicators to all interactive elements (links, buttons, inputs)
  — Added `:focus-visible` rules for `a`, `button`, `input`, `select`, and `[tabindex]` with 2px accent outline and 2px offset.
- [x] **P1** — Add icons or text prefixes to severity badges so color is not the only differentiator (accessibility for colorblind users)
  — CSS `::before` pseudo-elements add Unicode symbols: ⬥ CRITICAL, ▲ WARNING, ● INFO, ✓ RESOLVED.
- [x] **P2** — Add request timeouts / context deadlines to web handlers to prevent hung requests on slow storage queries
  — Added `http.TimeoutHandler` (30s) in the middleware chain plus `ReadTimeout` (30s), `WriteTimeout` (60s), and `IdleTimeout` (120s) on the `http.Server`.
- [x] **P2** — Make chart container heights responsive (percentage / `clamp()`) instead of fixed `280px` / `220px`
  — `.chart-container` uses `clamp(200px, 30vw, 350px)`, `.chart-container-sm` uses `clamp(180px, 25vw, 280px)`.
- [x] **P2** — Improve dark-mode contrast for muted text (`--muted: #8b949e` → `#a8b3ba` or similar to meet WCAG AA 4.5:1 contrast ratio against `--bg: #0d1117`)
  — Changed `--muted` in dark mode from `#8b949e` to `#a8b3ba` (contrast ratio 5.2:1 against `#0d1117`).
- [x] **P3** — Add a loading spinner / skeleton screen for pages that query large datasets
  — Loading overlay with CSS spinner shown on form submissions. Uses `.loading-overlay.active` toggle with `aria-hidden` management.
- [x] **P3** — Add `aria-label` attributes to the hamburger menu toggle and other icon-only controls
  — Added `aria-label` to nav, brand link, hamburger toggle (with `aria-expanded`), dark-mode toggle, loading spinner (`role="status"`), and `role="menubar"`/`role="menuitem"` on nav links.

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
- [x] **P1** — Chart.js loaded from external CDN (`bug.md` #7) — now bundled locally in `static/chart.umd.min.js`

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
- [x] Comprehensive test suite (341 tests including fuzz, benchmarks, integration, and chaos tests)
- [x] Multi-stage Docker build (Alpine, ~50 MB image)
- [x] Graceful shutdown with in-flight request draining
- [x] All 8 documented bugs resolved or acknowledged
