# Contributing to FlowLens

Thank you for considering contributing to FlowLens! This document covers the conventions, process, and standards for contributions.

## Getting Started

1. **Fork** the repository on GitHub.
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/<your-username>/FlowLens.git
   cd FlowLens
   ```
3. **Create a branch** for your change:
   ```bash
   git checkout -b feature/my-feature
   ```
4. **Make your changes**, following the coding standards below.
5. **Test** your changes:
   ```bash
   go test -race ./...
   ```
6. **Lint** your code:
   ```bash
   go vet ./...
   golangci-lint run
   ```
7. **Commit** with a clear message and **push** your branch.
8. **Open a Pull Request** against the `main` branch.

## Development Setup

### Prerequisites

- Go 1.25 or later
- golangci-lint (optional, for linting — [install](https://golangci-lint.run/welcome/install/))

### Build & Run

```bash
# Build
go build -o flowlens ./cmd/flowlens/

# Run with default config
./flowlens

# Run with custom config
./flowlens configs/flowlens.yaml
```

### Test

```bash
# All tests
go test ./...

# With race detector (same as CI)
go test -race -count=1 ./...

# With coverage report
go test -race -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Benchmarks
go test -bench=. -benchmem ./...
```

## Coding Standards

### Go Style

- Follow the [Effective Go](https://go.dev/doc/effective_go) guidelines.
- Use `gofmt` or `goimports` to format code (enforced by CI).
- All exported types and functions must have doc comments.
- Use named constants instead of magic numbers, especially in packet parsing.
- Error messages should start with a lowercase letter and not end with punctuation (Go convention).

### Error Handling

- Use the `httpError()` helper in web handlers for consistent error responses + logging.
- Always check and handle errors — the `errcheck` linter enforces this.
- Wrap errors with `fmt.Errorf("context: %w", err)` for traceability.

### Testing

- Write table-driven tests where appropriate.
- Place unit tests in the same package as the code under test.
- Integration tests go in `internal/integration_test.go`.
- Fuzz tests target protocol decoders that parse untrusted network input.
- Benchmark tests cover hot paths (ring buffer, flow stitching, decoders).
- Tests must pass with the race detector enabled (`-race`).

### Web Templates

- Templates use XHTML (`.xhtml` extension) with Go's `html/template`.
- All data tables must be wrapped in `<div class="table-responsive">` for mobile.
- Include CSRF tokens in all state-changing forms via `{{csrfToken}}`.
- Follow WCAG AA accessibility: focus indicators, ARIA labels, non-color-only severity indicators.

### CSS

- Styles live in `static/style.css` — no CSS frameworks.
- Use CSS custom properties (e.g. `var(--accent)`) for theming.
- Support both light and dark modes via `@media (prefers-color-scheme: dark)`.
- Responsive breakpoints at 900px and 600px.

## Project Layout

```
internal/
├── analysis/     # Advisory engine and analyzer modules
├── capture/      # Raw packet capture, PCAP reader
├── collector/    # UDP listeners, NetFlow/IPFIX/sFlow decoders
├── config/       # YAML config loader
├── geo/          # GeoIP lookup
├── logging/      # Structured logger
├── model/        # Flow struct, protocol helpers
├── storage/      # Ring buffer + SQLite backends
├── tracing/      # Tracer interface
└── web/          # HTTP server, handlers, templates, API
```

All application code lives under `internal/` — it is not importable by external packages.

## Pull Request Process

1. **One concern per PR** — keep changes focused and reviewable.
2. **Include tests** for new functionality or bug fixes.
3. **Update documentation** if your change affects user-facing behavior, configuration, or the API.
4. **Ensure CI passes** — the PR must pass `go vet`, `golangci-lint`, and `go test -race`.
5. **Describe your change** in the PR description, including motivation and any trade-offs.

### Commit Messages

Use clear, imperative commit messages:

```
feat: add sFlow counter sample display page
fix: prevent nil pointer in flow stitching with empty slice
docs: add reverse-proxy examples for nginx and Caddy
test: add fuzz test for IPFIX decoder
```

Prefixes: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `ci:`, `chore:`.

## Reporting Issues

When opening an issue, please include:

- **FlowLens version** (`./flowlens` prints the version on startup, or check the About page)
- **Go version** (`go version`)
- **OS and architecture**
- **Steps to reproduce** the problem
- **Expected vs. actual behavior**
- **Relevant log output** (if applicable)

## Security Issues

If you discover a security vulnerability, please report it **privately** via GitHub's [security advisory](https://github.com/darkace1998/FlowLens/security/advisories/new) feature rather than opening a public issue.

## License

By contributing to FlowLens, you agree that your contributions will be licensed under the same license as the project. See [LICENSE](LICENSE) for details.
