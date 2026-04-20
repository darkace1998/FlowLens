# FlowLens

Lightweight NetFlow/IPFIX/sFlow analyzer with a single-binary collector, dual-tier storage (memory + SQLite), built-in advisories, and a web dashboard.

## Why FlowLens

- Supports NetFlow v5/v9, IPFIX (v10), and sFlow v5
- Works well on small hosts while scaling to higher flow rates
- Provides actionable advisory insights (top talkers, scan detection, anomaly detection, DNS behavior, and more)
- Includes both web pages and JSON APIs for operator and automation workflows
- Ships as pure Go with Docker and Helm deployment options

## Quick Start

### Run from source

```bash
git clone https://github.com/darkace1998/FlowLens.git
cd FlowLens
go build -o flowlens ./cmd/flowlens/
./flowlens
```

### Run with Docker

```bash
docker build -t flowlens .
docker run -d \
  -p 2055:2055/udp \
  -p 4739:4739/udp \
  -p 6343:6343/udp \
  -p 8080:8080 \
  --name flowlens \
  flowlens
```

Open `http://localhost:8080`.

## Documentation

| Topic | Location |
|---|---|
| Documentation index | [`docs/README.md`](docs/README.md) |
| Architecture | [`docs/architecture.md`](docs/architecture.md) |
| Getting started and deployment | [`docs/getting-started.md`](docs/getting-started.md) |
| Configuration reference | [`docs/configuration.md`](docs/configuration.md) |
| Security and hardening | [`docs/security.md`](docs/security.md) |
| Web interface pages | [`docs/web-interface.md`](docs/web-interface.md) |
| REST API reference | [`docs/api.md`](docs/api.md) |
| Analyzer reference | [`docs/analyzers.md`](docs/analyzers.md) |
| Development workflow | [`docs/development.md`](docs/development.md) |
| Reverse proxy examples | [`docs/reverse-proxy.md`](docs/reverse-proxy.md) |

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

See [`LICENSE`](LICENSE).
