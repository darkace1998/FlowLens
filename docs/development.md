# Development Guide

## Prerequisites

- Go 1.25+
- `golangci-lint` v2 (optional but recommended for local lint parity)

## Build

```bash
go build -o flowlens ./cmd/flowlens/
```

Build with version metadata:

```bash
go build -ldflags="-s -w -X main.Version=$(git describe --tags --always --dirty)" \
  -o flowlens ./cmd/flowlens/
```

## Run

```bash
./flowlens
./flowlens configs/flowlens.yaml
```

## Test

```bash
go test ./...
go test -race -count=1 ./...
go test -race -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

Benchmarks:

```bash
go test -bench=. -benchmem ./...
```

Fuzzing examples:

```bash
go test -fuzz=FuzzDecodeNetFlowV5 -fuzztime=30s ./internal/collector/
go test -fuzz=FuzzDecodeNetFlowV9 -fuzztime=30s ./internal/collector/
go test -fuzz=FuzzDecodeIPFIX -fuzztime=30s ./internal/collector/
go test -fuzz=FuzzDecodeSFlow -fuzztime=30s ./internal/collector/
go test -fuzz=FuzzReadPcapFlows -fuzztime=30s ./internal/capture/
```

## Lint

```bash
go vet ./...
golangci-lint run ./...
```

## CI Workflows

- **CI**: `.github/workflows/ci.yml` (vet, lint, tests)
- **Release**: `.github/workflows/release.yml` (tag-gated release build and image push)
