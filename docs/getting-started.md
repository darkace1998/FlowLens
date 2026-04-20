# Getting Started

## Prerequisites

- Go 1.25+
- Optional: Docker / Docker Compose
- Optional: Helm (for Kubernetes)

## Run from Source

```bash
git clone https://github.com/darkace1998/FlowLens.git
cd FlowLens
go build -o flowlens ./cmd/flowlens/
./flowlens
```

Run with a custom config file:

```bash
./flowlens configs/flowlens.yaml
```

## Run with Docker

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

Run with custom config mount:

```bash
docker run -d \
  -p 2055:2055/udp \
  -p 4739:4739/udp \
  -p 6343:6343/udp \
  -p 8080:8080 \
  -v /path/to/flowlens.yaml:/app/configs/flowlens.yaml \
  --name flowlens \
  flowlens
```

## Run with Docker Compose

```bash
docker compose up -d
```

## Run with Helm

```bash
helm install flowlens deploy/helm/flowlens/
```

See chart options in `deploy/helm/flowlens/values.yaml`.

## Resource Sizing Guidance

| Environment | CPUs | Memory | Notes |
|---|---:|---:|---|
| Low traffic (<1K flows/s) | 0.5 | 128 MB | Home lab / small office |
| Medium traffic (1K–10K flows/s) | 1 | 256 MB | Branch deployment |
| High traffic (10K–50K flows/s) | 2 | 512 MB | Data center/core |
| Very high traffic (>50K flows/s) | 4 | 1 GB | Dedicated host recommended |

Primary disk consumers are the SQLite database and capture files. Use persistent volumes for `/app/data` and `/app/captures`.
