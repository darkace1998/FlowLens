# --- Build stage ---
# Pin base images by digest for reproducible builds.
FROM golang:1.24-alpine@sha256:8bee1901f1e530bfb4a7850aa7a479d17ae3a18beb6e09064ed54cfd245b7191 AS builder

RUN apk add --no-cache git

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.Version=$(git describe --tags --always --dirty 2>/dev/null || echo dev)" \
    -o /flowlens ./cmd/flowlens/

# --- Runtime stage ---
FROM alpine:3.21@sha256:c3f8e73fdb79deaebaa2037150150191b9dcbfba68b4a46d70103204c53f4709

RUN apk add --no-cache ca-certificates tzdata

# Run as non-root user for security.
RUN addgroup -S flowlens && adduser -S flowlens -G flowlens

WORKDIR /app

COPY --from=builder /flowlens /app/flowlens
COPY configs/flowlens.yaml /app/configs/flowlens.yaml
COPY static/ /app/static/

# Ensure the non-root user can write to data directories.
RUN mkdir -p /app/captures && chown -R flowlens:flowlens /app

USER flowlens

EXPOSE 2055/udp 4739/udp 8080/tcp

ENTRYPOINT ["/app/flowlens"]
CMD ["configs/flowlens.yaml"]
