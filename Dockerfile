# --- Build stage ---
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.Version=$(git describe --tags --always --dirty 2>/dev/null || echo dev)" \
    -o /flowlens ./cmd/flowlens/

# --- Runtime stage ---
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=builder /flowlens /app/flowlens
COPY configs/flowlens.yaml /app/configs/flowlens.yaml
COPY static/ /app/static/

EXPOSE 2055/udp 4739/udp 8080/tcp

ENTRYPOINT ["/app/flowlens"]
CMD ["configs/flowlens.yaml"]
