# Multi-stage Dockerfile for minimal transparenz image
FROM golang:1.22-alpine AS builder

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo \
    -ldflags '-extldflags "-static" -s -w' \
    -o transparenz cmd/transparenz/main.go

# Final minimal image
FROM scratch

LABEL org.opencontainers.image.source="https://github.com/deutschland-stack/transparenz"
LABEL org.opencontainers.image.description="BSI TR-03183 compliant SBOM generator"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Copy binary
COPY --from=builder /build/transparenz /transparenz

# Copy CA certificates for HTTPS
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

ENTRYPOINT ["/transparenz"]
CMD ["--help"]
