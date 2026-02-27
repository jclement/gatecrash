FROM golang:1.24-alpine AS builder
RUN apk add --no-cache curl git
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.Version=${VERSION}" -o gatecrash ./cmd/gatecrash

FROM alpine:3.23
RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -u 1000 gatecrash && \
    mkdir -p /etc/gatecrash /data && \
    chown gatecrash:gatecrash /etc/gatecrash /data
WORKDIR /app
COPY --from=builder /app/gatecrash .
EXPOSE 8080 443 80
ENV GATECRASH_CONFIG=/etc/gatecrash/gatecrash.toml
VOLUME ["/etc/gatecrash", "/data"]
USER gatecrash
CMD ["./gatecrash", "server", "--config", "/etc/gatecrash/gatecrash.toml"]
