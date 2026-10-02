FROM golang@sha256:ce864e7223ac17b1775e6fd0b4c0db580c2eb50e7953a427916379e4b92a1628 AS builder

ARG CADDY_VERSION=2.11.4
ARG CADDY_ARCHIVE_SHA256=2c3d02078286a6282cdb4d1d8744077788d556659dac0b64d8ed5886a7e5aeb9

RUN apk add --no-cache \
        ca-certificates=20260611-r0 \
        curl=8.22.0-r0 \
        tar=1.35-r5 \
        gzip=1.14-r3
WORKDIR /src
RUN curl -fsSL -o caddy.tar.gz \
        "https://github.com/caddyserver/caddy/archive/refs/tags/v${CADDY_VERSION}.tar.gz" \
    && echo "${CADDY_ARCHIVE_SHA256}  caddy.tar.gz" | sha256sum -c - \
    && tar xzf caddy.tar.gz \
    && rm caddy.tar.gz
WORKDIR /src/caddy-${CADDY_VERSION}

# Rebuild the pinned Caddy source with explicitly pinned dependency updates.
# Use host networking only for dependency resolution/build so Go can reach both
# the module proxy and checksum transparency log from constrained BuildKit hosts.
RUN --network=host go mod edit -go=1.26.0 \
        -require=github.com/quic-go/quic-go@v0.59.1 \
        -require=github.com/smallstep/certificates@v0.30.2 \
        -require=go.opentelemetry.io/otel@v1.44.0 \
        -require=go.opentelemetry.io/otel/sdk@v1.44.0 \
        -require=golang.org/x/crypto@v0.57.0 \
        -require=golang.org/x/net@v0.59.0 \
        -require=golang.org/x/text@v0.42.0 \
        -require=google.golang.org/grpc@v1.83.2 \
    && go mod tidy && \
    go build -trimpath -buildvcs=false -ldflags='-s -w' -o /out/caddy ./cmd/caddy

FROM caddy@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648

RUN apk add --no-cache \
        c-ares=1.34.8-r0 \
        curl=8.22.0-r0 \
        libcurl=8.22.0-r0 \
        libcrypto3=3.5.9-r0 \
        libssl3=3.5.9-r0

COPY --from=builder /out/caddy /usr/bin/caddy
COPY cloudflare-ipv4.txt cloudflare-ipv6.txt /etc/caddy/
