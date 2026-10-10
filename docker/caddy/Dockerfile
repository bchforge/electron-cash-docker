ARG CADDY_VERSION=2.11.7
ARG CADDY_ARCHIVE_SHA256=86e39de5fa0bc433a9cd574a00e7751059903401f3389c61f8937fd0ad0180f5

# Go 1.26.9 / Alpine 3.24 fixes CVE-2026-78667 and CVE-2026-97031.
FROM golang@sha256:cdfd4fe2da6b225d8b40c6b7a105736e548e83ff56d5d8f9394446eeb5eb84e0 AS builder

ARG CADDY_VERSION
ARG CADDY_ARCHIVE_SHA256
ENV GOTOOLCHAIN=local
COPY verify-version.sh /usr/local/bin/caddy-version-check
RUN sh /usr/local/bin/caddy-version-check "${CADDY_VERSION}" "${CADDY_ARCHIVE_SHA256}"

RUN apk add --no-cache \
        ca-certificates=20260909-r0 \
        curl=8.22.0-r0 \
        tar=1.35-r5 \
        gzip=1.14-r3
WORKDIR /src
RUN curl --proto '=https' -fsS -o caddy.tar.gz \
        "https://codeload.github.com/caddyserver/caddy/tar.gz/refs/tags/v${CADDY_VERSION}" \
    && echo "${CADDY_ARCHIVE_SHA256}  caddy.tar.gz" | sha256sum -c - \
    && tar xzf caddy.tar.gz \
    && rm caddy.tar.gz
WORKDIR /src/caddy-${CADDY_VERSION}

# Keep the verified release graph, with one explicit security update: x/net
# 0.60.0 fixes the newly published HTTP/2 advisories. Never use go get -u/tidy.
# Use host networking only for dependency resolution/build so Go can reach both
# the module proxy and checksum transparency log from constrained BuildKit hosts.
RUN --network=host mkdir -p /out && \
    sha256sum go.mod go.sum > /out/upstream-module-locks.sha256 && \
    go mod edit -require=golang.org/x/net@v0.60.0 && \
    go mod download golang.org/x/net@v0.60.0 && go mod download && go mod verify && \
    sha256sum go.mod go.sum > /tmp/module-inputs.sha256 && \
    go list -m all > /out/module-versions && \
    go list -mod=readonly -deps ./cmd/caddy > /out/package-deps && \
    ! grep -Eq '^golang.org/x/crypto/openpgp(/|$)' /out/package-deps && \
    go build -mod=readonly -trimpath -buildvcs=false \
        -ldflags="-s -w -X github.com/caddyserver/caddy/v2.CustomVersion=v${CADDY_VERSION}" \
        -o /out/caddy ./cmd/caddy && \
    sha256sum -c /tmp/module-inputs.sha256 && \
    test "$(/out/caddy version)" = "v${CADDY_VERSION}" && \
    go version -m /out/caddy > /out/build-info && \
    grep -q 'go1.26.9' /out/build-info && \
    printf '%s\n' "${CADDY_VERSION}" > /out/source-version && \
    printf '%s\n' "${CADDY_ARCHIVE_SHA256}" > /out/source.sha256

FROM caddy@sha256:d8542f48d34a9cf4e4c11a478865229840e87e4c96ea3f439101f31a5d35f75f
ARG CADDY_VERSION
ARG CADDY_ARCHIVE_SHA256
LABEL org.opencontainers.image.version="${CADDY_VERSION}" \
      org.opencontainers.image.source="https://github.com/caddyserver/caddy" \
      org.bchforge.caddy.source-sha256="${CADDY_ARCHIVE_SHA256}"

RUN apk add --no-cache \
        c-ares=1.34.8-r0 \
        curl=8.22.0-r0 \
        libcurl=8.22.0-r0 \
        libcrypto3=3.5.9-r0 \
        libssl3=3.5.9-r0 \
        zlib=1.3.2-r1

COPY --from=builder /out/caddy /usr/bin/caddy
COPY --from=builder /out/build-info /out/source-version /out/source.sha256 /etc/caddy/
COPY --from=builder /out/package-deps /out/module-versions /out/upstream-module-locks.sha256 /etc/caddy/
COPY verify-version.sh /usr/local/bin/caddy-version-check
COPY cloudflare-ipv4.txt cloudflare-ipv6.txt /etc/caddy/
