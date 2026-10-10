# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32

ARG UBUNTU_IMAGE=ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea

# This stage has no compiler. A bad source pin or release signature fails here,
# before the source is extracted or any Tor compilation starts.
FROM ${UBUNTU_IMAGE} AS tor-verifier

ARG TOR_VERSION
ARG TOR_SOURCE_SHA256

ENV DEBIAN_FRONTEND=noninteractive

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates=20260601~24.04.1 \
    curl=8.5.0-2ubuntu10.15 \
    gnupg=2.4.4-2ubuntu17.6 \
    && rm -rf /var/lib/apt/lists/*

COPY tor-release-keys.asc /usr/local/share/tor/tor-release-keys.asc

RUN set -eux; \
    if [[ ! "${TOR_VERSION}" =~ ^[0-9]+([.][0-9]+){3}$ ]]; then \
        echo "TOR_VERSION must be a stable numeric Tor release" >&2; \
        exit 1; \
    fi; \
    if [[ ! "${TOR_SOURCE_SHA256}" =~ ^[0-9a-fA-F]{64}$ ]]; then \
        echo "TOR_SOURCE_SHA256 must be a 64-character SHA-256 value" >&2; \
        exit 1; \
    fi; \
    archive="tor-${TOR_VERSION}.tar.gz"; \
    download_dir=/tmp/tor-download; \
    mkdir -p "${download_dir}"; \
    curl --fail --silent --show-error --location --retry 3 \
        -o "${download_dir}/${archive}" \
        "https://dist.torproject.org/${archive}"; \
    curl --fail --silent --show-error --location --retry 3 \
        -o "${download_dir}/${archive}.sha256sum" \
        "https://dist.torproject.org/${archive}.sha256sum"; \
    curl --fail --silent --show-error --location --retry 3 \
        -o "${download_dir}/${archive}.sha256sum.asc" \
        "https://dist.torproject.org/${archive}.sha256sum.asc"; \
    gpg --batch --no-options --dearmor \
        --output "${download_dir}/tor-release-keys.gpg" \
        /usr/local/share/tor/tor-release-keys.asc; \
    verification="$(gpgv --status-fd=1 \
        --keyring "${download_dir}/tor-release-keys.gpg" \
        "${download_dir}/${archive}.sha256sum.asc" \
        "${download_dir}/${archive}.sha256sum" 2>&1)" || { \
        printf '%s\n' "${verification}" >&2; \
        echo "Tor Project checksum signature verification failed" >&2; \
        exit 1; \
    }; \
    printf '%s\n' "${verification}"; \
    printf '%s\n' "${verification}" | \
        grep -Fq '[GNUPG:] VALIDSIG B74417EDDF22AC9F9E90F49142E86A2A11F48D36'; \
    printf '%s\n' "${verification}" | \
        grep -Fq '[GNUPG:] VALIDSIG 514102454D0A87DB0767A1EBBE6A0531C18A9179'; \
    expected_sha="$(printf '%s' "${TOR_SOURCE_SHA256}" | tr '[:upper:]' '[:lower:]')"; \
    official_sha="$(awk -v name="${archive}" '$2 == name { print $1 }' \
        "${download_dir}/${archive}.sha256sum")"; \
    if [ "${official_sha}" != "${expected_sha}" ]; then \
        echo "TOR_SOURCE_SHA256 does not match the Tor Project checksum file" >&2; \
        exit 1; \
    fi; \
    if ! printf '%s  %s\n' "${expected_sha}" "${download_dir}/${archive}" | \
        sha256sum -c -; then \
        echo "Tor source SHA-256 verification failed" >&2; \
        exit 1; \
    fi

FROM tor-verifier AS tor-builder

ARG TOR_VERSION

ENV DEBIAN_FRONTEND=noninteractive

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential=12.10ubuntu1 \
    libevent-dev=2.1.12-stable-9ubuntu2.2 \
    liblzma-dev=5.6.1+really5.4.5-1ubuntu0.3 \
    libseccomp-dev=2.5.5-1ubuntu3.1 \
    libssl-dev=3.0.13-0ubuntu3.16 \
    libzstd-dev=1.5.5+dfsg2-2build1.1 \
    pkg-config=1.8.1-2build1 \
    python3=3.12.3-0ubuntu2.1 \
    zlib1g-dev=1:1.3.dfsg-3.1ubuntu2.2 \
    && rm -rf /var/lib/apt/lists/*

COPY healthcheck.c /tmp/tor-healthcheck.c
COPY signal-mask-compat.py /tmp/signal-mask-compat.py

RUN set -eux; \
    archive="tor-${TOR_VERSION}.tar.gz"; \
    tar -xzf "/tmp/tor-download/${archive}" -C /tmp; \
    python3 /tmp/signal-mask-compat.py "/tmp/tor-${TOR_VERSION}/src/lib/sandbox/sandbox.c"; \
    cd "/tmp/tor-${TOR_VERSION}"; \
    ./configure \
        --prefix=/usr/local \
        --sysconfdir=/etc/tor \
        --localstatedir=/var \
        --disable-asciidoc \
        --disable-html-manual \
        --disable-manpage \
        --disable-module-dirauth \
        --disable-module-relay \
        --disable-system-torrc \
        --disable-systemd \
        --disable-unittests \
        --with-malloc=system; \
    make -j"$(nproc)"; \
    mkdir -p /tmp/tor-root; \
    make install DESTDIR=/tmp/tor-root; \
    install -Dm644 LICENSE /tmp/tor-root/usr/share/doc/tor/LICENSE; \
    cc -Os -static -Wall -Wextra -Werror \
        /tmp/tor-healthcheck.c -o /tmp/tor-healthcheck; \
    install -Dm755 /tmp/tor-healthcheck \
        /tmp/tor-root/usr/local/bin/tor-healthcheck

FROM ${UBUNTU_IMAGE} AS runtime

ARG TOR_VERSION

LABEL org.opencontainers.image.title="BCH Forge Tor client" \
      org.opencontainers.image.description="Auditable Tor SOCKS5 client built from official Tor Project source" \
      org.opencontainers.image.version="${TOR_VERSION}" \
      org.opencontainers.image.licenses="BSD-3-Clause and bundled third-party notices" \
      org.opencontainers.image.source="https://dist.torproject.org/"

ENV DEBIAN_FRONTEND=noninteractive

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates=20260601~24.04.1 \
    libevent-2.1-7t64=2.1.12-stable-9ubuntu2.2 \
    libevent-pthreads-2.1-7t64=2.1.12-stable-9ubuntu2.2 \
    liblzma5=5.6.1+really5.4.5-1ubuntu0.3 \
    libseccomp2=2.5.5-1ubuntu3.1 \
    libssl3t64=3.0.13-0ubuntu3.16 \
    libzstd1=1.5.5+dfsg2-2build1.1 \
    zlib1g=1:1.3.dfsg-3.1ubuntu2.2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=tor-builder /tmp/tor-root/usr/local/bin/tor /usr/local/bin/tor
COPY --from=tor-builder /tmp/tor-root/usr/local/bin/tor-healthcheck /usr/local/bin/tor-healthcheck
COPY --from=tor-builder /tmp/tor-root/usr/local/share/tor /usr/local/share/tor
COPY --from=tor-builder /tmp/tor-root/usr/share/doc/tor/LICENSE /usr/share/doc/tor/LICENSE
COPY torrc /etc/tor/torrc

RUN groupadd --gid 10001 tor && \
    useradd --uid 10001 --gid 10001 --home-dir /var/lib/tor \
        --no-create-home --shell /usr/sbin/nologin tor && \
    mkdir -p /var/lib/tor && \
    chown tor:tor /var/lib/tor && \
    chmod 700 /var/lib/tor && \
    chmod 644 /etc/tor/torrc /usr/share/doc/tor/LICENSE

USER 10001:10001
WORKDIR /var/lib/tor
VOLUME ["/var/lib/tor"]
EXPOSE 9050
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=6 \
    CMD ["/usr/local/bin/tor-healthcheck"]
ENTRYPOINT ["/usr/local/bin/tor"]
CMD ["-f", "/etc/tor/torrc"]
