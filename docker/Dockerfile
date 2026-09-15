FROM ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90 AS builder

ARG EC_VERSION
ARG EC_COMMIT
ARG EC_ARCHIVE_SHA256

ENV DEBIAN_FRONTEND=noninteractive

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    build-essential \
    cmake \
    automake \
    autoconf \
    libtool \
    pkg-config \
    python3 \
    python3-pip \
    python3-setuptools \
    python3-venv \
    python3-pyqt5 \
    python3-pyqt5.sip \
    python3-pyqt5.qtsvg \
    python3-dnspython \
    python3-qrcode \
    python3-socks \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp/electron-cash

RUN git clone https://github.com/Electron-Cash/Electron-Cash.git . && \
    git checkout --detach "${EC_COMMIT}" && \
    git submodule sync --recursive && \
    git submodule update --init --recursive && \
    ./contrib/make_secp

COPY docker/electron-cash-cve-2024-23342.patch /tmp/electron-cash-cve-2024-23342.patch

RUN git apply --check /tmp/electron-cash-cve-2024-23342.patch && \
    git apply --whitespace=error /tmp/electron-cash-cve-2024-23342.patch

RUN curl -fsSL -o /tmp/electron-cash.tar.gz \
        "https://github.com/Electron-Cash/Electron-Cash/releases/download/${EC_VERSION}/electron_cash-${EC_VERSION}.tar.gz" && \
    echo "${EC_ARCHIVE_SHA256}  /tmp/electron-cash.tar.gz" | sha256sum -c - && \
    tar xzf /tmp/electron-cash.tar.gz --strip-components=1 \
        -C /tmp/electron-cash "electron_cash-${EC_VERSION}/electroncash/locale" && \
    rm /tmp/electron-cash.tar.gz

RUN python3 -m venv --system-site-packages /opt/electroncash-venv

COPY requirements.txt /tmp/requirements.txt

RUN /opt/electroncash-venv/bin/pip install --no-cache-dir \
    --requirement /tmp/requirements.txt && \
    /opt/electroncash-venv/bin/pip check

RUN /opt/electroncash-venv/bin/python setup.py install \
    --single-version-externally-managed --root=/

FROM ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90 AS plugin-builder

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    python3 \
    tar \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build-plugins
COPY plugins.json /build-plugins/plugins.json
COPY docker/plugins/build_plugins.sh /build-plugins/build_plugins.sh
RUN PLUGIN_MANIFEST=/build-plugins/plugins.json \
    PLUGIN_OUTPUT_DIR=/build-plugins/zips \
    bash /build-plugins/build_plugins.sh

FROM ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90 AS runtime

ARG NOVNC_VERSION
ARG NOVNC_COMMIT
ARG NOVNC_ARCHIVE_SHA256

ENV DEBIAN_FRONTEND=noninteractive

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    dbus-x11 \
    fonts-dejavu-core \
    fonts-freefont-ttf \
    fontconfig \
    openbox \
    passwd \
    python3 \
    python3-pip \
    python3-pyqt5 \
    python3-pyqt5.sip \
    python3-pyqt5.qtsvg \
    python3-dnspython \
    python3-pyxdg \
    python3-qrcode \
    python3-socks \
    websockify \
    x11-utils \
    x11vnc \
    xvfb \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL -o "/tmp/novnc-${NOVNC_VERSION}.tar.gz" \
        "https://github.com/novnc/noVNC/archive/${NOVNC_COMMIT}.tar.gz" && \
    echo "${NOVNC_ARCHIVE_SHA256}  /tmp/novnc-${NOVNC_VERSION}.tar.gz" | sha256sum -c - && \
    tar xzf "/tmp/novnc-${NOVNC_VERSION}.tar.gz" -C /opt/ && \
    mv "/opt/noVNC-${NOVNC_COMMIT}" /opt/noVNC && \
    chmod -R a+rX /opt/noVNC && \
    rm "/tmp/novnc-${NOVNC_VERSION}.tar.gz"

COPY --from=builder /opt/electroncash-venv /opt/electroncash-venv
COPY --from=plugin-builder /build-plugins/zips/ /preinstalled-plugins/
COPY --from=plugin-builder /build-plugins/plugins.json /preinstalled-plugins/plugins.json

RUN groupadd --gid 10001 electroncash && \
    useradd --uid 10001 --gid 10001 --create-home \
        --home-dir /home/electroncash --shell /usr/sbin/nologin electroncash && \
    mkdir -p /home/electroncash/.electron-cash \
        /home/electroncash/.config/openbox \
        /home/electroncash/.local/share && \
    printf '%s\n' \
        '<?xml version="1.0" encoding="UTF-8"?>' \
        '<openbox_config>' \
        '  <applications>' \
        '    <application class="electron-cash" type="normal">' \
        '      <maximized>yes</maximized>' \
        '      <focus>yes</focus>' \
        '    </application>' \
        '  </applications>' \
        '</openbox_config>' \
        > /home/electroncash/.config/openbox/rc.xml && \
    chown -R electroncash:electroncash /home/electroncash

COPY docker/novnc-index.html /opt/noVNC/index.html
COPY docker/novnc-keepalive.js /opt/noVNC/novnc-keepalive.js

RUN python3 -c 'from pathlib import Path; path=Path("/opt/noVNC/vnc.html"); text=path.read_text(encoding="utf-8"); marker="<script src=\"/novnc-keepalive.js\"></script>"; assert marker not in text; assert "</head>" in text; path.write_text(text.replace("</head>", "  " + marker + "\n</head>", 1), encoding="utf-8")'

COPY --chown=electroncash:electroncash docker/entrypoint.sh /home/electroncash/entrypoint.sh
COPY --chown=electroncash:electroncash docker/cashfusion.sh /home/electroncash/cashfusion.sh
COPY --chown=electroncash:electroncash docker/cashfusion_autofuse.py /home/electroncash/cashfusion_autofuse.py
COPY --chown=electroncash:electroncash docker/electroncash-wrapper.py /home/electroncash/electroncash-wrapper.py
COPY --chown=electroncash:electroncash docker/electroncash-daemon-wrapper.py /home/electroncash/electroncash-daemon-wrapper.py

RUN chmod +x /home/electroncash/entrypoint.sh \
        /home/electroncash/cashfusion.sh \
        /home/electroncash/electroncash-wrapper.py \
        /home/electroncash/electroncash-daemon-wrapper.py

ENV HOME=/home/electroncash
WORKDIR /home/electroncash
EXPOSE 6080
ENTRYPOINT ["/home/electroncash/entrypoint.sh"]
