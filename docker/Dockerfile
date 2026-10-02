FROM ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90 AS builder

ARG EC_VERSION
ARG EC_COMMIT
ARG EC_ARCHIVE_SHA256

ENV DEBIAN_FRONTEND=noninteractive

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates=20260601~24.04.1 \
    curl=8.5.0-2ubuntu10.15 \
    git=1:2.43.0-1ubuntu7.3 \
    build-essential=12.10ubuntu1 \
    cmake=3.28.3-1build7 \
    automake=1:1.16.5-1.3ubuntu1 \
    autoconf=2.71-3 \
    libtool=2.4.7-7build1 \
    pkg-config=1.8.1-2build1 \
    python3=3.12.3-0ubuntu2.1 \
    python3-pip=24.0+dfsg-1ubuntu1.3 \
    python3-setuptools=68.1.2-2ubuntu1.2 \
    python3-venv=3.12.3-0ubuntu2.1 \
    python3-pyqt5=5.15.10+dfsg-1build6 \
    python3-pyqt5.sip=12.13.0-1build3 \
    python3-pyqt5.qtsvg=5.15.10+dfsg-1build6 \
    python3-dnspython=2.6.1-1ubuntu1 \
    python3-qrcode=7.4.2-4 \
    python3-socks=1.7.1+dfsg-1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp/electron-cash

# Build only the pinned secp256k1 submodule used by make_secp. Optional ZBar,
# OpenSSL, libevent, zlib, and Tor source builds are not enabled in this image;
# locale data is copied from the separately verified release archive below.
RUN git clone https://github.com/Electron-Cash/Electron-Cash.git . && \
    git checkout --detach "${EC_COMMIT}" && \
    git submodule sync -- contrib/secp256k1 && \
    git submodule update --init -- contrib/secp256k1 && \
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
    ca-certificates=20260601~24.04.1 \
    curl=8.5.0-2ubuntu10.15 \
    python3=3.12.3-0ubuntu2.1 \
    tar=1.35+dfsg-3ubuntu0.4 \
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
ARG HW_SUPPORT=0

ENV DEBIAN_FRONTEND=noninteractive

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates=20260601~24.04.1 \
    curl=8.5.0-2ubuntu10.15 \
    dbus-x11=1.14.10-4ubuntu4.1 \
    fonts-dejavu-core=2.37-8 \
    fonts-freefont-ttf=20211204+svn4273-2 \
    fontconfig=2.15.0-1.1ubuntu2 \
    openbox=3.6.1-12build5 \
    passwd=1:4.13+dfsg1-4ubuntu3.2 \
    python3=3.12.3-0ubuntu2.1 \
    python3-pip=24.0+dfsg-1ubuntu1.3 \
    python3-pyqt5=5.15.10+dfsg-1build6 \
    python3-pyqt5.sip=12.13.0-1build3 \
    python3-pyqt5.qtsvg=5.15.10+dfsg-1build6 \
    python3-dnspython=2.6.1-1ubuntu1 \
    python3-xdg=0.28-2 \
    python3-qrcode=7.4.2-4 \
    python3-socks=1.7.1+dfsg-1 \
    gnupg2=2.4.4-2ubuntu17.6 \
    gzip=1.12-1ubuntu3.2 \
    tar=1.35+dfsg-3ubuntu0.4 \
    websockify=0.10.0+dfsg1-5build2 \
    x11-utils=7.7+6build2 \
    x11vnc=0.9.16-10 \
    xauth=1:1.1.2-1build1 \
    xvfb=2:21.1.12-1ubuntu1.8 \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL -o "/tmp/novnc-${NOVNC_VERSION}.tar.gz" \
        "https://codeload.github.com/novnc/noVNC/tar.gz/${NOVNC_COMMIT}" && \
    echo "${NOVNC_ARCHIVE_SHA256}  /tmp/novnc-${NOVNC_VERSION}.tar.gz" | sha256sum -c - && \
    tar xzf "/tmp/novnc-${NOVNC_VERSION}.tar.gz" -C /opt/ && \
    mv "/opt/noVNC-${NOVNC_COMMIT}" /opt/noVNC && \
    chmod -R a+rX /opt/noVNC && \
    rm "/tmp/novnc-${NOVNC_VERSION}.tar.gz"

RUN python3 -c 'from pathlib import Path; path=Path("/opt/noVNC/vnc.html"); text=path.read_text(encoding="utf-8"); title="<title>noVNC</title>"; branded="<title>Electron Cash Docker</title>"; favicon="<link rel=\"icon\" type=\"image/svg+xml\" href=\"/favicon.svg\">"; assert text.count(title) == 1, "expected exactly one unbranded noVNC title"; text=text.replace(title, branded, 1); head_start=text.find("<head>"); head_end=text.find("</head>", head_start); assert head_start >= 0 and head_end > head_start, "vnc.html head is missing"; assert text.count(favicon) <= 1, "duplicate Electron Cash Docker favicon links"; text=text if favicon in text else text[:head_end] + "  " + favicon + "\n" + text[head_end:]; path.write_text(text, encoding="utf-8"); head_start=text.find("<head>"); head_end=text.find("</head>", head_start); favicon_index=text.find(favicon); assert text.count(branded) == 1, "expected exactly one branded noVNC title"; assert text.count(favicon) == 1 and head_start < favicon_index < head_end, "expected exactly one favicon link inside head"'

COPY --from=builder /opt/electroncash-venv /opt/electroncash-venv

# Ledger's pinned upstream plugin imports hid and btchip. Keep these libraries
# out of the ordinary image; the overlay opts in to this separate build path.
RUN if [ "${HW_SUPPORT}" = 1 ]; then \
        apt-get update && apt-get install -y --no-install-recommends \
            libhidapi-libusb0=0.14.0-1build1 \
            && rm -rf /var/lib/apt/lists/* && \
        /opt/electroncash-venv/bin/pip install --no-cache-dir hidapi==0.14.0.post4 && \
        curl -fsSL -o /tmp/btchip-python.tar.gz \
            https://files.pythonhosted.org/packages/30/fd/16394adaff5736840aeda77163d5f6f593091d687a1807ff02dedcfc7bca/btchip-python-0.1.32.tar.gz && \
        echo '34f5e0c161c08f65dc0d070ba2ff4c315ed21c4b7e0faa32a46862d0dc1b8f55  /tmp/btchip-python.tar.gz' | sha256sum -c - && \
        mkdir /tmp/btchip-source && tar xzf /tmp/btchip-python.tar.gz -C /tmp/btchip-source --strip-components=1 && \
        python3 -c 'from pathlib import Path; p=Path("/tmp/btchip-source/setup.py"); s=p.read_text(); old="python-pyscard>=1.6.12-4build1"; assert s.count(old)==1; p.write_text(s.replace(old, "pyscard>=1.6.12"))' && \
        /opt/electroncash-venv/bin/pip install --no-cache-dir --no-deps /tmp/btchip-source && \
        rm -rf /tmp/btchip-source /tmp/btchip-python.tar.gz && \
        /opt/electroncash-venv/bin/pip check; \
    elif [ "${HW_SUPPORT}" != 0 ]; then exit 1; fi
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
COPY docker/auth-session/favicon.svg /opt/noVNC/favicon.svg
COPY docker/novnc-keepalive.js /opt/noVNC/novnc-keepalive.js
COPY VERSION /etc/electroncash-docker/VERSION

RUN python3 -c 'from pathlib import Path; path=Path("/opt/noVNC/vnc.html"); text=path.read_text(encoding="utf-8"); marker="<script src=\"/novnc-keepalive.js\"></script>"; assert marker not in text; assert "</head>" in text; path.write_text(text.replace("</head>", "  " + marker + "\n</head>", 1), encoding="utf-8")'

COPY --chown=electroncash:electroncash docker/entrypoint.sh /home/electroncash/entrypoint.sh
COPY --chown=electroncash:electroncash docker/cashfusion.sh /home/electroncash/cashfusion.sh
COPY --chown=electroncash:electroncash docker/cashfusion_defaults.py /home/electroncash/cashfusion_defaults.py
COPY --chown=electroncash:electroncash docker/network_selection.py /home/electroncash/network_selection.py
COPY docker/prepare-xauthority.py /home/electroncash/prepare-xauthority.py
COPY --chown=electroncash:electroncash docker/backup_tool.py /home/electroncash/backup_tool.py
COPY --chown=electroncash:electroncash docker/backup.sh /home/electroncash/backup.sh
COPY --chown=electroncash:electroncash docker/electroncash-wrapper.py /home/electroncash/electroncash-wrapper.py
COPY --chown=electroncash:electroncash docker/electroncash-daemon-wrapper.py /home/electroncash/electroncash-daemon-wrapper.py

RUN chmod +x /home/electroncash/entrypoint.sh \
        /home/electroncash/cashfusion.sh \
        /home/electroncash/backup.sh \
        /home/electroncash/electroncash-wrapper.py \
        /home/electroncash/electroncash-daemon-wrapper.py

ENV HOME=/home/electroncash
WORKDIR /home/electroncash
EXPOSE 6080
ENTRYPOINT ["/home/electroncash/entrypoint.sh"]
