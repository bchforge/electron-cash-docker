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

RUN curl -fsSL -o /tmp/electron-cash.tar.gz \
        "https://github.com/Electron-Cash/Electron-Cash/releases/download/${EC_VERSION}/electron_cash-${EC_VERSION}.tar.gz" && \
    echo "${EC_ARCHIVE_SHA256}  /tmp/electron-cash.tar.gz" | sha256sum -c - && \
    tar xzf /tmp/electron-cash.tar.gz --strip-components=1 \
        -C /tmp/electron-cash "electron_cash-${EC_VERSION}/electroncash/locale" && \
    rm /tmp/electron-cash.tar.gz

RUN python3 -m venv --system-site-packages /opt/electroncash-venv

RUN /opt/electroncash-venv/bin/pip install --no-cache-dir \
    pyaes==1.6.1 \
    ecdsa==0.19.1 \
    requests==2.32.3 \
    qrcode==7.4.2 \
    protobuf==5.28.2 \
    jsonrpclib-pelix==0.4.0 \
    PySocks==1.7.1 \
    python-dateutil==2.9.0 \
    stem==1.8.2 \
    certifi==2024.7.4 \
    pathvalidate==3.2.0 \
    qdarkstyle==3.2.3

RUN /opt/electroncash-venv/bin/python setup.py install \
    --single-version-externally-managed --root=/

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
COPY --chown=electroncash:electroncash docker/entrypoint.sh /home/electroncash/entrypoint.sh
COPY --chown=electroncash:electroncash docker/cashfusion.sh /home/electroncash/cashfusion.sh
COPY --chown=electroncash:electroncash docker/electroncash-wrapper.py /home/electroncash/electroncash-wrapper.py

RUN chmod +x /home/electroncash/entrypoint.sh \
        /home/electroncash/cashfusion.sh \
        /home/electroncash/electroncash-wrapper.py

ENV HOME=/home/electroncash
WORKDIR /home/electroncash
EXPOSE 6080
ENTRYPOINT ["/home/electroncash/entrypoint.sh"]
