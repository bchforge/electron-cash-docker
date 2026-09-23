FROM ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        fail2ban=1.0.2-3ubuntu0.1 \
        iptables=1.8.10-3ubuntu2 \
        python3=3.12.3-0ubuntu2.1 \
        ca-certificates=20260601~24.04.1 \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
COPY caddy_ban.py /usr/local/bin/caddy-ban
COPY caddy-log-adapter.py /usr/local/bin/caddy-log-adapter
COPY filter.d/caddy-basicauth.conf /etc/fail2ban/filter.d/caddy-basicauth.conf
COPY action.d/caddy-ban.conf /etc/fail2ban/action.d/caddy-ban.conf

RUN chmod 0755 /entrypoint.sh /usr/local/bin/caddy-ban /usr/local/bin/caddy-log-adapter

ENTRYPOINT ["/entrypoint.sh"]
