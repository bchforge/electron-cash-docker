FROM ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates=20260601~24.04.1 \
        python3=3.12.3-0ubuntu2.1 \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 10001 authsession && \
    useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin authsession

COPY docker/auth-session/server.py /home/authsession/server.py
COPY docker/login_locale.py /home/authsession/login_locale.py
COPY docker/login_catalog.py docker/login-translations.tsv /home/authsession/
COPY docker/auth-session/favicon.svg /home/authsession/favicon.svg
COPY VERSION /etc/electroncash-docker/VERSION
RUN chown 10001:10001 /home/authsession/server.py /home/authsession/favicon.svg && \
    chmod 0555 /home/authsession/server.py /home/authsession/favicon.svg /etc/electroncash-docker/VERSION && \
    install -d -o 10001 -g 10001 -m 0700 /auth-data

USER 10001:10001
WORKDIR /home/authsession
EXPOSE 8080
ENTRYPOINT ["python3", "/home/authsession/server.py"]
