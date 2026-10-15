FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    APP_BASE=/opt/ad-audit

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openssh-client \
        openssl \
        fonts-dejavu-core \
        tzdata \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/ad-audit

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY docker/entrypoint.sh /opt/ad-audit/entrypoint.sh
RUN chmod +x /opt/ad-audit/entrypoint.sh

RUN mkdir -p /opt/ad-audit/data /opt/ad-audit/reports \
    && printf '%s\n' \
        'openssl_conf = openssl_init' \
        '[openssl_init]' \
        'providers = provider_sect' \
        '[provider_sect]' \
        'default = default_sect' \
        'legacy = legacy_sect' \
        '[default_sect]' \
        'activate = 1' \
        '[legacy_sect]' \
        'activate = 1' \
        > /opt/ad-audit/openssl-legacy.cnf

ENV OPENSSL_CONF=/opt/ad-audit/openssl-legacy.cnf

EXPOSE 8000

CMD ["/opt/ad-audit/entrypoint.sh"]
