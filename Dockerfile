FROM python:buster

WORKDIR /app
COPY ./ /app

RUN set -eux; \
    pip install --no-cache-dir .; \
    chmod +x /app/docker-entrypoint.sh

ENTRYPOINT [ "/app/docker-entrypoint.sh" ]