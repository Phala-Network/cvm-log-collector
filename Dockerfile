FROM python:3.13-slim-bookworm@sha256:281d39ff02e3b389401586134ff9e6572954687822a58055ec07a60ded4e0b7f

# journalctl reads the two mounted journal directories. No daemon or package
# installation runs in the deployed container. Debian notices remain intact.
RUN apt-get update \
    && apt-get install -y --no-install-recommends systemd \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY collector.py credentials_only.py /app/
COPY LICENSE /usr/share/licenses/cvm-log-collector/LICENSE
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENTRYPOINT ["python3", "-u", "/app/collector.py"]
