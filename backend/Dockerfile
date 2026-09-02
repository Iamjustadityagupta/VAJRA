FROM python:3.12-slim
ARG TARGETARCH
ARG SYFT_VERSION=1.33.0
ARG OSV_VERSION=2.2.2

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app

WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY tools/install_security_tools.sh /tmp/install_security_tools.sh
RUN TARGETARCH=${TARGETARCH:-amd64} SYFT_VERSION=${SYFT_VERSION} OSV_VERSION=${OSV_VERSION} /bin/sh /tmp/install_security_tools.sh \
    && rm -f /tmp/install_security_tools.sh

COPY . ./
RUN useradd --create-home --shell /usr/sbin/nologin vajra \
    && mkdir -p /app/runs \
    && chown -R vajra:vajra /app
USER vajra

EXPOSE 8000
HEALTHCHECK --interval=20s --timeout=5s --retries=5 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3)"
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1"]
