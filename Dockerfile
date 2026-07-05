FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    NETOPS_PORT=8092

WORKDIR /app

# Non-root: the bridge holds device credentials in env / mounted secrets and needs no
# filesystem writes at runtime. Defense in depth for a service that can reach infra.
RUN useradd --create-home --uid 1000 slimx

COPY pyproject.toml README.md ./
COPY slimx_netops ./slimx_netops
# Core install only. Add `[live]` (netmiko/pysnmp) in the deployment image that actually
# reaches devices — keep the default image light and fixture-capable for demos/CI.
RUN pip install --no-cache-dir .

USER slimx

EXPOSE 8092

HEALTHCHECK --interval=15s --timeout=3s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8092/health', timeout=2)"

CMD ["sh", "-c", "uvicorn slimx_netops.service:app --host 0.0.0.0 --port ${NETOPS_PORT:-8092}"]
