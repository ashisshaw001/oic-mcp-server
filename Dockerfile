FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8080

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY oic_mcp ./oic_mcp

# Run as an unprivileged user. Mount the INI read-only, e.g.
#   -v $PWD/oic.ini:/config/oic.ini:ro -e OIC_CONFIG_FILE=/config/oic.ini
RUN useradd --system --uid 10001 --no-create-home oicmcp
USER oicmcp

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD python -c "import urllib.request,os; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"MCP_PORT\",\"8080\")}/healthz', timeout=2)"

CMD ["python", "-m", "oic_mcp"]
