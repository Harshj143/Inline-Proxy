# MCP Security Gateway — central-mode image.
#
# One image runs either role (the entrypoint is the `mcp-gateway` CLI):
#   * gateway:  mcp-gateway serve --config /config/gateway.yaml
#   * console:  mcp-gateway console serve --index ... --audit ... --users ...
# See docker-compose.yml for the full stack (gateway + console + redis + postgres).
FROM python:3.12-slim

# Server + shared-state + vault extras; heavy NER/anomaly tiers stay out of the
# image (opt in per deployment). No build toolchain needed for these wheels.
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir -e ".[server,vault,redis,postgres]"

# Drop privileges: the gateway handles untrusted upstream output; it should
# never run as root.
RUN useradd --create-home --uid 10001 app \
    && mkdir -p /data /config \
    && chown -R app /app /data /config
USER app

# 8080 = central gateway (Streamable HTTP); 8000 = console (see compose).
EXPOSE 8080 8000

ENTRYPOINT ["mcp-gateway"]
CMD ["serve", "--config", "/config/gateway.yaml", "--host", "0.0.0.0", "--port", "8080"]
