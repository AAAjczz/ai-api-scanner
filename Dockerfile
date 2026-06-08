FROM python:3.11-slim

LABEL org.opencontainers.image.title="AI API Security Scanner"
LABEL org.opencontainers.image.description="Scan OpenAI-compatible API endpoints for security misconfigurations"
LABEL org.opencontainers.image.source="https://github.com/AAAjczz/ai-api-scanner"
LABEL org.opencontainers.image.licenses="MIT"

# Install only requests — zero other deps
RUN pip install --no-cache-dir requests==2.31.0

# Copy scanner source (src layout)
COPY src/ai_api_scanner/ /app/ai_api_scanner/
COPY entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh

WORKDIR /app

ENTRYPOINT ["/app/entrypoint.sh"]
