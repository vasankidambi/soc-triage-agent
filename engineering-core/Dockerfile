# Minimal non-root container for the defensive SOC triage agent.
FROM python:3.12-slim

# Run as an unprivileged user rather than root.
RUN useradd --create-home --uid 1000 appuser
WORKDIR /app

COPY --chown=appuser:appuser . /app
RUN pip install --no-cache-dir .

USER 1000

# Liveness: confirm the package imports cleanly.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD ["python", "-c", "import soc_triage_agent"]

# Default: run one synthetic triage through the approval path.
ENTRYPOINT ["soc-triage"]
CMD ["--decision", "approve", "--thread-id", "demo-approved-001"]
