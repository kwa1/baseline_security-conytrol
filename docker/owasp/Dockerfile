# --------------------------------------------------
# Stage 1: Build tools (Trivy, Conftest, OPA)
# --------------------------------------------------
FROM alpine:3.19 AS tools

ARG TRIVY_VERSION=0.49.1
ARG CONFTEST_VERSION=0.52.0
ARG OPA_VERSION=0.61.0

RUN apk add --no-cache curl ca-certificates tar

# Install Trivy
RUN curl -sfL https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz \
    | tar -xz -C /usr/local/bin trivy

# Install Conftest
RUN curl -sfL https://github.com/open-policy-agent/conftest/releases/download/v${CONFTEST_VERSION}/conftest_${CONFTEST_VERSION}_Linux_x86_64.tar.gz \
    | tar -xz -C /usr/local/bin conftest

# Install OPA
RUN curl -sfL -o /usr/local/bin/opa \
    https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_linux_amd64 \
    && chmod +x /usr/local/bin/opa

# --------------------------------------------------
# Stage 2: Runtime image
# --------------------------------------------------
FROM python:3.11-slim-bookworm

LABEL org.opencontainers.image.title="OWASP Security Gates"
LABEL org.opencontainers.image.description="SBOM, OWASP Top 10, OPA policy enforcement pipeline"
LABEL org.opencontainers.image.vendor="Security Engineering"
LABEL org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH="/usr/local/bin:${PATH}"

# Install runtime OS dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    jq \
    git \
    awscli \
    && rm -rf /var/lib/apt/lists/*

# Copy security tools from build stage
COPY --from=tools /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=tools /usr/local/bin/conftest /usr/local/bin/conftest
COPY --from=tools /usr/local/bin/opa /usr/local/bin/opa

# Create non-root user (CIS benchmark aligned)
RUN useradd -m -u 10001 security && mkdir -p /app && chown -R security:security /app

WORKDIR /app
USER security

# Python dependencies
COPY scripts/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY scripts/ scripts/
COPY policy/ policy/
COPY exceptions/ exceptions/

# Default entrypoint
ENTRYPOINT ["python3", "scripts/owasp_analyzer.py"]
