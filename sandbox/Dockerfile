FROM python:3.14.7-slim-trixie@sha256:51dafde81dbdb6ebde285137a295cf18a47ca95234fe388a343719cb97305b3d

ARG WITH_SEMGREP=1
ARG WITH_CBM=1
ARG SEMGREP_VERSION=1.179.0
ARG CBM_VERSION=0.12.1
ARG CBM_SHA256_AMD64=8c3d0341064301e78ecc84cf7348d4e2c6562a0f57448243ea560aaa34de36c1
ARG CBM_SHA256_ARM64=ed0f1f548cd79b121c401c2e9f7841c189a001af26d3768368088c24f6a53533
ARG TARGETARCH

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0 \
    SEMGREP_SETTINGS_FILE=/tmp/semgrep/settings.yml \
    SEMGREP_LOG_FILE=/tmp/semgrep/semgrep.log \
    SEMGREP_VERSION_CACHE_PATH=/tmp/semgrep/version

RUN apt-get update \
 && apt-get install -y --no-install-recommends ripgrep git ca-certificates jq tree file binutils \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt && rm /tmp/requirements.txt

RUN if [ "$WITH_SEMGREP" = "1" ]; then \
      python -m venv /opt/semgrep \
      && /opt/semgrep/bin/pip install "semgrep==${SEMGREP_VERSION}" \
      && ln -s /opt/semgrep/bin/semgrep /usr/local/bin/semgrep; \
    fi

RUN if [ "$WITH_CBM" = "1" ]; then \
      arch="${TARGETARCH:-$(dpkg --print-architecture)}" \
      && case "$arch" in \
           amd64) sum="$CBM_SHA256_AMD64" ;; \
           arm64) sum="$CBM_SHA256_ARM64" ;; \
           *) echo "codebase-memory-mcp has no build for $arch" >&2; exit 1 ;; \
         esac \
      && python -c "import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], '/tmp/cbm.tar.gz')" \
           "https://github.com/DeusData/codebase-memory-mcp/releases/download/v${CBM_VERSION}/codebase-memory-mcp-linux-${arch}-portable.tar.gz" \
      && echo "${sum}  /tmp/cbm.tar.gz" | sha256sum -c - \
      && mkdir /tmp/cbm \
      && tar -xzf /tmp/cbm.tar.gz -C /tmp/cbm \
      && find /tmp/cbm -type f -name codebase-memory-mcp -exec install -m 0755 {} /usr/local/bin/codebase-memory-mcp \; \
      && test -x /usr/local/bin/codebase-memory-mcp \
      && rm -rf /tmp/cbm /tmp/cbm.tar.gz; \
    fi

ENV ARAD_IN_SANDBOX=1
