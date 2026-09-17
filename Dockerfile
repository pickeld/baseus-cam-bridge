FROM python:3.12-slim

# ffmpeg for muxing, curl to fetch the MediaMTX release, ca-certificates for TLS.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ffmpeg curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install MediaMTX (media server). Override version/arch with build args if needed.
ARG MEDIAMTX_VERSION=1.11.3
ARG TARGETARCH=amd64
RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) MTX_ARCH=amd64 ;; \
        arm64) MTX_ARCH=arm64v8 ;; \
        arm) MTX_ARCH=armv7 ;; \
        *) MTX_ARCH=amd64 ;; \
    esac; \
    curl -fsSL -o /tmp/mediamtx.tar.gz \
        "https://github.com/bluenviron/mediamtx/releases/download/v${MEDIAMTX_VERSION}/mediamtx_v${MEDIAMTX_VERSION}_linux_${MTX_ARCH}.tar.gz"; \
    tar -xzf /tmp/mediamtx.tar.gz -C /usr/local/bin mediamtx; \
    rm -f /tmp/mediamtx.tar.gz; \
    /usr/local/bin/mediamtx --version || true

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY baseus_bridge ./baseus_bridge

ENV BASEUS_RUNTIME_DIR=/run/baseus \
    MEDIAMTX_BIN=/usr/local/bin/mediamtx \
    PYTHONUNBUFFERED=1

# RTSP / HLS / WebRTC (+ WebRTC ICE udp)
EXPOSE 8554 8888 8889 8189/udp

CMD ["python", "-m", "baseus_bridge", "serve"]
