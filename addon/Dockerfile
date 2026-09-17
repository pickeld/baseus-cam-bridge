ARG BUILD_FROM
FROM ${BUILD_FROM}

# ffmpeg for muxing, python for the bridge, curl to fetch MediaMTX.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip ffmpeg curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# --- MediaMTX (media server) ---
ARG MEDIAMTX_VERSION=1.11.3
ARG BUILD_ARCH=amd64
RUN set -eux; \
    case "${BUILD_ARCH}" in \
        amd64)   MTX_ARCH=amd64 ;; \
        aarch64) MTX_ARCH=arm64v8 ;; \
        armv7)   MTX_ARCH=armv7 ;; \
        *)       MTX_ARCH=amd64 ;; \
    esac; \
    curl -fsSL -o /tmp/mediamtx.tar.gz \
        "https://github.com/bluenviron/mediamtx/releases/download/v${MEDIAMTX_VERSION}/mediamtx_v${MEDIAMTX_VERSION}_linux_${MTX_ARCH}.tar.gz"; \
    tar -xzf /tmp/mediamtx.tar.gz -C /usr/local/bin mediamtx; \
    rm -f /tmp/mediamtx.tar.gz; \
    /usr/local/bin/mediamtx --version || true

# --- the bridge package (single source of truth: installed from the repo) ---
ARG BASEUS_REF=main
RUN pip3 install --no-cache-dir --break-system-packages \
        "baseus-cam-bridge @ git+https://github.com/pickeld/baseus-cam-bridge@${BASEUS_REF}"

ENV BASEUS_RUNTIME_DIR=/data/run \
    MEDIAMTX_BIN=/usr/local/bin/mediamtx \
    PYTHONUNBUFFERED=1

COPY run.sh /run.sh
RUN chmod a+x /run.sh

# RTSP / HLS / WebRTC (+ WebRTC ICE udp)
EXPOSE 8554 8888 8889 8189/udp

CMD [ "/run.sh" ]
