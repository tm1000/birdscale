# birdscale: bridge a Tailscale tailnet to a NetBird network.
# Official, pinned tailscale and netbird releases (no patched forks) plus the birdscaled supervisor.

# ---- build birdscaled --------------------------------------------------------
# tailscale.com v1.104.4 requires Go >= 1.27.3 (checked: golang:1.27.3-trixie exists on Docker Hub).
# Runs on the build host's architecture and cross-compiles (no QEMU needed for the Go build).
FROM --platform=$BUILDPLATFORM golang:1.27.3-trixie AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
ARG TARGETARCH
# VERSION is stamped into the binary: shown in the logs, the status page and birdscale_build_info.
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux GOARCH="${TARGETARCH:-amd64}" \
    go build -trimpath \
      -ldflags="-s -w -X github.com/tm1000/birdscale/internal/version.Version=${VERSION}" \
      -o /out/birdscaled ./cmd/birdscaled

# ---- fetch and verify the vendor binaries ------------------------------------
# Only downloads and unpacks tarballs for $TARGETARCH, so it runs on the build host's architecture.
FROM --platform=$BUILDPLATFORM debian:trixie-slim AS fetch
# Exact pinned releases. Checked 2026-11-02:
#   tailscale 1.104.4  https://pkgs.tailscale.com/stable/?mode=json
#   netbird   0.82.0   https://github.com/netbirdio/netbird/releases/tag/v0.82.0
# Renovate bumps these (see renovate.json). Keep TAILSCALE_VERSION equal to the tailscale.com
# module version in go.mod (CI checks this). No checksum to edit: both are fetched at build time below.
# renovate: datasource=github-releases depName=tailscale/tailscale extractVersion=^v(?<version>.+)$
ARG TAILSCALE_VERSION=1.104.5
# renovate: datasource=github-releases depName=netbirdio/netbird extractVersion=^v(?<version>.+)$
ARG NETBIRD_VERSION=0.82.0
ARG TARGETARCH
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

# Tailscale static tarball, verified against the .sha256 published next to it.
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in amd64|arm64) arch="${TARGETARCH:-amd64}" ;; *) echo "unsupported arch ${TARGETARCH}" >&2; exit 1 ;; esac; \
    f="tailscale_${TAILSCALE_VERSION}_${arch}.tgz"; \
    cd /tmp; \
    curl -fsSLO "https://pkgs.tailscale.com/stable/${f}"; \
    echo "$(curl -fsSL "https://pkgs.tailscale.com/stable/${f}.sha256")  ${f}" | sha256sum -c -; \
    tar -xzf "${f}"; \
    install -m 0755 "tailscale_${TAILSCALE_VERSION}_${arch}/tailscale" "tailscale_${TAILSCALE_VERSION}_${arch}/tailscaled" /usr/local/bin/

# NetBird client tarball, verified against the release checksums file.
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in amd64|arm64) arch="${TARGETARCH:-amd64}" ;; *) echo "unsupported arch ${TARGETARCH}" >&2; exit 1 ;; esac; \
    f="netbird_${NETBIRD_VERSION}_linux_${arch}.tar.gz"; \
    base="https://github.com/netbirdio/netbird/releases/download/v${NETBIRD_VERSION}"; \
    cd /tmp; \
    curl -fsSLO "${base}/${f}"; \
    curl -fsSL "${base}/netbird_${NETBIRD_VERSION}_checksums.txt" | grep " ${f}\$" | sha256sum -c -; \
    tar -xzf "${f}" netbird; \
    install -m 0755 netbird /usr/local/bin/netbird

# ---- runtime -----------------------------------------------------------------
FROM debian:trixie-slim
ARG VERSION=dev
LABEL org.opencontainers.image.title="birdscale" \
      org.opencontainers.image.description="Bridge a Tailscale tailnet to a NetBird network" \
      org.opencontainers.image.source="https://github.com/tm1000/birdscale" \
      org.opencontainers.image.version="${VERSION}"
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates iproute2 iptables nftables \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /var/lib/tailscale /var/run/tailscale /etc/netbird

COPY --from=fetch /usr/local/bin/tailscale /usr/local/bin/tailscaled /usr/local/bin/netbird /usr/local/bin/
COPY --from=build /out/birdscaled /usr/local/bin/birdscaled

# Same defaults as the official netbirdio/netbird image, plus NB_STATE_DIR:
# v0.82 keeps profiles in /var/lib/netbird; NB_STATE_DIR keeps them in /etc/netbird (the volume).
ENV NB_LOG_FILE=console \
    NB_DAEMON_ADDR=unix:///var/run/netbird.sock \
    NB_ENABLE_CAPTURE=false \
    NB_STATE_DIR=/etc/netbird

VOLUME ["/var/lib/tailscale", "/etc/netbird"]
HEALTHCHECK --interval=30s --timeout=10s --start-period=90s --retries=3 CMD ["birdscaled", "health"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["birdscaled"]
