#!/usr/bin/env sh
set -eu

ARCH="${TARGETARCH:-amd64}"
case "$ARCH" in
  amd64) SUFFIX="amd64" ;;
  arm64) SUFFIX="arm64" ;;
  *) echo "Unsupported TARGETARCH: $ARCH" >&2; exit 1 ;;
esac

# Syft and OSV-Scanner are external security tools, not Python libraries.
# Pin them through build args in the Dockerfile for reproducible deployments.
SYFT_VERSION="${SYFT_VERSION:-1.33.0}"
OSV_VERSION="${OSV_VERSION:-2.2.2}"

mkdir -p /tmp/security-tools
curl -fsSL "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${SUFFIX}.tar.gz" -o /tmp/security-tools/syft.tgz
 tar -xzf /tmp/security-tools/syft.tgz -C /tmp/security-tools
install -m 0755 /tmp/security-tools/syft /usr/local/bin/syft

curl -fsSL "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_${SUFFIX}" -o /usr/local/bin/osv-scanner
chmod 0755 /usr/local/bin/osv-scanner
rm -rf /tmp/security-tools
