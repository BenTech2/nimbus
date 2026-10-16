#!/usr/bin/env bash
# Build Nimbus for 64-bit ARM Linux (aarch64) in Docker, e.g. for the Steam Frame.
#
#   npm run build:linux-arm64
#
# On an Apple Silicon Mac this runs natively (Docker's Linux VM is ARM). On an Intel/AMD
# machine Docker emulates ARM with QEMU, which works but is much slower.
# The installers land in dist-linux-arm64/. Builds reuse cached downloads and compiled
# dependencies in Docker volumes, so the second build is much faster.
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE=nimbus-build-linux-arm64
OUT="$PWD/dist-linux-arm64"

docker build --platform linux/arm64 -t "$IMAGE" -f docker/linux-arm64.Dockerfile docker
mkdir -p "$OUT"

# The repo is mounted read-only and copied in, so the Linux build never touches this
# machine's node_modules or Rust target folder.
docker run --rm --platform linux/arm64 \
  -v "$PWD":/repo:ro \
  -v "$OUT":/out \
  -v nimbus-arm64-cargo:/root/.cargo/registry \
  -v nimbus-arm64-target:/build/src-tauri/target \
  -v nimbus-arm64-npm:/root/.npm \
  "$IMAGE" bash -euo pipefail -c '
    rsync -a --delete --exclude node_modules --exclude src-tauri/target --exclude dist \
      --exclude "dist-linux-*" --exclude .git /repo/ /build/
    cd /build
    npm ci --no-audit --no-fund
    npm run tauri build
    rm -f /out/*.AppImage /out/*.deb /out/*.rpm
    cp src-tauri/target/release/bundle/appimage/*.AppImage src-tauri/target/release/bundle/deb/*.deb src-tauri/target/release/bundle/rpm/*.rpm /out/
  '
echo
echo "Linux ARM64 builds:"
ls -lh "$OUT"
