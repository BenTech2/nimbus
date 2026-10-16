# Build environment for Nimbus on 64-bit ARM Linux (e.g. the Steam Frame, Raspberry Pi 5,
# Snapdragon laptops). Ubuntu 22.04 keeps the glibc requirement low, so the result runs on
# older and newer distributions alike, including SteamOS.
FROM --platform=linux/arm64 ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential curl ca-certificates file git rsync pkg-config xdg-utils \
      libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev libssl-dev libudev-dev patchelf \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
ENV PATH=/root/.cargo/bin:$PATH
# The AppImage tools are themselves AppImages; containers have no FUSE, so let them unpack.
ENV APPIMAGE_EXTRACT_AND_RUN=1
