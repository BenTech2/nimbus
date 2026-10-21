# A Linux desktop over RDP for the Remote Desktop tests: user "tester", password "nimbus-test".
#   docker build -t nimbus-xrdp src-tauri/tests/xrdp
#   docker run -d --name nimbus-xrdp -p 3390:3389 --shm-size=512m nimbus-xrdp
FROM debian:trixie-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    xrdp xorgxrdp xfce4 xfce4-terminal dbus-x11 x11-xserver-utils xauth ssl-cert sudo procps xclip mousepad \
 && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash tester && echo 'tester:nimbus-test' | chpasswd && adduser xrdp ssl-cert \
 && echo 'startxfce4' > /home/tester/.xsession && chown tester:tester /home/tester/.xsession
EXPOSE 3389
CMD rm -f /var/run/xrdp/*.pid; /usr/sbin/xrdp-sesman && exec /usr/sbin/xrdp --nodaemon
