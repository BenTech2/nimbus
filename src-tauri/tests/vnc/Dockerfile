# A Linux desktop over VNC for the VNC tests (TigerVNC):
#   :5901  VNC password "nimbus-v" (no encryption)
#   :5902  VeNCrypt X509Vnc (TLS with a self-signed certificate), same password
#   docker build -t nimbus-vnc src-tauri/tests/vnc
#   docker run -d --name nimbus-vnc -p 5901:5901 -p 5902:5902 --shm-size=512m nimbus-vnc
FROM debian:trixie-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    tigervnc-standalone-server tigervnc-tools xfce4 xfce4-terminal dbus-x11 x11-xserver-utils xclip openssl procps \
 && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash tester && mkdir -p /home/tester/.vnc \
 && echo nimbus-v | vncpasswd -f > /home/tester/.vnc/passwd && chmod 600 /home/tester/.vnc/passwd \
 && openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj /CN=nimbus-vnc -keyout /home/tester/.vnc/key.pem -out /home/tester/.vnc/cert.pem \
 && chown -R tester:tester /home/tester/.vnc
RUN mkdir -p /tmp/.X11-unix /tmp/.ICE-unix && chmod 1777 /tmp/.X11-unix /tmp/.ICE-unix
COPY start.sh /start.sh
USER tester
EXPOSE 5901 5902
CMD ["sh", "/start.sh"]
