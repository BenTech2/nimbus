cd /home/tester
Xvnc :1 -rfbport 5901 -geometry 1280x800 -depth 24 -SecurityTypes VncAuth -PasswordFile .vnc/passwd -AcceptSetDesktopSize=1 -localhost=0 -alwaysshared &
Xvnc :2 -rfbport 5902 -geometry 1280x800 -depth 24 -SecurityTypes X509Vnc -X509Cert .vnc/cert.pem -X509Key .vnc/key.pem -PasswordFile .vnc/passwd -localhost=0 -alwaysshared &
sleep 1
DISPLAY=:1 dbus-launch startxfce4 &
DISPLAY=:2 dbus-launch startxfce4 &
wait
