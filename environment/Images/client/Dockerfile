FROM ubuntu:24.04

# Make it so there is no need to interact (press y) during docker build process
ENV DEBIAN_FRONTEND=noninteractive

# Firefox environment variables to prevent crashes
ENV MOZ_DISABLE_CONTENT_SANDBOX=1
ENV MOZ_DISABLE_GMP_SANDBOX=1
ENV MOZ_DISABLE_RDD_SANDBOX=1
ENV MOZ_DISABLE_SOCKET_PROCESS_SANDBOX=1

# Create Firefox profile with stability settings
COPY Images/client/profiles.ini /root/.mozilla/firefox/profiles.ini

# Firefox user preferences for stability
COPY Images/client/user.js /root/.mozilla/firefox/default.profile/user.js

# update sources and install packages
RUN apt update && \
 apt install -y --no-install-recommends software-properties-common && \
 add-apt-repository -y ppa:mozillateam/ppa && \
 echo "Package: *" > /etc/apt/preferences.d/mozilla-firefox && \
 echo "Pin: release o=LP-PPA-mozillateam" >> /etc/apt/preferences.d/mozilla-firefox && \
 echo "Pin-Priority: 1001" >> /etc/apt/preferences.d/mozilla-firefox && \
 echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections && \
 apt install -y --no-install-recommends \
 iproute2 \
 ssh jq \
 curl unzip \
 netcat-openbsd \
 iputils-ping iptables dnsutils \
 xvfb xfce4 xfce4-terminal dbus-x11 xtv x11-utils\
 x11vnc firefox-esr x11-xserver-utils x11-apps \
 novnc websockify socat && \
 apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy startup file into container
COPY Images/client/client.startup /root/
COPY Images/client/create_p12.sh /
RUN chmod +x /root/client.startup 

# Expose ports used by the VNC server and interface
EXPOSE 5900 6080
CMD ["/bin/bash"]
