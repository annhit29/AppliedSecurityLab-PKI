FROM debian:12

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

ARG LAB_ROOT_PASSWORD
ARG LAB_SSH_PASSWORD

# Install essential packages: networking, python, SSH, nginx, openssl
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iproute2 netcat-openbsd curl \
        iputils-ping iptables dnsutils \
        python3 python3-pip python3-venv\
        openssh-server nginx openssl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

ENV PATH="/var/www/webserver/venv/bin:$PATH"
RUN python3 -m venv /var/www/webserver/venv \
    && /var/www/webserver/venv/bin/pip install --no-cache-dir flask gunicorn requests cryptography

# Create a normal user for SSH access
RUN useradd -m -s /bin/bash webserver && \
    echo "webserver:${LAB_SSH_PASSWORD}" | chpasswd

# Prepare SSH: create runtime dir & set root password
RUN mkdir -p /var/run/sshd && \
    echo "root:${LAB_ROOT_PASSWORD}" | chpasswd

# Enable root login over SSH
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Create private key and CSR 
RUN mkdir -p /etc/ssl/webserver && \
    openssl genrsa -out /etc/ssl/webserver/webserver.key 2048 && \
    openssl req -new -key /etc/ssl/webserver/webserver.key -out /etc/ssl/webserver/webserver.csr \
        -subj "/CN=webserver" \
        -addext "subjectAltName=DNS:webserver,IP:10.100.0.1"

# Copy startup, web app scripts
COPY Images/webserver/webserver.startup /root/
COPY Images/webserver/webserver.startserver /root/
COPY Images/webserver/webserver.py /var/www/webserver
COPY Images/webserver/templates /var/www/webserver/templates
RUN chmod +x /root/webserver.startup /root/webserver.startserver 

# Launch apps from the dedicated folder
WORKDIR /var/www/webserver

# Expose SSH, HTTPS ports
EXPOSE 22 443

# Default shell if startup script ends
CMD ["/bin/bash"]
