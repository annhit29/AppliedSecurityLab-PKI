FROM debian:12

ENV DEBIAN_FRONTEND=noninteractive

ARG LAB_ROOT_PASSWORD
ARG LAB_SSH_PASSWORD
ARG MYSQL_ROOT_PASSWORD
ARG AUTH_DB_PASSWORD
ARG JWT_SECRET

ENV MYSQL_ROOT_PASSWORD=${MYSQL_ROOT_PASSWORD} \
    AUTH_DB_PASSWORD=${AUTH_DB_PASSWORD} \
    JWT_SECRET=${JWT_SECRET}

# Install required packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iproute2 iputils-ping iptables dnsutils curl \
        openssl nginx openssh-server xinetd netcat-openbsd \
        python3 python3-pip python3-venv jq && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

ENV PATH="/var/www/authserver/venv/bin:$PATH"
RUN python3 -m venv /var/www/authserver/venv \
    && /var/www/authserver/venv/bin/pip install --no-cache-dir flask gunicorn requests PyJWT mysql-connector-python 

### --- MySQL INSTALLATION (same as logserver) --- ###
# Install packages needed for MySQL installation
RUN apt-get update && apt-get install -y \
    wget lsb-release gnupg ca-certificates

# Required legacy MySQL GPG key import
RUN curl -fsSL "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0xB7B3B788A8D3785C" \
        -o /tmp/mysql_release_old.asc && \
    gpg --import /tmp/mysql_release_old.asc && \
    gpg --batch --yes --output /usr/share/keyrings/mysql-apt-config.gpg \
        --export BCA43417C3B485DD128EC6D4B7B3B788A8D3785C && \
    rm /tmp/mysql_release_old.asc

# Install MySQL APT repo config
RUN wget https://dev.mysql.com/get/mysql-apt-config_0.8.32-1_all.deb && \
    DEBIAN_FRONTEND=noninteractive dpkg -i mysql-apt-config_0.8.32-1_all.deb && \
    rm mysql-apt-config_0.8.32-1_all.deb && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y mysql-server

# Create a normal user for SSH access
RUN useradd -m -s /bin/bash authserver && \
    echo "authserver:${LAB_SSH_PASSWORD}" | chpasswd

# Prepare SSH
RUN mkdir -p /var/run/sshd && \
    echo "root:${LAB_ROOT_PASSWORD}" | chpasswd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Create private key and CSR 
RUN mkdir -p /etc/ssl/authserver && \
    openssl genrsa -out /etc/ssl/authserver/authserver.key 2048 && \
    openssl req -new -key /etc/ssl/authserver/authserver.key -out /etc/ssl/authserver/authserver.csr \
        -subj "/CN=authserver" \
        -addext "subjectAltName=DNS:authserver,IP:10.101.0.1"

# Copy startup scripts
COPY Images/authserver/authserver.startup /root/
COPY Images/authserver/authserver.startserver /root/
COPY Images/authserver/auth.py /var/www/authserver
# Include synthetic seed data (no real or course-provided identities).
COPY Images/authserver/seed_users.sql /root/seed_users.sql

RUN chmod +x /root/authserver.startup /root/authserver.startserver 

# Launch apps from the dedicated folder
WORKDIR /var/www/authserver

# Expose SSH and HTTPS
EXPOSE 22 443

# Run the startup script as entrypoint
CMD ["/bin/bash"]
