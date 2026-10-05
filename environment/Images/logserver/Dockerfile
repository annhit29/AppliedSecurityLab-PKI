FROM debian:12

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/var/www/venv/bin:$PATH"

# Build args -> env
ARG DB_USER_LOGAPP DB_PASS_LOGAPP
ARG DB_USER_READONLY DB_PASS_READONLY
ARG DB_USER_REVOKE DB_PASS_REVOKE
ARG MYSQL_ROOT_PASSWORD LAB_ROOT_PASSWORD LAB_SSH_PASSWORD

ENV DB_USER_LOGAPP=${DB_USER_LOGAPP} \
    DB_PASS_LOGAPP=${DB_PASS_LOGAPP} \
    DB_USER_READONLY=${DB_USER_READONLY} \
    DB_PASS_READONLY=${DB_PASS_READONLY} \
    DB_USER_REVOKE=${DB_USER_REVOKE} \
    DB_PASS_REVOKE=${DB_PASS_REVOKE} \
    MYSQL_ROOT_PASSWORD=${MYSQL_ROOT_PASSWORD}

# Install base packages + import the MySQL GPG key the OLD WAY
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 python3-venv python3-pip \
        nginx openssl iproute2 iputils-ping iptables curl \
        openssh-server netcat-openbsd \
        wget lsb-release gnupg ca-certificates

# REQUIRED LEGACY MYSQL GPG KEY IMPORT
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
    # Now apt can safely read the mysql repo
    apt-get update && \
    # Install MySQL server
    DEBIAN_FRONTEND=noninteractive apt-get install -y mysql-server

# Python environment
RUN python3 -m venv /var/www/venv && \
    /var/www/venv/bin/pip install --no-cache-dir \
        flask gunicorn mysql-connector-python && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Create a normal user for SSH access
RUN useradd -m -s /bin/bash logserver && \
    echo "logserver:${LAB_SSH_PASSWORD}" | chpasswd

# Setup SSH + SSL
RUN mkdir -p /var/run/sshd && \
    echo "root:${LAB_ROOT_PASSWORD}" | chpasswd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    \
    mkdir -p /etc/ssl/logserver && \
    openssl genrsa -out /etc/ssl/logserver/logserver.key 2048 && \
    openssl req -new -key /etc/ssl/logserver/logserver.key \
        -out /etc/ssl/logserver/logserver.csr \
        -subj "/CN=logserver" \
        -addext "subjectAltName=DNS:logserver,IP:10.101.0.3"

# Copy app files
COPY Images/logserver/logserver.startup /root/
COPY Images/logserver/logserver.startserver /root/
COPY Images/logserver/save_logs.py /var/www/logserver/save_logs.py
COPY Images/logserver/logserver_schema.sql /root/logserver_schema.sql

RUN chmod +x /root/logserver.startup \
             /root/logserver.startserver \
             /var/www/logserver/save_logs.py 

WORKDIR /var/www/logserver
EXPOSE 22 443

CMD ["/bin/bash"]
