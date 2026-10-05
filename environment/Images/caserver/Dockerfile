FROM debian:12

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

ARG LAB_ROOT_PASSWORD
ARG LAB_SSH_PASSWORD

# Install base packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iproute2 iputils-ping iptables dnsutils curl \
        nginx openssl python3 python3-pip python3-venv ca-certificates \
        openssh-server xinetd netcat-openbsd && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

ENV PATH="/var/www/caserver/venv/bin:$PATH"
RUN python3 -m venv /var/www/caserver/venv \
    && /var/www/caserver/venv/bin/pip install --no-cache-dir flask gunicorn requests cryptography

# Create a normal user for SSH access
RUN useradd -m -s /bin/bash caserver && \
    echo "caserver:${LAB_SSH_PASSWORD}" | chpasswd

# Setup SSH
RUN mkdir -p /var/run/sshd && \
    echo "root:${LAB_ROOT_PASSWORD}" | chpasswd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Prepare CA directories and basic config
RUN mkdir -p /etc/ssl/ca/certs \
    /etc/ssl/ca/crl \
    /etc/ssl/ca/newcerts \
    /etc/ssl/ca/private \
    /etc/ssl/ca/csr && \
    chmod 700 /etc/ssl/ca/private && \
    touch /etc/ssl/ca/index.txt && \
    echo 1000 > /etc/ssl/ca/serial

# Set up key for encrypting the private keys in archive
RUN openssl rand -out "/etc/ssl/ca/aes_key.bin" 32 && \
    chmod 600 "/etc/ssl/ca/aes_key.bin"

# Create a root CA key + certificate 
RUN openssl genrsa -out /etc/ssl/ca/private/ca.key.pem 4096 && \
    chmod 400 /etc/ssl/ca/private/ca.key.pem && \
    openssl req -x509 -new -nodes -days 3650 \
        -key /etc/ssl/ca/private/ca.key.pem \
        -sha256 -out /etc/ssl/ca/certs/ca.cert.pem \
        -subj "/CN=caserver"

# Minimal OpenSSL CA config + CRL support
RUN cat > /etc/ssl/ca/openssl.cnf <<'EOF'
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = /etc/ssl/ca
certs             = $dir/certs
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
RANDFILE          = $dir/private/.rand

private_key       = $dir/private/ca.key.pem
certificate       = $dir/certs/ca.cert.pem

default_days      = 375
default_md        = sha256
policy            = policy_strict
email_in_dn       = no
copy_extensions   = copy

crlnumber         = $dir/crlnumber
crl_dir           = $dir/crl
default_crl_days  = 30

[ policy_strict ]
commonName              = supplied

[ server_client_cert ]
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth

[ server_cert ]
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[ client_cert ]
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth

[ crl_ext ]
authorityKeyIdentifier=keyid:always
EOF

# Initialize CRL database file
RUN echo 1000 > /etc/ssl/ca/crlnumber && \
    openssl ca -config /etc/ssl/ca/openssl.cnf -gencrl -out /etc/ssl/ca/crl/ca.crl.pem

# Generate key + CRT for admin user
#RUN mkdir -p /etc/ssl/client && \
#    openssl genrsa -out /etc/ssl/client/client.key 2048 && \
#    openssl req -new -key /etc/ssl/client/client.key \
#        -out /etc/ssl/client/client.csr \
#        -subj "/CN=ps" && \
#    openssl ca -batch -config /etc/ssl/ca/openssl.cnf \
#        -extensions client_cert \
#        -in /etc/ssl/client/client.csr \
#        -out /etc/ssl/client/client.crt \
#        -notext -md sha256 && \
#    openssl pkcs12 -export \
#        -in /etc/ssl/client/client.crt \
#        -inkey /etc/ssl/client/client.key \
#        -out /etc/ssl/client/client.p12 \
#        -passout pass:

# Generate key + CRT for nginx
# both as a client and server <- server_client_cert
RUN mkdir -p /etc/ssl/nginx && \
    openssl genrsa -out /etc/ssl/nginx/nginx.key 2048 && \
    openssl req -new -key /etc/ssl/nginx/nginx.key \
        -out /etc/ssl/nginx/nginx.csr \
        -subj "/CN=caserver" \
        -addext "subjectAltName=DNS:caserver,IP:10.101.0.2" && \
    openssl ca -batch -config /etc/ssl/ca/openssl.cnf \
        -extensions server_client_cert \
        -in /etc/ssl/nginx/nginx.csr \
        -out /etc/ssl/nginx/nginx.crt \
        -notext -md sha256 && \
    chmod 400 /etc/ssl/nginx/nginx.key

# Write a safe nginx site config for mTLS + proxying to Flask
RUN rm -f /etc/nginx/sites-enabled/default && \
    cat > /etc/nginx/sites-available/caserver <<'NGINX_CONF'
server {
    listen 443 ssl;
    server_name caserver;

    ssl_certificate /etc/ssl/nginx/nginx.crt;
    ssl_certificate_key /etc/ssl/nginx/nginx.key;

    # Require client certificate (mTLS)
    ssl_client_certificate /etc/ssl/ca/certs/ca.cert.pem;
    ssl_verify_client on;
    ssl_verify_depth 1;

    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers on;

    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY always; 
    add_header Referrer-Policy: no-referrer;

    location = /issue {
        proxy_pass http://127.0.0.1:5000/issue;
        proxy_set_header X-Client-Cert $ssl_client_s_dn;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location = /validate {
        proxy_pass http://127.0.0.1:5000/validate;
        proxy_set_header X-Client-Cert $ssl_client_s_dn;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location = /revoke {
        proxy_pass http://127.0.0.1:5000/revoke;
        proxy_set_header X-Client-Cert $ssl_client_s_dn;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location = /crl {
        proxy_pass http://127.0.0.1:5000/crl;
        proxy_set_header X-Client-Cert $ssl_client_s_dn;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location = /ca_info {
        proxy_pass http://127.0.0.1:5000/ca_info;
        proxy_set_header X-Client-Cert $ssl_client_s_dn;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # A minimal endpoint forwarded to Flask
    location / {
        proxy_pass http://127.0.0.1:5000/;
        proxy_set_header X-Client-Cert $ssl_client_s_dn;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
NGINX_CONF

RUN ln -s /etc/nginx/sites-available/caserver /etc/nginx/sites-enabled/caserver

# Copy application files (you had those paths)
COPY Images/caserver/caserver.startup /root/caserver.startup
COPY Images/caserver/caserver.startserver /root/caserver.startserver
COPY Images/caserver/ca_api.py /var/www/caserver

RUN chmod +x /root/caserver.startup /root/caserver.startserver

# Launch apps from the dedicated folder
WORKDIR /var/www/caserver

# Expose SSH + HTTPS
EXPOSE 22 443

# TODO send configs

# Use the startup script as the container entrypoint
CMD ["/bin/bash"]
