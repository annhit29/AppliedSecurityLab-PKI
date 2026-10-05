# Base image
FROM debian:12

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

ARG LAB_ROOT_PASSWORD
ARG LAB_SSH_PASSWORD

# Install only required packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iproute2 iptables iputils-ping openssh-server xinetd netcat-openbsd passwd && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Create a normal user for SSH access
RUN useradd -m -s /bin/bash fw2 && \
    echo "fw2:${LAB_SSH_PASSWORD}" | chpasswd

# Prepare SSH server
RUN mkdir -p /var/run/sshd && \
    echo "root:${LAB_ROOT_PASSWORD}" | chpasswd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Copy startup script
COPY Images/fw2/fw2.startup /root/
RUN chmod +x /root/fw2.startup

# Expose SSH port
EXPOSE 22

# Default shell if startup script ends
CMD ["/bin/bash"]
