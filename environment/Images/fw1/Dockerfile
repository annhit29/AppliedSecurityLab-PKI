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
RUN useradd -m -s /bin/bash fw1 && \
    echo "fw1:${LAB_SSH_PASSWORD}" | chpasswd

# Prepare SSH server
RUN mkdir -p /var/run/sshd && \
    echo "root:${LAB_ROOT_PASSWORD}" | chpasswd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Copy startup script
COPY Images/fw1/fw1.startup /root/
RUN chmod +x /root/fw1.startup

# Expose SSH port
EXPOSE 22

# Default shell if startup script ends
CMD ["/bin/bash"]
