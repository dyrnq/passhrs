FROM alpine:3.19

RUN apk add --no-cache openssh-server openssh-sftp-server

RUN ssh-keygen -A

# Ensure AllowTcpForwarding is yes — only one line
RUN sed -i '/^AllowTcpForwarding/d; /^#AllowTcpForwarding/d' /etc/ssh/sshd_config && \
    sed -i '/^GatewayPorts/d; /^#GatewayPorts/d' /etc/ssh/sshd_config && \
    sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "AllowTcpForwarding yes" >> /etc/ssh/sshd_config && \
    echo "GatewayPorts yes" >> /etc/ssh/sshd_config && \
    echo "AcceptEnv LANG LC_*" >> /etc/ssh/sshd_config

RUN adduser -D testuser && echo "testuser:testpass" | chpasswd

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]
