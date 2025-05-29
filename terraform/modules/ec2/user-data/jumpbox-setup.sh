#!/bin/bash
# Jump Box (Bastion Host) Setup Script

set -e

# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Install essential tools
sudo apt-get install -y \
    htop \
    vim \
    curl \
    wget \
    git \
    tree \
    unzip \
    jq \
    awscli \
    net-tools \
    nmap \
    telnet \
    ssh \
    rsync

# Install Session Manager plugin for AWS CLI
wget https://s3.amazonaws.com/session-manager-downloads/plugin/latest/ubuntu_64bit/session-manager-plugin.deb
sudo dpkg -i session-manager-plugin.deb

# Configure SSH for port forwarding and jump host functionality
sudo tee -a /etc/ssh/sshd_config << EOF

# Jump Box Configuration
AllowTcpForwarding yes
GatewayPorts no
X11Forwarding yes
ClientAliveInterval 60
ClientAliveCountMax 3
MaxSessions 10
EOF

sudo systemctl restart sshd

# Create SSH configuration template for users
cat > /home/ubuntu/.ssh/config << EOF
# SSH Configuration for SOC Lab
# Use this jump box to access private instances

Host wazuh-server
    HostName WAZUH_PRIVATE_IP
    User ubuntu
    Port 22
    IdentityFile ~/.ssh/lab-key.pem
    
Host linux-endpoint
    HostName LINUX_PRIVATE_IP
    User ubuntu
    Port 22
    IdentityFile ~/.ssh/lab-key.pem
    
Host windows-endpoint
    HostName WINDOWS_PRIVATE_IP
    User Administrator
    Port 3389
    IdentityFile ~/.ssh/lab-key.pem
EOF

chmod 600 /home/ubuntu/.ssh/config

# Install monitoring tools
sudo apt-get install -y iotop sysstat nethogs

# Install Docker for any containerized tools
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker ubuntu

# Create useful aliases
cat >> /home/ubuntu/.bashrc << EOF

# SOC Lab Aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias grep='grep --color=auto'
alias fgrep='fgrep --color=auto'
alias egrep='egrep --color=auto'

# Network aliases
alias ports='netstat -tulanp'
alias listening='ss -tuln'
alias connections='ss -tun'

# System monitoring
alias topcpu='ps aux --sort=-%cpu | head'
alias topmem='ps aux --sort=-%mem | head'
EOF

# Create connection helper scripts
cat > /home/ubuntu/connect-wazuh.sh << 'EOF'
#!/bin/bash
echo "Connecting to Wazuh server..."
ssh -i ~/.ssh/lab-key.pem ubuntu@WAZUH_PRIVATE_IP
EOF

cat > /home/ubuntu/connect-linux.sh << 'EOF'
#!/bin/bash
echo "Connecting to Linux endpoint..."
ssh -i ~/.ssh/lab-key.pem ubuntu@LINUX_PRIVATE_IP
EOF

cat > /home/ubuntu/tunnel-wazuh.sh << 'EOF'
#!/bin/bash
echo "Creating SSH tunnel to Wazuh dashboard..."
echo "Access dashboard at: https://localhost:8443"
ssh -i ~/.ssh/lab-key.pem -L 8443:localhost:443 ubuntu@WAZUH_PRIVATE_IP
EOF

chmod +x /home/ubuntu/*.sh

# Install AWS CloudWatch agent
wget https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb
sudo dpkg -i amazon-cloudwatch-agent.deb

# Create welcome message
cat > /home/ubuntu/README.txt << EOF
=== SOC Lab Jump Box ===

This is your jump box (bastion host) for accessing the SOC lab environment.

Available connection scripts:
- ./connect-wazuh.sh     - Connect to Wazuh server
- ./connect-linux.sh     - Connect to Linux endpoint  
- ./tunnel-wazuh.sh      - Create tunnel to Wazuh dashboard

Important:
1. Upload your private key as ~/.ssh/lab-key.pem
2. Set proper permissions: chmod 600 ~/.ssh/lab-key.pem
3. Update the IP addresses in the scripts with actual private IPs

Useful commands:
- ports              - Show listening ports
- topcpu             - Show top CPU processes
- topmem             - Show top memory processes

For AWS CLI access, the instance has an IAM role attached.

Happy hacking!
EOF

# Configure log rotation
sudo tee /etc/logrotate.d/jumpbox << EOF
/var/log/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    copytruncate
}
EOF

echo "Jump box setup completed!"
echo "SSH tunneling and port forwarding enabled."
echo "See ~/README.txt for usage instructions."