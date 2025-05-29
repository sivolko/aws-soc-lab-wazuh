#!/bin/bash
# Wazuh Server Setup Script

set -e

# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Install required packages
sudo apt-get install -y curl wget gnupg lsb-release apt-transport-https

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker ubuntu

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Create directories
sudo mkdir -p /opt/wazuh
sudo chown ubuntu:ubuntu /opt/wazuh
cd /opt/wazuh

# Download Wazuh Docker configuration
wget https://packages.wazuh.com/4.7/docker/docker-compose.yml
wget https://packages.wazuh.com/4.7/docker/generate-indexer-certs.yml
wget https://packages.wazuh.com/4.7/docker/config/wazuh_indexer_ssl_certs/wazuh-certificates-tool.sh

# Set up environment variables
cat > .env << EOF
WAZUH_STACK_VERSION=4.7.3
ELASTIC_PASSWORD=${wazuh_password}
KIBANA_PASSWORD=${wazuh_password}
WAZUH_USERNAME=admin
WAZUH_PASSWORD=${wazuh_password}
API_USERNAME=wazuh-wui
API_PASSWORD=${wazuh_password}
HASH_ALGORITHM=bcrypt
INDEXER_USERNAME=admin
INDEXER_PASSWORD=${wazuh_password}
DASHBOARD_USERNAME=kibanaserver
DASHBOARD_PASSWORD=${wazuh_password}
EOF

# Generate certificates
sudo docker-compose -f generate-indexer-certs.yml run --rm generator

# Set proper permissions
sudo chown -R ubuntu:ubuntu /opt/wazuh

# Install AWS CLI
sudo apt-get install -y awscli

# Install CloudWatch agent
wget https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb
sudo dpkg -i amazon-cloudwatch-agent.deb

# Configure system for Wazuh
echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
sudo sysctl -w vm.max_map_count=262144

# Increase file limits
echo 'ubuntu soft nofile 65536' | sudo tee -a /etc/security/limits.conf
echo 'ubuntu hard nofile 65536' | sudo tee -a /etc/security/limits.conf

# Start Wazuh stack
sudo docker-compose up -d

# Wait for services to start
sleep 60

# Create startup script
cat > /opt/wazuh/start-wazuh.sh << 'EOF'
#!/bin/bash
cd /opt/wazuh
sudo docker-compose up -d
EOF

chmod +x /opt/wazuh/start-wazuh.sh

# Create systemd service for auto-start
sudo tee /etc/systemd/system/wazuh.service > /dev/null <<EOF
[Unit]
Description=Wazuh Docker Stack
Requires=docker.service
After=docker.service

[Service]
Restart=always
User=ubuntu
Group=docker
WorkingDirectory=/opt/wazuh
ExecStart=/usr/local/bin/docker-compose up
ExecStop=/usr/local/bin/docker-compose down

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable wazuh.service
sudo systemctl start wazuh.service

# Create log rotation configuration
sudo tee /etc/logrotate.d/wazuh << EOF
/opt/wazuh/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    copytruncate
}
EOF

# Setup monitoring script
cat > /home/ubuntu/health-check.sh << 'EOF'
#!/bin/bash
# Simple health check for Wazuh components
echo "Checking Wazuh components..."
docker-compose -f /opt/wazuh/docker-compose.yml ps
echo "\nWazuh Manager API status:"
curl -k -u admin:${WAZUH_PASSWORD} https://localhost:55000/
echo "\nWazuh Dashboard status:"
curl -k https://localhost:443/app/wazuh
EOF

chmod +x /home/ubuntu/health-check.sh

echo "Wazuh installation completed!"
echo "Dashboard URL: https://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):443"
echo "Username: admin"
echo "Password: ${wazuh_password}"