#!/bin/bash
# Ubuntu Endpoint Setup Script with Wazuh Agent

set -e

# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Install required packages
sudo apt-get install -y curl wget gnupg lsb-release software-properties-common

# Install monitoring tools
sudo apt-get install -y htop iotop sysstat auditd

# Install Docker for vulnerable applications
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker ubuntu

# Install vulnerable web applications
sudo mkdir -p /opt/vulnerable-apps
cd /opt/vulnerable-apps

# DVWA (Damn Vulnerable Web Application)
cat > docker-compose.yml << EOF
version: '3'
services:
  dvwa:
    image: vulnerables/web-dvwa
    ports:
      - "8080:80"
    restart: always
    
  webgoat:
    image: webgoat/goatandwolf
    ports:
      - "8081:8080"
    restart: always
    
  juiceshop:
    image: bkimminich/juice-shop
    ports:
      - "8082:3000"
    restart: always
EOF

sudo docker-compose up -d

# Wait for Wazuh server to be ready
echo "Waiting for Wazuh server to be ready..."
sleep 120

# Install Wazuh Agent
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee -a /etc/apt/sources.list.d/wazuh.list
sudo apt-get update

# Set Wazuh manager IP
echo "WAZUH_MANAGER='${wazuh_server_ip}'" | sudo tee -a /var/ossec/etc/preloaded-vars.conf
echo "WAZUH_PROTOCOL='tcp'" | sudo tee -a /var/ossec/etc/preloaded-vars.conf
echo "WAZUH_REGISTRATION_SERVER='${wazuh_server_ip}'" | sudo tee -a /var/ossec/etc/preloaded-vars.conf

# Install and configure Wazuh agent
sudo WAZUH_MANAGER='${wazuh_server_ip}' apt-get install -y wazuh-agent

# Configure Wazuh agent
sudo sed -i "s/<server>.*<\/server>/<server>${wazuh_server_ip}<\/server>/g" /var/ossec/etc/ossec.conf

# Enable additional monitoring
sudo tee -a /var/ossec/etc/ossec.conf << EOF
  <syscheck>
    <directories check_all="yes" realtime="yes">/home,/root,/etc,/var/www</directories>
  </syscheck>
  
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
  
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>
  
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/access.log</location>
  </localfile>
  
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/error.log</location>
  </localfile>
EOF

# Start and enable Wazuh agent
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

# Install additional security tools
sudo apt-get install -y fail2ban rkhunter chkrootkit

# Configure fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Install web server for testing
sudo apt-get install -y apache2
sudo systemctl enable apache2
sudo systemctl start apache2

# Create test files for file integrity monitoring
sudo mkdir -p /var/www/html/test
echo "Test file for FIM" | sudo tee /var/www/html/test/fim-test.txt

# Create script for generating test logs
cat > /home/ubuntu/generate-test-logs.sh << 'EOF'
#!/bin/bash
# Generate various types of logs for testing

echo "Generating authentication logs..."
logger -p auth.info "Test SSH login for user testuser"
logger -p auth.warning "Failed SSH login attempt for user admin"

echo "Generating web server logs..."
curl -s http://localhost/ > /dev/null
curl -s http://localhost/nonexistent > /dev/null

echo "Generating system logs..."
logger -p kern.info "Test kernel message"
logger -p daemon.warning "Test daemon warning"

echo "Test logs generated successfully!"
EOF

chmod +x /home/ubuntu/generate-test-logs.sh

# Create cron job for regular log generation
(crontab -l 2>/dev/null; echo "*/15 * * * * /home/ubuntu/generate-test-logs.sh") | crontab -

# AWS CloudWatch agent
wget https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb
sudo dpkg -i amazon-cloudwatch-agent.deb

echo "Ubuntu endpoint setup completed!"
echo "Vulnerable applications available at:"
echo "  - DVWA: http://$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4):8080"
echo "  - WebGoat: http://$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4):8081/goatandwolf"
echo "  - OWASP Juice Shop: http://$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4):8082"
echo "Wazuh agent connected to: ${wazuh_server_ip}"