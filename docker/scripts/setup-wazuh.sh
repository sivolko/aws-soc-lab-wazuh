#!/bin/bash
# Wazuh Docker Setup Script for SOC Lab

set -e

echo "[INFO] Starting Wazuh Docker setup..."

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "[ERROR] Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "[ERROR] Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Create necessary directories
echo "[INFO] Creating required directories..."
mkdir -p config/wazuh_indexer_ssl_certs
mkdir -p config/wazuh-indexer
mkdir -p config/wazuh-dashboard
mkdir -p data/wazuh-indexer
mkdir -p data/wazuh-manager
mkdir -p logs

# Generate certificates if they don't exist
if [ ! -f "config/wazuh_indexer_ssl_certs/root-ca.pem" ]; then
    echo "[INFO] Generating SSL certificates..."
    ./scripts/generate-certs.sh
else
    echo "[INFO] SSL certificates already exist."
fi

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "[INFO] Creating .env file from template..."
    cp .env.example .env
    
    # Generate random passwords
    WAZUH_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-16)
    INDEXER_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-16)
    API_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-16)
    DASHBOARD_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-16)
    
    # Update .env file with generated passwords
    sed -i "s/SecurePassword123!/$WAZUH_PASSWORD/g" .env
    sed -i "s/INDEXER_PASSWORD=.*/INDEXER_PASSWORD=$INDEXER_PASSWORD/" .env
    sed -i "s/API_PASSWORD=.*/API_PASSWORD=$API_PASSWORD/" .env
    sed -i "s/DASHBOARD_PASSWORD=.*/DASHBOARD_PASSWORD=$DASHBOARD_PASSWORD/" .env
    
    echo "[INFO] Generated random passwords and updated .env file"
    echo "[INFO] Please save these credentials:"
    echo "  Wazuh Admin Password: $WAZUH_PASSWORD"
    echo "  Indexer Password: $INDEXER_PASSWORD"
    echo "  API Password: $API_PASSWORD"
    echo "  Dashboard Password: $DASHBOARD_PASSWORD"
else
    echo "[INFO] .env file already exists."
fi

# Set proper permissions
echo "[INFO] Setting file permissions..."
chmod 600 .env
chmod -R 755 config/
chmod -R 644 config/wazuh_indexer_ssl_certs/*.pem
chmod -R 644 config/wazuh_indexer_ssl_certs/*.key

# Increase virtual memory for Elasticsearch
echo "[INFO] Configuring system settings for Elasticsearch..."
echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
sudo sysctl -w vm.max_map_count=262144

# Pull Docker images
echo "[INFO] Pulling Docker images..."
docker-compose pull

# Start Wazuh stack
echo "[INFO] Starting Wazuh stack..."
docker-compose up -d

# Wait for services to be ready
echo "[INFO] Waiting for services to start..."
sleep 30

# Check service health
echo "[INFO] Checking service health..."
for i in {1..12}; do
    if docker-compose ps | grep -q "Up"; then
        echo "[INFO] Services are starting up... (attempt $i/12)"
        sleep 10
    else
        echo "[ERROR] Services failed to start properly"
        docker-compose logs
        exit 1
    fi
done

# Final health check
echo "[INFO] Performing final health checks..."

# Check Wazuh Manager
if docker-compose exec -T wazuh-manager /var/ossec/bin/wazuh-control status | grep -q "wazuh-execd is running"; then
    echo "[SUCCESS] Wazuh Manager is running"
else
    echo "[WARNING] Wazuh Manager may not be fully ready yet"
fi

# Check Wazuh Indexer
if curl -s -k -u admin:$(grep INDEXER_PASSWORD .env | cut -d= -f2) https://localhost:9200/_cluster/health | grep -q "yellow\|green"; then
    echo "[SUCCESS] Wazuh Indexer is running"
else
    echo "[WARNING] Wazuh Indexer may not be fully ready yet"
fi

# Check Wazuh Dashboard
if curl -s -k https://localhost:443 | grep -q "Wazuh"; then
    echo "[SUCCESS] Wazuh Dashboard is accessible"
else
    echo "[WARNING] Wazuh Dashboard may not be fully ready yet"
fi

echo ""
echo "==================================================="
echo "          Wazuh SOC Lab Setup Complete!"
echo "==================================================="
echo ""
echo "Dashboard URL: https://$(hostname -I | awk '{print $1}'):443"
echo "Username: admin"
echo "Password: $(grep WAZUH_PASSWORD .env | cut -d= -f2)"
echo ""
echo "Manager API: https://$(hostname -I | awk '{print $1}'):55000"
echo "Indexer: https://$(hostname -I | awk '{print $1}'):9200"
echo ""
echo "To view logs: docker-compose logs -f"
echo "To stop: docker-compose down"
echo "To restart: docker-compose restart"
echo ""
echo "For agent installation on endpoints:"
echo "wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.3-1_amd64.deb"
echo "sudo WAZUH_MANAGER='$(hostname -I | awk '{print $1}')' dpkg -i wazuh-agent_4.7.3-1_amd64.deb"
echo "sudo systemctl enable wazuh-agent"
echo "sudo systemctl start wazuh-agent"
echo ""
echo "Happy hunting! 🛡️"