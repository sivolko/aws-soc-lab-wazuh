#!/bin/bash
# Wazuh Restore Script

set -e

if [ $# -eq 0 ]; then
    echo "Usage: $0 <backup-file.tar.gz>"
    echo "Example: $0 /opt/wazuh-backups/wazuh-backup-20241201_120000.tar.gz"
    exit 1
fi

BACKUP_FILE="$1"
RESTORE_DIR="/tmp/wazuh-restore-$(date +%Y%m%d_%H%M%S)"

if [ ! -f "$BACKUP_FILE" ]; then
    echo "[ERROR] Backup file not found: $BACKUP_FILE"
    exit 1
fi

echo "[INFO] Starting Wazuh restore from: $BACKUP_FILE"

# Stop current Wazuh stack
echo "[INFO] Stopping current Wazuh stack..."
docker-compose down

# Create restore directory
mkdir -p $RESTORE_DIR

# Extract backup
echo "[INFO] Extracting backup..."
tar -xzf "$BACKUP_FILE" -C $RESTORE_DIR

# Find the backup directory (should be only one)
BACKUP_DIR=$(find $RESTORE_DIR -maxdepth 1 -name "wazuh-backup-*" -type d | head -1)

if [ -z "$BACKUP_DIR" ]; then
    echo "[ERROR] Invalid backup format"
    exit 1
fi

echo "[INFO] Found backup directory: $BACKUP_DIR"

# Display backup metadata
if [ -f "$BACKUP_DIR/backup-metadata.txt" ]; then
    echo "[INFO] Backup metadata:"
    cat "$BACKUP_DIR/backup-metadata.txt"
    echo ""
fi

# Confirm restore
read -p "Do you want to continue with the restore? This will overwrite current data. (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "[INFO] Restore cancelled"
    rm -rf $RESTORE_DIR
    exit 0
fi

# Backup current configuration (just in case)
echo "[INFO] Creating safety backup of current configuration..."
SAFETY_BACKUP="/tmp/wazuh-safety-backup-$(date +%Y%m%d_%H%M%S).tar.gz"
tar -czf $SAFETY_BACKUP config/ docker-compose.yml .env 2>/dev/null || true
echo "[INFO] Safety backup created: $SAFETY_BACKUP"

# Restore Docker configurations
echo "[INFO] Restoring Docker configurations..."
cp -r $BACKUP_DIR/config/ ./
cp $BACKUP_DIR/docker-compose.yml ./
cp $BACKUP_DIR/.env ./

# Start Wazuh stack
echo "[INFO] Starting Wazuh stack..."
docker-compose up -d

# Wait for services to start
echo "[INFO] Waiting for services to start..."
sleep 30

# Restore Wazuh configuration
echo "[INFO] Restoring Wazuh configuration..."
docker cp $BACKUP_DIR/wazuh-config.tar.gz wazuh-manager:/tmp/
docker-compose exec -T wazuh-manager bash -c "cd /tmp && tar -xzf wazuh-config.tar.gz && cp -r var/ossec/etc/* /var/ossec/etc/ && cp -r var/ossec/rules/* /var/ossec/rules/ && cp -r var/ossec/decoders/* /var/ossec/decoders/"

# Restore Wazuh data
echo "[INFO] Restoring Wazuh data..."
docker cp $BACKUP_DIR/wazuh-data.tar.gz wazuh-manager:/tmp/
docker-compose exec -T wazuh-manager bash -c "cd /tmp && tar -xzf wazuh-data.tar.gz && cp -r var/ossec/logs/* /var/ossec/logs/ || true && cp -r var/ossec/stats/* /var/ossec/stats/ || true"

# Restore Indexer data
echo "[INFO] Restoring Indexer data..."
docker cp $BACKUP_DIR/indexer-snapshot.tar.gz wazuh-indexer:/tmp/
docker-compose exec -T wazuh-indexer bash -c "cd /tmp && tar -xzf indexer-snapshot.tar.gz && cp -r usr/share/wazuh-indexer/snapshots/* /usr/share/wazuh-indexer/snapshots/ || true"

# Restart services
echo "[INFO] Restarting services..."
docker-compose restart

# Wait for services to be ready
echo "[INFO] Waiting for services to be ready..."
sleep 60

# Verify services
echo "[INFO] Verifying services..."
for i in {1..12}; do
    if docker-compose ps | grep -q "Up"; then
        echo "[INFO] Services are running (attempt $i/12)"
        break
    else
        echo "[WARNING] Services not ready yet, waiting..."
        sleep 10
    fi
done

# Clean up
echo "[INFO] Cleaning up temporary files..."
rm -rf $RESTORE_DIR
docker-compose exec -T wazuh-manager rm -f /tmp/wazuh-config.tar.gz /tmp/wazuh-data.tar.gz
docker-compose exec -T wazuh-indexer rm -f /tmp/indexer-snapshot.tar.gz

echo ""
echo "==================================================="
echo "          Wazuh Restore Completed!"
echo "==================================================="
echo ""
echo "Dashboard URL: https://$(hostname -I | awk '{print $1}'):443"
echo "Username: admin"
echo "Password: $(grep WAZUH_PASSWORD .env | cut -d= -f2)"
echo ""
echo "Safety backup of previous config: $SAFETY_BACKUP"
echo ""
echo "Please verify that all services are working correctly."
echo "Check logs with: docker-compose logs -f"
echo ""
echo "Restore completed successfully! 🛡️"