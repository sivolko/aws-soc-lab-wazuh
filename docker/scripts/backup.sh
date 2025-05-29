#!/bin/bash
# Wazuh Backup Script

set -e

BACKUP_DIR="/opt/wazuh-backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="wazuh-backup-$DATE"
BACKUP_PATH="$BACKUP_DIR/$BACKUP_NAME"
RETENTION_DAYS=7

echo "[INFO] Starting Wazuh backup: $BACKUP_NAME"

# Create backup directory
sudo mkdir -p $BACKUP_DIR

# Create temporary backup directory
mkdir -p /tmp/$BACKUP_NAME

# Backup Wazuh configuration
echo "[INFO] Backing up Wazuh configuration..."
docker-compose exec -T wazuh-manager tar -czf /tmp/wazuh-config.tar.gz /var/ossec/etc /var/ossec/rules /var/ossec/decoders
docker cp wazuh-manager:/tmp/wazuh-config.tar.gz /tmp/$BACKUP_NAME/

# Backup Wazuh data
echo "[INFO] Backing up Wazuh data..."
docker-compose exec -T wazuh-manager tar -czf /tmp/wazuh-data.tar.gz /var/ossec/logs /var/ossec/stats /var/ossec/queue
docker cp wazuh-manager:/tmp/wazuh-data.tar.gz /tmp/$BACKUP_NAME/

# Backup Indexer data
echo "[INFO] Backing up Indexer data..."
docker-compose exec -T wazuh-indexer /usr/share/wazuh-indexer/bin/opensearch-snapshot-tool create-snapshot --snapshot-name backup-$DATE --repository fs-repo
docker-compose exec -T wazuh-indexer tar -czf /tmp/indexer-snapshot.tar.gz /usr/share/wazuh-indexer/snapshots
docker cp wazuh-indexer:/tmp/indexer-snapshot.tar.gz /tmp/$BACKUP_NAME/

# Backup Docker configurations
echo "[INFO] Backing up Docker configurations..."
cp -r config/ /tmp/$BACKUP_NAME/
cp docker-compose.yml /tmp/$BACKUP_NAME/
cp .env /tmp/$BACKUP_NAME/

# Create metadata file
cat > /tmp/$BACKUP_NAME/backup-metadata.txt << EOF
Backup Name: $BACKUP_NAME
Backup Date: $(date)
Wazuh Version: $(docker-compose exec -T wazuh-manager /var/ossec/bin/wazuh-control info | grep VERSION)
Indexer Version: $(docker-compose exec -T wazuh-indexer cat /usr/share/wazuh-indexer/VERSION)
Dashboard Version: $(docker-compose exec -T wazuh-dashboard cat /usr/share/wazuh-dashboard/VERSION)
Host: $(hostname)
IP Address: $(hostname -I | awk '{print $1}')
Docker Compose Version: $(docker-compose --version)
Backup Size: $(du -sh /tmp/$BACKUP_NAME | cut -f1)
EOF

# Compress the entire backup
echo "[INFO] Compressing backup..."
tar -czf $BACKUP_PATH.tar.gz -C /tmp $BACKUP_NAME

# Clean up temporary files
rm -rf /tmp/$BACKUP_NAME
docker-compose exec -T wazuh-manager rm -f /tmp/wazuh-config.tar.gz /tmp/wazuh-data.tar.gz
docker-compose exec -T wazuh-indexer rm -f /tmp/indexer-snapshot.tar.gz

# Set permissions
sudo chown $(whoami):$(whoami) $BACKUP_PATH.tar.gz
chmod 600 $BACKUP_PATH.tar.gz

# Calculate backup size
BACKUP_SIZE=$(du -sh $BACKUP_PATH.tar.gz | cut -f1)

echo "[SUCCESS] Backup completed: $BACKUP_PATH.tar.gz ($BACKUP_SIZE)"

# Clean up old backups
echo "[INFO] Cleaning up backups older than $RETENTION_DAYS days..."
find $BACKUP_DIR -name "wazuh-backup-*.tar.gz" -type f -mtime +$RETENTION_DAYS -delete

# List current backups
echo "[INFO] Current backups:"
ls -lh $BACKUP_DIR/wazuh-backup-*.tar.gz 2>/dev/null || echo "No backups found"

echo "[INFO] Backup process completed successfully!"