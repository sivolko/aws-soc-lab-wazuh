# Docker Configurations

This directory contains all Docker and container-related configurations for the SOC Lab.

## Structure

```
docker/
├── wazuh/                    # Wazuh SIEM stack
│   ├── single-node/         # Single-node deployment
│   ├── multi-node/          # Multi-node cluster (future)
│   └── custom-configs/      # Custom configurations
├── vulnerable-apps/         # Intentionally vulnerable applications
│   ├── dvwa/               # Damn Vulnerable Web Application
│   ├── webgoat/            # WebGoat security training
│   └── juice-shop/         # OWASP Juice Shop
├── monitoring/              # Additional monitoring tools
├── docker-compose.yml       # Main compose file
├── docker-compose.override.yml.example
└── .env.example            # Environment variables template
```

## Wazuh Single-Node Deployment

The Wazuh deployment includes:
- **Wazuh Manager** - Central management and analysis
- **Wazuh Indexer** - Data storage and indexing (Elasticsearch-based)
- **Wazuh Dashboard** - Web interface (Kibana-based)
- **Filebeat** - Log shipping and forwarding

## Quick Start

1. **Prepare Environment**
   ```bash
   cd docker
   cp .env.example .env
   # Configure environment variables in .env
   ```

2. **Deploy Wazuh Stack**
   ```bash
   docker-compose up -d
   ```

3. **Verify Deployment**
   ```bash
   docker-compose ps
   docker-compose logs wazuh-manager
   ```

4. **Access Dashboard**
   - URL: https://your-server:443
   - Default credentials in .env file

## Resource Requirements

| Component | CPU | Memory | Storage |
|-----------|-----|--------|---------|
| Wazuh Manager | 2 cores | 4GB | 50GB |
| Wazuh Indexer | 2 cores | 4GB | 100GB |
| Wazuh Dashboard | 1 core | 1GB | 10GB |

## Persistent Data

All data is stored in Docker volumes:
- `wazuh_manager_data` - Manager configuration and logs
- `wazuh_indexer_data` - Elasticsearch indices
- `wazuh_dashboard_data` - Dashboard configurations

## Backup Strategy

```bash
# Backup volumes
docker-compose exec wazuh-manager /scripts/backup.sh

# Export configurations
docker-compose exec wazuh-manager tar -czf /backup/config.tar.gz /var/ossec/etc
```

---

🐳 **Containerized Security FTW!**