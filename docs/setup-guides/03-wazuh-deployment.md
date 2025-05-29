# Wazuh SIEM Deployment Guide

This guide walks you through deploying and configuring the Wazuh SIEM platform after your AWS infrastructure is ready.

## Overview

The Wazuh deployment consists of:
- **Wazuh Manager**: Central analysis engine and rule processor
- **Wazuh Indexer**: Elasticsearch-based data storage and search
- **Wazuh Dashboard**: Kibana-based web interface for visualization
- **Filebeat**: Log forwarding and data collection

## Prerequisites

Before starting, ensure:
- [ ] AWS infrastructure deployed successfully ([previous guide](02-aws-infrastructure.md))
- [ ] Jump box accessible via SSH
- [ ] Wazuh server running and accessible from jump box
- [ ] Docker and Docker Compose installed on Wazuh server

## Step 1: Access Wazuh Server

### Connect via Jump Box

```bash
# Get connection details from Terraform outputs
cd terraform
JUMP_IP=$(terraform output -raw jump_box_public_ip)
WAZUH_PRIVATE_IP=$(terraform output -raw wazuh_server_private_ip)

# Connect to jump box
ssh -i ../soc-lab-key.pem ubuntu@$JUMP_IP

# From jump box, connect to Wazuh server
ssh -i ~/.ssh/soc-lab-key.pem ubuntu@$WAZUH_PRIVATE_IP
```

### Verify Initial Setup

```bash
# Check if Docker is running
sudo systemctl status docker

# Check if Wazuh containers are starting
docker ps -a

# Check available disk space
df -h

# Check memory usage
free -h
```

## Step 2: Deploy Wazuh Stack

### Download Wazuh Docker Configuration

```bash
# Create Wazuh directory
sudo mkdir -p /opt/wazuh
cd /opt/wazuh

# Download official Wazuh Docker configuration
sudo curl -so docker-compose.yml https://raw.githubusercontent.com/wazuh/wazuh-docker/v4.7.0/single-node/docker-compose.yml

# Download environment configuration
sudo curl -so .env https://raw.githubusercontent.com/wazuh/wazuh-docker/v4.7.0/single-node/.env
```

### Configure Environment Variables

```bash
# Edit environment configuration
sudo vim .env
```

**Key Configuration Options:**
```bash
# Wazuh version
WAZUH_VERSION=4.7.0

# Elastic Stack version  
ELASTIC_VERSION=7.17.13

# Generate strong passwords
INDEXER_PASSWORD=$(openssl rand -base64 32)
WAZUH_API_PASSWORD=$(openssl rand -base64 32)
DASHBOARD_PASSWORD=$(openssl rand -base64 32)

# Set custom passwords
echo "INDEXER_PASSWORD=$INDEXER_PASSWORD" | sudo tee -a .env
echo "WAZUH_API_PASSWORD=$WAZUH_API_PASSWORD" | sudo tee -a .env  
echo "DASHBOARD_PASSWORD=$DASHBOARD_PASSWORD" | sudo tee -a .env

# Save passwords for later use
echo "Wazuh Passwords:" | sudo tee /opt/wazuh/passwords.txt
echo "Indexer: $INDEXER_PASSWORD" | sudo tee -a /opt/wazuh/passwords.txt
echo "API: $WAZUH_API_PASSWORD" | sudo tee -a /opt/wazuh/passwords.txt
echo "Dashboard: $DASHBOARD_PASSWORD" | sudo tee -a /opt/wazuh/passwords.txt
sudo chmod 600 /opt/wazuh/passwords.txt
```

### Custom Docker Compose Configuration

```bash
# Create custom docker-compose.yml with proper networking
sudo tee docker-compose.yml > /dev/null << 'EOF'
version: '3.7'

services:
  wazuh.manager:
    image: wazuh/wazuh-manager:4.7.0
    hostname: wazuh.manager
    restart: always
    ulimits:
      memlock:
        soft: -1
        hard: -1
      nofile:
        soft: 655360
        hard: 655360
    ports:
      - "1514:1514"
      - "1515:1515"
      - "514:514/udp"
      - "55000:55000"
    environment:
      - INDEXER_URL=https://wazuh.indexer:9200
      - INDEXER_USERNAME=admin
      - INDEXER_PASSWORD=${INDEXER_PASSWORD}
      - FILEBEAT_SSL_VERIFICATION_MODE=full
      - SSL_CERTIFICATE_AUTHORITIES=/etc/ssl/root-ca.pem
      - SSL_CERTIFICATE=/etc/ssl/filebeat.pem
      - SSL_KEY=/etc/ssl/filebeat.key
      - API_USERNAME=wazuh-wui
      - API_PASSWORD=${WAZUH_API_PASSWORD}
    volumes:
      - wazuh_api_configuration:/var/ossec/api/configuration
      - wazuh_etc:/var/ossec/etc
      - wazuh_logs:/var/ossec/logs
      - wazuh_queue:/var/ossec/queue
      - wazuh_var_multigroups:/var/ossec/var/multigroups
      - wazuh_integrations:/var/ossec/integrations
      - wazuh_active_response:/var/ossec/active-response/bin
      - wazuh_agentless:/var/ossec/agentless
      - wazuh_wodles:/var/ossec/wodles
      - filebeat_etc:/etc/filebeat
      - filebeat_var:/var/lib/filebeat
      - ./config/wazuh_indexer_ssl_certs/root-ca-manager.pem:/etc/ssl/root-ca.pem
      - ./config/wazuh_indexer_ssl_certs/wazuh.manager.pem:/etc/ssl/filebeat.pem
      - ./config/wazuh_indexer_ssl_certs/wazuh.manager-key.pem:/etc/ssl/filebeat.key
      - ./config/wazuh_cluster/wazuh_manager.conf:/wazuh-config-mount/etc/ossec.conf

  wazuh.indexer:
    image: wazuh/wazuh-indexer:4.7.0
    hostname: wazuh.indexer
    restart: always
    ports:
      - "9200:9200"
    environment:
      - "OPENSEARCH_JAVA_OPTS=-Xms1024m -Xmx1024m"
    ulimits:
      memlock:
        soft: -1
        hard: -1
      nofile:
        soft: 65536
        hard: 65536
    volumes:
      - wazuh-indexer-data:/var/lib/wazuh-indexer
      - ./config/wazuh_indexer_ssl_certs/root-ca.pem:/usr/share/wazuh-indexer/certs/root-ca.pem
      - ./config/wazuh_indexer_ssl_certs/wazuh.indexer-key.pem:/usr/share/wazuh-indexer/certs/wazuh.indexer.key
      - ./config/wazuh_indexer_ssl_certs/wazuh.indexer.pem:/usr/share/wazuh-indexer/certs/wazuh.indexer.pem
      - ./config/wazuh_indexer_ssl_certs/admin.pem:/usr/share/wazuh-indexer/certs/admin.pem
      - ./config/wazuh_indexer_ssl_certs/admin-key.pem:/usr/share/wazuh-indexer/certs/admin-key.pem
      - ./config/wazuh_indexer/wazuh.indexer.yml:/usr/share/wazuh-indexer/opensearch.yml
      - ./config/wazuh_indexer/internal_users.yml:/usr/share/wazuh-indexer/opensearch-security/internal_users.yml

  wazuh.dashboard:
    image: wazuh/wazuh-dashboard:4.7.0
    hostname: wazuh.dashboard
    restart: always
    ports:
      - 443:5601
    environment:
      - INDEXER_USERNAME=admin
      - INDEXER_PASSWORD=${INDEXER_PASSWORD}
      - WAZUH_API_URL=https://wazuh.manager
      - DASHBOARD_USERNAME=kibanaserver
      - DASHBOARD_PASSWORD=${DASHBOARD_PASSWORD}
      - API_USERNAME=wazuh-wui
      - API_PASSWORD=${WAZUH_API_PASSWORD}
    volumes:
      - ./config/wazuh_indexer_ssl_certs/wazuh.dashboard.pem:/usr/share/wazuh-dashboard/certs/wazuh-dashboard.pem
      - ./config/wazuh_indexer_ssl_certs/wazuh.dashboard-key.pem:/usr/share/wazuh-dashboard/certs/wazuh-dashboard-key.pem
      - ./config/wazuh_indexer_ssl_certs/root-ca.pem:/usr/share/wazuh-dashboard/certs/root-ca.pem
      - ./config/wazuh_dashboard/opensearch_dashboards.yml:/usr/share/wazuh-dashboard/config/opensearch_dashboards.yml
      - ./config/wazuh_dashboard/wazuh.yml:/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
    depends_on:
      - wazuh.indexer
    links:
      - wazuh.indexer:wazuh.indexer
      - wazuh.manager:wazuh.manager

volumes:
  wazuh_api_configuration:
  wazuh_etc:
  wazuh_logs:
  wazuh_queue:
  wazuh_var_multigroups:
  wazuh_integrations:
  wazuh_active_response:
  wazuh_agentless:
  wazuh_wodles:
  filebeat_etc:
  filebeat_var:
  wazuh-indexer-data:
EOF
```

## Step 3: Generate SSL Certificates

### Download Certificate Generation Script

```bash
# Download Wazuh certificate generation script
sudo curl -so wazuh-certs-tool.sh https://packages.wazuh.com/4.7/wazuh-certs-tool.sh
sudo chmod +x wazuh-certs-tool.sh

# Create certificate configuration
sudo tee config.yml > /dev/null << 'EOF'
nodes:
  # Wazuh indexer nodes
  indexer:
    - name: wazuh.indexer
      ip: wazuh.indexer
    #- name: wazuh2.indexer
    #  ip: <wazuh2.indexer-ip>
    #- name: wazuh3.indexer
    #  ip: <wazuh3.indexer-ip>

  # Wazuh server nodes
  server:
    - name: wazuh.manager
      ip: wazuh.manager
    #- name: wazuh2.manager
    #  ip: <wazuh2.manager-ip>
    #- name: wazuh3.manager
    #  ip: <wazuh3.manager-ip>

  # Wazuh dashboard nodes
  dashboard:
    - name: wazuh.dashboard
      ip: wazuh.dashboard
EOF

# Generate certificates
sudo ./wazuh-certs-tool.sh -A

# Extract certificates to proper directory
sudo mkdir -p config/wazuh_indexer_ssl_certs
sudo tar -xf ./wazuh-certificates.tar -C config/wazuh_indexer_ssl_certs/ --strip-components=1
```

### Create Required Configuration Directories

```bash
# Create configuration directories
sudo mkdir -p config/wazuh_cluster
sudo mkdir -p config/wazuh_indexer  
sudo mkdir -p config/wazuh_dashboard

# Set proper permissions
sudo chown -R 1000:1000 config/
sudo chmod -R 755 config/
```

## Step 4: Configure Wazuh Components

### Wazuh Manager Configuration

```bash
# Create Wazuh manager configuration
sudo tee config/wazuh_cluster/wazuh_manager.conf > /dev/null << 'EOF'
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
    <smtp_server>localhost</smtp_server>
    <email_from>wazuhsiem@localhost</email_from>
    <email_to>admin@localhost</email_to>
    <hostname>wazuh-manager</hostname>
    <description>Wazuh manager</description>
  </global>

  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <!-- Choose between "plain", "json", or "plain,json" for format -->
  <logging>
    <log_format>json</log_format>
  </logging>

  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>

  <!-- Policy monitoring -->
  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>

    <!-- Frequency that rootcheck is executed - every 12 hours -->
    <frequency>43200</frequency>

    <rootkit_files>/var/ossec/etc/rootcheck/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>/var/ossec/etc/rootcheck/rootkit_trojans.txt</rootkit_trojans>

    <skip_nfs>yes</skip_nfs>
  </rootcheck>

  <wodle name="cis-cat">
    <disabled>yes</disabled>
    <timeout>1800</timeout>
    <interval>1d</interval>
    <scan-on-start>yes</scan-on-start>
  </wodle>

  <!-- File integrity monitoring -->
  <syscheck>
    <disabled>no</disabled>

    <!-- Frequency that syscheck is executed default every 12 hours -->
    <frequency>43200</frequency>

    <scan_on_start>yes</scan_on_start>

    <!-- Generate alert when new file detected -->
    <alert_new_files>yes</alert_new_files>

    <!-- Don't ignore files that change more than 'frequency' times -->
    <auto_ignore frequency="10" timeframe="3600">no</auto_ignore>

    <!-- Directories to check  (perform all possible verifications) -->
    <directories>/etc,/usr/bin,/usr/sbin</directories>
    <directories>/bin,/sbin,/boot</directories>

    <!-- Files/directories to ignore -->
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/random.seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/httpd/logs</ignore>
    <ignore>/etc/utmpx</ignore>
    <ignore>/etc/wtmpx</ignore>
    <ignore>/etc/cups/certs</ignore>
    <ignore>/etc/dumpdates</ignore>
    <ignore>/etc/svc/volatile</ignore>

    <!-- Check the file, but never compute the diff -->
    <nodiff>/etc/ssl/private.key</nodiff>
  </syscheck>

  <!-- Active response -->
  <global>
    <white_list>127.0.0.1</white_list>
    <white_list>^localhost.localdomain$</white_list>
    <white_list>10.0.0.0/8</white_list>
  </global>

  <command>
    <name>disable-account</name>
    <executable>disable-account.sh</executable>
    <expect>user</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>restart-ossec</name>
    <executable>restart-ossec.sh</executable>
    <expect></expect>
  </command>

  <command>
    <name>firewall-drop</name>
    <executable>firewall-drop.sh</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>host-deny</name>
    <executable>host-deny.sh</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>route-null</name>
    <executable>route-null.sh</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <!-- Files to monitor (localfiles) -->
  <localfile>
    <log_format>command</log_format>
    <command>df -P</command>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>netstat -tulpn | sed 's/\([[:alnum:]]\+\)\ \+[[:digit:]]\+\ \+[[:digit:]]\+\ \+\(.*\):\([[:digit:]]*\)\ \+\([0-9\.\:\*]\+\).\+\ \([[:digit:]]*\/[[:alnum:]\-]*\).*/\1 \2 \3 \4 \5/' | sort -k 4 -g | sed 's/.*://' | sed 1,2d</command>
    <alias>netstat listening ports</alias>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>last -n 20</command>
    <frequency>360</frequency>
  </localfile>

  <rule_dir>ruleset/rules</rule_dir>
  <include_dir>ruleset/decoders</include_dir>
  <list>etc/lists/audit-keys</list>
  <list>etc/lists/amazon/aws-eventnames</list>
  <list>etc/lists/security-eventchannel</list>

  <!-- Configuration for wazuh-authd -->
  <auth>
    <disabled>no</disabled>
    <port>1515</port>
    <use_source_ip>no</use_source_ip>
    <purge>yes</purge>
    <use_password>no</use_password>
    <ciphers>HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH</ciphers>
    <!-- <ssl_agent_ca></ssl_agent_ca> -->
    <ssl_verify_host>no</ssl_verify_host>
    <ssl_manager_cert>/var/ossec/etc/sslmanager.cert</ssl_manager_cert>
    <ssl_manager_key>/var/ossec/etc/sslmanager.key</ssl_manager_key>
    <ssl_auto_negotiate>no</ssl_auto_negotiate>
  </auth>

  <cluster>
    <name>wazuh</name>
    <node_name>node01</node_name>
    <node_type>master</node_type>
    <key></key>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
        <node>NODE_IP</node>
    </nodes>
    <hidden>no</hidden>
    <disabled>yes</disabled>
  </cluster>

</ossec_config>
EOF
```

### Wazuh Indexer Configuration

```bash
# Create indexer configuration
sudo tee config/wazuh_indexer/wazuh.indexer.yml > /dev/null << 'EOF'
network.host: 0.0.0.0
node.name: wazuh.indexer
cluster.initial_master_nodes:
- wazuh.indexer
cluster.name: wazuh-cluster
node.max_local_storage_nodes: 3
path.data: /var/lib/wazuh-indexer
path.logs: /var/log/wazuh-indexer

bootstrap.memory_lock: true

# HTTP
http.port: 9200

# Transport layer
transport.tcp.port: 9300

# REST API
plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: /usr/share/wazuh-indexer/certs/wazuh.indexer.pem
plugins.security.ssl.http.pemkey_filepath: /usr/share/wazuh-indexer/certs/wazuh.indexer.key
plugins.security.ssl.http.pemtrustedcas_filepath: /usr/share/wazuh-indexer/certs/root-ca.pem

# Transport layer
plugins.security.ssl.transport.enabled: true
plugins.security.ssl.transport.pemcert_filepath: /usr/share/wazuh-indexer/certs/wazuh.indexer.pem
plugins.security.ssl.transport.pemkey_filepath: /usr/share/wazuh-indexer/certs/wazuh.indexer.key
plugins.security.ssl.transport.pemtrustedcas_filepath: /usr/share/wazuh-indexer/certs/root-ca.pem

# Authentication
plugins.security.nodes_dn:
- "CN=wazuh.indexer,OU=Wazuh,O=Wazuh,L=California,C=US"

plugins.security.authcz.admin_dn:
- "CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US"

plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.system_indices.enabled: true
plugins.security.system_indices.indices: [".opendistro-alerting-config", ".opendistro-alerting-alert*", ".opendistro-anomaly-results*", ".opendistro-anomaly-detector*", ".opendistro-anomaly-checkpoints", ".opendistro-anomaly-detection-state", ".opendistro-reports-*", ".opendistro-notifications-*", ".opendistro-notebooks", ".opensearch-observability", ".opendistro-asynchronous-search-response*", ".replication-metadata-store"]
cluster.routing.allocation.disk.threshold_enabled: false
node.roles: ["master", "ingest", "data"]
EOF
```

### Wazuh Dashboard Configuration

```bash
# Create dashboard configuration
sudo tee config/wazuh_dashboard/opensearch_dashboards.yml > /dev/null << 'EOF'
server.host: 0.0.0.0
server.port: 5601
opensearch.hosts: https://wazuh.indexer:9200
opensearch.ssl.verificationMode: full
opensearch.username: kibanaserver
opensearch.password: ${DASHBOARD_PASSWORD}
opensearch.ssl.certificateAuthorities: ["/usr/share/wazuh-dashboard/certs/root-ca.pem"]
server.ssl.enabled: true
server.ssl.key: "/usr/share/wazuh-dashboard/certs/wazuh-dashboard-key.pem"
server.ssl.certificate: "/usr/share/wazuh-dashboard/certs/wazuh-dashboard.pem"
opensearch.ssl.certificate: "/usr/share/wazuh-dashboard/certs/wazuh-dashboard.pem"
opensearch.ssl.key: "/usr/share/wazuh-dashboard/certs/wazuh-dashboard-key.pem"
uiSettings.overrides.defaultRoute: /app/wz-home
opensearch.requestHeadersWhitelist: ["securitytenant","Authorization"]
opensearch_security.multitenancy.enabled: false
opensearch_security.readonly_mode.roles: ["kibana_read_only"]
server.xsrf.whitelist: ["/_opendistro/_security/saml/acs", "/_opendistro/_security/saml/logout", "/_opendistro/_security/saml/acs/idpinitiated"]
opensearch_security.cookie.secure: false
EOF

# Create Wazuh API configuration
sudo tee config/wazuh_dashboard/wazuh.yml > /dev/null << 'EOF'
hosts:
  - default:
      url: https://wazuh.manager
      port: 55000
      username: wazuh-wui
      password: ${WAZUH_API_PASSWORD}
      run_as: false
logging.level: info
logging.json: false
wazuh.monitoring.enabled: true
wazuh.monitoring.frequency: 900
wazuh.monitoring.shards: 1
wazuh.monitoring.replicas: 0
EOF
```

## Step 5: Deploy Wazuh Stack

### Start Wazuh Services

```bash
# Make sure we're in the right directory
cd /opt/wazuh

# Start all services
sudo docker-compose up -d

# Check service status
sudo docker-compose ps

# Follow logs during startup
sudo docker-compose logs -f
```

### Monitor Service Health

```bash
# Check individual service logs
sudo docker-compose logs wazuh.manager
sudo docker-compose logs wazuh.indexer  
sudo docker-compose logs wazuh.dashboard

# Check service health
curl -k -u admin:${INDEXER_PASSWORD} https://localhost:9200/_cluster/health?pretty

# Check Wazuh API
curl -k -u wazuh-wui:${WAZUH_API_PASSWORD} https://localhost:55000/
```

## Step 6: Configure Firewall and Access

### Configure Security Groups (if needed)

```bash
# From your local machine, update security group if needed
cd terraform

# Check current security group rules
aws ec2 describe-security-groups --group-ids $(terraform output -raw wazuh_security_group_id)

# If you need to add rules for external access:
# aws ec2 authorize-security-group-ingress --group-id $(terraform output -raw wazuh_security_group_id) --protocol tcp --port 443 --cidr YOUR_IP/32
```

### Set up SSH Tunneling for Dashboard Access

```bash
# From your local machine, create SSH tunnel
JUMP_IP=$(terraform output -raw jump_box_public_ip)
WAZUH_PRIVATE_IP=$(terraform output -raw wazuh_server_private_ip)

# Create tunnel for Wazuh dashboard (port 443 -> 8443 locally)
ssh -i soc-lab-key.pem -L 8443:$WAZUH_PRIVATE_IP:443 ubuntu@$JUMP_IP -N

# In another terminal, create tunnel for API access
ssh -i soc-lab-key.pem -L 55000:$WAZUH_PRIVATE_IP:55000 ubuntu@$JUMP_IP -N
```

## Step 7: Initial Dashboard Setup

### Access Wazuh Dashboard

1. **Open Browser**: Navigate to `https://localhost:8443`
2. **Accept Certificate**: Click "Advanced" → "Proceed to localhost"
3. **Login**:
   - Username: `admin`
   - Password: `admin` (default, should be changed)

### Initial Configuration Wizard

1. **Welcome Screen**: Click "Next" to start configuration
2. **API Configuration**: 
   - URL: `https://wazuh.manager:55000`
   - Username: `wazuh-wui`
   - Password: Use the `WAZUH_API_PASSWORD` from earlier
3. **Test Connection**: Click "Test" to verify API connectivity
4. **Save Configuration**: Click "Save" to complete setup

### Change Default Passwords

```bash
# Connect to Wazuh server
ssh -i ~/.ssh/soc-lab-key.pem ubuntu@$WAZUH_PRIVATE_IP

# Change dashboard admin password
cd /opt/wazuh
sudo docker-compose exec wazuh.indexer /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /usr/share/wazuh-indexer/opensearch-security/ -nhnv -cacert /usr/share/wazuh-indexer/certs/root-ca.pem -cert /usr/share/wazuh-indexer/certs/admin.pem -key /usr/share/wazuh-indexer/certs/admin-key.pem -icl

# Use the Wazuh dashboard to change passwords:
# Security → Internal Users → admin → Edit
```

## Step 8: Configure Index Templates and Policies

### Create Index Lifecycle Policies

Access **Management** → **Index Management** → **Policies**:

```json
{
  "policy": {
    "description": "Wazuh alerts lifecycle policy",
    "default_state": "hot",
    "states": [
      {
        "name": "hot",
        "actions": [],
        "transitions": [
          {
            "state_name": "warm",
            "conditions": {
              "min_index_age": "7d"
            }
          }
        ]
      },
      {
        "name": "warm",
        "actions": [
          {
            "replica_count": {
              "number_of_replicas": 0
            }
          }
        ],
        "transitions": [
          {
            "state_name": "cold",
            "conditions": {
              "min_index_age": "30d"
            }
          }
        ]
      },
      {
        "name": "cold",
        "actions": [],
        "transitions": [
          {
            "state_name": "delete",
            "conditions": {
              "min_index_age": "90d"
            }
          }
        ]
      },
      {
        "name": "delete",
        "actions": [
          {
            "delete": {}
          }
        ]
      }
    ]
  }
}
```

### Configure Index Templates

Create index template for Wazuh alerts:

**Management** → **Index Templates** → **Create template**:

```json
{
  "index_patterns": ["wazuh-alerts-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "index.refresh_interval": "5s",
      "index.lifecycle.name": "wazuh-alerts-policy",
      "index.lifecycle.rollover_alias": "wazuh-alerts"
    },
    "mappings": {
      "properties": {
        "timestamp": {
          "type": "date",
          "format": "strict_date_optional_time||epoch_millis"
        },
        "rule": {
          "properties": {
            "level": {
              "type": "integer"
            },
            "id": {
              "type": "keyword"
            }
          }
        },
        "agent": {
          "properties": {
            "name": {
              "type": "keyword"
            },
            "ip": {
              "type": "ip"
            }
          }
        }
      }
    }
  }
}
```

## Step 9: Verify Installation

### Check Service Status

```bash
# Check all containers are running
sudo docker-compose ps

# Verify services are responding
curl -k https://localhost:9200/_cluster/health?pretty
curl -k https://localhost:443  # Dashboard
curl -k https://localhost:55000  # API
```

### Test API Connectivity

```bash
# Test Wazuh API endpoints
WAZUH_API_PASSWORD=$(cat /opt/wazuh/passwords.txt | grep "API:" | cut -d' ' -f2)

# Get API information
curl -k -u wazuh-wui:$WAZUH_API_PASSWORD https://localhost:55000/

# List agents (should be empty initially)
curl -k -u wazuh-wui:$WAZUH_API_PASSWORD https://localhost:55000/agents

# Get manager information
curl -k -u wazuh-wui:$WAZUH_API_PASSWORD https://localhost:55000/manager/info
```

### Dashboard Functionality Test

1. **Navigate to Discover**: Verify data visualization
2. **Check Security Events**: Go to Security Events dashboard
3. **Verify Modules**: Ensure all modules load correctly
4. **Test Search**: Perform basic searches in Discover tab

## Step 10: Performance Tuning

### Optimize Java Heap Settings

```bash
# Edit docker-compose.yml to adjust memory settings
sudo vim docker-compose.yml

# For wazuh.indexer service, adjust:
environment:
  - "OPENSEARCH_JAVA_OPTS=-Xms2g -Xmx2g"  # Adjust based on available RAM

# Restart services after changes
sudo docker-compose restart wazuh.indexer
```

### Configure Log Rotation

```bash
# Create logrotate configuration
sudo tee /etc/logrotate.d/wazuh-docker > /dev/null << 'EOF'
/var/lib/docker/containers/*/*-json.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
    postrotate
        docker kill --signal="USR1" $(docker ps -q) 2>/dev/null || true
    endscript
}
EOF
```

## Step 11: Backup and Monitoring

### Set up Automated Backups

```bash
# Create backup script
sudo tee /opt/wazuh/backup.sh > /dev/null << 'EOF'
#!/bin/bash
BACKUP_DIR="/opt/wazuh/backups"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Backup Wazuh configuration
tar -czf $BACKUP_DIR/wazuh-config-$DATE.tar.gz /opt/wazuh/config/

# Create Elasticsearch snapshot
curl -X PUT "localhost:9200/_snapshot/backup-$DATE" -H 'Content-Type: application/json' -d'
{
  "type": "fs",
  "settings": {
    "location": "/usr/share/wazuh-indexer/backup-'$DATE'"
  }
}'

# Cleanup old backups (keep 7 days)
find $BACKUP_DIR -name "*.tar.gz" -mtime +7 -delete
EOF

sudo chmod +x /opt/wazuh/backup.sh

# Schedule daily backups
sudo crontab -e
# Add: 0 2 * * * /opt/wazuh/backup.sh
```

### Set up Health Monitoring

```bash
# Create health check script
sudo tee /opt/wazuh/health-check.sh > /dev/null << 'EOF'
#!/bin/bash
LOGFILE="/var/log/wazuh-health.log"

echo "$(date): Starting health check" >> $LOGFILE

# Check container status
if ! docker-compose ps | grep -q "Up"; then
    echo "$(date): ERROR - Some containers are not running" >> $LOGFILE
    docker-compose ps >> $LOGFILE
fi

# Check Elasticsearch cluster health
HEALTH=$(curl -s -k https://localhost:9200/_cluster/health | jq -r '.status')
if [ "$HEALTH" != "green" ] && [ "$HEALTH" != "yellow" ]; then
    echo "$(date): ERROR - Elasticsearch cluster health is $HEALTH" >> $LOGFILE
fi

# Check Wazuh API
if ! curl -s -k https://localhost:55000/ > /dev/null; then
    echo "$(date): ERROR - Wazuh API is not responding" >> $LOGFILE
fi

echo "$(date): Health check completed" >> $LOGFILE
EOF

sudo chmod +x /opt/wazuh/health-check.sh

# Schedule health checks every 5 minutes
sudo crontab -e
# Add: */5 * * * * /opt/wazuh/health-check.sh
```

## Troubleshooting Common Issues

### Container Startup Issues

**Problem**: Containers fail to start
**Solution**:
```bash
# Check logs
sudo docker-compose logs

# Check available memory
free -h

# Check disk space
df -h

# Restart services
sudo docker-compose down
sudo docker-compose up -d
```

### Certificate Issues

**Problem**: SSL/TLS certificate errors
**Solution**:
```bash
# Regenerate certificates
cd /opt/wazuh
sudo ./wazuh-certs-tool.sh -A
sudo tar -xf ./wazuh-certificates.tar -C config/wazuh_indexer_ssl_certs/ --strip-components=1
sudo docker-compose restart
```

### Performance Issues

**Problem**: Slow dashboard or high resource usage
**Solution**:
```bash
# Check resource usage
docker stats

# Adjust Java heap size (edit docker-compose.yml)
sudo vim docker-compose.yml

# Increase instance size if needed (via Terraform)
# Or add resource limits to prevent OOM
```

### Dashboard Access Issues

**Problem**: Cannot access Wazuh dashboard
**Solution**:
```bash
# Check dashboard container
sudo docker-compose logs wazuh.dashboard

# Verify port forwarding
ss -tlnp | grep 443

# Check security group rules
aws ec2 describe-security-groups --group-ids $(terraform output -raw wazuh_security_group_id)
```

## Next Steps

With Wazuh SIEM deployed successfully:

1. **✅ Wazuh SIEM Ready**
2. **→ Next**: [Endpoint Configuration](04-endpoint-configuration.md)
3. **Then**: Deploy and configure Wazuh agents on endpoints
4. **Finally**: Start with attack scenarios and monitoring

## Summary

You have successfully:
- ✅ Deployed Wazuh Manager, Indexer, and Dashboard
- ✅ Configured SSL certificates and secure communication
- ✅ Set up proper networking and access controls
- ✅ Implemented backup and monitoring procedures
- ✅ Configured performance optimization settings

The Wazuh SIEM is now ready to receive and analyze security events from your endpoints!

---

**🎉 Excellent!** Your Wazuh SIEM platform is operational. Continue to the next guide to configure your endpoints and start monitoring security events.
