#!/bin/bash
# SSL Certificate Generation Script for Wazuh

set -e

CERT_DIR="config/wazuh_indexer_ssl_certs"
CONFIG_DIR="config"

echo "[INFO] Generating SSL certificates for Wazuh components..."

# Create certificate directory
mkdir -p $CERT_DIR

# Generate root CA private key
echo "[INFO] Generating root CA private key..."
openssl genrsa -out $CERT_DIR/root-ca-key.pem 2048

# Generate root CA certificate
echo "[INFO] Generating root CA certificate..."
openssl req -new -x509 -sha256 -key $CERT_DIR/root-ca-key.pem -out $CERT_DIR/root-ca.pem -days 3650 -subj "/C=US/ST=CA/L=SOC-Lab/O=Wazuh-SOC-Lab/CN=root-ca"

# Generate admin private key and certificate
echo "[INFO] Generating admin certificates..."
openssl genrsa -out $CERT_DIR/admin-key.pem 2048
openssl req -new -key $CERT_DIR/admin-key.pem -out $CERT_DIR/admin.csr -subj "/C=US/ST=CA/L=SOC-Lab/O=Wazuh-SOC-Lab/CN=admin"
openssl x509 -req -in $CERT_DIR/admin.csr -CA $CERT_DIR/root-ca.pem -CAkey $CERT_DIR/root-ca-key.pem -CAcreateserial -out $CERT_DIR/admin.pem -days 3650 -sha256

# Generate Wazuh Indexer certificates
echo "[INFO] Generating Wazuh Indexer certificates..."
openssl genrsa -out $CERT_DIR/wazuh.indexer-key.pem 2048
openssl req -new -key $CERT_DIR/wazuh.indexer-key.pem -out $CERT_DIR/wazuh.indexer.csr -subj "/C=US/ST=CA/L=SOC-Lab/O=Wazuh-SOC-Lab/CN=wazuh.indexer"

# Create SAN extension file for indexer
cat > $CERT_DIR/wazuh.indexer.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = wazuh-indexer
DNS.2 = wazuh.indexer
DNS.3 = localhost
IP.1 = 127.0.0.1
EOF

openssl x509 -req -in $CERT_DIR/wazuh.indexer.csr -CA $CERT_DIR/root-ca.pem -CAkey $CERT_DIR/root-ca-key.pem -CAcreateserial -out $CERT_DIR/wazuh.indexer.pem -days 3650 -sha256 -extfile $CERT_DIR/wazuh.indexer.ext

# Generate Wazuh Manager certificates
echo "[INFO] Generating Wazuh Manager certificates..."
openssl genrsa -out $CERT_DIR/wazuh.manager-key.pem 2048
openssl req -new -key $CERT_DIR/wazuh.manager-key.pem -out $CERT_DIR/wazuh.manager.csr -subj "/C=US/ST=CA/L=SOC-Lab/O=Wazuh-SOC-Lab/CN=wazuh.manager"

# Create SAN extension file for manager
cat > $CERT_DIR/wazuh.manager.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = wazuh-manager
DNS.2 = wazuh.manager
DNS.3 = localhost
IP.1 = 127.0.0.1
EOF

openssl x509 -req -in $CERT_DIR/wazuh.manager.csr -CA $CERT_DIR/root-ca.pem -CAkey $CERT_DIR/root-ca-key.pem -CAcreateserial -out $CERT_DIR/wazuh.manager.pem -days 3650 -sha256 -extfile $CERT_DIR/wazuh.manager.ext

# Generate Wazuh Dashboard certificates
echo "[INFO] Generating Wazuh Dashboard certificates..."
openssl genrsa -out $CERT_DIR/wazuh.dashboard-key.pem 2048
openssl req -new -key $CERT_DIR/wazuh.dashboard-key.pem -out $CERT_DIR/wazuh.dashboard.csr -subj "/C=US/ST=CA/L=SOC-Lab/O=Wazuh-SOC-Lab/CN=wazuh.dashboard"

# Create SAN extension file for dashboard
cat > $CERT_DIR/wazuh.dashboard.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = wazuh-dashboard
DNS.2 = wazuh.dashboard
DNS.3 = localhost
IP.1 = 127.0.0.1
EOF

openssl x509 -req -in $CERT_DIR/wazuh.dashboard.csr -CA $CERT_DIR/root-ca.pem -CAkey $CERT_DIR/root-ca-key.pem -CAcreateserial -out $CERT_DIR/wazuh.dashboard.pem -days 3650 -sha256 -extfile $CERT_DIR/wazuh.dashboard.ext

# Create copies for different naming conventions
cp $CERT_DIR/root-ca.pem $CERT_DIR/root-ca-manager.pem

# Set proper permissions
chmod 644 $CERT_DIR/*.pem
chmod 600 $CERT_DIR/*-key.pem

# Clean up CSR and extension files
rm -f $CERT_DIR/*.csr $CERT_DIR/*.ext $CERT_DIR/*.srl

echo "[SUCCESS] SSL certificates generated successfully!"
echo "[INFO] Certificates saved in: $CERT_DIR/"
echo "[INFO] Root CA: $CERT_DIR/root-ca.pem"
echo "[INFO] Admin cert: $CERT_DIR/admin.pem"
echo "[INFO] Indexer cert: $CERT_DIR/wazuh.indexer.pem"
echo "[INFO] Manager cert: $CERT_DIR/wazuh.manager.pem"
echo "[INFO] Dashboard cert: $CERT_DIR/wazuh.dashboard.pem"