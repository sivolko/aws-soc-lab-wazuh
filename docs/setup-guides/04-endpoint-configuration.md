# Endpoint Configuration Guide

This guide covers configuring the monitored endpoints (Linux and Windows) with Wazuh agents and security monitoring capabilities.

## Overview

After deploying Wazuh SIEM, you need to:
- **Install Wazuh agents** on Linux and Windows endpoints
- **Configure monitoring** for system events, logs, and file integrity
- **Deploy vulnerable applications** for testing and training
- **Verify connectivity** and data flow to SIEM
- **Configure custom rules** for specific detection scenarios

## Prerequisites

Before starting, ensure:
- [ ] Wazuh SIEM deployed and accessible ([previous guide](03-wazuh-deployment.md))
- [ ] All endpoints are running and accessible via jump box
- [ ] Wazuh manager accepting agent connections on port 1514/1515
- [ ] SSH access to all endpoints configured

## Step 1: Prepare Wazuh Manager for Agents

### Access Wazuh Manager

```bash
# Connect to jump box
JUMP_IP=$(terraform output -raw jump_box_public_ip)
ssh -i soc-lab-key.pem ubuntu@$JUMP_IP

# Connect to Wazuh server
WAZUH_PRIVATE_IP=$(terraform output -raw wazuh_server_private_ip)
ssh -i ~/.ssh/soc-lab-key.pem ubuntu@$WAZUH_PRIVATE_IP
```

### Configure Agent Registration

```bash
# Enter Wazuh manager container
sudo docker exec -it wazuh_wazuh.manager_1 bash

# Enable auto-enrollment (if desired)
# Edit ossec.conf to allow automatic agent registration
echo '<auth>
  <disabled>no</disabled>
  <port>1515</port>
  <use_source_ip>yes</use_source_ip>
  <purge>yes</purge>
  <use_password>no</use_password>
  <force>
    <enabled>yes</enabled>
    <key_mismatch>yes</key_mismatch>
    <disconnected_time>1h</disconnected_time>
    <after_registration_time>1h</after_registration_time>
  </force>
</auth>' >> /var/ossec/etc/ossec.conf

# Restart Wazuh manager to apply changes
/var/ossec/bin/wazuh-control restart
```

### Pre-register Agents (Recommended)

```bash
# Still in Wazuh manager container
# Register Linux endpoint
/var/ossec/bin/manage_agents -a linux-endpoint 10.0.3.200 linux-endpoint-001

# Register Windows endpoint  
/var/ossec/bin/manage_agents -a windows-endpoint 10.0.3.201 windows-endpoint-001

# List registered agents
/var/ossec/bin/manage_agents -l

# Extract agent keys for later use
/var/ossec/bin/manage_agents -e linux-endpoint-001 > /tmp/linux-agent-key
/var/ossec/bin/manage_agents -e windows-endpoint-001 > /tmp/windows-agent-key

# Copy keys to host filesystem
cp /tmp/*-agent-key /var/ossec/etc/
exit  # Exit container
```

## Step 2: Configure Linux Endpoint

### Access Linux Endpoint

```bash
# From jump box, connect to Linux endpoint
LINUX_PRIVATE_IP=$(terraform output -raw linux_endpoint_private_ip)
ssh -i ~/.ssh/soc-lab-key.pem ubuntu@$LINUX_PRIVATE_IP
```

### Install Wazuh Agent

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Download and install Wazuh agent
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee -a /etc/apt/sources.list.d/wazuh.list

sudo apt update
sudo apt install wazuh-agent -y
```

### Configure Wazuh Agent

```bash
# Configure agent to connect to Wazuh manager
sudo tee /var/ossec/etc/ossec.conf > /dev/null << 'EOF'
<ossec_config>
  <client>
    <server>
      <address>10.0.3.100</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>ubuntu, ubuntu20, ubuntu20.04</config-profile>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
    <crypto_method>aes</crypto_method>
  </client>

  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>

  <!-- File integrity monitoring -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <alert_new_files>yes</alert_new_files>

    <!-- Directories to monitor -->
    <directories check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
    <directories check_all="yes">/bin,/sbin</directories>
    <directories check_all="yes" realtime="yes">/var/www</directories>
    <directories check_all="yes" realtime="yes">/home</directories>

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
  </syscheck>

  <!-- Rootcheck -->
  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
    <frequency>43200</frequency>
    <rootkit_files>/var/ossec/etc/rootcheck/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>/var/ossec/etc/rootcheck/rootkit_trojans.txt</rootkit_trojans>
    <skip_nfs>yes</skip_nfs>
  </rootcheck>

  <!-- Log analysis -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/dpkg.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/kern.log</location>
  </localfile>

  <!-- Apache logs -->
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/access.log</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/error.log</location>
  </localfile>

  <!-- Command monitoring -->
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

  <!-- Active response -->
  <active-response>
    <disabled>no</disabled>
    <ca_store>/var/ossec/etc/wpk_root.pem</ca_store>
    <ca_verification>yes</ca_verification>
  </active-response>

</ossec_config>
EOF
```

### Register Agent with Manager

```bash
# Method 1: Using pre-generated key (if available)
sudo /var/ossec/bin/manage_agents -i linux-agent-key  # If key file copied from manager

# Method 2: Manual registration
sudo /var/ossec/bin/agent-auth -m 10.0.3.100 -A linux-endpoint

# Method 3: Interactive registration
sudo /var/ossec/bin/manage_agents
# Choose option A (Add agent)
# Agent name: linux-endpoint
# Agent IP: 10.0.3.200
# Agent ID: (auto-generated)
# Confirm: y
# Choose option E (Extract key for agent)
# Agent ID: (enter the ID from above)
# Copy the key
# Choose option Q (Quit)

# Import the agent key
sudo /var/ossec/bin/manage_agents
# Choose option I (Import key from another server)
# Paste the key
# Confirm: y
# Choose option Q (Quit)
```

### Start and Enable Wazuh Agent

```bash
# Start Wazuh agent
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

# Check service status
sudo systemctl status wazuh-agent

# Check agent logs
sudo tail -f /var/ossec/logs/ossec.log

# Verify connection to manager
sudo /var/ossec/bin/agent_control -lc
```

## Step 3: Install Vulnerable Applications on Linux

### Install Apache Web Server

```bash
# Install Apache
sudo apt install apache2 -y

# Enable and start Apache
sudo systemctl enable apache2
sudo systemctl start apache2

# Configure basic security headers
sudo tee /etc/apache2/conf-available/security.conf > /dev/null << 'EOF'
ServerTokens Prod
ServerSignature Off
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options DENY
Header always set X-XSS-Protection "1; mode=block"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
EOF

sudo a2enconf security
sudo a2enmod headers
sudo systemctl reload apache2

# Create a simple test page
sudo tee /var/www/html/index.html > /dev/null << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>SOC Lab - Linux Endpoint</title>
</head>
<body>
    <h1>SOC Lab Linux Endpoint</h1>
    <p>This server is part of the AWS SOC Lab training environment.</p>
    <ul>
        <li><a href="/dvwa/">DVWA - Damn Vulnerable Web Application</a></li>
        <li><a href="/webgoat/">WebGoat - OWASP Web Security Training</a></li>
        <li><a href="/juiceshop/">Juice Shop - OWASP Modern Web Application</a></li>
    </ul>
</body>
</html>
EOF
```

### Install Docker for Vulnerable Apps

```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Verify installation
docker --version
docker-compose --version
```

### Deploy DVWA (Damn Vulnerable Web Application)

```bash
# Create DVWA directory
mkdir -p ~/vulnerable-apps/dvwa
cd ~/vulnerable-apps/dvwa

# Create docker-compose.yml for DVWA
tee docker-compose.yml > /dev/null << 'EOF'
version: '3.7'

services:
  dvwa:
    image: vulnerables/web-dvwa
    container_name: dvwa
    ports:
      - "8080:80"
    environment:
      - MYSQL_HOSTNAME=dvwa-mysql
      - MYSQL_DATABASE=dvwa
      - MYSQL_USERNAME=dvwa
      - MYSQL_PASSWORD=p@ssw0rd
    depends_on:
      - dvwa-mysql
    volumes:
      - ./config:/etc/dvwa
    restart: unless-stopped

  dvwa-mysql:
    image: mysql:5.7
    container_name: dvwa-mysql
    environment:
      - MYSQL_ROOT_PASSWORD=dvwa
      - MYSQL_DATABASE=dvwa
      - MYSQL_USER=dvwa
      - MYSQL_PASSWORD=p@ssw0rd
    volumes:
      - dvwa-mysql-data:/var/lib/mysql
    restart: unless-stopped

volumes:
  dvwa-mysql-data:
EOF

# Start DVWA
docker-compose up -d

# Wait for startup and check status
sleep 30
docker-compose ps
curl http://localhost:8080
```

### Deploy WebGoat

```bash
# Create WebGoat directory
mkdir -p ~/vulnerable-apps/webgoat
cd ~/vulnerable-apps/webgoat

# Create docker-compose.yml for WebGoat
tee docker-compose.yml > /dev/null << 'EOF'
version: '3.7'

services:
  webgoat:
    image: webgoat/webgoat-8.0
    container_name: webgoat
    ports:
      - "8081:8080"
    environment:
      - WEBGOAT_HOST=0.0.0.0
      - WEBGOAT_PORT=8080
    restart: unless-stopped
EOF

# Start WebGoat
docker-compose up -d

# Check status
docker-compose ps
curl http://localhost:8081/WebGoat
```

### Deploy OWASP Juice Shop

```bash
# Create Juice Shop directory
mkdir -p ~/vulnerable-apps/juiceshop
cd ~/vulnerable-apps/juiceshop

# Create docker-compose.yml for Juice Shop
tee docker-compose.yml > /dev/null << 'EOF'
version: '3.7'

services:
  juice-shop:
    image: bkimminich/juice-shop
    container_name: juice-shop
    ports:
      - "3000:3000"
    restart: unless-stopped
EOF

# Start Juice Shop
docker-compose up -d

# Check status
docker-compose ps
curl http://localhost:3000
```

### Configure Apache Reverse Proxy

```bash
# Enable required Apache modules
sudo a2enmod proxy
sudo a2enmod proxy_http
sudo a2enmod rewrite

# Create virtual host configurations
sudo tee /etc/apache2/sites-available/vulnerable-apps.conf > /dev/null << 'EOF'
<VirtualHost *:80>
    ServerName linux-endpoint.lab
    DocumentRoot /var/www/html

    # DVWA Proxy
    ProxyPreserveHost On
    ProxyPass /dvwa/ http://localhost:8080/
    ProxyPassReverse /dvwa/ http://localhost:8080/

    # WebGoat Proxy
    ProxyPass /webgoat/ http://localhost:8081/WebGoat/
    ProxyPassReverse /webgoat/ http://localhost:8081/WebGoat/

    # Juice Shop Proxy
    ProxyPass /juiceshop/ http://localhost:3000/
    ProxyPassReverse /juiceshop/ http://localhost:3000/

    ErrorLog ${APACHE_LOG_DIR}/vulnerable-apps_error.log
    CustomLog ${APACHE_LOG_DIR}/vulnerable-apps_access.log combined
</VirtualHost>
EOF

# Enable the site
sudo a2ensite vulnerable-apps.conf
sudo systemctl reload apache2
```

## Step 4: Configure Windows Endpoint

### Access Windows Endpoint

```bash
# From jump box, connect to Windows endpoint
WINDOWS_PRIVATE_IP=$(terraform output -raw windows_endpoint_private_ip)

# Use RDP or PowerShell remoting (if configured)
# For this guide, we'll assume PowerShell remoting or direct access
```

### Download Wazuh Agent

```powershell
# Open PowerShell as Administrator
# Download Wazuh Windows agent
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi" -OutFile "C:\temp\wazuh-agent.msi"
```

### Install Wazuh Agent

```powershell
# Install Wazuh agent silently
Start-Process msiexec.exe -ArgumentList '/i C:\temp\wazuh-agent.msi /quiet WAZUH_MANAGER="10.0.3.100" WAZUH_AGENT_NAME="windows-endpoint" WAZUH_REGISTRATION_SERVER="10.0.3.100"' -Wait

# Alternative: Interactive installation
# Double-click wazuh-agent.msi and follow wizard
# Manager IP: 10.0.3.100
# Agent name: windows-endpoint
```

### Configure Wazuh Agent

```powershell
# Navigate to Wazuh installation directory
cd "C:\Program Files (x86)\ossec-agent"

# Configure ossec.conf
$ossecConfig = @"
<ossec_config>
  <client>
    <server>
      <address>10.0.3.100</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>windows</config-profile>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
    <crypto_method>aes</crypto_method>
  </client>

  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>

  <!-- File integrity monitoring -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <alert_new_files>yes</alert_new_files>

    <!-- Windows directories to monitor -->
    <directories check_all="yes">C:\Windows\System32</directories>
    <directories check_all="yes">C:\Windows\SysWOW64</directories>
    <directories check_all="yes" realtime="yes">C:\Users</directories>
    <directories check_all="yes" realtime="yes">C:\Program Files</directories>
    <directories check_all="yes">C:\Windows\System32\drivers</directories>

    <!-- Registry monitoring -->
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies</windows_registry>
    <windows_registry>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run</windows_registry>

    <!-- Ignore patterns -->
    <ignore>C:\Windows\System32\LogFiles</ignore>
    <ignore>C:\Windows\System32\wbem\Logs</ignore>
    <ignore>C:\Windows\Logs</ignore>
    <ignore>C:\Windows\Temp</ignore>
  </syscheck>

  <!-- Rootcheck -->
  <rootcheck>
    <disabled>no</disabled>
    <windows_apps>yes</windows_apps>
    <windows_malware>yes</windows_malware>
    <frequency>43200</frequency>
  </rootcheck>

  <!-- Windows Event Log monitoring -->
  <localfile>
    <location>Application</location>
    <log_format>eventlog</log_format>
  </localfile>

  <localfile>
    <location>System</location>
    <log_format>eventlog</log_format>
  </localfile>

  <localfile>
    <location>Security</location>
    <log_format>eventlog</log_format>
    <query>Event/System[EventID != 5156]</query>
  </localfile>

  <!-- PowerShell logging -->
  <localfile>
    <location>Microsoft-Windows-PowerShell/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- Process creation monitoring -->
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- IIS logs (if applicable) -->
  <localfile>
    <location>C:\inetpub\logs\LogFiles\W3SVC1\*.log</location>
    <log_format>iis</log_format>
  </localfile>

  <!-- Active response -->
  <active-response>
    <disabled>no</disabled>
    <ca_store>wpk_root.pem</ca_store>
    <ca_verification>yes</ca_verification>
  </active-response>
</ossec_config>
"@

# Write configuration
$ossecConfig | Out-File -FilePath "ossec.conf" -Encoding UTF8
```

### Register Windows Agent

```powershell
# Register agent with manager
.\agent-auth.exe -m 10.0.3.100 -A windows-endpoint

# Alternative: Manual key registration
# Run: .\manage_agents.exe
# Follow prompts to add agent or import key
```

### Start Wazuh Agent Service

```powershell
# Start Wazuh agent service
Start-Service WazuhSvc

# Set service to start automatically
Set-Service WazuhSvc -StartupType Automatic

# Check service status
Get-Service WazuhSvc

# Check agent logs
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 20
```

## Step 5: Install Windows Security Tools

### Install Sysmon for Enhanced Logging

```powershell
# Download Sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\temp\Sysmon.zip"

# Extract Sysmon
Expand-Archive -Path "C:\temp\Sysmon.zip" -DestinationPath "C:\temp\Sysmon"

# Download Sysmon configuration
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\temp\sysmon-config.xml"

# Install Sysmon with configuration
cd C:\temp\Sysmon
.\Sysmon64.exe -accepteula -i ..\sysmon-config.xml
```

### Configure PowerShell Logging

```powershell
# Enable PowerShell script block logging
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $regPath -Force
Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1
Set-ItemProperty -Path $regPath -Name "EnableScriptBlockInvocationLogging" -Value 1

# Enable PowerShell module logging
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
New-Item -Path $regPath -Force
Set-ItemProperty -Path $regPath -Name "EnableModuleLogging" -Value 1

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"
New-Item -Path $regPath -Force
Set-ItemProperty -Path $regPath -Name "*" -Value "*"

# Enable PowerShell transcription
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
New-Item -Path $regPath -Force
Set-ItemProperty -Path $regPath -Name "EnableTranscripting" -Value 1
Set-ItemProperty -Path $regPath -Name "OutputDirectory" -Value "C:\PowerShellTranscripts"
Set-ItemProperty -Path $regPath -Name "EnableInvocationHeader" -Value 1

# Create transcript directory
New-Item -Path "C:\PowerShellTranscripts" -ItemType Directory -Force
```

### Install IIS and Vulnerable Web Applications

```powershell
# Enable IIS
Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole, IIS-WebServer, IIS-CommonHttpFeatures, IIS-HttpErrors, IIS-HttpLogging, IIS-RequestMonitor -All

# Download and install XAMPP for additional web stack
Invoke-WebRequest -Uri "https://downloadsapachefriends.global.ssl.fastly.net/8.2.4/xampp-windows-x64-8.2.4-0-VS16-installer.exe" -OutFile "C:\temp\xampp-installer.exe"

# Install XAMPP silently
Start-Process "C:\temp\xampp-installer.exe" -ArgumentList "/S" -Wait

# Start XAMPP services
cd "C:\xampp"
.\xampp-control.exe
```

## Step 6: Verify Agent Connectivity

### Check Agent Status from Wazuh Manager

```bash
# Connect to Wazuh manager
ssh -i ~/.ssh/soc-lab-key.pem ubuntu@$WAZUH_PRIVATE_IP

# Enter Wazuh manager container
sudo docker exec -it wazuh_wazuh.manager_1 bash

# List all agents
/var/ossec/bin/agent_control -lc

# Check specific agent details
/var/ossec/bin/agent_control -i 001  # Linux agent
/var/ossec/bin/agent_control -i 002  # Windows agent

# View agent logs
tail -f /var/ossec/logs/ossec.log | grep -E "(agent|Agent)"
```

### Verify Data Collection

Access Wazuh Dashboard via SSH tunnel:
```bash
# From local machine
ssh -i soc-lab-key.pem -L 8443:$WAZUH_PRIVATE_IP:443 ubuntu@$JUMP_IP -N
```

Navigate to `https://localhost:8443` and verify:
1. **Agents tab**: Both agents show as "Active"
2. **Discover tab**: Events from both agents are visible
3. **Security Events**: Real-time alerts are flowing

### Test Alert Generation

**Linux Endpoint Tests:**
```bash
# SSH to Linux endpoint
ssh -i ~/.ssh/soc-lab-key.pem ubuntu@$LINUX_PRIVATE_IP

# Generate test alerts
sudo su - root  # Privilege escalation
echo "test" > /etc/passwd.bak  # File integrity alert
for i in {1..5}; do ssh root@localhost; done  # Failed authentication attempts
curl http://localhost:8080/vulnerabilities/sqli/  # Web application access
```

**Windows Endpoint Tests:**
```powershell
# On Windows endpoint
# Create test files in monitored directory
New-Item -Path "C:\Program Files\test.txt" -ItemType File

# Generate PowerShell events
Get-Process | Where-Object {$_.CPU -gt 100}

# Simulate process creation
notepad.exe
taskkill /f /im notepad.exe
```

## Step 7: Configure Custom Detection Rules

### Create Custom Rules for Vulnerable Applications

```bash
# On Wazuh manager
sudo docker exec -it wazuh_wazuh.manager_1 bash

# Create custom rules file
tee /var/ossec/etc/rules/local_rules.xml > /dev/null << 'EOF'
<group name="local,attack,web_attack">

  <!-- DVWA Attack Detection -->
  <rule id="100001" level="12">
    <if_sid>31103</if_sid>
    <url>/dvwa/vulnerabilities/</url>
    <description>DVWA vulnerability exploitation attempt detected</description>
    <mitre>
      <id>T1190</id>
    </mitre>
  </rule>

  <!-- SQL Injection Detection -->
  <rule id="100002" level="15">
    <if_sid>31103</if_sid>
    <url>/dvwa/vulnerabilities/sqli/</url>
    <match>union|select|drop|insert|update|delete</match>
    <description>SQL injection attack detected on DVWA</description>
    <mitre>
      <id>T1190</id>
    </mitre>
  </rule>

  <!-- XSS Attack Detection -->
  <rule id="100003" level="12">
    <if_sid>31103</if_sid>
    <url>/dvwa/vulnerabilities/xss/</url>
    <match><script|javascript:|onload|onerror</match>
    <description>XSS attack detected on DVWA</description>
    <mitre>
      <id>T1190</id>
    </mitre>
  </rule>

  <!-- Command Injection Detection -->
  <rule id="100004" level="15">
    <if_sid>31103</if_sid>
    <url>/dvwa/vulnerabilities/exec/</url>
    <match>|;|&&|\|\||`|$\(</match>
    <description>Command injection attack detected on DVWA</description>
    <mitre>
      <id>T1190</id>
    </mitre>
  </rule>

  <!-- File Upload Attack -->
  <rule id="100005" level="12">
    <if_sid>31103</if_sid>
    <url>/dvwa/vulnerabilities/upload/</url>
    <match>\.php|\.asp|\.jsp|\.exe</match>
    <description>Malicious file upload attempt detected</description>
    <mitre>
      <id>T1190</id>
    </mitre>
  </rule>

  <!-- Brute Force Detection -->
  <rule id="100006" level="10" frequency="5" timeframe="300">
    <if_matched_sid>100001</if_matched_sid>
    <same_source_ip/>
    <description>Multiple DVWA exploitation attempts from same source</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>

  <!-- WebGoat Attack Detection -->
  <rule id="100007" level="12">
    <if_sid>31103</if_sid>
    <url>/WebGoat/</url>
    <match>attack|exploit|payload</match>
    <description>WebGoat training attack detected</description>
    <mitre>
      <id>T1190</id>
    </mitre>
  </rule>

  <!-- Juice Shop Attack Detection -->
  <rule id="100008" level="12">
    <if_sid>31103</if_sid>
    <url>/juiceshop/</url>
    <match>admin|' or |union select|<script</match>
    <description>Juice Shop attack detected</description>
    <mitre>
      <id>T1190</id>
    </mitre>
  </rule>

</group>

<!-- Windows-specific rules -->
<group name="local,windows,attack">

  <!-- PowerShell Suspicious Activity -->
  <rule id="100010" level="12">
    <if_sid>91533</if_sid>
    <match>Invoke-Expression|IEX|DownloadString|Net.WebClient</match>
    <description>Suspicious PowerShell activity detected</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>

  <!-- Process Injection -->
  <rule id="100011" level="15">
    <if_sid>92000</if_sid>
    <match>CreateRemoteThread|WriteProcessMemory|VirtualAllocEx</match>
    <description>Process injection technique detected</description>
    <mitre>
      <id>T1055</id>
    </mitre>
  </rule>

  <!-- Credential Dumping -->
  <rule id="100012" level="15">
    <if_sid>92000</if_sid>
    <match>lsass.exe|SAM|SYSTEM|mimikatz</match>
    <description>Credential dumping attempt detected</description>
    <mitre>
      <id>T1003</id>
    </mitre>
  </rule>

</group>
EOF

# Restart Wazuh manager to load new rules
/var/ossec/bin/wazuh-control restart
```

### Create Custom Decoders

```bash
# Create custom decoders for application logs
tee /var/ossec/etc/decoders/local_decoder.xml > /dev/null << 'EOF'
<decoder_group name="local">

  <!-- DVWA Log Decoder -->
  <decoder name="dvwa-access">
    <parent>apache-access</parent>
    <regex offset="after_parent">^(\S+) \S+ \S+ \[\S+ \S+\] "(\S+) (\S+.*dvwa\S*) \S+" (\S+) \S+</regex>
    <order>srcip,method,url,response_code</order>
  </decoder>

  <!-- Custom Application Decoder -->
  <decoder name="custom-app">
    <program_name>custom-app</program_name>
    <regex>^(\w+): (.+)$</regex>
    <order>level,message</order>
  </decoder>

</decoder_group>
EOF
```

## Step 8: Configure Monitoring Dashboards

### Create Custom Dashboards in Wazuh

1. **Access Wazuh Dashboard**: Navigate to Management → App Settings → Pattern
2. **Create Index Pattern**: `wazuh-alerts-*`
3. **Configure Visualizations**:
   - **Vulnerable Apps Traffic**: Filter by `/dvwa/`, `/webgoat/`, `/juiceshop/`
   - **Attack Types**: Group by rule ID and description
   - **Geographic Distribution**: Map source IPs
   - **Timeline Analysis**: Events over time

### Sample Dashboard Queries

**Top Attack Types:**
```json
{
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-24h"}}},
        {"terms": {"rule.id": [100001, 100002, 100003, 100004, 100005]}}
      ]
    }
  },
  "aggs": {
    "attack_types": {
      "terms": {"field": "rule.description.keyword"}
    }
  }
}
```

**Failed Authentication Attempts:**
```json
{
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-1h"}}},
        {"match": {"rule.groups": "authentication_failed"}}
      ]
    }
  },
  "aggs": {
    "source_ips": {
      "terms": {"field": "data.srcip"}
    }
  }
}
```

## Step 9: Testing and Validation

### Comprehensive Testing Script

```bash
# Create testing script on Linux endpoint
tee ~/test-monitoring.sh > /dev/null << 'EOF'
#!/bin/bash

echo "=== SOC Lab Monitoring Test ==="

# Test 1: File Integrity Monitoring
echo "1. Testing File Integrity Monitoring..."
sudo touch /etc/test-fim-file
sleep 5
sudo rm /etc/test-fim-file

# Test 2: Web Application Attacks
echo "2. Testing Web Application Attack Detection..."
curl "http://localhost:8080/dvwa/vulnerabilities/sqli/?id=1' UNION SELECT 1,2--"
curl "http://localhost:8080/dvwa/vulnerabilities/xss/?name=<script>alert('xss')</script>"

# Test 3: Brute Force Simulation
echo "3. Testing Brute Force Detection..."
for i in {1..6}; do
  curl "http://localhost:8080/dvwa/login.php" -d "username=admin&password=wrong$i"
  sleep 1
done

# Test 4: Command Execution
echo "4. Testing Command Execution Detection..."
curl "http://localhost:8080/dvwa/vulnerabilities/exec/?ip=127.0.0.1;id"

# Test 5: Log Generation
echo "5. Generating various log entries..."
logger "SOC Lab Test: Authentication test"
sudo useradd testuser 2>/dev/null || true
sudo userdel testuser 2>/dev/null || true

echo "Test completed. Check Wazuh dashboard for alerts."
EOF

chmod +x ~/test-monitoring.sh
./test-monitoring.sh
```

### Windows Testing Script

```powershell
# Create Windows testing script
$testScript = @'
Write-Host "=== SOC Lab Windows Monitoring Test ==="

# Test 1: PowerShell Suspicious Activity
Write-Host "1. Testing PowerShell Detection..."
Invoke-Expression "Get-Process"

# Test 2: File System Changes
Write-Host "2. Testing File Integrity Monitoring..."
New-Item -Path "C:\Program Files\test-file.txt" -ItemType File
Start-Sleep 5
Remove-Item -Path "C:\Program Files\test-file.txt" -Force

# Test 3: Registry Changes
Write-Host "3. Testing Registry Monitoring..."
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "TestEntry" -Value "test.exe" -Force
Start-Sleep 5
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "TestEntry" -Force

# Test 4: Process Creation
Write-Host "4. Testing Process Monitoring..."
Start-Process notepad -PassThru | ForEach-Object { Start-Sleep 2; Stop-Process $_ -Force }

# Test 5: Event Log Entries
Write-Host "5. Generating Event Log entries..."
Write-EventLog -LogName Application -Source "SOC Lab Test" -EventId 1000 -Message "Test event for monitoring"

Write-Host "Windows test completed. Check Wazuh dashboard for alerts."
'@

$testScript | Out-File -FilePath "C:\temp\test-monitoring.ps1" -Encoding UTF8
PowerShell.exe -ExecutionPolicy Bypass -File "C:\temp\test-monitoring.ps1"
```

### Validate Alert Generation

Check Wazuh Dashboard for:
- [ ] File integrity monitoring alerts
- [ ] Web application attack alerts  
- [ ] Authentication failure alerts
- [ ] PowerShell execution alerts
- [ ] Registry modification alerts
- [ ] Process creation events

## Troubleshooting Common Issues

### Agent Connection Issues

**Problem**: Agent not connecting to manager
**Solutions**:
```bash
# Check network connectivity
ping 10.0.3.100

# Check firewall rules
sudo ufw status  # Linux
netsh advfirewall show allprofiles  # Windows

# Verify agent configuration
sudo cat /var/ossec/etc/ossec.conf  # Linux
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.conf"  # Windows

# Check agent logs
sudo tail -f /var/ossec/logs/ossec.log  # Linux
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 20  # Windows
```

### Performance Issues

**Problem**: High resource usage or slow response
**Solutions**:
```bash
# Adjust agent configuration
# Reduce monitoring frequency
# Disable unnecessary modules
# Optimize log rotation

# Linux: Edit /var/ossec/etc/ossec.conf
<syscheck>
  <frequency>86400</frequency>  <!-- Once daily -->
</syscheck>

# Windows: Similar changes in ossec.conf
```

### Log Collection Issues

**Problem**: Logs not appearing in Wazuh
**Solutions**:
```bash
# Verify log file permissions
ls -la /var/log/apache2/  # Linux
Get-Acl "C:\inetpub\logs\LogFiles\W3SVC1\"  # Windows

# Check localfile configuration in ossec.conf
# Restart agent after configuration changes
sudo systemctl restart wazuh-agent  # Linux
Restart-Service WazuhSvc  # Windows
```

## Next Steps

With endpoints configured and monitored:

1. **✅ Linux Endpoint Ready**: Wazuh agent installed, vulnerable apps deployed
2. **✅ Windows Endpoint Ready**: Wazuh agent installed, logging configured  
3. **✅ Custom Rules Created**: Detection rules for attack scenarios
4. **→ Next**: [Attack Scenarios and Red Team Operations](../attack-scenarios/)

## Summary

You have successfully:
- ✅ Installed and configured Wazuh agents on Linux and Windows endpoints
- ✅ Deployed vulnerable applications for training scenarios
- ✅ Configured comprehensive log monitoring and file integrity checking
- ✅ Created custom detection rules for web application attacks
- ✅ Set up PowerShell and Sysmon logging on Windows
- ✅ Verified agent connectivity and alert generation
- ✅ Created testing scripts for validation

Your SOC Lab is now fully operational with comprehensive endpoint monitoring!

---

**🎉 Outstanding!** Your endpoints are now monitored and ready for security training scenarios. Proceed to attack scenarios to test your detection capabilities.
