#!/bin/bash
# Kali Linux Attack Box Setup Script

set -e

# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Install additional security tools
sudo apt-get install -y \
    metasploit-framework \
    nmap \
    nikto \
    sqlmap \
    gobuster \
    dirb \
    hydra \
    john \
    hashcat \
    burpsuite \
    zaproxy \
    wireshark \
    tcpdump \
    netcat-traditional \
    socat \
    proxychains4 \
    tor \
    exploitdb \
    searchsploit \
    masscan \
    fierce \
    dnsenum \
    dnsrecon \
    theharvester \
    recon-ng \
    maltego \
    social-engineer-toolkit \
    beef-xss \
    wpscan \
    cmseek \
    whatweb \
    webshells \
    laudanum \
    weevely \
    shellnoob \
    commix \
    xerosploit \
    bettercap \
    responder \
    impacket-scripts \
    bloodhound \
    crackmapexec \
    evil-winrm \
    powersploit \
    empire \
    covenant \
    sliver-client

# Install Python tools
sudo pip3 install \
    pwntools \
    ropper \
    ropgadget \
    angr \
    pycrypto \
    requests \
    beautifulsoup4 \
    paramiko \
    scapy \
    python-nmap \
    shodan \
    censys \
    virustotal-api

# Install Go tools
sudo apt-get install -y golang-go
export GOPATH=/opt/go
export PATH=$PATH:/opt/go/bin
sudo mkdir -p /opt/go/{bin,src,pkg}
sudo chown -R kali:kali /opt/go

# Add Go to profile
echo 'export GOPATH=/opt/go' | sudo tee -a /etc/profile
echo 'export PATH=$PATH:/opt/go/bin' | sudo tee -a /etc/profile

# Install additional Go security tools
go install github.com/OJ/gobuster/v3@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/ffuf/ffuf@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/httprobe@latest
go install github.com/tomnomnom/assetfinder@latest

# Install Docker for additional tools
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker kali

# Create custom wordlists directory
sudo mkdir -p /opt/wordlists
cd /opt/wordlists

# Download popular wordlists
sudo wget https://github.com/danielmiessler/SecLists/archive/master.zip -O seclists.zip
sudo unzip seclists.zip
sudo mv SecLists-master SecLists
sudo rm seclists.zip

# Download other useful wordlists
sudo wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
sudo wget https://raw.githubusercontent.com/rapid7/metasploit-framework/master/data/wordlists/common_users.txt
sudo wget https://raw.githubusercontent.com/rapid7/metasploit-framework/master/data/wordlists/common_passwords.txt

# Set permissions
sudo chown -R kali:kali /opt/wordlists

# Configure Metasploit
sudo systemctl enable postgresql
sudo systemctl start postgresql
sudo msfdb init

# Configure VNC for GUI access
sudo apt-get install -y tightvncserver
vncserver :1 -geometry 1920x1080 -depth 24

# Create VNC startup script
cat > /home/kali/.vnc/xstartup << 'EOF'
#!/bin/bash
# Uncomment the following two lines for normal desktop:
# unset SESSION_MANAGER
# exec /etc/X11/xinit/xinitrc

[ -x /etc/vnc/xstartup ] && exec /etc/vnc/xstartup
[ -r $HOME/.Xresources ] && xrdb $HOME/.Xresources
xsetroot -solid grey
vncconfig -iconic &
x-terminal-emulator -geometry 80x24+10+10 -ls -title "$VNCDESKTOP Desktop" &
x-window-manager &
EOF

chmod +x /home/kali/.vnc/xstartup

# Configure SSH
sudo systemctl enable ssh
sudo systemctl start ssh

# Allow password authentication for SSH (for lab purposes)
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
sudo systemctl restart ssh

# Create attack simulation scripts directory
mkdir -p /home/kali/attack-scripts
cd /home/kali/attack-scripts

# Create network reconnaissance script
cat > network-recon.sh << 'EOF'
#!/bin/bash
# Network Reconnaissance Script

if [ $# -eq 0 ]; then
    echo "Usage: $0 <target_network>"
    echo "Example: $0 10.0.0.0/24"
    exit 1
fi

TARGET=$1
echo "Starting network reconnaissance on $TARGET"

echo "[+] Host Discovery with Nmap..."
nmap -sn $TARGET | tee host-discovery.txt

echo "[+] Port Scanning discovered hosts..."
grep -oP '\d+\.\d+\.\d+\.\d+' host-discovery.txt | while read host; do
    echo "Scanning $host..."
    nmap -sV -sC -O $host -oN "scan-$host.txt" &
done

wait
echo "Network reconnaissance completed!"
EOF

# Create web application testing script
cat > web-app-test.sh << 'EOF'
#!/bin/bash
# Web Application Testing Script

if [ $# -eq 0 ]; then
    echo "Usage: $0 <target_url>"
    echo "Example: $0 http://10.0.3.100"
    exit 1
fi

TARGET=$1
echo "Starting web application testing on $TARGET"

echo "[+] Directory enumeration with Gobuster..."
gobuster dir -u $TARGET -w /opt/wordlists/SecLists/Discovery/Web-Content/common.txt -o gobuster-results.txt

echo "[+] Nikto scan..."
nikto -h $TARGET -o nikto-results.txt

echo "[+] Whatweb fingerprinting..."
whatweb $TARGET | tee whatweb-results.txt

echo "[+] Checking for common vulnerabilities..."
curl -s $TARGET | grep -i "version\|powered\|generator" | tee tech-stack.txt

echo "Web application testing completed!"
EOF

# Create password attack script
cat > password-attack.sh << 'EOF'
#!/bin/bash
# Password Attack Script

if [ $# -lt 2 ]; then
    echo "Usage: $0 <target_ip> <service> [username_list] [password_list]"
    echo "Services: ssh, ftp, telnet, smb, rdp"
    echo "Example: $0 10.0.3.100 ssh"
    exit 1
fi

TARGET=$1
SERVICE=$2
USERLIST=${3:-/opt/wordlists/common_users.txt}
PASSLIST=${4:-/opt/wordlists/common_passwords.txt}

echo "Starting password attack on $TARGET ($SERVICE)"

case $SERVICE in
    ssh)
        hydra -L $USERLIST -P $PASSLIST $TARGET ssh -o hydra-ssh-results.txt
        ;;
    ftp)
        hydra -L $USERLIST -P $PASSLIST $TARGET ftp -o hydra-ftp-results.txt
        ;;
    rdp)
        hydra -L $USERLIST -P $PASSLIST rdp://$TARGET -o hydra-rdp-results.txt
        ;;
    *)
        echo "Unsupported service: $SERVICE"
        exit 1
        ;;
esac

echo "Password attack completed!"
EOF

# Create privilege escalation enumeration script
cat > privesc-enum.sh << 'EOF'
#!/bin/bash
# Privilege Escalation Enumeration Script

echo "[+] System Information"
uname -a
cat /etc/os-release

echo "\n[+] Current User and Groups"
id
groups

echo "\n[+] Sudo Permissions"
sudo -l 2>/dev/null

echo "\n[+] SUID Binaries"
find / -perm -4000 -type f 2>/dev/null

echo "\n[+] Writable Directories"
find / -writable -type d 2>/dev/null | head -20

echo "\n[+] Interesting Files"
find / -name "*.conf" -o -name "*.config" -o -name "*.bak" 2>/dev/null | head -20

echo "\n[+] Network Connections"
netstat -tulnp 2>/dev/null

echo "\n[+] Running Processes"
ps aux --sort=-%cpu | head -20

echo "Privilege escalation enumeration completed!"
EOF

# Make scripts executable
chmod +x *.sh

# Create custom aliases
cat >> /home/kali/.bashrc << 'EOF'

# SOC Lab Custom Aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias grep='grep --color=auto'

# Security tool aliases
alias nmap-quick='nmap -sV -sC -O'
alias nmap-stealth='nmap -sS -sV -O'
alias ports='nmap -p- --open'
alias webenum='gobuster dir -u'
alias sqltest='sqlmap -u'

# Custom functions
quickscan() {
    if [ $# -eq 0 ]; then
        echo "Usage: quickscan <target>"
        return 1
    fi
    nmap -sV -sC -O $1 -oN "quickscan-$1.txt"
}

webtest() {
    if [ $# -eq 0 ]; then
        echo "Usage: webtest <url>"
        return 1
    fi
    nikto -h $1
    gobuster dir -u $1 -w /opt/wordlists/SecLists/Discovery/Web-Content/common.txt
}
EOF

# Create desktop shortcuts for common tools
mkdir -p /home/kali/Desktop

cat > /home/kali/Desktop/Metasploit.desktop << 'EOF'
[Desktop Entry]
Name=Metasploit Framework
Comment=Penetration Testing Platform
Exec=gnome-terminal -- msfconsole
Icon=metasploit
Terminal=false
Type=Application
Categories=Security;
EOF

cat > /home/kali/Desktop/Burp-Suite.desktop << 'EOF'
[Desktop Entry]
Name=Burp Suite
Comment=Web Application Security Testing
Exec=burpsuite
Icon=burpsuite
Terminal=false
Type=Application
Categories=Security;
EOF

chmod +x /home/kali/Desktop/*.desktop

# Set up auto-start services
sudo systemctl enable postgresql
sudo systemctl enable ssh

# Create info file
cat > /home/kali/SOC-Lab-Info.txt << 'EOF'
SOC Lab Kali Linux Attack Box Setup Complete
==========================================

This Kali Linux instance has been configured with:

✓ Full Kali Linux tool suite
✓ Additional security tools and frameworks
✓ Custom wordlists and payloads
✓ VNC server for GUI access (port 5901)
✓ SSH server enabled
✓ Metasploit framework configured
✓ Custom attack simulation scripts

Available Scripts:
- ~/attack-scripts/network-recon.sh
- ~/attack-scripts/web-app-test.sh
- ~/attack-scripts/password-attack.sh
- ~/attack-scripts/privesc-enum.sh

VNC Access:
- Port: 5901
- Connect with VNC client to <public-ip>:5901

SSH Access:
- Username: kali
- Use your SSH key for authentication

Wordlists Location: /opt/wordlists/
Go Tools: /opt/go/bin/

For penetration testing purposes only!
EOF

chown kali:kali /home/kali/SOC-Lab-Info.txt

echo "Kali Linux attack box setup completed!"
echo "VNC server running on port 5901"
echo "SSH server enabled"
echo "Ready for penetration testing activities!"