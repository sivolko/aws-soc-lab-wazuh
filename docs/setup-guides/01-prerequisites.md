# Prerequisites

Before deploying the AWS SOC Lab, ensure you have all the necessary tools, accounts, and configurations in place.

## Required Accounts and Services

### 1. AWS Account

**Account Requirements:**
- Active AWS account with billing enabled
- Sufficient service limits for the deployment
- Admin-level access or appropriate IAM permissions

**Required IAM Permissions:**
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:*",
                "vpc:*",
                "iam:*",
                "s3:*",
                "cloudtrail:*",
                "logs:*",
                "cloudwatch:*"
            ],
            "Resource": "*"
        }
    ]
}
```

**Service Limits to Check:**
- EC2 instances: At least 5 instances
- VPC: 1 VPC (default limit: 5)
- Elastic IPs: 2 addresses
- EBS volumes: 10 volumes
- S3 buckets: 2 buckets

### 2. Domain and DNS (Optional)

If you want custom domain access:
- Registered domain name
- Route 53 hosted zone (or external DNS provider)
- SSL certificates (Let's Encrypt recommended)

## Required Software and Tools

### 1. Terraform

**Installation:**

```bash
# Linux/macOS (using Homebrew)
brew install terraform

# Linux (using package manager)
wget https://releases.hashicorp.com/terraform/1.6.0/terraform_1.6.0_linux_amd64.zip
unzip terraform_1.6.0_linux_amd64.zip
sudo mv terraform /usr/local/bin/

# Windows (using Chocolatey)
choco install terraform

# Verify installation
terraform --version
```

**Required Version:** >= 1.0

### 2. AWS CLI

**Installation:**

```bash
# Linux/macOS
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# macOS (using Homebrew)
brew install awscli

# Windows
# Download and run the AWS CLI MSI installer

# Verify installation
aws --version
```

**Configuration:**
```bash
# Configure AWS credentials
aws configure
# Enter:
# - AWS Access Key ID
# - AWS Secret Access Key
# - Default region (e.g., us-east-1)
# - Default output format (json)

# Test configuration
aws sts get-caller-identity
```

### 3. Docker and Docker Compose

**Docker Installation:**

```bash
# Linux (Ubuntu/Debian)
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# macOS
brew install docker
# Or download Docker Desktop

# Windows
# Download and install Docker Desktop

# Verify installation
docker --version
docker run hello-world
```

**Docker Compose Installation:**

```bash
# Linux
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# macOS (included with Docker Desktop)
# Windows (included with Docker Desktop)

# Verify installation
docker-compose --version
```

### 4. Git

**Installation:**

```bash
# Linux (Ubuntu/Debian)
sudo apt-get install git

# Linux (CentOS/RHEL)
sudo yum install git

# macOS
brew install git
# Or use Xcode Command Line Tools

# Windows
# Download from https://git-scm.com/download/win

# Verify installation
git --version
```

### 5. SSH Client

**Linux/macOS:** Usually pre-installed
**Windows:** Use built-in OpenSSH, PuTTY, or WSL

```bash
# Test SSH availability
ssh -V
```

### 6. Text Editor/IDE

**Recommended Options:**
- **Visual Studio Code** (with Terraform and Docker extensions)
- **Vim/Nano** (for command-line editing)
- **IntelliJ IDEA** (with Terraform plugin)
- **Sublime Text**

## System Requirements

### Local Machine Specifications

**Minimum Requirements:**
- **CPU:** 2 cores
- **RAM:** 4GB
- **Storage:** 10GB free space
- **Network:** Broadband internet connection
- **OS:** Windows 10+, macOS 10.14+, or Linux (Ubuntu 18.04+)

**Recommended Specifications:**
- **CPU:** 4+ cores
- **RAM:** 8GB+
- **Storage:** 50GB+ SSD
- **Network:** Stable broadband with low latency

### Network Requirements

**Bandwidth:**
- **Minimum:** 10 Mbps download, 5 Mbps upload
- **Recommended:** 50+ Mbps download, 10+ Mbps upload

**Firewall/Proxy:**
- Outbound HTTPS (443) access required
- SSH (22) access required
- VNC (5900-5999) access for GUI tools

**Corporate Networks:**
- May require proxy configuration for AWS CLI
- VPN access might be needed for SSH connections
- Check with IT department for required firewall rules

## AWS Key Pair Setup

### Create EC2 Key Pair

**Via AWS Console:**
1. Navigate to EC2 → Key Pairs
2. Click "Create key pair"
3. Name: `soc-lab-key`
4. Type: RSA
5. Format: .pem
6. Download and save securely

**Via AWS CLI:**
```bash
# Create key pair
aws ec2 create-key-pair --key-name soc-lab-key --query 'KeyMaterial' --output text > soc-lab-key.pem

# Set proper permissions
chmod 600 soc-lab-key.pem

# Verify key creation
aws ec2 describe-key-pairs --key-names soc-lab-key
```

### Key Security Best Practices

**Storage:**
- Store in secure location (e.g., `~/.ssh/`)
- Set restrictive file permissions (600)
- Never commit to version control
- Consider using AWS Systems Manager Session Manager as alternative

**Backup:**
- Keep backup copy in secure location
- Consider using encrypted storage
- Document key location and purpose

## Cost Planning

### Estimated Costs

**Monthly Costs (USD):**
```
Wazuh Server (t3.large):     ~$60
Windows Endpoint (t3.micro): ~$8
Linux Endpoint (t3.micro):   ~$8
Kali Attacker (t3.small):    ~$15
Jump Box (t3.micro):         ~$8
Storage (EBS):               ~$15
Data Transfer:               ~$5
Total:                       ~$119/month
```

**Cost Optimization Options:**
- **Spot Instances:** 50-70% savings (with interruption risk)
- **Reserved Instances:** 30-60% savings (1-3 year commitment)
- **Scheduled Shutdown:** Save during non-use hours
- **Right-sizing:** Monitor and adjust instance sizes

### Billing Alerts

**Set up AWS Billing Alerts:**

```bash
# Create billing alarm (AWS CLI)
aws cloudwatch put-metric-alarm \
    --alarm-name "SOC-Lab-Billing-Alert" \
    --alarm-description "Alert when SOC Lab costs exceed $150" \
    --metric-name EstimatedCharges \
    --namespace AWS/Billing \
    --statistic Maximum \
    --period 86400 \
    --threshold 150 \
    --comparison-operator GreaterThanThreshold \
    --dimensions Name=Currency,Value=USD \
    --evaluation-periods 1
```

## Security Considerations

### Network Security

**IP Whitelisting:**
```bash
# Find your public IP
curl https://ipinfo.io/ip

# Use this IP in terraform.tfvars:
# allowed_cidr_blocks = ["YOUR_IP/32"]
```

**VPN Considerations:**
- If using VPN, whitelist VPN exit IP
- Consider multiple IP ranges for team access
- Regular IP address updates as needed

### Credential Security

**AWS Credentials:**
- Use IAM users with minimal required permissions
- Enable MFA on AWS root account
- Rotate access keys regularly
- Consider using AWS IAM roles where possible

**SSH Keys:**
- Generate strong RSA keys (2048+ bits)
- Use unique keys for different environments
- Implement key rotation policy
- Consider using AWS Systems Manager for access

## Knowledge Prerequisites

### Required Skills

**Basic Level:**
- Command line navigation (Linux/Windows)
- Basic networking concepts (IP addresses, ports, protocols)
- Understanding of virtualization concepts
- Text editor usage

**Intermediate Level:**
- AWS services overview (EC2, VPC, S3, IAM)
- Docker containers and containerization
- Infrastructure as Code concepts
- Basic security concepts

### Recommended Learning Resources

**AWS Fundamentals:**
- [AWS Cloud Practitioner Essentials](https://aws.amazon.com/training/course-descriptions/cloud-practitioner-essentials/)
- [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/)

**Docker and Containers:**
- [Docker Official Tutorial](https://docs.docker.com/get-started/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)

**Terraform:**
- [Terraform Getting Started](https://learn.hashicorp.com/terraform)
- [Terraform AWS Provider](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)

**Cybersecurity:**
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

## Troubleshooting Common Issues

### AWS CLI Issues

**Problem:** "Unable to locate credentials"
**Solution:**
```bash
# Check AWS configuration
aws configure list

# Reconfigure if needed
aws configure

# Verify with test call
aws sts get-caller-identity
```

### Terraform Issues

**Problem:** "Provider plugin not found"
**Solution:**
```bash
# Reinitialize Terraform
terraform init -upgrade

# Clear cache if needed
rm -rf .terraform/
terraform init
```

### Docker Issues

**Problem:** "Permission denied" on Linux
**Solution:**
```bash
# Add user to docker group
sudo usermod -aG docker $USER

# Restart or re-login
su - $USER

# Test docker access
docker run hello-world
```

### Network Access Issues

**Problem:** Cannot access deployed services
**Solution:**
1. Check security group rules
2. Verify your public IP hasn't changed
3. Confirm services are running
4. Check VPC routing configuration

## Pre-Deployment Checklist

Before proceeding to deployment, verify:

- [ ] AWS account set up with sufficient permissions
- [ ] AWS CLI installed and configured
- [ ] Terraform installed (version >= 1.0)
- [ ] Docker and Docker Compose installed
- [ ] Git installed and configured
- [ ] SSH key pair created in AWS
- [ ] Public IP address identified for security groups
- [ ] Text editor/IDE configured
- [ ] Billing alerts configured
- [ ] Required knowledge and documentation reviewed
- [ ] Network connectivity verified
- [ ] Local system meets requirements

## Next Steps

Once all prerequisites are met:

1. **Clone the Repository:** Get the SOC Lab code
2. **Configure Variables:** Set up terraform.tfvars
3. **Deploy Infrastructure:** Run Terraform deployment
4. **Verify Installation:** Test all components
5. **Start Learning:** Begin with attack scenarios

---

**Ready to proceed?** Continue to [AWS Infrastructure Setup](02-aws-infrastructure.md)