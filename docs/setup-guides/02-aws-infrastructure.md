# AWS Infrastructure Setup

This guide walks you through deploying the complete AWS infrastructure for the SOC Lab using Terraform.

## Overview

The infrastructure deployment creates:
- **VPC with public/private subnets**
- **5 EC2 instances** (Wazuh, endpoints, jump box, Kali)
- **Security groups** with least-privilege access
- **IAM roles and policies**
- **S3 bucket** for logs and backups
- **CloudTrail** for API logging
- **CloudWatch** monitoring and alarms

## Step 1: Repository Setup

### Clone the Repository

```bash
# Clone the SOC Lab repository
git clone https://github.com/sivolko/aws-soc-lab-wazuh.git
cd aws-soc-lab-wazuh

# Verify repository structure
ls -la
```

**Expected Structure:**
```
aws-soc-lab-wazuh/
├── terraform/           # Infrastructure as Code
├── docker/             # Wazuh SIEM configuration
├── scripts/            # Automation scripts
├── docs/               # Documentation
└── README.md           # Project overview
```

### Navigate to Terraform Directory

```bash
cd terraform
ls -la
```

**Key Files:**
- `main.tf` - Main Terraform configuration
- `variables.tf` - Input variables
- `outputs.tf` - Output values
- `providers.tf` - Provider configurations
- `terraform.tfvars.example` - Example variables file

## Step 2: Configure Variables

### Create Configuration File

```bash
# Copy example configuration
cp terraform.tfvars.example terraform.tfvars

# Edit configuration
vim terraform.tfvars  # or your preferred editor
```

### Essential Configuration

**terraform.tfvars:**
```hcl
# AWS Configuration
aws_region = "us-east-1"  # Choose your preferred region
environment = "dev"
project_name = "aws-soc-lab"

# CRITICAL: Replace with your AWS key pair name
key_name = "soc-lab-key"  # Must exist in your AWS account

# CRITICAL: Replace with your public IP for security
allowed_cidr_blocks = ["203.0.113.0/32"]  # Your IP address

# Instance configuration (adjust based on budget)
instance_types = {
  wazuh_server     = "t3.large"   # 2 vCPU, 8GB RAM
  windows_endpoint = "t3.micro"   # 1 vCPU, 1GB RAM
  linux_endpoint   = "t3.micro"   # 1 vCPU, 1GB RAM
  kali_attacker    = "t3.small"   # 1 vCPU, 2GB RAM
  jump_box         = "t3.micro"   # 1 vCPU, 1GB RAM
}

# Component toggles
enable_windows_endpoint = true
enable_linux_endpoint = true
enable_kali_attacker = true

# Cost optimization
use_spot_instances = false  # Set true for 50-70% savings

# Monitoring
enable_vpc_flow_logs = true
enable_cloudtrail = true
```

### Find Your Public IP

```bash
# Method 1: Using curl
curl https://ipinfo.io/ip

# Method 2: Using dig
dig +short myip.opendns.com @resolver1.opendns.com

# Method 3: Using web browser
# Visit: https://whatismyipaddress.com/
```

**⚠️ Security Warning:** Always restrict `allowed_cidr_blocks` to your specific IP address. Using `0.0.0.0/0` opens your lab to the entire internet!

### Validate Configuration

```bash
# Check if key pair exists
aws ec2 describe-key-pairs --key-names soc-lab-key

# Verify AWS credentials
aws sts get-caller-identity

# Check region availability
aws ec2 describe-availability-zones --region us-east-1
```

## Step 3: Initialize Terraform

### Initialize Working Directory

```bash
# Initialize Terraform (downloads providers)
terraform init
```

**Expected Output:**
```
Initializing the backend...
Initializing provider plugins...
- Finding hashicorp/aws versions matching "~> 5.0"...
- Installing hashicorp/aws v5.x.x...
- Installed hashicorp/aws v5.x.x

Terraform has been successfully initialized!
```

### Validate Configuration

```bash
# Validate syntax and configuration
terraform validate

# Expected output: "Success! The configuration is valid."
```

### Format Code

```bash
# Format Terraform files
terraform fmt -recursive
```

## Step 4: Plan Deployment

### Create Deployment Plan

```bash
# Generate and review deployment plan
terraform plan -out=tfplan
```

**Plan Review Checklist:**
- [ ] Correct number of resources (typically 50+ resources)
- [ ] Proper instance types selected
- [ ] Security groups have restrictive rules
- [ ] VPC CIDR doesn't conflict with existing networks
- [ ] Key pair name matches your AWS key
- [ ] Region is correct

**Key Resources to Verify:**
```
Plan: XX to add, 0 to change, 0 to destroy.

Expected resources:
- aws_vpc.main
- aws_internet_gateway.main
- aws_subnet.public[0-1]
- aws_subnet.private[0-1]
- aws_instance.wazuh_server
- aws_instance.jump_box
- aws_instance.linux_endpoint[0]
- aws_instance.windows_endpoint[0]
- aws_instance.kali_attacker[0]
- aws_security_group.wazuh
- aws_security_group.endpoint
- aws_security_group.attacker
- aws_security_group.jumpbox
```

### Cost Estimation

```bash
# Optional: Use terraform cost estimation tools
# Install infracost (optional)
curl -fsSL https://raw.githubusercontent.com/infracost/infracost/master/scripts/install.sh | sh

# Generate cost estimate
infracost breakdown --path .
```

## Step 5: Deploy Infrastructure

### Apply Terraform Configuration

```bash
# Deploy infrastructure
terraform apply tfplan
```

**Deployment Process:**
1. **Confirmation:** Type `yes` when prompted
2. **Duration:** Typically takes 10-15 minutes
3. **Progress:** Watch resource creation in real-time
4. **Completion:** Note the output values

**Expected Timeline:**
```
[0-2 min]   VPC and networking components
[2-5 min]   Security groups and IAM roles
[5-10 min]  EC2 instances launching
[10-12 min] User data scripts executing
[12-15 min] Final configuration and outputs
```

### Monitor Deployment

**In another terminal:**
```bash
# Watch EC2 instances
watch "aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,State.Name,Tags[?Key==\`Name\`].Value|[0]]' --output table"

# Monitor CloudFormation (if using)
aws cloudformation describe-stacks --stack-name aws-soc-lab
```

## Step 6: Verify Deployment

### Check Terraform Outputs

```bash
# Display all outputs
terraform output

# Get specific outputs
terraform output wazuh_dashboard_url
terraform output jump_box_public_ip
terraform output -raw wazuh_admin_password
```

**Expected Outputs:**
```
jump_box_public_ip = "203.0.113.10"
kali_attacker_public_ip = "203.0.113.11"
wazuh_dashboard_url = "https://203.0.113.12:443"
wazuh_admin_password = <sensitive>
wazuh_server_private_ip = "10.0.3.100"
ssh_connection_commands = <sensitive>
```

### Test Instance Connectivity

```bash
# Get connection information
terraform output ssh_connection_commands

# Test jump box connectivity
JUMP_IP=$(terraform output -raw jump_box_public_ip)
ssh -i ../soc-lab-key.pem -o ConnectTimeout=10 ubuntu@$JUMP_IP "echo 'Jump box accessible'"

# Test Kali connectivity
KALI_IP=$(terraform output -raw kali_attacker_public_ip)
ssh -i ../soc-lab-key.pem -o ConnectTimeout=10 kali@$KALI_IP "echo 'Kali box accessible'"
```

### Verify AWS Resources

```bash
# List created instances
aws ec2 describe-instances \
  --filters "Name=tag:Project,Values=AWS-SOC-Lab" \
  --query 'Reservations[*].Instances[*].[InstanceId,InstanceType,State.Name,PublicIpAddress,PrivateIpAddress,Tags[?Key==`Name`].Value|[0]]' \
  --output table

# Check VPC
aws ec2 describe-vpcs \
  --filters "Name=tag:Project,Values=AWS-SOC-Lab" \
  --query 'Vpcs[*].[VpcId,CidrBlock,State,Tags[?Key==`Name`].Value|[0]]' \
  --output table

# Verify security groups
aws ec2 describe-security-groups \
  --filters "Name=tag:Project,Values=AWS-SOC-Lab" \
  --query 'SecurityGroups[*].[GroupId,GroupName,Description]' \
  --output table
```

## Step 7: Wait for User Data Scripts

### Understanding User Data Execution

Each instance runs initialization scripts that:
- **Wazuh Server:** Installs Docker, deploys Wazuh stack
- **Linux Endpoint:** Installs Wazuh agent, vulnerable apps
- **Windows Endpoint:** Installs Wazuh agent, configures logging
- **Kali Attacker:** Installs security tools and custom scripts
- **Jump Box:** Configures SSH tunneling and management tools

### Monitor Script Execution

```bash
# Check user data script logs (via Session Manager)
JUMP_IP=$(terraform output -raw jump_box_public_ip)

# SSH to jump box and check logs
ssh -i ../soc-lab-key.pem ubuntu@$JUMP_IP

# On jump box, check cloud-init logs
sudo tail -f /var/log/cloud-init-output.log

# Check specific service status
sudo systemctl status docker
docker ps  # Should show Wazuh containers after ~10 minutes
```

### Typical Initialization Timeline

```
Minute 0-2:   Instances boot and start user data scripts
Minute 2-5:   Package updates and basic software installation
Minute 5-8:   Docker installation and Wazuh deployment begins
Minute 8-12:  Wazuh containers starting, agents installing
Minute 12-15: Final configuration and service verification
Minute 15+:   All services should be operational
```

## Step 8: Access Verification

### Test Wazuh Dashboard

```bash
# Get Wazuh information
WAZUH_URL=$(terraform output -raw wazuh_dashboard_url)
WAZUH_PASSWORD=$(terraform output -raw wazuh_admin_password)

echo "Wazuh Dashboard: $WAZUH_URL"
echo "Username: admin"
echo "Password: $WAZUH_PASSWORD"

# Test dashboard accessibility
curl -k -I "$WAZUH_URL" --connect-timeout 10
```

**Expected Response:**
```
HTTP/2 200
server: nginx
content-type: text/html
```

### Test SSH Access

```bash
# Connect to jump box
JUMP_IP=$(terraform output -raw jump_box_public_ip)
ssh -i ../soc-lab-key.pem ubuntu@$JUMP_IP

# From jump box, connect to private instances
# (Copy your private key to jump box first)
scp -i ../soc-lab-key.pem ../soc-lab-key.pem ubuntu@$JUMP_IP:~/.ssh/
ssh ubuntu@$JUMP_IP

# On jump box:
chmod 600 ~/.ssh/soc-lab-key.pem
ssh -i ~/.ssh/soc-lab-key.pem ubuntu@10.0.3.100  # Wazuh server
```

## Step 9: Troubleshooting Common Issues

### Deployment Failures

**Issue:** "InvalidKeyPair.NotFound"
**Solution:**
```bash
# Verify key pair exists
aws ec2 describe-key-pairs --key-names soc-lab-key

# Create if missing
aws ec2 create-key-pair --key-name soc-lab-key --query 'KeyMaterial' --output text > soc-lab-key.pem
chmod 600 soc-lab-key.pem
```

**Issue:** "UnauthorizedOperation" 
**Solution:**
```bash
# Check AWS credentials and permissions
aws sts get-caller-identity
aws iam get-user

# Verify IAM permissions include EC2, VPC, IAM access
```

**Issue:** Resource limit exceeded
**Solution:**
```bash
# Check service limits
aws service-quotas get-service-quota --service-code ec2 --quota-code L-1216C47A  # Running On-Demand instances

# Request limit increase if needed
aws service-quotas request-service-quota-increase --service-code ec2 --quota-code L-1216C47A --desired-value 20
```

### Network Connectivity Issues

**Issue:** Cannot access instances
**Solution:**
1. **Check Security Groups:**
   ```bash
   aws ec2 describe-security-groups --group-ids sg-xxxxxxxxx
   ```

2. **Verify Public IP:**
   ```bash
   curl https://ipinfo.io/ip
   # Update terraform.tfvars with current IP
   ```

3. **Check Instance Status:**
   ```bash
   aws ec2 describe-instance-status --instance-ids i-xxxxxxxxx
   ```

### Service Startup Issues

**Issue:** Wazuh dashboard not accessible
**Solution:**
```bash
# SSH to Wazuh server via jump box
# Check Docker services
docker-compose -f /opt/wazuh/docker-compose.yml ps

# Check logs
docker-compose -f /opt/wazuh/docker-compose.yml logs wazuh-manager

# Restart if needed
docker-compose -f /opt/wazuh/docker-compose.yml restart
```

## Step 10: Save Deployment Information

### Create Deployment Summary

```bash
# Save all outputs to file
terraform output > ../deployment-outputs.txt

# Create quick reference
cat > ../deployment-summary.txt << EOF
AWS SOC Lab Deployment Summary
==============================
Deployment Date: $(date)
Region: $(terraform output -raw aws_region || echo 'us-east-1')

Access Information:
------------------
Wazuh Dashboard: $(terraform output -raw wazuh_dashboard_url)
Username: admin
Password: $(terraform output -raw wazuh_admin_password)

SSH Access:
-----------
Jump Box: ssh -i soc-lab-key.pem ubuntu@$(terraform output -raw jump_box_public_ip)
Kali Box: ssh -i soc-lab-key.pem kali@$(terraform output -raw kali_attacker_public_ip)

Private IPs:
------------
Wazuh Server: $(terraform output -raw wazuh_server_private_ip)
Linux Endpoint: $(terraform output -raw linux_endpoint_private_ip || echo 'N/A')
Windows Endpoint: $(terraform output -raw windows_endpoint_private_ip || echo 'N/A')

Estimated Monthly Cost: ~$119 USD

To destroy: cd terraform && terraform destroy
EOF

echo "Deployment summary saved to deployment-summary.txt"
```

### Backup Terraform State

```bash
# Create backup of terraform state
cp terraform.tfstate terraform.tfstate.backup.$(date +%Y%m%d_%H%M%S)

# Consider storing state in S3 for team environments
# (Advanced topic - see Terraform remote state documentation)
```

## Next Steps

With infrastructure deployed successfully:

1. **✅ Infrastructure Ready**
2. **→ Next:** [Wazuh SIEM Deployment](03-wazuh-deployment.md)
3. **Then:** [Endpoint Configuration](04-endpoint-configuration.md)
4. **Finally:** [Attack Scenarios](../attack-scenarios/)

## Cost Management

### Monitor Spending

```bash
# Set up billing alert
aws cloudwatch put-metric-alarm \
  --alarm-name "SOC-Lab-Cost-Alert" \
  --alarm-description "SOC Lab monthly cost alert" \
  --metric-name EstimatedCharges \
  --namespace AWS/Billing \
  --statistic Maximum \
  --period 86400 \
  --threshold 150 \
  --comparison-operator GreaterThanThreshold \
  --dimensions Name=Currency,Value=USD
```

### Auto-Shutdown (Optional)

```bash
# Create auto-shutdown script (runs on jump box)
ssh -i ../soc-lab-key.pem ubuntu@$JUMP_IP

# On jump box:
sudo crontab -e
# Add: 0 18 * * * /usr/local/bin/aws ec2 stop-instances --instance-ids i-xxx i-yyy
```

## Infrastructure Cleanup

When you're done with the lab:

```bash
# Destroy all resources
terraform destroy

# Confirm with: yes
# This will remove all AWS resources and stop billing
```

---

**🎉 Congratulations!** Your AWS infrastructure is now deployed and ready for SOC operations. Continue to the next guide to configure Wazuh SIEM.