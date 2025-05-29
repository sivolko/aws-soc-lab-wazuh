# AWS SOC Lab Deployment Guide

## Prerequisites

Before deploying the AWS SOC Lab, ensure you have:

1. **AWS Account** with appropriate permissions
2. **AWS CLI** installed and configured
3. **Terraform** >= 1.0 installed
4. **SSH Key Pair** created in your AWS region
5. **Git** for cloning the repository

## Step-by-Step Deployment

### 1. Clone the Repository

```bash
git clone https://github.com/sivolko/aws-soc-lab-wazuh.git
cd aws-soc-lab-wazuh
```

### 2. Configure AWS Credentials

```bash
# Option 1: Using AWS CLI
aws configure

# Option 2: Using environment variables
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-east-1"
```

### 3. Create SSH Key Pair (if not exists)

```bash
# Create key pair in AWS
aws ec2 create-key-pair --key-name soc-lab-key --query 'KeyMaterial' --output text > soc-lab-key.pem
chmod 600 soc-lab-key.pem
```

### 4. Configure Terraform Variables

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` with your values:

```hcl
# Required: Replace with your AWS key pair name
key_name = "soc-lab-key"

# Security: Replace with your public IP
allowed_cidr_blocks = ["YOUR_PUBLIC_IP/32"]

# Optional: Customize other settings
aws_region = "us-east-1"
project_name = "aws-soc-lab"
environment = "dev"
```

**⚠️ Important Security Note:**
Replace `YOUR_PUBLIC_IP` with your actual public IP address. Find it using:
```bash
curl https://ipinfo.io/ip
```

### 5. Initialize and Deploy Terraform

```bash
# Initialize Terraform
terraform init

# Review the deployment plan
terraform plan

# Deploy the infrastructure
terraform apply
```

Type `yes` when prompted to confirm the deployment.

### 6. Get Deployment Information

After successful deployment:

```bash
# Get all outputs
terraform output

# Get specific information
terraform output wazuh_dashboard_url
terraform output -raw wazuh_admin_password
terraform output ssh_connection_commands
```

### 7. Access Your Lab

#### Wazuh Dashboard
```
URL: https://WAZUH_PUBLIC_IP:443
Username: admin
Password: [from terraform output]
```

#### SSH Access
```bash
# Connect to jump box
ssh -i soc-lab-key.pem ubuntu@JUMP_BOX_PUBLIC_IP

# From jump box, connect to private instances
ssh ubuntu@WAZUH_PRIVATE_IP
ssh ubuntu@LINUX_ENDPOINT_PRIVATE_IP
```

#### Kali Linux
```bash
# SSH access
ssh -i soc-lab-key.pem kali@KALI_PUBLIC_IP

# VNC access (GUI)
vncviewer KALI_PUBLIC_IP:5901
```

## Post-Deployment Steps

### 1. Verify Wazuh Installation

```bash
# SSH to Wazuh server
ssh -i soc-lab-key.pem -o ProxyJump=ubuntu@JUMP_BOX_IP ubuntu@WAZUH_PRIVATE_IP

# Check Wazuh services
cd /opt/wazuh
docker-compose ps

# Check agent connections
docker-compose exec wazuh-manager /var/ossec/bin/agent_control -lc
```

### 2. Test Vulnerable Applications

**Linux Endpoint:**
```
- DVWA: http://LINUX_PRIVATE_IP:8080
- WebGoat: http://LINUX_PRIVATE_IP:8081/goatandwolf
- OWASP Juice Shop: http://LINUX_PRIVATE_IP:8082
```

**Windows Endpoint:**
```
- Vulnerable PHP app: http://WINDOWS_PRIVATE_IP/vulnerable-app/
- XAMPP: http://WINDOWS_PRIVATE_IP/
```

### 3. Generate Test Events

**Linux:**
```bash
# SSH to Linux endpoint
./generate-test-logs.sh
```

**Windows:**
```powershell
# RDP to Windows endpoint
# Test events are generated automatically via scheduled task
```

## Cost Management

### Estimated Monthly Costs
- **Wazuh Server (t3.large):** ~$60
- **Other instances:** ~$39
- **Storage & Data transfer:** ~$10
- **Total:** ~$109/month

### Cost Optimization Tips

1. **Use Spot Instances:**
   ```hcl
   use_spot_instances = true
   ```

2. **Auto-shutdown instances:**
   ```bash
   # Use provided scripts
   ./scripts/maintenance/auto-shutdown.sh
   ```

3. **Destroy when not needed:**
   ```bash
   terraform destroy
   ```

## Troubleshooting

### Common Issues

1. **Terraform deployment fails:**
   - Check AWS credentials and permissions
   - Verify key pair exists in the specified region
   - Ensure unique S3 bucket names

2. **Can't access Wazuh dashboard:**
   - Wait 5-10 minutes for initial setup
   - Check security group allows your IP
   - Verify instance is running

3. **Agents not connecting:**
   - Check security group rules (ports 1514-1516)
   - Verify agent configuration on endpoints
   - Check network connectivity

### Getting Help

1. **Check logs:**
   ```bash
   # Wazuh logs
   docker-compose logs wazuh-manager
   
   # System logs
   sudo journalctl -u wazuh
   ```

2. **Run health checks:**
   ```bash
   ./health-check.sh
   ```

3. **Create GitHub issue** with:
   - Error messages
   - Terraform version
   - AWS region
   - Deployment logs

## Security Considerations

1. **Network Security:**
   - Restrict `allowed_cidr_blocks` to your IP
   - Use jump box for private instance access
   - Enable VPC Flow Logs

2. **Access Control:**
   - Rotate SSH keys regularly
   - Use IAM roles instead of access keys
   - Enable MFA on AWS account

3. **Monitoring:**
   - Monitor AWS CloudTrail logs
   - Set up billing alerts
   - Review security group changes

## Next Steps

After successful deployment:

1. **Explore Wazuh:** Create custom rules and dashboards
2. **Practice attacks:** Use Kali Linux for penetration testing
3. **Learn detection:** Analyze generated alerts and logs
4. **Customize:** Add your own vulnerable applications
5. **Contribute:** Share improvements via GitHub

---

🎯 **Happy Hacking!** Your SOC Lab is ready for cybersecurity training!

For detailed guides and attack scenarios, check the `docs/` directory.