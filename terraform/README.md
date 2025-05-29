# Terraform Infrastructure

This directory contains all Infrastructure as Code (IaC) configurations for the AWS SOC Lab.

## Structure

```
terraform/
├── modules/                 # Reusable Terraform modules
│   ├── vpc/                # VPC and networking
│   ├── security-groups/    # Security group definitions
│   ├── ec2/               # EC2 instance configurations
│   └── iam/               # IAM roles and policies
├── environments/          # Environment-specific configurations
│   ├── dev/              # Development environment
│   ├── staging/          # Staging environment
│   └── prod/             # Production environment
├── main.tf               # Main Terraform configuration
├── variables.tf          # Input variables
├── outputs.tf            # Output values
├── providers.tf          # Provider configurations
└── terraform.tfvars.example  # Example variables file
```

## Quick Start

1. **Prerequisites**
   ```bash
   # Install Terraform
   terraform --version  # Ensure >= 1.0
   
   # Configure AWS credentials
   aws configure
   ```

2. **Initialize Terraform**
   ```bash
   cd terraform
   terraform init
   ```

3. **Configure Variables**
   ```bash
   cp terraform.tfvars.example terraform.tfvars
   # Edit terraform.tfvars with your values
   ```

4. **Plan and Apply**
   ```bash
   terraform plan
   terraform apply
   ```

## Cost Optimization

- Use spot instances where appropriate
- Implement auto-shutdown schedules
- Right-size instances based on usage
- Use GP3 EBS volumes for cost efficiency

## Security Considerations

- All resources tagged appropriately
- Least privilege access applied
- Encryption at rest and in transit
- VPC Flow Logs enabled
- CloudTrail logging configured

---

🏗️ **Infrastructure as Code FTW!**