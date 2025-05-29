# VPC Outputs
output "vpc_id" {
  description = "ID of the VPC"
  value       = module.vpc.vpc_id
}

output "vpc_cidr_block" {
  description = "CIDR block of the VPC"
  value       = module.vpc.vpc_cidr_block
}

output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = module.vpc.public_subnet_ids
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = module.vpc.private_subnet_ids
}

# Security Group Outputs
output "wazuh_security_group_id" {
  description = "ID of the Wazuh security group"
  value       = module.security_groups.wazuh_security_group_id
}

output "endpoint_security_group_id" {
  description = "ID of the endpoint security group"
  value       = module.security_groups.endpoint_security_group_id
}

# EC2 Instance Outputs
output "wazuh_server_id" {
  description = "ID of the Wazuh server instance"
  value       = module.ec2.wazuh_server_id
}

output "wazuh_server_private_ip" {
  description = "Private IP of the Wazuh server"
  value       = module.ec2.wazuh_server_private_ip
}

output "wazuh_server_public_ip" {
  description = "Public IP of the Wazuh server"
  value       = module.ec2.wazuh_server_public_ip
  sensitive   = true
}

output "wazuh_dashboard_url" {
  description = "URL for Wazuh dashboard"
  value       = "https://${module.ec2.wazuh_server_public_ip}:443"
  sensitive   = true
}

output "jump_box_id" {
  description = "ID of the jump box instance"
  value       = module.ec2.jump_box_id
}

output "jump_box_public_ip" {
  description = "Public IP of the jump box"
  value       = module.ec2.jump_box_public_ip
  sensitive   = true
}

output "linux_endpoint_id" {
  description = "ID of the Linux endpoint instance"
  value       = var.enable_linux_endpoint ? module.ec2.linux_endpoint_id : null
}

output "linux_endpoint_private_ip" {
  description = "Private IP of the Linux endpoint"
  value       = var.enable_linux_endpoint ? module.ec2.linux_endpoint_private_ip : null
}

output "windows_endpoint_id" {
  description = "ID of the Windows endpoint instance"
  value       = var.enable_windows_endpoint ? module.ec2.windows_endpoint_id : null
  sensitive   = true
}

output "windows_endpoint_private_ip" {
  description = "Private IP of the Windows endpoint"
  value       = var.enable_windows_endpoint ? module.ec2.windows_endpoint_private_ip : null
}

output "kali_attacker_id" {
  description = "ID of the Kali attacker instance"
  value       = var.enable_kali_attacker ? module.ec2.kali_attacker_id : null
}

output "kali_attacker_public_ip" {
  description = "Public IP of the Kali attacker"
  value       = var.enable_kali_attacker ? module.ec2.kali_attacker_public_ip : null
  sensitive   = true
}

# Credentials
output "wazuh_admin_password" {
  description = "Wazuh admin password"
  value       = random_password.wazuh_admin_password.result
  sensitive   = true
}

# S3 Bucket
output "logs_bucket_name" {
  description = "Name of the S3 bucket for logs"
  value       = aws_s3_bucket.soc_lab_logs.bucket
}

# Connection Information
output "ssh_connection_commands" {
  description = "SSH connection commands for instances"
  value = {
    jump_box = "ssh -i ${var.key_name}.pem ubuntu@${module.ec2.jump_box_public_ip}"
    wazuh_server = "ssh -i ${var.key_name}.pem -o ProxyJump=ubuntu@${module.ec2.jump_box_public_ip} ubuntu@${module.ec2.wazuh_server_private_ip}"
    linux_endpoint = var.enable_linux_endpoint ? "ssh -i ${var.key_name}.pem -o ProxyJump=ubuntu@${module.ec2.jump_box_public_ip} ubuntu@${module.ec2.linux_endpoint_private_ip}" : null
    kali_attacker = var.enable_kali_attacker ? "ssh -i ${var.key_name}.pem kali@${module.ec2.kali_attacker_public_ip}" : null
  }
  sensitive = true
}

# Quick Start Information
output "quick_start_info" {
  description = "Quick start information for the lab"
  value = {
    wazuh_dashboard_url = "https://${module.ec2.wazuh_server_public_ip}:443"
    wazuh_credentials = {
      username = "admin"
      password = "<use 'terraform output wazuh_admin_password' to get password>"
    }
    ssh_key_required = var.key_name
    estimated_monthly_cost = "~$99 USD"
    deployment_region = var.aws_region
  }
}