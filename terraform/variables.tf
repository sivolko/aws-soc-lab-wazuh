# AWS Region
variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

# Environment
variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
}

# Project name
variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "aws-soc-lab"
}

# VPC Configuration
variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.0.3.0/24", "10.0.4.0/24"]
}

# Instance Configuration
variable "instance_types" {
  description = "EC2 instance types for different components"
  type = object({
    wazuh_server    = string
    windows_endpoint = string
    linux_endpoint   = string
    kali_attacker   = string
    jump_box        = string
  })
  default = {
    wazuh_server    = "t3.large"
    windows_endpoint = "t3.micro"
    linux_endpoint   = "t3.micro"
    kali_attacker   = "t3.small"
    jump_box        = "t3.micro"
  }
}

# Key Pair
variable "key_name" {
  description = "AWS Key Pair name for EC2 access"
  type        = string
}

# Allowed IP for SSH access
variable "allowed_cidr_blocks" {
  description = "CIDR blocks allowed for SSH access"
  type        = list(string)
  default     = ["0.0.0.0/0"]  # Restrict this in production
}

# Wazuh Configuration
variable "wazuh_version" {
  description = "Wazuh version to deploy"
  type        = string
  default     = "4.7.3"
}

# Enable/Disable Components
variable "enable_vulnerable_apps" {
  description = "Enable vulnerable applications for testing"
  type        = bool
  default     = true
}

variable "enable_windows_endpoint" {
  description = "Enable Windows endpoint"
  type        = bool
  default     = true
}

variable "enable_linux_endpoint" {
  description = "Enable Linux endpoint"
  type        = bool
  default     = true
}

variable "enable_kali_attacker" {
  description = "Enable Kali Linux attacker box"
  type        = bool
  default     = true
}

# Monitoring and Logging
variable "enable_vpc_flow_logs" {
  description = "Enable VPC Flow Logs"
  type        = bool
  default     = true
}

variable "enable_cloudtrail" {
  description = "Enable CloudTrail logging"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "Log retention period in days"
  type        = number
  default     = 30
}

# Cost Optimization
variable "use_spot_instances" {
  description = "Use spot instances where possible"
  type        = bool
  default     = false
}

variable "auto_shutdown_time" {
  description = "Time to auto-shutdown instances (24h format, e.g., '18:00')"
  type        = string
  default     = "18:00"
}

# Tags
variable "common_tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default = {
    Project     = "AWS-SOC-Lab"
    Environment = "Development"
    Owner       = "Security-Team"
    Purpose     = "Security-Training"
  }
}