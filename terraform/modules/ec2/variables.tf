variable "project_name" {
  description = "Name of the project"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "key_name" {
  description = "AWS Key Pair name"
  type        = string
}

variable "instance_types" {
  description = "EC2 instance types"
  type = object({
    wazuh_server     = string
    windows_endpoint = string
    linux_endpoint   = string
    kali_attacker    = string
    jump_box         = string
  })
}

variable "use_spot_instances" {
  description = "Use spot instances"
  type        = bool
  default     = false
}

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "public_subnet_ids" {
  description = "Public subnet IDs"
  type        = list(string)
}

variable "private_subnet_ids" {
  description = "Private subnet IDs"
  type        = list(string)
}

variable "wazuh_security_group_id" {
  description = "Security group ID for Wazuh server"
  type        = string
}

variable "endpoint_security_group_id" {
  description = "Security group ID for endpoints"
  type        = string
}

variable "attacker_security_group_id" {
  description = "Security group ID for attacker box"
  type        = string
}

variable "jumpbox_security_group_id" {
  description = "Security group ID for jump box"
  type        = string
}

variable "wazuh_instance_profile" {
  description = "IAM instance profile for Wazuh server"
  type        = string
}

variable "endpoint_instance_profile" {
  description = "IAM instance profile for endpoints"
  type        = string
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
  description = "Enable Kali attacker box"
  type        = bool
  default     = true
}

variable "wazuh_admin_password" {
  description = "Admin password for Wazuh"
  type        = string
  sensitive   = true
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}