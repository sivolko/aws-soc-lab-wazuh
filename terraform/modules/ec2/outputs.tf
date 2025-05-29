# Wazuh Server Outputs
output "wazuh_server_id" {
  description = "ID of the Wazuh server instance"
  value       = aws_instance.wazuh_server.id
}

output "wazuh_server_private_ip" {
  description = "Private IP address of the Wazuh server"
  value       = aws_instance.wazuh_server.private_ip
}

output "wazuh_server_public_ip" {
  description = "Public IP address of the Wazuh server"
  value       = aws_eip.wazuh_server.public_ip
}

output "wazuh_server_private_dns" {
  description = "Private DNS name of the Wazuh server"
  value       = aws_instance.wazuh_server.private_dns
}

# Jump Box Outputs
output "jump_box_id" {
  description = "ID of the jump box instance"
  value       = aws_instance.jump_box.id
}

output "jump_box_public_ip" {
  description = "Public IP address of the jump box"
  value       = aws_instance.jump_box.public_ip
}

output "jump_box_private_ip" {
  description = "Private IP address of the jump box"
  value       = aws_instance.jump_box.private_ip
}

# Linux Endpoint Outputs
output "linux_endpoint_id" {
  description = "ID of the Linux endpoint instance"
  value       = var.enable_linux_endpoint ? aws_instance.linux_endpoint[0].id : null
}

output "linux_endpoint_private_ip" {
  description = "Private IP address of the Linux endpoint"
  value       = var.enable_linux_endpoint ? aws_instance.linux_endpoint[0].private_ip : null
}

output "linux_endpoint_private_dns" {
  description = "Private DNS name of the Linux endpoint"
  value       = var.enable_linux_endpoint ? aws_instance.linux_endpoint[0].private_dns : null
}

# Windows Endpoint Outputs
output "windows_endpoint_id" {
  description = "ID of the Windows endpoint instance"
  value       = var.enable_windows_endpoint ? aws_instance.windows_endpoint[0].id : null
}

output "windows_endpoint_private_ip" {
  description = "Private IP address of the Windows endpoint"
  value       = var.enable_windows_endpoint ? aws_instance.windows_endpoint[0].private_ip : null
}

output "windows_endpoint_private_dns" {
  description = "Private DNS name of the Windows endpoint"
  value       = var.enable_windows_endpoint ? aws_instance.windows_endpoint[0].private_dns : null
}

# Kali Attacker Outputs
output "kali_attacker_id" {
  description = "ID of the Kali attacker instance"
  value       = var.enable_kali_attacker ? aws_instance.kali_attacker[0].id : null
}

output "kali_attacker_public_ip" {
  description = "Public IP address of the Kali attacker"
  value       = var.enable_kali_attacker ? aws_instance.kali_attacker[0].public_ip : null
}

output "kali_attacker_private_ip" {
  description = "Private IP address of the Kali attacker"
  value       = var.enable_kali_attacker ? aws_instance.kali_attacker[0].private_ip : null
}

# All Instance IDs for management
output "all_instance_ids" {
  description = "List of all instance IDs"
  value = compact([
    aws_instance.wazuh_server.id,
    aws_instance.jump_box.id,
    var.enable_linux_endpoint ? aws_instance.linux_endpoint[0].id : "",
    var.enable_windows_endpoint ? aws_instance.windows_endpoint[0].id : "",
    var.enable_kali_attacker ? aws_instance.kali_attacker[0].id : ""
  ])
}

# Private IPs for internal communication
output "private_ips" {
  description = "Map of instance names to private IPs"
  value = {
    wazuh_server    = aws_instance.wazuh_server.private_ip
    jump_box        = aws_instance.jump_box.private_ip
    linux_endpoint  = var.enable_linux_endpoint ? aws_instance.linux_endpoint[0].private_ip : null
    windows_endpoint = var.enable_windows_endpoint ? aws_instance.windows_endpoint[0].private_ip : null
    kali_attacker   = var.enable_kali_attacker ? aws_instance.kali_attacker[0].private_ip : null
  }
}

# Public IPs for external access
output "public_ips" {
  description = "Map of instance names to public IPs"
  value = {
    wazuh_server  = aws_eip.wazuh_server.public_ip
    jump_box      = aws_instance.jump_box.public_ip
    kali_attacker = var.enable_kali_attacker ? aws_instance.kali_attacker[0].public_ip : null
  }
}