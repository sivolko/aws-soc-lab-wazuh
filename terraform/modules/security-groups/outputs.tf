output "wazuh_security_group_id" {
  description = "ID of the Wazuh security group"
  value       = aws_security_group.wazuh.id
}

output "endpoint_security_group_id" {
  description = "ID of the endpoint security group"
  value       = aws_security_group.endpoint.id
}

output "attacker_security_group_id" {
  description = "ID of the attacker security group"
  value       = aws_security_group.attacker.id
}

output "jumpbox_security_group_id" {
  description = "ID of the jump box security group"
  value       = aws_security_group.jumpbox.id
}

output "alb_security_group_id" {
  description = "ID of the ALB security group"
  value       = aws_security_group.alb.id
}