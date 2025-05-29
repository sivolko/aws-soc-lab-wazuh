output "wazuh_instance_profile" {
  description = "Instance profile for Wazuh server"
  value       = aws_iam_instance_profile.wazuh_server.name
}

output "endpoint_instance_profile" {
  description = "Instance profile for endpoints"
  value       = aws_iam_instance_profile.endpoint.name
}

output "attacker_instance_profile" {
  description = "Instance profile for attacker box"
  value       = aws_iam_instance_profile.attacker.name
}

output "wazuh_role_arn" {
  description = "ARN of the Wazuh server role"
  value       = aws_iam_role.wazuh_server.arn
}

output "endpoint_role_arn" {
  description = "ARN of the endpoint role"
  value       = aws_iam_role.endpoint.arn
}

output "attacker_role_arn" {
  description = "ARN of the attacker role"
  value       = aws_iam_role.attacker.arn
}