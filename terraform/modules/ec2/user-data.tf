# User data for Wazuh server
locals {
  wazuh_user_data = base64encode(templatefile("${path.module}/user-data/wazuh-server.sh", {
    wazuh_password = var.wazuh_admin_password
    region         = data.aws_region.current.name
    project_name   = var.project_name
    environment    = var.environment
  }))
  
  ubuntu_user_data = base64encode(templatefile("${path.module}/user-data/ubuntu-endpoint.sh", {
    wazuh_server_ip = aws_instance.wazuh_server.private_ip
    region          = data.aws_region.current.name
    project_name    = var.project_name
    environment     = var.environment
  }))
  
  windows_user_data = base64encode(templatefile("${path.module}/user-data/windows-endpoint.ps1", {
    wazuh_server_ip = aws_instance.wazuh_server.private_ip
    region          = data.aws_region.current.name
    project_name    = var.project_name
    environment     = var.environment
  }))
  
  kali_user_data = base64encode(templatefile("${path.module}/user-data/kali-setup.sh", {
    region       = data.aws_region.current.name
    project_name = var.project_name
    environment  = var.environment
  }))
  
  jumpbox_user_data = base64encode(templatefile("${path.module}/user-data/jumpbox-setup.sh", {
    region       = data.aws_region.current.name
    project_name = var.project_name
    environment  = var.environment
  }))
}