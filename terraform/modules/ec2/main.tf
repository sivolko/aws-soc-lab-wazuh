# Wazuh SIEM Server
resource "aws_instance" "wazuh_server" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_types.wazuh_server
  key_name               = var.key_name
  subnet_id              = var.private_subnet_ids[0]
  vpc_security_group_ids = [var.wazuh_security_group_id]
  iam_instance_profile   = var.wazuh_instance_profile
  
  # Enhanced monitoring
  monitoring = true
  
  # EBS optimization
  ebs_optimized = true
  
  # Root volume configuration
  root_block_device {
    volume_type           = "gp3"
    volume_size           = 50
    iops                  = 3000
    throughput            = 125
    encrypted             = true
    delete_on_termination = true
    
    tags = merge(var.tags, {
      Name = "${var.project_name}-${var.environment}-wazuh-root"
    })
  }
  
  # Additional EBS volume for data
  ebs_block_device {
    device_name           = "/dev/sdf"
    volume_type           = "gp3"
    volume_size           = 100
    iops                  = 3000
    throughput            = 125
    encrypted             = true
    delete_on_termination = false
    
    tags = merge(var.tags, {
      Name = "${var.project_name}-${var.environment}-wazuh-data"
    })
  }
  
  user_data = local.wazuh_user_data
  
  tags = merge(var.tags, {
    Name        = "${var.project_name}-${var.environment}-wazuh-server"
    Component   = "SIEM"
    Role        = "Wazuh-Manager"
    Backup      = "Daily"
    AutoShutdown = "false"  # Keep SIEM running
  })
  
  lifecycle {
    ignore_changes = [ami]
  }
}

# Jump Box (Bastion Host)
resource "aws_instance" "jump_box" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_types.jump_box
  key_name               = var.key_name
  subnet_id              = var.public_subnet_ids[0]
  vpc_security_group_ids = [var.jumpbox_security_group_id]
  
  # Associate public IP
  associate_public_ip_address = true
  
  # Enhanced monitoring
  monitoring = true
  
  root_block_device {
    volume_type           = "gp3"
    volume_size           = 20
    encrypted             = true
    delete_on_termination = true
    
    tags = merge(var.tags, {
      Name = "${var.project_name}-${var.environment}-jumpbox-root"
    })
  }
  
  user_data = local.jumpbox_user_data
  
  tags = merge(var.tags, {
    Name      = "${var.project_name}-${var.environment}-jump-box"
    Component = "Access"
    Role      = "Bastion-Host"
    AutoShutdown = "true"
  })
  
  lifecycle {
    ignore_changes = [ami]
  }
}

# Linux Endpoint
resource "aws_instance" "linux_endpoint" {
  count = var.enable_linux_endpoint ? 1 : 0
  
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_types.linux_endpoint
  key_name               = var.key_name
  subnet_id              = var.private_subnet_ids[0]
  vpc_security_group_ids = [var.endpoint_security_group_id]
  iam_instance_profile   = var.endpoint_instance_profile
  
  # Enhanced monitoring
  monitoring = true
  
  root_block_device {
    volume_type           = "gp3"
    volume_size           = 30
    encrypted             = true
    delete_on_termination = true
    
    tags = merge(var.tags, {
      Name = "${var.project_name}-${var.environment}-linux-endpoint-root"
    })
  }
  
  user_data = local.ubuntu_user_data
  
  tags = merge(var.tags, {
    Name      = "${var.project_name}-${var.environment}-linux-endpoint"
    Component = "Endpoint"
    Role      = "Monitored-Host"
    OS        = "Ubuntu"
    AutoShutdown = "true"
  })
  
  # Ensure Wazuh server is created first
  depends_on = [aws_instance.wazuh_server]
  
  lifecycle {
    ignore_changes = [ami]
  }
}

# Windows Endpoint
resource "aws_instance" "windows_endpoint" {
  count = var.enable_windows_endpoint ? 1 : 0
  
  ami                    = data.aws_ami.windows.id
  instance_type          = var.instance_types.windows_endpoint
  key_name               = var.key_name
  subnet_id              = var.private_subnet_ids[1]
  vpc_security_group_ids = [var.endpoint_security_group_id]
  iam_instance_profile   = var.endpoint_instance_profile
  
  # Enhanced monitoring
  monitoring = true
  
  root_block_device {
    volume_type           = "gp3"
    volume_size           = 50
    encrypted             = true
    delete_on_termination = true
    
    tags = merge(var.tags, {
      Name = "${var.project_name}-${var.environment}-windows-endpoint-root"
    })
  }
  
  user_data = local.windows_user_data
  
  tags = merge(var.tags, {
    Name      = "${var.project_name}-${var.environment}-windows-endpoint"
    Component = "Endpoint"
    Role      = "Monitored-Host"
    OS        = "Windows-Server-2019"
    AutoShutdown = "true"
  })
  
  # Ensure Wazuh server is created first
  depends_on = [aws_instance.wazuh_server]
  
  lifecycle {
    ignore_changes = [ami]
  }
}

# Kali Linux Attacker Box
resource "aws_instance" "kali_attacker" {
  count = var.enable_kali_attacker ? 1 : 0
  
  ami                    = data.aws_ami.kali.id
  instance_type          = var.instance_types.kali_attacker
  key_name               = var.key_name
  subnet_id              = var.public_subnet_ids[1]
  vpc_security_group_ids = [var.attacker_security_group_id]
  
  # Associate public IP
  associate_public_ip_address = true
  
  # Enhanced monitoring
  monitoring = true
  
  root_block_device {
    volume_type           = "gp3"
    volume_size           = 40
    encrypted             = true
    delete_on_termination = true
    
    tags = merge(var.tags, {
      Name = "${var.project_name}-${var.environment}-kali-root"
    })
  }
  
  user_data = local.kali_user_data
  
  tags = merge(var.tags, {
    Name         = "${var.project_name}-${var.environment}-kali-attacker"
    Component    = "RedTeam"
    Role         = "Attack-Box"
    OS           = "Kali-Linux"
    AutoShutdown = "true"
  })
  
  lifecycle {
    ignore_changes = [ami]
  }
}

# Elastic IP for Wazuh Server (for consistent dashboard access)
resource "aws_eip" "wazuh_server" {
  instance = aws_instance.wazuh_server.id
  domain   = "vpc"
  
  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-wazuh-eip"
  })
  
  depends_on = [aws_instance.wazuh_server]
}

# CloudWatch Alarms for monitoring
resource "aws_cloudwatch_metric_alarm" "wazuh_cpu" {
  alarm_name          = "${var.project_name}-${var.environment}-wazuh-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "120"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors wazuh server cpu utilization"
  alarm_actions       = []
  
  dimensions = {
    InstanceId = aws_instance.wazuh_server.id
  }
  
  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "wazuh_memory" {
  alarm_name          = "${var.project_name}-${var.environment}-wazuh-high-memory"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "MemoryUtilization"
  namespace           = "CWAgent"
  period              = "120"
  statistic           = "Average"
  threshold           = "85"
  alarm_description   = "This metric monitors wazuh server memory utilization"
  alarm_actions       = []
  
  dimensions = {
    InstanceId = aws_instance.wazuh_server.id
  }
  
  tags = var.tags
}

# Auto-shutdown schedule (Lambda function will be created separately)
resource "aws_ssm_parameter" "auto_shutdown_config" {
  name  = "/${var.project_name}/${var.environment}/auto-shutdown-config"
  type  = "String"
  value = jsonencode({
    enabled = true
    shutdown_time = "18:00"
    timezone = "UTC"
    exclude_instances = [aws_instance.wazuh_server.id]  # Don't shutdown SIEM
    include_instances = compact([
      aws_instance.jump_box.id,
      try(aws_instance.linux_endpoint[0].id, ""),
      try(aws_instance.windows_endpoint[0].id, ""),
      try(aws_instance.kali_attacker[0].id, "")
    ])
  })
  
  description = "Auto-shutdown configuration for SOC lab instances"
  
  tags = var.tags
}