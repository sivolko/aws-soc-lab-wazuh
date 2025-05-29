# Security Group for Wazuh SIEM Server
resource "aws_security_group" "wazuh" {
  name_prefix = "${var.project_name}-${var.environment}-wazuh-"
  description = "Security group for Wazuh SIEM server"
  vpc_id      = var.vpc_id

  # SSH access from jump box
  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.jumpbox.id]
    description     = "SSH from jump box"
  }

  # Wazuh Dashboard (HTTPS)
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
    description = "Wazuh Dashboard HTTPS"
  }

  # Wazuh Manager API
  ingress {
    from_port   = 55000
    to_port     = 55000
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "Wazuh Manager API"
  }

  # Wazuh Agent Registration and Communication
  ingress {
    from_port   = 1514
    to_port     = 1514
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "Wazuh Agent Registration"
  }

  ingress {
    from_port   = 1515
    to_port     = 1515
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "Wazuh Agent Communication"
  }

  # Wazuh Cluster Communication
  ingress {
    from_port   = 1516
    to_port     = 1516
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "Wazuh Cluster Communication"
  }

  # Elasticsearch Communication
  ingress {
    from_port   = 9200
    to_port     = 9200
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "Elasticsearch API"
  }

  ingress {
    from_port   = 9300
    to_port     = 9300
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "Elasticsearch Node Communication"
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-wazuh-sg"
    Purpose = "Wazuh SIEM Server"
  })
}

# Security Group for Endpoints (Windows/Linux)
resource "aws_security_group" "endpoint" {
  name_prefix = "${var.project_name}-${var.environment}-endpoint-"
  description = "Security group for monitored endpoints"
  vpc_id      = var.vpc_id

  # SSH access from jump box (Linux)
  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.jumpbox.id]
    description     = "SSH from jump box"
  }

  # RDP access from jump box (Windows)
  ingress {
    from_port       = 3389
    to_port         = 3389
    protocol        = "tcp"
    security_groups = [aws_security_group.jumpbox.id]
    description     = "RDP from jump box"
  }

  # WinRM for Windows management
  ingress {
    from_port       = 5985
    to_port         = 5986
    protocol        = "tcp"
    security_groups = [aws_security_group.jumpbox.id]
    description     = "WinRM from jump box"
  }

  # HTTP/HTTPS for vulnerable web apps
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "HTTP for web applications"
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "HTTPS for web applications"
  }

  # Custom application ports
  ingress {
    from_port   = 8000
    to_port     = 8999
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "Custom application ports"
  }

  # ICMP for ping
  ingress {
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = [var.vpc_cidr]
    description = "ICMP ping"
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-endpoint-sg"
    Purpose = "Monitored Endpoints"
  })
}

# Security Group for Kali Attacker Box
resource "aws_security_group" "attacker" {
  name_prefix = "${var.project_name}-${var.environment}-attacker-"
  description = "Security group for Kali Linux attacker box"
  vpc_id      = var.vpc_id

  # SSH access
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
    description = "SSH access"
  }

  # VNC for GUI access
  ingress {
    from_port   = 5900
    to_port     = 5999
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
    description = "VNC GUI access"
  }

  # Web interface for tools
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
    description = "Web interface for tools"
  }

  # Allow all outbound traffic (needed for attack tools)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-attacker-sg"
    Purpose = "Kali Linux Attacker Box"
  })
}

# Security Group for Jump Box (Bastion Host)
resource "aws_security_group" "jumpbox" {
  name_prefix = "${var.project_name}-${var.environment}-jumpbox-"
  description = "Security group for jump box (bastion host)"
  vpc_id      = var.vpc_id

  # SSH access from allowed IPs
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
    description = "SSH access from allowed IPs"
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-jumpbox-sg"
    Purpose = "Jump Box (Bastion Host)"
  })
}

# Security Group for Load Balancer (future use)
resource "aws_security_group" "alb" {
  name_prefix = "${var.project_name}-${var.environment}-alb-"
  description = "Security group for Application Load Balancer"
  vpc_id      = var.vpc_id

  # HTTP
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP from internet"
  }

  # HTTPS
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS from internet"
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-alb-sg"
    Purpose = "Application Load Balancer"
  })
}