# IAM Role for Wazuh Server
resource "aws_iam_role" "wazuh_server" {
  name = "${var.project_name}-${var.environment}-wazuh-server-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-wazuh-server-role"
    Purpose = "Wazuh Server IAM Role"
  })
}

# IAM Policy for Wazuh Server
resource "aws_iam_role_policy" "wazuh_server" {
  name = "${var.project_name}-${var.environment}-wazuh-server-policy"
  role = aws_iam_role.wazuh_server.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams",
          "logs:DescribeLogGroups"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::${var.project_name}-*",
          "arn:aws:s3:::${var.project_name}-*/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath",
          "ssm:PutParameter"
        ]
        Resource = "arn:aws:ssm:*:*:parameter/${var.project_name}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:CreateSecret",
          "secretsmanager:UpdateSecret"
        ]
        Resource = "arn:aws:secretsmanager:*:*:secret:${var.project_name}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceStatus",
          "ec2:DescribeTags"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData",
          "cloudwatch:GetMetricStatistics",
          "cloudwatch:ListMetrics"
        ]
        Resource = "*"
      }
    ]
  })
}

# Attach AWS managed policies to Wazuh server role
resource "aws_iam_role_policy_attachment" "wazuh_ssm" {
  role       = aws_iam_role.wazuh_server.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "wazuh_cloudwatch" {
  role       = aws_iam_role.wazuh_server.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# Instance Profile for Wazuh Server
resource "aws_iam_instance_profile" "wazuh_server" {
  name = "${var.project_name}-${var.environment}-wazuh-server-profile"
  role = aws_iam_role.wazuh_server.name

  tags = var.tags
}

# IAM Role for Endpoints
resource "aws_iam_role" "endpoint" {
  name = "${var.project_name}-${var.environment}-endpoint-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-endpoint-role"
    Purpose = "Endpoint IAM Role"
  })
}

# IAM Policy for Endpoints
resource "aws_iam_role_policy" "endpoint" {
  name = "${var.project_name}-${var.environment}-endpoint-policy"
  role = aws_iam_role.endpoint.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParameterHistory"
        ]
        Resource = "arn:aws:ssm:*:*:parameter/${var.project_name}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = "arn:aws:secretsmanager:*:*:secret:${var.project_name}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
      }
    ]
  })
}

# Attach AWS managed policies to endpoint role
resource "aws_iam_role_policy_attachment" "endpoint_ssm" {
  role       = aws_iam_role.endpoint.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "endpoint_cloudwatch" {
  role       = aws_iam_role.endpoint.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# Instance Profile for Endpoints
resource "aws_iam_instance_profile" "endpoint" {
  name = "${var.project_name}-${var.environment}-endpoint-profile"
  role = aws_iam_role.endpoint.name

  tags = var.tags
}

# IAM Role for Attacker Box
resource "aws_iam_role" "attacker" {
  name = "${var.project_name}-${var.environment}-attacker-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-attacker-role"
    Purpose = "Attacker Box IAM Role"
  })
}

# Minimal IAM Policy for Attacker Box (security best practice)
resource "aws_iam_role_policy" "attacker" {
  name = "${var.project_name}-${var.environment}-attacker-policy"
  role = aws_iam_role.attacker.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# Instance Profile for Attacker Box
resource "aws_iam_instance_profile" "attacker" {
  name = "${var.project_name}-${var.environment}-attacker-profile"
  role = aws_iam_role.attacker.name

  tags = var.tags
}

# Service-Linked Role for EC2 Spot Instances (if using spot)
data "aws_iam_role" "spot_fleet_role" {
  name = "aws-ec2-spot-fleet-tagging-role"
}

# Create the spot fleet service role if it doesn't exist
resource "aws_iam_role" "spot_fleet_role" {
  count = var.use_spot_instances ? 1 : 0
  name  = "aws-ec2-spot-fleet-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "spotfleet.amazonaws.com"
        }
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "spot_fleet_policy" {
  count      = var.use_spot_instances ? 1 : 0
  role       = aws_iam_role.spot_fleet_role[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2SpotFleetTaggingRole"
}