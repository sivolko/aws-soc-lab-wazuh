# Data sources
data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

# Random password for Wazuh admin
resource "random_password" "wazuh_admin_password" {
  length  = 16
  special = true
}

# Random password for database
resource "random_password" "database_password" {
  length  = 16
  special = true
}

# VPC Module
module "vpc" {
  source = "./modules/vpc"
  
  project_name             = var.project_name
  environment             = var.environment
  vpc_cidr                = var.vpc_cidr
  public_subnet_cidrs     = var.public_subnet_cidrs
  private_subnet_cidrs    = var.private_subnet_cidrs
  availability_zones      = data.aws_availability_zones.available.names
  enable_vpc_flow_logs    = var.enable_vpc_flow_logs
  log_retention_days      = var.log_retention_days
  
  tags = var.common_tags
}

# Security Groups Module
module "security_groups" {
  source = "./modules/security-groups"
  
  project_name        = var.project_name
  environment         = var.environment
  vpc_id              = module.vpc.vpc_id
  vpc_cidr            = var.vpc_cidr
  allowed_cidr_blocks = var.allowed_cidr_blocks
  
  tags = var.common_tags
}

# IAM Roles Module
module "iam" {
  source = "./modules/iam"
  
  project_name = var.project_name
  environment  = var.environment
  
  tags = var.common_tags
}

# EC2 Instances Module
module "ec2" {
  source = "./modules/ec2"
  
  project_name              = var.project_name
  environment              = var.environment
  key_name                 = var.key_name
  instance_types           = var.instance_types
  use_spot_instances       = var.use_spot_instances
  
  # Network configuration
  vpc_id                   = module.vpc.vpc_id
  public_subnet_ids        = module.vpc.public_subnet_ids
  private_subnet_ids       = module.vpc.private_subnet_ids
  
  # Security groups
  wazuh_security_group_id     = module.security_groups.wazuh_security_group_id
  endpoint_security_group_id  = module.security_groups.endpoint_security_group_id
  attacker_security_group_id  = module.security_groups.attacker_security_group_id
  jumpbox_security_group_id   = module.security_groups.jumpbox_security_group_id
  
  # IAM roles
  wazuh_instance_profile    = module.iam.wazuh_instance_profile
  endpoint_instance_profile = module.iam.endpoint_instance_profile
  
  # Component toggles
  enable_windows_endpoint = var.enable_windows_endpoint
  enable_linux_endpoint   = var.enable_linux_endpoint
  enable_kali_attacker    = var.enable_kali_attacker
  
  # Passwords
  wazuh_admin_password = random_password.wazuh_admin_password.result
  
  tags = var.common_tags
}

# S3 Bucket for logs and backups
resource "aws_s3_bucket" "soc_lab_logs" {
  bucket = "${var.project_name}-${var.environment}-logs-${random_password.database_password.id}"
}

resource "aws_s3_bucket_versioning" "soc_lab_logs_versioning" {
  bucket = aws_s3_bucket.soc_lab_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_encryption" "soc_lab_logs_encryption" {
  bucket = aws_s3_bucket.soc_lab_logs.id
  
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "soc_lab_logs_pab" {
  bucket = aws_s3_bucket.soc_lab_logs.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# CloudTrail (if enabled)
resource "aws_cloudtrail" "security_trail" {
  count                        = var.enable_cloudtrail ? 1 : 0
  name                        = "${var.project_name}-${var.environment}-trail"
  s3_bucket_name              = aws_s3_bucket.soc_lab_logs.bucket
  s3_key_prefix               = "cloudtrail"
  include_global_service_events = true
  is_multi_region_trail       = true
  enable_logging              = true
  
  event_selector {
    read_write_type                 = "All"
    include_management_events       = true
    exclude_management_event_sources = []
    
    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.soc_lab_logs.arn}/*"]
    }
  }
  
  depends_on = [aws_s3_bucket_policy.cloudtrail_bucket_policy]
}

# S3 bucket policy for CloudTrail
resource "aws_s3_bucket_policy" "cloudtrail_bucket_policy" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.soc_lab_logs.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.soc_lab_logs.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.soc_lab_logs.arn}/cloudtrail/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}