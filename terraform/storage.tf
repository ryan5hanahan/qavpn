# Random ID for unique bucket naming
resource "random_id" "bucket_suffix" {
  byte_length = 4
}

# S3 Bucket for qavpn configuration and logs
resource "aws_s3_bucket" "qavpn_config" {
  bucket = "qavpn-config-${random_id.bucket_suffix.hex}"

  tags = {
    Name        = "qavpn-config"
    Environment = var.environment
    Project     = "qavpn"
  }
}

resource "aws_s3_bucket_versioning" "qavpn_config_versioning" {
  bucket = aws_s3_bucket.qavpn_config.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "qavpn_config_encryption" {
  bucket = aws_s3_bucket.qavpn_config.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "qavpn_config_pab" {
  bucket = aws_s3_bucket.qavpn_config.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Database subnet group (conditional)
resource "aws_db_subnet_group" "qavpn_db_subnet_group" {
  count      = var.enable_database ? 1 : 0
  name       = "qavpn-db-subnet-group"
  subnet_ids = aws_subnet.private_subnets[*].id

  tags = {
    Name        = "qavpn-db-subnet-group"
    Environment = var.environment
    Project     = "qavpn"
  }
}

# RDS Aurora Cluster (conditional)
resource "aws_rds_cluster" "qavpn_cluster" {
  count                       = var.enable_database ? 1 : 0
  cluster_identifier          = "qavpn-cluster"
  engine                     = "aurora-mysql"
  engine_version             = "8.0.mysql_aurora.3.02.0"
  availability_zones         = var.availability_zones
  database_name              = "qavpn"
  master_username            = "admin"
  manage_master_user_password = true
  db_subnet_group_name       = aws_db_subnet_group.qavpn_db_subnet_group[0].name
  vpc_security_group_ids     = [aws_security_group.db_sg[0].id]

  backup_retention_period      = var.backup_retention_days
  preferred_backup_window      = "07:00-09:00"
  preferred_maintenance_window = "sun:09:00-sun:10:00"

  storage_encrypted   = true
  skip_final_snapshot = true

  tags = {
    Name        = "qavpn-cluster"
    Environment = var.environment
    Project     = "qavpn"
  }
}

# RDS Aurora Instances (conditional)
resource "aws_rds_cluster_instance" "qavpn_cluster_instances" {
  count              = var.enable_database ? 2 : 0
  identifier         = "qavpn-${count.index}"
  cluster_identifier = aws_rds_cluster.qavpn_cluster[0].id
  instance_class     = var.db_instance_class
  engine             = aws_rds_cluster.qavpn_cluster[0].engine
  engine_version     = aws_rds_cluster.qavpn_cluster[0].engine_version

  performance_insights_enabled = true
  monitoring_interval         = 60
  monitoring_role_arn        = aws_iam_role.rds_enhanced_monitoring[0].arn

  tags = {
    Name        = "qavpn-db-${count.index}"
    Environment = var.environment
    Project     = "qavpn"
  }
}
