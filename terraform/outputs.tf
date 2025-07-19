# VPC Outputs
output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.qavpn_vpc.id
}

output "vpc_cidr_block" {
  description = "CIDR block of the VPC"
  value       = aws_vpc.qavpn_vpc.cidr_block
}

# Subnet Outputs
output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = aws_subnet.public_subnets[*].id
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = aws_subnet.private_subnets[*].id
}

# Load Balancer Outputs
output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer"
  value       = aws_lb.qavpn_alb.dns_name
}

output "alb_zone_id" {
  description = "Zone ID of the Application Load Balancer"
  value       = aws_lb.qavpn_alb.zone_id
}

output "nlb_dns_name" {
  description = "DNS name of the Network Load Balancer"
  value       = aws_lb.qavpn_nlb.dns_name
}

output "nlb_zone_id" {
  description = "Zone ID of the Network Load Balancer"
  value       = aws_lb.qavpn_nlb.zone_id
}

# S3 Bucket Outputs
output "config_bucket_name" {
  description = "Name of the S3 bucket for configuration"
  value       = aws_s3_bucket.qavpn_config.bucket
}

output "config_bucket_arn" {
  description = "ARN of the S3 bucket for configuration"
  value       = aws_s3_bucket.qavpn_config.arn
}

# Database Outputs (conditional)
output "database_endpoint" {
  description = "RDS cluster endpoint"
  value       = var.enable_database ? aws_rds_cluster.qavpn_cluster[0].endpoint : null
}

output "database_reader_endpoint" {
  description = "RDS cluster reader endpoint"
  value       = var.enable_database ? aws_rds_cluster.qavpn_cluster[0].reader_endpoint : null
}

# Auto Scaling Group Outputs
output "asg_name" {
  description = "Name of the Auto Scaling Group"
  value       = aws_autoscaling_group.qavpn_asg.name
}

output "asg_arn" {
  description = "ARN of the Auto Scaling Group"
  value       = aws_autoscaling_group.qavpn_asg.arn
}

# Security Group Outputs
output "alb_security_group_id" {
  description = "ID of the ALB security group"
  value       = aws_security_group.alb_sg.id
}

output "app_security_group_id" {
  description = "ID of the application security group"
  value       = aws_security_group.app_sg.id
}

# Connection Information
output "qavpn_web_url" {
  description = "URL to access qavpn web interface"
  value       = var.certificate_arn != "" ? "https://${aws_lb.qavpn_alb.dns_name}" : "http://${aws_lb.qavpn_alb.dns_name}"
}

output "qavpn_vpn_endpoint" {
  description = "VPN endpoint for client connections"
  value       = aws_lb.qavpn_nlb.dns_name
}

output "qavpn_vpn_port" {
  description = "VPN port for client connections"
  value       = var.vpn_port
}
