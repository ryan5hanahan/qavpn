# QAVPN Terraform AWS Infrastructure

This Terraform configuration deploys a highly available, scalable QAVPN infrastructure on AWS.

## Architecture Overview

The infrastructure includes:

- **VPC with Multi-AZ deployment** across 3 availability zones
- **Application Load Balancer** for HTTP/HTTPS management traffic
- **Network Load Balancer** for VPN UDP/TCP traffic
- **Auto Scaling Group** with configurable scaling policies
- **S3 bucket** for configuration storage with encryption
- **CloudWatch monitoring** and alerting
- **Optional RDS Aurora cluster** for user management
- **Security groups** with least privilege access

## Prerequisites

1. **AWS CLI configured** with appropriate credentials
2. **Terraform >= 1.0** installed
3. **EC2 Key Pair** created (optional, for SSH access)
4. **ACM Certificate** (optional, for HTTPS)

## Quick Start

1. **Clone and navigate to terraform directory:**
   ```bash
   cd terraform
   ```

2. **Copy and customize variables:**
   ```bash
   cp terraform.tfvars.example terraform.tfvars
   # Edit terraform.tfvars with your specific values
   ```

3. **Initialize Terraform:**
   ```bash
   terraform init
   ```

4. **Plan deployment:**
   ```bash
   terraform plan
   ```

5. **Deploy infrastructure:**
   ```bash
   terraform apply
   ```

## Configuration Variables

### Required Variables
- `aws_region`: AWS region for deployment
- `environment`: Environment name (dev/staging/prod)

### Network Configuration
- `vpc_cidr`: CIDR block for VPC (default: 10.0.0.0/16)
- `availability_zones`: List of AZs to deploy across

### Compute Configuration
- `instance_type`: EC2 instance type (default: t3.medium)
- `min_size`: Minimum ASG instances (default: 2)
- `max_size`: Maximum ASG instances (default: 10)
- `desired_capacity`: Desired ASG instances (default: 3)

### Security Configuration
- `key_pair_name`: EC2 Key Pair for SSH access (optional)
- `allowed_ssh_cidrs`: CIDR blocks allowed SSH access
- `certificate_arn`: ACM certificate ARN for HTTPS (optional)

### Service Configuration
- `qavpn_port`: Port for qavpn service (default: 8080)
- `vpn_port`: Port for VPN traffic (default: 1194)

### Optional Features
- `enable_database`: Enable RDS Aurora cluster (default: false)
- `enable_monitoring`: Enable detailed monitoring (default: true)
- `backup_retention_days`: Backup retention period (default: 30)

## Outputs

After deployment, Terraform provides:

- **qavpn_web_url**: Web interface URL
- **qavpn_vpn_endpoint**: VPN endpoint for clients
- **alb_dns_name**: Application Load Balancer DNS
- **nlb_dns_name**: Network Load Balancer DNS
- **config_bucket_name**: S3 configuration bucket

## Security Features

### Network Security
- Private subnets for application instances
- Security groups with minimal required access
- NAT Gateways for outbound internet access
- Encrypted EBS volumes

### Data Security
- S3 bucket encryption at rest
- RDS encryption (when enabled)
- IAM roles with least privilege
- VPC flow logs (optional)

### Monitoring
- CloudWatch metrics and alarms
- Auto-scaling based on CPU utilization
- Application and infrastructure logs
- Health checks for load balancers

## Cost Optimization

### Default Configuration Costs (us-west-2)
- **EC2 instances**: ~$95/month (3 x t3.medium)
- **Load Balancers**: ~$25/month (ALB + NLB)
- **NAT Gateways**: ~$135/month (3 x NAT Gateway)
- **Storage**: ~$10/month (EBS + S3)
- **Data Transfer**: Variable based on usage

### Cost Reduction Options
1. **Single AZ deployment**: Reduce NAT Gateway costs
2. **Smaller instances**: Use t3.small for lower traffic
3. **Reserved Instances**: 1-year commitment for 40% savings
4. **Spot Instances**: Configure ASG with spot instances

## Deployment Environments

### Development
```hcl
environment = "dev"
instance_type = "t3.small"
min_size = 1
max_size = 3
desired_capacity = 1
enable_database = false
```

### Production
```hcl
environment = "prod"
instance_type = "t3.medium"
min_size = 2
max_size = 10
desired_capacity = 3
enable_database = true
enable_monitoring = true
```

## Maintenance

### Updates
```bash
# Update infrastructure
terraform plan
terraform apply

# Update application
# Instances will automatically pull latest code on restart
```

### Scaling
```bash
# Manual scaling
aws autoscaling set-desired-capacity \
  --auto-scaling-group-name qavpn-asg \
  --desired-capacity 5
```

### Monitoring
- CloudWatch Dashboard: AWS Console → CloudWatch
- Application Logs: CloudWatch Logs → /aws/ec2/qavpn
- Metrics: Custom namespace QAVPN/EC2

## Troubleshooting

### Common Issues

1. **Certificate not found**
   - Ensure ACM certificate exists in the same region
   - Certificate must be validated

2. **SSH access denied**
   - Check security group rules
   - Verify key pair name and allowed CIDRs

3. **Health check failures**
   - Verify qavpn service is running on instances
   - Check security group allows health check traffic

4. **High costs**
   - Review NAT Gateway usage
   - Consider single AZ for dev environments
   - Monitor data transfer costs

### Debugging Commands
```bash
# Check Terraform state
terraform show

# Validate configuration
terraform validate

# Check AWS resources
aws ec2 describe-instances --filters "Name=tag:Project,Values=qavpn"
aws elbv2 describe-load-balancers --names qavpn-alb qavpn-nlb
```

## Cleanup

To destroy the infrastructure:

```bash
terraform destroy
```

**Warning**: This will permanently delete all resources including data in S3 and RDS (if enabled).

## Support

For issues related to:
- **Terraform configuration**: Check this README and Terraform docs
- **QAVPN application**: See main project documentation
- **AWS services**: Consult AWS documentation

## Security Considerations

1. **Secrets Management**: Use AWS Secrets Manager for sensitive data
2. **Network Access**: Restrict SSH access to known IP ranges
3. **Monitoring**: Enable CloudTrail for API logging
4. **Updates**: Regularly update AMIs and application code
5. **Backup**: Enable automated backups for critical data
