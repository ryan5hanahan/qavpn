# Application Load Balancer Security Group
resource "aws_security_group" "alb_sg" {
  name_prefix = "qavpn-alb-"
  vpc_id      = aws_vpc.qavpn_vpc.id

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "qavpn-alb-sg"
    Environment = var.environment
    Project     = "qavpn"
  }
}

# qavpn Application Security Group
resource "aws_security_group" "app_sg" {
  name_prefix = "qavpn-app-"
  vpc_id      = aws_vpc.qavpn_vpc.id

  ingress {
    description     = "qavpn service from ALB"
    from_port       = var.qavpn_port
    to_port         = var.qavpn_port
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  ingress {
    description = "SSH access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_ssh_cidrs
  }

  # Allow VPN traffic on various ports
  ingress {
    description = "VPN UDP traffic"
    from_port   = var.vpn_port
    to_port     = var.vpn_port
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "VPN TCP traffic"
    from_port   = var.vpn_port
    to_port     = var.vpn_port
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Health check from ALB
  ingress {
    description     = "Health check"
    from_port       = var.qavpn_port
    to_port         = var.qavpn_port
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "qavpn-app-sg"
    Environment = var.environment
    Project     = "qavpn"
  }
}

# Database Security Group (conditional)
resource "aws_security_group" "db_sg" {
  count       = var.enable_database ? 1 : 0
  name_prefix = "qavpn-db-"
  vpc_id      = aws_vpc.qavpn_vpc.id

  ingress {
    description     = "MySQL/Aurora"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.app_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "qavpn-db-sg"
    Environment = var.environment
    Project     = "qavpn"
  }
}
