# Application Load Balancer
resource "aws_lb" "qavpn_alb" {
  name               = "qavpn-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = aws_subnet.public_subnets[*].id

  enable_deletion_protection = false

  tags = {
    Name        = "qavpn-alb"
    Environment = var.environment
    Project     = "qavpn"
  }
}

# Target Group for HTTP/HTTPS traffic
resource "aws_lb_target_group" "qavpn_tg" {
  name     = "qavpn-tg"
  port     = var.qavpn_port
  protocol = "HTTP"
  vpc_id   = aws_vpc.qavpn_vpc.id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    matcher             = "200"
    path                = "/health"
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    unhealthy_threshold = 2
  }

  tags = {
    Name        = "qavpn-tg"
    Environment = var.environment
    Project     = "qavpn"
  }
}

# ALB Listener (HTTP) - Redirect to HTTPS
resource "aws_lb_listener" "qavpn_http" {
  load_balancer_arn = aws_lb.qavpn_alb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# ALB Listener (HTTPS) - Conditional on certificate
resource "aws_lb_listener" "qavpn_https" {
  count             = var.certificate_arn != "" ? 1 : 0
  load_balancer_arn = aws_lb.qavpn_alb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.qavpn_tg.arn
  }
}

# ALB Listener (HTTP) - Direct forward when no certificate
resource "aws_lb_listener" "qavpn_http_direct" {
  count             = var.certificate_arn == "" ? 1 : 0
  load_balancer_arn = aws_lb.qavpn_alb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.qavpn_tg.arn
  }
}

# Network Load Balancer for VPN traffic
resource "aws_lb" "qavpn_nlb" {
  name               = "qavpn-nlb"
  internal           = false
  load_balancer_type = "network"
  subnets            = aws_subnet.public_subnets[*].id

  enable_deletion_protection = false

  tags = {
    Name        = "qavpn-nlb"
    Environment = var.environment
    Project     = "qavpn"
  }
}

# NLB Target Group for VPN UDP traffic
resource "aws_lb_target_group" "qavpn_vpn_udp_tg" {
  name     = "qavpn-vpn-udp-tg"
  port     = var.vpn_port
  protocol = "UDP"
  vpc_id   = aws_vpc.qavpn_vpc.id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    port                = var.qavpn_port
    protocol            = "HTTP"
    path                = "/health"
    timeout             = 6
    unhealthy_threshold = 2
  }

  tags = {
    Name        = "qavpn-vpn-udp-tg"
    Environment = var.environment
    Project     = "qavpn"
  }
}

# NLB Target Group for VPN TCP traffic
resource "aws_lb_target_group" "qavpn_vpn_tcp_tg" {
  name     = "qavpn-vpn-tcp-tg"
  port     = var.vpn_port
  protocol = "TCP"
  vpc_id   = aws_vpc.qavpn_vpc.id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    port                = var.qavpn_port
    protocol            = "HTTP"
    path                = "/health"
    timeout             = 6
    unhealthy_threshold = 2
  }

  tags = {
    Name        = "qavpn-vpn-tcp-tg"
    Environment = var.environment
    Project     = "qavpn"
  }
}

# NLB Listeners
resource "aws_lb_listener" "qavpn_vpn_udp" {
  load_balancer_arn = aws_lb.qavpn_nlb.arn
  port              = var.vpn_port
  protocol          = "UDP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.qavpn_vpn_udp_tg.arn
  }
}

resource "aws_lb_listener" "qavpn_vpn_tcp" {
  load_balancer_arn = aws_lb.qavpn_nlb.arn
  port              = var.vpn_port
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.qavpn_vpn_tcp_tg.arn
  }
}
