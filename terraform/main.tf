terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.1"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# VPC for qavpn infrastructure
resource "aws_vpc" "qavpn_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "qavpn-vpc"
    Environment = var.environment
    Project     = "qavpn"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "qavpn_igw" {
  vpc_id = aws_vpc.qavpn_vpc.id

  tags = {
    Name        = "qavpn-igw"
    Environment = var.environment
    Project     = "qavpn"
  }
}

# Public subnets for load balancer
resource "aws_subnet" "public_subnets" {
  count             = length(var.availability_zones)
  vpc_id            = aws_vpc.qavpn_vpc.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone = var.availability_zones[count.index]

  map_public_ip_on_launch = true

  tags = {
    Name        = "qavpn-public-subnet-${count.index + 1}"
    Environment = var.environment
    Project     = "qavpn"
    Type        = "public"
  }
}

# Private subnets for application servers
resource "aws_subnet" "private_subnets" {
  count             = length(var.availability_zones)
  vpc_id            = aws_vpc.qavpn_vpc.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 10)
  availability_zone = var.availability_zones[count.index]

  tags = {
    Name        = "qavpn-private-subnet-${count.index + 1}"
    Environment = var.environment
    Project     = "qavpn"
    Type        = "private"
  }
}

# NAT Gateways for private subnet internet access
resource "aws_eip" "nat_eips" {
  count  = length(var.availability_zones)
  domain = "vpc"

  tags = {
    Name        = "qavpn-nat-eip-${count.index + 1}"
    Environment = var.environment
    Project     = "qavpn"
  }
}

resource "aws_nat_gateway" "nat_gateways" {
  count         = length(var.availability_zones)
  allocation_id = aws_eip.nat_eips[count.index].id
  subnet_id     = aws_subnet.public_subnets[count.index].id

  tags = {
    Name        = "qavpn-nat-gateway-${count.index + 1}"
    Environment = var.environment
    Project     = "qavpn"
  }

  depends_on = [aws_internet_gateway.qavpn_igw]
}

# Route tables
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.qavpn_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.qavpn_igw.id
  }

  tags = {
    Name        = "qavpn-public-rt"
    Environment = var.environment
    Project     = "qavpn"
  }
}

resource "aws_route_table" "private_rt" {
  count  = length(var.availability_zones)
  vpc_id = aws_vpc.qavpn_vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat_gateways[count.index].id
  }

  tags = {
    Name        = "qavpn-private-rt-${count.index + 1}"
    Environment = var.environment
    Project     = "qavpn"
  }
}

# Route table associations
resource "aws_route_table_association" "public_rta" {
  count          = length(aws_subnet.public_subnets)
  subnet_id      = aws_subnet.public_subnets[count.index].id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table_association" "private_rta" {
  count          = length(aws_subnet.private_subnets)
  subnet_id      = aws_subnet.private_subnets[count.index].id
  route_table_id = aws_route_table.private_rt[count.index].id
}
