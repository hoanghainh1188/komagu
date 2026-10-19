# Boilerplate 3: Multi-Region Infrastructure as Code (Terraform / OpenTofu)
# Primary Active Cluster (Tokyo) and Standby DR Cluster (Osaka)

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  alias  = "primary"
  region = var.primary_region
}

provider "aws" {
  alias  = "secondary"
  region = var.secondary_region
}

# 1. Primary VPC & Networking (Tokyo: Multi-AZ across 1a, 1c)
resource "aws_vpc" "primary" {
  provider             = aws.primary
  cidr_block           = "10.100.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "${var.project_name}-primary-vpc"
    Environment = var.environment
    Tier        = "Active-Workload"
  }
}

resource "aws_internet_gateway" "primary_igw" {
  provider = aws.primary
  vpc_id   = aws_vpc.primary.id

  tags = {
    Name        = "${var.project_name}-primary-igw"
    Environment = var.environment
  }
}

resource "aws_route_table" "primary_public_rt" {
  provider = aws.primary
  vpc_id   = aws_vpc.primary.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.primary_igw.id
  }

  tags = {
    Name = "${var.project_name}-primary-public-rt"
  }
}

resource "aws_subnet" "primary_public_1a" {
  provider                = aws.primary
  vpc_id                  = aws_vpc.primary.id
  cidr_block              = "10.100.1.0/24"
  availability_zone       = "${var.primary_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.project_name}-primary-public-1a"
  }
}

resource "aws_subnet" "primary_public_1c" {
  provider                = aws.primary
  vpc_id                  = aws_vpc.primary.id
  cidr_block              = "10.100.2.0/24"
  availability_zone       = "${var.primary_region}c"
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.project_name}-primary-public-1c"
  }
}

resource "aws_route_table_association" "primary_public_1a" {
  provider       = aws.primary
  subnet_id      = aws_subnet.primary_public_1a.id
  route_table_id = aws_route_table.primary_public_rt.id
}

resource "aws_route_table_association" "primary_public_1c" {
  provider       = aws.primary
  subnet_id      = aws_subnet.primary_public_1c.id
  route_table_id = aws_route_table.primary_public_rt.id
}

resource "aws_security_group" "primary_default_sg" {
  provider    = aws.primary
  vpc_id      = aws_vpc.primary.id
  name        = "${var.project_name}-primary-default-sg"
  description = "Default egress-only security group for primary workloads"

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-primary-default-sg"
  }
}

# 2. Secondary Standby DR VPC (Osaka: Multi-AZ across 3a, 3b)
resource "aws_vpc" "secondary" {
  provider             = aws.secondary
  cidr_block           = "10.200.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "${var.project_name}-dr-standby-vpc"
    Environment = var.environment
    Tier        = "Disaster-Recovery"
  }
}

resource "aws_subnet" "secondary_private_3a" {
  provider          = aws.secondary
  vpc_id            = aws_vpc.secondary.id
  cidr_block        = "10.200.10.0/24"
  availability_zone = "${var.secondary_region}a"

  tags = {
    Name = "${var.project_name}-secondary-private-3a"
  }
}

# 3. ECS Container Clusters
resource "aws_ecs_cluster" "primary" {
  provider = aws.primary
  name     = "${var.project_name}-${var.environment}-primary-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Role = "Active-Primary"
  }
}

resource "aws_ecs_cluster" "secondary" {
  provider = aws.secondary
  name     = "${var.project_name}-${var.environment}-standby-dr-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Role = "Standby-DR"
  }
}
