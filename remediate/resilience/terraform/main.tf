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

# 1. Primary VPC & Networking (Tokyo: Multi-AZ across 1a, 1c, 1d)
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

resource "aws_subnet" "primary_public_1a" {
  provider          = aws.primary
  vpc_id            = aws_vpc.primary.id
  cidr_block        = "10.100.1.0/24"
  availability_zone = "${var.primary_region}a"

  tags = {
    Name = "${var.project_name}-primary-public-1a"
  }
}

resource "aws_subnet" "primary_public_1c" {
  provider          = aws.primary
  vpc_id            = aws_vpc.primary.id
  cidr_block        = "10.100.2.0/24"
  availability_zone = "${var.primary_region}c"

  tags = {
    Name = "${var.project_name}-primary-public-1c"
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
