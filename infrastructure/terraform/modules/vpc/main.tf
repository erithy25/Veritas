# ═══════════════════════════════════════════════════════════════
# Veritas VPC Module
# Multi-tier network segmentation for security isolation
# ═══════════════════════════════════════════════════════════════

variable "environment" {
  type = string
}

variable "region" {
  type = string
}

variable "cluster_name" {
  type = string
}

variable "vpc_cidr" {
  type = string
}

variable "public_subnets" {
  type = map(string)
}

variable "application_subnets" {
  type = map(string)
}

variable "gpu_subnets" {
  type = map(string)
}

variable "data_subnets" {
  type = map(string)
}

variable "security_subnets" {
  type = map(string)
}

variable "sandbox_subnets" {
  type = map(string)
}

# ─── VPC ────────────────────────────────────────────────────

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "veritas-${var.environment}-vpc"
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
  }
}

# ─── Internet Gateway ──────────────────────────────────────

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "veritas-${var.environment}-igw"
  }
}

# ─── NAT Gateways (one per AZ for HA) ─────────────────────

resource "aws_eip" "nat" {
  for_each = var.public_subnets
  domain   = "vpc"

  tags = {
    Name = "veritas-${var.environment}-nat-eip-${each.key}"
  }
}

resource "aws_nat_gateway" "main" {
  for_each      = var.public_subnets
  allocation_id = aws_eip.nat[each.key].id
  subnet_id     = aws_subnet.public[each.key].id

  tags = {
    Name = "veritas-${var.environment}-nat-${each.key}"
  }
}

# ─── Public Subnets ────────────────────────────────────────

resource "aws_subnet" "public" {
  for_each = var.public_subnets

  vpc_id                  = aws_vpc.main.id
  cidr_block              = each.value
  availability_zone       = each.key
  map_public_ip_on_launch = false  # No auto-assign public IPs

  tags = {
    Name = "veritas-${var.environment}-public-${each.key}"
    Tier = "public"
    "kubernetes.io/role/elb" = "1"
  }
}

# ─── Application Subnets (CPU workloads) ───────────────────

resource "aws_subnet" "application" {
  for_each = var.application_subnets

  vpc_id            = aws_vpc.main.id
  cidr_block        = each.value
  availability_zone = each.key

  tags = {
    Name = "veritas-${var.environment}-application-${each.key}"
    Tier = "application"
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
    "kubernetes.io/role/internal-elb" = "1"
  }
}

# ─── GPU Subnets (ML workloads) ────────────────────────────

resource "aws_subnet" "gpu" {
  for_each = var.gpu_subnets

  vpc_id            = aws_vpc.main.id
  cidr_block        = each.value
  availability_zone = each.key

  tags = {
    Name = "veritas-${var.environment}-gpu-${each.key}"
    Tier = "gpu"
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
  }
}

# ─── Data Subnets (Databases, Kafka, Redis) ────────────────

resource "aws_subnet" "data" {
  for_each = var.data_subnets

  vpc_id            = aws_vpc.main.id
  cidr_block        = each.value
  availability_zone = each.key

  tags = {
    Name = "veritas-${var.environment}-data-${each.key}"
    Tier = "data"
  }
}

# ─── Security Subnets (HSM only) ──────────────────────────

resource "aws_subnet" "security" {
  for_each = var.security_subnets

  vpc_id            = aws_vpc.main.id
  cidr_block        = each.value
  availability_zone = each.key

  tags = {
    Name = "veritas-${var.environment}-security-${each.key}"
    Tier = "security"
  }
}

# ─── Sandbox Subnets (Isolated, no production access) ──────

resource "aws_subnet" "sandbox" {
  for_each = var.sandbox_subnets

  vpc_id            = aws_vpc.main.id
  cidr_block        = each.value
  availability_zone = each.key

  tags = {
    Name = "veritas-${var.environment}-sandbox-${each.key}"
    Tier = "sandbox"
  }
}

# ─── Route Tables ──────────────────────────────────────────

# Public route table (routes to IGW)
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "veritas-${var.environment}-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  for_each       = var.public_subnets
  subnet_id      = aws_subnet.public[each.key].id
  route_table_id = aws_route_table.public.id
}

# Private route tables (one per AZ, routes to NAT)
resource "aws_route_table" "private" {
  for_each = var.public_subnets
  vpc_id   = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main[each.key].id
  }

  tags = {
    Name = "veritas-${var.environment}-private-rt-${each.key}"
  }
}

# Associate private subnets with route tables
resource "aws_route_table_association" "application" {
  for_each       = var.application_subnets
  subnet_id      = aws_subnet.application[each.key].id
  route_table_id = aws_route_table.private[each.key].id
}

resource "aws_route_table_association" "gpu" {
  for_each       = var.gpu_subnets
  subnet_id      = aws_subnet.gpu[each.key].id
  route_table_id = aws_route_table.private[each.key].id
}

resource "aws_route_table_association" "data" {
  for_each       = var.data_subnets
  subnet_id      = aws_subnet.data[each.key].id
  route_table_id = aws_route_table.private[each.key].id
}

# Sandbox: Isolated route table (NO internet access)
resource "aws_route_table" "sandbox" {
  vpc_id = aws_vpc.main.id
  # No routes to internet or NAT - completely isolated

  tags = {
    Name = "veritas-${var.environment}-sandbox-rt"
  }
}

resource "aws_route_table_association" "sandbox" {
  for_each       = var.sandbox_subnets
  subnet_id      = aws_subnet.sandbox[each.key].id
  route_table_id = aws_route_table.sandbox.id
}

# ─── VPC Flow Logs ─────────────────────────────────────────

resource "aws_flow_log" "main" {
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow_log.arn
  log_destination = aws_cloudwatch_log_group.flow_log.arn
}

resource "aws_cloudwatch_log_group" "flow_log" {
  name              = "/veritas/${var.environment}/vpc-flow-logs"
  retention_in_days = 90
}

resource "aws_iam_role" "flow_log" {
  name = "veritas-${var.environment}-flow-log-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "vpc-flow-logs.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy" "flow_log" {
  name = "veritas-${var.environment}-flow-log-policy"
  role = aws_iam_role.flow_log.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Effect   = "Allow"
      Resource = "*"
    }]
  })
}

# ─── Outputs ───────────────────────────────────────────────

output "vpc_id" {
  value = aws_vpc.main.id
}

output "public_subnet_ids" {
  value = [for s in aws_subnet.public : s.id]
}

output "application_subnet_ids" {
  value = [for s in aws_subnet.application : s.id]
}

output "gpu_subnet_ids" {
  value = [for s in aws_subnet.gpu : s.id]
}

output "data_subnet_ids" {
  value = [for s in aws_subnet.data : s.id]
}

output "security_subnet_ids" {
  value = [for s in aws_subnet.security : s.id]
}

output "sandbox_subnet_ids" {
  value = [for s in aws_subnet.sandbox : s.id]
}
