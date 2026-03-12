# ═══════════════════════════════════════════════════════════════
# Veritas B2B - Production Environment
# Primary Region: eu-central-1 (Frankfurt)
# ═══════════════════════════════════════════════════════════════

terraform {
  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.27"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.12"
    }
  }

  backend "s3" {
    bucket         = "veritas-terraform-state"
    key            = "production/eu-central-1/terraform.tfstate"
    region         = "eu-central-1"
    encrypt        = true
    dynamodb_table = "veritas-terraform-lock"
  }
}

# ─── Provider Configuration ─────────────────────────────────

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Environment = "production"
      Project     = "veritas-b2b"
      ManagedBy   = "terraform"
      Team        = "platform"
    }
  }
}

# ─── Variables ──────────────────────────────────────────────

variable "aws_region" {
  description = "AWS region for primary deployment"
  type        = string
  default     = "eu-central-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "cluster_name" {
  description = "EKS cluster name"
  type        = string
  default     = "veritas-production"
}

# ─── VPC Module ─────────────────────────────────────────────

module "vpc" {
  source = "../../modules/vpc"

  environment    = var.environment
  region         = var.aws_region
  cluster_name   = var.cluster_name

  vpc_cidr       = "10.10.0.0/16"

  public_subnets = {
    "eu-central-1a" = "10.10.0.0/20"
    "eu-central-1b" = "10.10.16.0/20"
  }

  application_subnets = {
    "eu-central-1a" = "10.10.32.0/20"
    "eu-central-1b" = "10.10.48.0/20"
  }

  gpu_subnets = {
    "eu-central-1a" = "10.10.64.0/20"
    "eu-central-1b" = "10.10.80.0/20"
  }

  data_subnets = {
    "eu-central-1a" = "10.10.96.0/20"
    "eu-central-1b" = "10.10.112.0/20"
  }

  security_subnets = {
    "eu-central-1a" = "10.10.128.0/24"
    "eu-central-1b" = "10.10.129.0/24"
  }

  sandbox_subnets = {
    "eu-central-1a" = "10.10.192.0/20"
    "eu-central-1b" = "10.10.208.0/20"
  }
}

# ─── EKS Cluster ────────────────────────────────────────────

module "eks" {
  source = "../../modules/eks"

  environment  = var.environment
  cluster_name = var.cluster_name
  vpc_id       = module.vpc.vpc_id

  application_subnet_ids = module.vpc.application_subnet_ids
  gpu_subnet_ids         = module.vpc.gpu_subnet_ids

  # CPU Node Groups
  cpu_node_groups = {
    gateway = {
      instance_types = ["c7g.2xlarge"]
      min_size       = 2
      max_size       = 20
      desired_size   = 4
      labels = {
        "veritas.security/role" = "gateway"
      }
    }
    application = {
      instance_types = ["c7g.4xlarge"]
      min_size       = 4
      max_size       = 40
      desired_size   = 8
      labels = {
        "veritas.security/role" = "application"
      }
    }
  }

  # GPU Node Groups
  gpu_node_groups = {
    l2_biometric = {
      instance_types = ["g5.2xlarge"]
      min_size       = 2
      max_size       = 16
      desired_size   = 4
      gpu_type       = "nvidia-t4"
      labels = {
        "veritas.security/role" = "l2-biometric"
        "nvidia.com/gpu"        = "true"
      }
      taints = [{
        key    = "nvidia.com/gpu"
        value  = "true"
        effect = "NO_SCHEDULE"
      }]
    }
    l3_inference = {
      instance_types = ["p4d.24xlarge"]
      min_size       = 2
      max_size       = 32
      desired_size   = 4
      gpu_type       = "nvidia-a100"
      labels = {
        "veritas.security/role" = "l3-inference"
        "nvidia.com/gpu"        = "true"
      }
      taints = [{
        key    = "nvidia.com/gpu"
        value  = "true"
        effect = "NO_SCHEDULE"
      }]
    }
  }

  # Cluster addons
  enable_istio            = true
  enable_prometheus       = true
  enable_gpu_operator     = true
  enable_cluster_autoscaler = true
}

# ─── Kafka (MSK) ───────────────────────────────────────────

module "kafka" {
  source = "../../modules/kafka"

  environment     = var.environment
  cluster_name    = "${var.cluster_name}-kafka"
  vpc_id          = module.vpc.vpc_id
  subnet_ids      = module.vpc.data_subnet_ids

  broker_count       = 6
  broker_instance_type = "kafka.m5.4xlarge"
  broker_ebs_size_gb = 1000

  kafka_version      = "3.6.0"
  encryption_at_rest = true
  encryption_in_transit = "TLS"

  # Topic auto-creation disabled (managed via application)
  auto_create_topics = false
}

# ─── Redis (ElastiCache) ───────────────────────────────────

module "redis" {
  source = "../../modules/redis"

  environment    = var.environment
  cluster_name   = "${var.cluster_name}-redis"
  vpc_id         = module.vpc.vpc_id
  subnet_ids     = module.vpc.data_subnet_ids

  node_type      = "cache.r7g.2xlarge"
  num_node_groups = 6
  replicas_per_group = 1

  encryption_at_rest  = true
  encryption_in_transit = true
  auth_token_enabled  = true
}

# ─── PostgreSQL (RDS) ──────────────────────────────────────

module "postgresql" {
  source = "../../modules/postgresql"

  environment    = var.environment
  identifier     = "${var.cluster_name}-postgres"
  vpc_id         = module.vpc.vpc_id
  subnet_ids     = module.vpc.data_subnet_ids

  instance_class   = "db.r7g.2xlarge"
  engine_version   = "16.2"
  storage_gb       = 1000
  storage_type     = "gp3"
  multi_az         = true

  # TimescaleDB extension
  parameter_group_params = {
    "shared_preload_libraries" = "timescaledb"
  }

  backup_retention_days   = 35
  deletion_protection     = true
  performance_insights    = true
}

# ─── ClickHouse ────────────────────────────────────────────

module "clickhouse" {
  source = "../../modules/clickhouse"

  environment    = var.environment
  vpc_id         = module.vpc.vpc_id
  subnet_ids     = module.vpc.data_subnet_ids

  instance_type  = "i4i.4xlarge"
  cluster_size   = 3
  replication_factor = 2
}

# ─── CloudHSM ──────────────────────────────────────────────

module "hsm" {
  source = "../../modules/hsm"

  environment    = var.environment
  vpc_id         = module.vpc.vpc_id
  subnet_ids     = module.vpc.security_subnet_ids

  hsm_count      = 2  # HA pair
}

# ─── S3 Buckets ────────────────────────────────────────────

module "s3" {
  source = "../../modules/s3"

  environment = var.environment

  buckets = {
    models = {
      name       = "veritas-${var.environment}-models"
      versioning = true
      lifecycle_rules = []
    }
    audit_logs = {
      name       = "veritas-${var.environment}-audit"
      versioning = true
      lifecycle_rules = [
        {
          id                     = "archive-to-glacier"
          transition_days        = 365
          transition_storage_class = "GLACIER_DEEP_ARCHIVE"
          expiration_days        = 3650  # 10 years
        }
      ]
    }
    reports = {
      name       = "veritas-${var.environment}-reports"
      versioning = true
      lifecycle_rules = []
    }
  }

  # All buckets encrypted with customer-managed KMS key
  kms_key_arn = module.kms.key_arn
}

# ─── Monitoring ────────────────────────────────────────────

module "monitoring" {
  source = "../../modules/monitoring"

  environment    = var.environment
  cluster_name   = var.cluster_name
  vpc_id         = module.vpc.vpc_id

  enable_managed_prometheus = true
  enable_managed_grafana    = true

  alert_endpoints = {
    pagerduty_critical = var.pagerduty_critical_endpoint
    pagerduty_high     = var.pagerduty_high_endpoint
    slack_alerts       = var.slack_alerts_webhook
    slack_monitoring    = var.slack_monitoring_webhook
  }
}

# ─── Outputs ───────────────────────────────────────────────

output "vpc_id" {
  value = module.vpc.vpc_id
}

output "eks_cluster_endpoint" {
  value = module.eks.cluster_endpoint
}

output "kafka_bootstrap_brokers" {
  value     = module.kafka.bootstrap_brokers_tls
  sensitive = true
}

output "redis_endpoint" {
  value     = module.redis.primary_endpoint
  sensitive = true
}

output "postgresql_endpoint" {
  value     = module.postgresql.endpoint
  sensitive = true
}

output "hsm_cluster_id" {
  value = module.hsm.cluster_id
}
