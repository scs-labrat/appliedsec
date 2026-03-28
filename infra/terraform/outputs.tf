# =============================================================================
# Outputs — displayed after deploy and used by CI/CD
# =============================================================================

output "dashboard_url" {
  description = "URL to access the ALUSKORT dashboard"
  value       = var.domain_name != "" ? "https://${var.domain_name}" : "http://${module.alb.dns_name}"
}

output "alb_dns_name" {
  description = "ALB DNS name (use for CNAME if custom domain)"
  value       = module.alb.dns_name
}

output "ecr_repositories" {
  description = "ECR repository URLs for CI/CD image push"
  value       = module.ecr.repository_urls
}

output "rds_endpoint" {
  description = "RDS PostgreSQL endpoint"
  value       = module.rds.endpoint
  sensitive   = true
}

output "redis_endpoint" {
  description = "ElastiCache Redis endpoint"
  value       = module.elasticache.endpoint
  sensitive   = true
}

output "kafka_brokers" {
  description = "MSK bootstrap broker string"
  value       = module.msk.bootstrap_brokers
  sensitive   = true
}

output "ecs_cluster" {
  description = "ECS cluster name"
  value       = module.ecs.cluster_name
}

output "vpc_id" {
  description = "VPC ID"
  value       = module.vpc.vpc_id
}

output "account_id" {
  description = "AWS account ID"
  value       = local.account_id
}
