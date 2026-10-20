# Boilerplate 3: Outputs

output "primary_vpc_id" {
  description = "Primary Tokyo VPC ID"
  value       = aws_vpc.primary.id
}

output "secondary_vpc_id" {
  description = "Standby Osaka DR VPC ID"
  value       = aws_vpc.secondary.id
}

output "primary_ecs_cluster_name" {
  description = "Active ECS Cluster Name in Tokyo"
  value       = aws_ecs_cluster.primary.name
}

output "secondary_ecs_cluster_name" {
  description = "Standby DR ECS Cluster Name in Osaka"
  value       = aws_ecs_cluster.secondary.name
}

output "immutable_worm_bucket_arn" {
  description = "ARN of S3 Object Lock Compliance WORM bucket in Osaka"
  value       = aws_s3_bucket.immutable_worm_backup.arn
}

output "immutable_worm_bucket_name" {
  description = "Name of S3 Object Lock Compliance WORM bucket in Osaka"
  value       = aws_s3_bucket.immutable_worm_backup.id
}

output "backup_writer_role_arn" {
  description = "ARN of IAM role authorized to write WORM backups"
  value       = aws_iam_role.backup_writer.arn
}

output "backup_restore_role_arn" {
  description = "ARN of IAM role authorized to restore from WORM backups"
  value       = aws_iam_role.backup_restore.arn
}

output "security_officer_role_arn" {
  description = "ARN of Security Officer IAM role authorized for KMS key administration"
  value       = aws_iam_role.security_officer.arn
}

output "worm_access_logs_bucket_arn" {
  description = "ARN of S3 bucket storing WORM access logs"
  value       = aws_s3_bucket.worm_access_logs.arn
}

