# Boilerplate 3: Multi-Region Infrastructure & Immutable Backup Variables

variable "primary_region" {
  description = "Primary AWS region for active container workloads"
  type        = string
  default     = "ap-northeast-1" # Tokyo
}

variable "secondary_region" {
  description = "Secondary AWS region for immutable WORM backups and standby DR cluster"
  type        = string
  default     = "ap-northeast-3" # Osaka
}

variable "project_name" {
  description = "Project and workload prefix"
  type        = string
  default     = "komagu"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "production"
}

variable "worm_retention_days" {
  description = "Retention period for WORM immutable backups in Compliance Mode (cannot be deleted even by root)"
  type        = number
  default     = 365
}

variable "enable_cross_region_replication" {
  description = "Replicate primary state snapshots to secondary WORM bucket"
  type        = bool
  default     = true
}
