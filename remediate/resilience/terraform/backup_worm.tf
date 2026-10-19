# Boilerplate 3: WORM Immutable Backup Storage (AWS S3 Object Lock Compliance Mode)
# Immune to Ransomware, Mass Deletion, and Root Credential Compromise

data "aws_caller_identity" "current" {}

# 1. KMS CMK in Secondary Region (Osaka) with Strict Role Separation
resource "aws_kms_key" "worm_backup_key" {
  provider                = aws.secondary
  description             = "KMS Key for Komainu WORM Immutable Backups in Osaka"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootKeyAdministration"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowBackupWriterKeyUsage"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.replication_role[0].arn
        }
        Action = [
          "kms:Encrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyDirectKeyDeletionProtectionNote"
        Effect = "Deny"
        Principal = "*"
        Action = [
          "kms:ScheduleKeyDeletion",
          "kms:DisableKey"
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "aws:PrincipalArn" = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/KomainuSecurityOfficer"
          }
        }
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-worm-backup-key"
    Compliance  = "WORM-Immutable"
    Environment = var.environment
  }
}

# 2. S3 Access Logging Bucket (Osaka)
resource "aws_s3_bucket" "worm_access_logs" {
  provider = aws.secondary
  bucket   = "${var.project_name}-${var.environment}-worm-logs-${var.secondary_region}"

  tags = {
    Name        = "Komainu WORM Access Logs"
    Environment = var.environment
  }
}

resource "aws_s3_bucket_public_access_block" "logs_public_block" {
  provider = aws.secondary
  bucket   = aws_s3_bucket.worm_access_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# 3. Immutable WORM Storage Bucket (Secondary Region: Osaka)
resource "aws_s3_bucket" "immutable_worm_backup" {
  provider = aws.secondary
  bucket   = "${var.project_name}-${var.environment}-worm-backup-${var.secondary_region}"

  # Object Lock MUST be enabled at creation time
  object_lock_enabled = true

  tags = {
    Name        = "Komainu Immutable WORM Backup"
    Compliance  = "S3-Object-Lock-Compliance"
    Environment = var.environment
  }
}

# 4. Explicit Bucket Versioning (Required by Object Lock and Replication)
resource "aws_s3_bucket_versioning" "worm_versioning" {
  provider = aws.secondary
  bucket   = aws_s3_bucket.immutable_worm_backup.id

  versioning_configuration {
    status = "Enabled"
  }
}

# 5. Bucket Access Logging
resource "aws_s3_bucket_logging" "worm_logging" {
  provider = aws.secondary
  bucket   = aws_s3_bucket.immutable_worm_backup.id

  target_bucket = aws_s3_bucket.worm_access_logs.id
  target_prefix = "worm-access-logs/"
}

# 6. Enforce Strict Compliance Mode (WORM)
resource "aws_s3_bucket_object_lock_configuration" "compliance_lock" {
  provider = aws.secondary
  bucket   = aws_s3_bucket.immutable_worm_backup.id

  rule {
    default_retention {
      mode = "COMPLIANCE" # COMPLIANCE mode cannot be overwritten, altered, or bypassed even by AWS root account
      days = var.worm_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.worm_versioning]
}

# 7. Enforce KMS Server-Side Encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "worm_encryption" {
  provider = aws.secondary
  bucket   = aws_s3_bucket.immutable_worm_backup.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.worm_backup_key.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# 8. Block All Public Access
resource "aws_s3_bucket_public_access_block" "worm_public_block" {
  provider = aws.secondary
  bucket   = aws_s3_bucket.immutable_worm_backup.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# 9. S3 Bucket Policy: Enforce HTTPS & Encrypted Transport
resource "aws_s3_bucket_policy" "deny_destructive_actions" {
  provider = aws.secondary
  bucket   = aws_s3_bucket.immutable_worm_backup.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceSSLRequestsOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.immutable_worm_backup.arn,
          "${aws_s3_bucket.immutable_worm_backup.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid       = "DenyUnencryptedObjectUploads"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.immutable_worm_backup.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      }
    ]
  })
}

# 10. Cross-Region Replication Infrastructure (Primary Tokyo -> Secondary Osaka)
resource "aws_s3_bucket" "primary_backup" {
  count    = var.enable_cross_region_replication ? 1 : 0
  provider = aws.primary
  bucket   = "${var.project_name}-${var.environment}-primary-state-${var.primary_region}"

  tags = {
    Name        = "Komainu Primary Active State"
    Environment = var.environment
  }
}

resource "aws_s3_bucket_versioning" "primary_versioning" {
  count    = var.enable_cross_region_replication ? 1 : 0
  provider = aws.primary
  bucket   = aws_s3_bucket.primary_backup[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_iam_role" "replication_role" {
  count = var.enable_cross_region_replication ? 1 : 0
  name  = "${var.project_name}-s3-crr-replication-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_policy" "replication_policy" {
  count = var.enable_cross_region_replication ? 1 : 0
  name  = "${var.project_name}-s3-crr-replication-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:GetReplicationConfiguration",
          "s3:ListBucket"
        ]
        Effect   = "Allow"
        Resource = aws_s3_bucket.primary_backup[0].arn
      },
      {
        Action = [
          "s3:GetObjectVersionForReplication",
          "s3:GetObjectVersionAcl",
          "s3:GetObjectVersionTagging"
        ]
        Effect   = "Allow"
        Resource = "${aws_s3_bucket.primary_backup[0].arn}/*"
      },
      {
        Action = [
          "s3:ReplicateObject",
          "s3:ReplicateDelete",
          "s3:ReplicateTags"
        ]
        Effect   = "Allow"
        Resource = "${aws_s3_bucket.immutable_worm_backup.arn}/*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "replication_attachment" {
  count      = var.enable_cross_region_replication ? 1 : 0
  role       = aws_iam_role.replication_role[0].name
  policy_arn = aws_iam_policy.replication_policy[0].arn
}

resource "aws_s3_bucket_replication_configuration" "crr" {
  count      = var.enable_cross_region_replication ? 1 : 0
  provider   = aws.primary
  role       = aws_iam_role.replication_role[0].arn
  bucket     = aws_s3_bucket.primary_backup[0].id

  rule {
    id     = "ReplicateToOsakaWORM"
    status = "Enabled"

    destination {
      bucket        = aws_s3_bucket.immutable_worm_backup.arn
      storage_class = "STANDARD"
    }
  }

  depends_on = [
    aws_s3_bucket_versioning.primary_versioning,
    aws_s3_bucket_versioning.worm_versioning
  ]
}
