# Boilerplate 3: WORM Immutable Backup Storage (AWS S3 Object Lock Compliance Mode)
# Immune to Ransomware, Mass Deletion, and Root Credential Compromise

# 1. KMS CMK in Secondary Region (Osaka)
resource "aws_kms_key" "worm_backup_key" {
  provider                = aws.secondary
  description             = "KMS Key for Komainu WORM Immutable Backups in Osaka"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name        = "${var.project_name}-worm-backup-key"
    Compliance  = "WORM-Immutable"
    Environment = var.environment
  }
}

# 2. Immutable WORM Storage Bucket (Secondary Region: Osaka)
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

# 3. Enforce Strict Compliance Mode (WORM)
resource "aws_s3_bucket_object_lock_configuration" "compliance_lock" {
  provider = aws.secondary
  bucket   = aws_s3_bucket.immutable_worm_backup.id

  rule {
    default_retention {
      mode = "COMPLIANCE" # COMPLIANCE mode cannot be overwritten, altered, or bypassed even by AWS root account
      days = var.worm_retention_days
    }
  }
}

# 4. Enforce KMS Server-Side Encryption
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

# 5. Block All Public Access
resource "aws_s3_bucket_public_access_block" "worm_public_block" {
  provider = aws.secondary
  bucket   = aws_s3_bucket.immutable_worm_backup.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# 6. S3 Bucket Policy: Explicit Deny on Delete and Modify
resource "aws_s3_bucket_policy" "deny_destructive_actions" {
  provider = aws.secondary
  bucket   = aws_s3_bucket.immutable_worm_backup.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyObjectDeletionDuringRetention"
        Effect    = "Deny"
        Principal = "*"
        Action = [
          "s3:DeleteObject",
          "s3:DeleteObjectVersion"
        ]
        Resource = "${aws_s3_bucket.immutable_worm_backup.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-object-lock-mode" = "COMPLIANCE"
          }
        }
      },
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
      }
    ]
  })
}
