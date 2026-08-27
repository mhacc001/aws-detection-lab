terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  name_prefix = "detlab"
  account_id  = data.aws_caller_identity.current.account_id
}

# ---------------------------------------------------------------------------
# S3 bucket for CloudTrail logs
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "trail" {
  bucket        = "${local.name_prefix}-cloudtrail-${local.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.trail.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.trail.arn}/AWSLogs/${local.account_id}/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.trail.arn, "${aws_s3_bucket.trail.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# CloudWatch log group + CloudTrail
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "trail" {
  name              = "/aws/cloudtrail/${local.name_prefix}"
  retention_in_days = 7
}

resource "aws_iam_role" "trail_to_cw" {
  name = "${local.name_prefix}-cloudtrail-cw"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "trail_to_cw" {
  name = "${local.name_prefix}-cloudtrail-cw"
  role = aws_iam_role.trail_to_cw.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.trail.arn}:*"
    }]
  })
}

resource "aws_cloudtrail" "main" {
  name                          = "${local.name_prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.trail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.trail_to_cw.arn
  depends_on                    = [aws_s3_bucket_policy.trail]
}

# ---------------------------------------------------------------------------
# SNS for alerts
# ---------------------------------------------------------------------------
resource "aws_sns_topic" "alerts" {
  name = "${local.name_prefix}-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ---------------------------------------------------------------------------
# Detections: metric filters + alarms
# ---------------------------------------------------------------------------
locals {
  detections = {
    root_account_used = {
      pattern     = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
      description  = "Root account activity - T1078.004"
    }
    console_login_no_mfa = {
      pattern     = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") && ($.responseElements.ConsoleLogin = \"Success\") }"
      description = "Console sign-in without MFA - T1078.004"
    }
    cloudtrail_tampering = {
      pattern     = "{ ($.eventName = \"StopLogging\") || ($.eventName = \"DeleteTrail\") || ($.eventName = \"UpdateTrail\") }"
      description = "CloudTrail disabled or altered - T1562.008"
    }
    iam_policy_change = {
      pattern     = "{ ($.eventName = \"PutUserPolicy\") || ($.eventName = \"PutRolePolicy\") || ($.eventName = \"AttachUserPolicy\") || ($.eventName = \"AttachRolePolicy\") || ($.eventName = \"CreatePolicyVersion\") }"
      description = "IAM policy modification - T1098"
    }
    access_key_created = {
      pattern     = "{ ($.eventName = \"CreateAccessKey\") }"
      description = "New access key created - T1098.001"
    }
    s3_public_access = {
      pattern     = "{ ($.eventName = \"PutBucketPolicy\") || ($.eventName = \"PutBucketAcl\") || ($.eventName = \"DeletePublicAccessBlock\") || ($.eventName = \"PutBucketPublicAccessBlock\") }"
      description = "S3 bucket access policy change - T1530 / T1567.002"
    }
  }
}

resource "aws_cloudwatch_log_metric_filter" "d" {
  for_each       = local.detections
  name           = "${local.name_prefix}-${each.key}"
  log_group_name = aws_cloudwatch_log_group.trail.name
  pattern        = each.value.pattern

  metric_transformation {
    name          = "${local.name_prefix}-${each.key}"
    namespace     = "DetectionLab"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "d" {
  for_each            = local.detections
  alarm_name          = "${local.name_prefix}-${each.key}"
  alarm_description    = each.value.description
  namespace           = "DetectionLab"
  metric_name         = "${local.name_prefix}-${each.key}"
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# ---------------------------------------------------------------------------
# GuardDuty
# ---------------------------------------------------------------------------
resource "aws_guardduty_detector" "main" {
  enable = true
}

# ---------------------------------------------------------------------------
# Attacker principal for simulation (no console, minimal starting perms)
# ---------------------------------------------------------------------------
resource "aws_iam_user" "attacker" {
  name          = "${local.name_prefix}-attacker"
  force_destroy = true
}

resource "aws_iam_user_policy" "attacker_start" {
  name = "starting-perms"
  user = aws_iam_user.attacker.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "iam:List*", "iam:Get*", "iam:CreateAccessKey", "iam:PutUserPolicy",
        "s3:CreateBucket", "s3:PutBucketPolicy", "s3:PutBucketAcl",
        "cloudtrail:StopLogging", "cloudtrail:DescribeTrails"
      ]
      Resource = "*"
    }]
  })
}
