output "cloudtrail_bucket" {
  value = aws_s3_bucket.trail.id
}

output "log_group" {
  value = aws_cloudwatch_log_group.trail.name
}

output "sns_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "guardduty_detector_id" {
  value = data.aws_guardduty_detector.main.id
}

output "attacker_user" {
  value = aws_iam_user.attacker.name
}

output "alarm_names" {
  value = [for k, v in aws_cloudwatch_metric_alarm.d : v.alarm_name]
}
