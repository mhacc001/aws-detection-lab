variable "region" {
  description = "AWS region to deploy the lab into"
  type        = string
  default     = "us-east-1"
}

variable "alert_email" {
  description = "Email address that receives SNS alerts. You must confirm the subscription."
  type        = string
}
