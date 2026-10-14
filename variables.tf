variable "aws_region" {
  description = "Target AWS Region"
  type        = string
  default     = "eu-north-1"
}

variable "discord_webhook_url" {
  description = "Discord incoming webhook URL for incident alerts"
  type        = string
  sensitive   = true
  default     = ""
}