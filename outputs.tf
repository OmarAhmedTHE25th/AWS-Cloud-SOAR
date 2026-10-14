output "lambda_function_arn" {
  description = "ARN of the automated remediation Lambda"
  value       = aws_lambda_function.remediation_fn.arn
}

output "eventbridge_rule_arn" {
  description = "ARN of the incident detection EventBridge rule"
  value       = aws_cloudwatch_event_rule.detect_security_incidents.arn
}