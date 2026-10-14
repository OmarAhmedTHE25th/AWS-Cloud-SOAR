terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# 1. Package Lambda Code
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda/lambda_function.py"
  output_path = "${path.module}/lambda_payload.zip"
}

# 2. IAM Role for Lambda
resource "aws_iam_role" "lambda_exec_role" {
  name = "auto-quarantine-sg-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# 3. CloudWatch Logging Policy
resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# 4. Least-Privilege Remediation Policy
resource "aws_iam_role_policy" "lambda_remediation_policy" {
  name = "LambdaRemediationPolicy"
  role = aws_iam_role.lambda_exec_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowRevokeIngress"
        Effect = "Allow"
        Action = [
          "ec2:DescribeSecurityGroups",
          "ec2:RevokeSecurityGroupIngress"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowRestartCloudTrail"
        Effect = "Allow"
        Action = [
          "cloudtrail:StartLogging",
          "cloudtrail:DescribeTrails",
          "cloudtrail:GetTrailStatus"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowEnforceS3BlockPublicAccess"
        Effect = "Allow"
        Action = [
          "s3:PutBucketPublicAccessBlock",
          "s3:GetBucketPublicAccessBlock"
        ]
        Resource = "*"
      }
    ]
  })
}

# 5. Lambda Function
resource "aws_lambda_function" "remediation_fn" {
  function_name    = "auto-quarantine-sg"
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  role             = aws_iam_role.lambda_exec_role.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.12"
  timeout          = 15
  memory_size      = 128

  environment {
    variables = {
      DISCORD_WEBHOOK_URL = var.discord_webhook_url
    }
  }
}

# 6. EventBridge Rule
resource "aws_cloudwatch_event_rule" "detect_security_incidents" {
  name        = "detect-cloud-threats"
  description = "Captures SG exposure, CloudTrail disable attempts, and S3 tampering"

  event_pattern = jsonencode({
    source      = ["aws.ec2", "aws.cloudtrail", "aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "AuthorizeSecurityGroupIngress",
        "StopLogging",
        "PutBucketPublicAccessBlock",
        "DeleteBucketPublicAccessBlock"
      ]
    }
  })
}

# 7. EventBridge Target
resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.detect_security_incidents.name
  target_id = "AutoRemediateThreats"
  arn       = aws_lambda_function.remediation_fn.arn
}

# 8. Lambda Permission to allow EventBridge Invocation
resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediation_fn.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.detect_security_incidents.arn
}