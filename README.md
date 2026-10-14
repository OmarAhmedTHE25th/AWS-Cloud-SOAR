# AWS Cloud SOAR: Automated Threat Detection & Incident Response Pipeline

An event-driven automated containment architecture deployed on AWS using Terraform. It detects common initial access, defense evasion, and data exposure techniques in real time via CloudTrail and EventBridge, executing sub-second serverless remediation via Python (`boto3`) and pushing incident cards to a SecOps Discord channel.

## Architecture

```text
[AWS API Call] 
       │
       ▼
[AWS CloudTrail] (Management Events)
       │
       ▼
[Amazon EventBridge] (Rule Pattern Matching)
       │
       ▼
[AWS Lambda (boto3)] ───► [Automated Remediation] (EC2, CloudTrail, S3)
       │
       └────────────────► [Discord Webhook] (Formatted Incident Embed)