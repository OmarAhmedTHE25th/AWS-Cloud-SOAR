# AWS Cloud SOAR: Automated Threat Detection & Incident Response Pipeline

An event-driven, fully automated cloud security pipeline deployed on AWS using Terraform. It monitors CloudTrail in real time, detects high-risk misconfigurations and defense evasion attempts, and executes sub-second serverless remediation — no human intervention required.

Incident cards with full forensic context (actor ARN, source IP, affected resource, mitigation status) are pushed to a SecOps Discord channel the moment a response fires.

---

## Architecture

```text
[AWS API Call]
      │
      ▼
[AWS CloudTrail]          ← captures all management-plane events
      │
      ▼
[Amazon EventBridge]      ← pattern-matches on targeted event names
      │
      ▼
[AWS Lambda (Python 3.12, boto3)]
      │
      ├──► [Automated Remediation]   (EC2 / CloudTrail / S3)
      │
      └──► [Discord Webhook]         (formatted incident embed)
```

The entire stack — Lambda, IAM role, least-privilege policy, EventBridge rule, and invocation permissions — is defined in Terraform and deployed with a single `terraform apply`.

---

## Detection & Response Coverage

| Event | Threat Category | MITRE ATT&CK | Automated Response |
|---|---|---|---|
| `AuthorizeSecurityGroupIngress` | Initial Access — exposed admin ports | T1190 | Revokes the 0.0.0.0/0 rule from the security group immediately |
| `StopLogging` | Defense Evasion — audit log tampering | T1562.001 | Restarts CloudTrail logging on the targeted trail |
| `DeleteBucketPublicAccessBlock` | Data Exposure — S3 made public | T1530 | Re-applies full Block Public Access (all 4 flags) |
| `PutBucketPublicAccessBlock` (weakened) | Data Exposure — S3 access weakening | T1530 | Re-enforces strict Block Public Access if any flag is relaxed |

---

## Response Playbooks

### 🚨 Security Group — Public Admin Port Exposure
Fires when a rule opens **port 22 (SSH) or 3389 (RDP)** to `0.0.0.0/0`. The Lambda parses the IP permissions in the CloudTrail event, identifies the violating rules, and calls `ec2:RevokeSecurityGroupIngress` to remove them before any attacker can act. Also catches all-traffic (`-1`) rules exposed to the internet.

### 🛡️ CloudTrail — Defense Evasion Prevention
`StopLogging` is a well-known attacker move to blind defenders before lateral movement or exfiltration. The Lambda detects it the moment EventBridge fires and immediately calls `cloudtrail:StartLogging` to restore visibility on the targeted trail.

### 🪣 S3 — Public Access Block Enforcement
Any attempt to delete or weaken the S3 Block Public Access configuration triggers a full re-enforcement: all four flags (`BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets`) are set back to `true`. Calls originating from the Lambda's own IAM role are explicitly filtered out to prevent self-triggering loops.

---

## Discord Incident Alerts

Every remediation action fires a structured Discord embed containing:

- **Threat title and severity color** (red / orange / green by playbook)
- **Affected resource** (security group ID / trail name / S3 bucket)
- **Actor ARN** — who triggered the event
- **Source IP** — where the call came from
- **Mitigation status** — confirmation of the remediation action taken

The webhook bot name is `AWS Cloud Sentinel`.

---

## IAM — Least Privilege Policy

The Lambda execution role is granted only the permissions it needs for remediation:

| Permission Set | Actions |
|---|---|
| EC2 | `ec2:RevokeSecurityGroupIngress`, `ec2:DescribeSecurityGroups` |
| CloudTrail | `cloudtrail:StartLogging`, `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus` |
| S3 | `s3:PutBucketPublicAccessBlock`, `s3:GetBucketPublicAccessBlock` |
| Logging | `AWSLambdaBasicExecutionRole` (CloudWatch Logs) |

---

## Deployment

### Prerequisites
- [Terraform](https://developer.hashicorp.com/terraform/install) >= 1.5.0
- AWS credentials configured (`aws configure` or environment variables)
- A Discord webhook URL for your SecOps channel

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/OmarAhmedTHE25th/AWS-Cloud-SOAR.git
cd AWS-Cloud-SOAR

# 2. Initialize Terraform
terraform init

# 3. Deploy (set your webhook URL and target region)
terraform apply \
  -var="discord_webhook_url=https://discord.com/api/webhooks/..." \
  -var="aws_region=eu-north-1"

# 4. Confirm and apply
# Type `yes` when prompted
```

> **Note:** `discord_webhook_url` is marked `sensitive` in Terraform — it will not appear in plan output or state diffs.

### Outputs

After a successful apply, Terraform prints:

| Output | Description |
|---|---|
| `lambda_function_arn` | ARN of the remediation Lambda |
| `eventbridge_rule_arn` | ARN of the EventBridge detection rule |

### Teardown

```bash
terraform destroy \
  -var="discord_webhook_url=placeholder" \
  -var="aws_region=eu-north-1"
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| IaC | Terraform >= 1.5, AWS Provider ~> 5.0 |
| Runtime | AWS Lambda — Python 3.12 |
| Event Source | AWS CloudTrail + Amazon EventBridge |
| Remediation SDK | boto3 (EC2, CloudTrail, S3 clients) |
| Alerting | Discord Incoming Webhooks |
| Default Region | `eu-north-1` (configurable) |
