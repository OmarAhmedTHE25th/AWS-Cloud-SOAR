import json
import os
import boto3
import logging
import urllib.request

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2 = boto3.client('ec2')
cloudtrail = boto3.client('cloudtrail')
s3 = boto3.client('s3')

BLOCKED_PORTS = {22, 3389}
DISCORD_WEBHOOK_URL = os.environ.get('DISCORD_WEBHOOK_URL')


def send_discord_alert(title, description, color, fields):
    if not DISCORD_WEBHOOK_URL:
        logger.warning("DISCORD_WEBHOOK_URL environment variable is not configured.")
        return

    payload = {
        "username": "AWS Cloud Sentinel",
        "avatar_url": "https://a0.awsstatic.com/libra-css/images/logos/aws_logo_smile_1200x630.png",
        "embeds": [
            {
                "title": title,
                "description": description,
                "color": color,
                "fields": fields,
                "footer": {"text": "Automated Incident Response Pipeline | AWS Lambda"}
            }
        ]
    }

    try:
        req = urllib.request.Request(
            DISCORD_WEBHOOK_URL,
            data=json.dumps(payload).encode('utf-8'),
            headers={
                'Content-Type': 'application/json',
                'User-Agent': 'AWS-Lambda-SOAR'
            }
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            logger.info("Discord webhook sent successfully, status: %s", response.status)
    except Exception as e:
        logger.error("Failed to deliver Discord notification: %s", str(e))


def handle_sg_ingress(detail):
    request_elements = detail.get('requestParameters', {})
    user_identity = detail.get('userIdentity', {})
    
    caller_arn = user_identity.get('arn', 'Unknown')
    source_ip = detail.get('sourceIPAddress', 'Unknown')
    group_id = request_elements.get('groupId')
    
    ip_permissions_wrapper = request_elements.get('ipPermissions', {})
    ip_permissions = ip_permissions_wrapper.get('items', [])
    
    if not group_id or not ip_permissions:
        return {"status": "NOOP"}

    revocations = []
    exposed_ports = []

    for perm in ip_permissions:
        from_port = perm.get('fromPort')
        to_port = perm.get('toPort')
        ip_protocol = perm.get('ipProtocol')
        ip_ranges = perm.get('ipRanges', {}).get('items', [])

        port_match = False
        if from_port is not None and to_port is not None:
            for bp in BLOCKED_PORTS:
                if from_port <= bp <= to_port:
                    port_match = True
                    exposed_ports.append(f"{from_port}-{to_port}/{ip_protocol}")
                    break
        elif ip_protocol == '-1':
            port_match = True
            exposed_ports.append("ALL/-1")

        if not port_match:
            continue

        for ip_range in ip_ranges:
            if ip_range.get('cidrIp') == '0.0.0.0/0':
                revocation_entry = {
                    'IpProtocol': ip_protocol,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }
                if from_port is not None:
                    revocation_entry['FromPort'] = from_port
                if to_port is not None:
                    revocation_entry['ToPort'] = to_port
                revocations.append(revocation_entry)
                break

    if revocations:
        logger.info(f"Revoking {len(revocations)} unauthorized ingress rule(s) on {group_id}...")
        ec2.revoke_security_group_ingress(
            GroupId=group_id,
            IpPermissions=revocations
        )
        
        send_discord_alert(
            title="🚨 High Risk: Public Security Group Ingress Revoked",
            description=f"Automated remediation stripped 0.0.0.0/0 exposure on security group `{group_id}`.",
            color=15158332,
            fields=[
                {"name": "Security Group", "value": f"`{group_id}`", "inline": True},
                {"name": "Ports Targeted", "value": f"`{', '.join(exposed_ports)}`", "inline": True},
                {"name": "Source IP", "value": f"`{source_ip}`", "inline": True},
                {"name": "Actor ARN", "value": f"```{caller_arn}```", "inline": False},
                {"name": "Mitigation Status", "value": "✅ Ingress rule immediately revoked via boto3.", "inline": False}
            ]
        )
        return {"status": "REMEDIATED_SG", "groupId": group_id}

    return {"status": "CLEAN"}


def handle_stop_logging(detail):
    request_elements = detail.get('requestParameters', {})
    user_identity = detail.get('userIdentity', {})
    
    caller_arn = user_identity.get('arn', 'Unknown')
    source_ip = detail.get('sourceIPAddress', 'Unknown')
    trail_name = request_elements.get('name')

    if trail_name:
        logger.info(f"Restarting logging on trail: {trail_name}...")
        cloudtrail.start_logging(Name=trail_name)
        
        send_discord_alert(
            title="🛡️ Critical: CloudTrail Defense Evasion Prevented",
            description=f"A user attempted to stop audit logging on trail `{trail_name}`.",
            color=15844367,
            fields=[
                {"name": "Trail Name", "value": f"`{trail_name}`", "inline": True},
                {"name": "Source IP", "value": f"`{source_ip}`", "inline": True},
                {"name": "Actor ARN", "value": f"```{caller_arn}```", "inline": False},
                {"name": "Mitigation Status", "value": "✅ Logging restarted instantly via cloudtrail.start_logging.", "inline": False}
            ]
        )
        return {"status": "REMEDIATED_TRAIL", "trail": trail_name, "caller": caller_arn}

    return {"status": "NOOP"}


def handle_s3_tampering(detail):
    request_elements = detail.get('requestParameters', {})
    user_identity = detail.get('userIdentity', {})
    
    caller_arn = user_identity.get('arn', 'Unknown')
    source_ip = detail.get('sourceIPAddress', 'Unknown')
    bucket_name = request_elements.get('bucketName')

    if "auto-quarantine-sg" in caller_arn:
        logger.info("Ignoring S3 update initiated by our own Lambda remediation role.")
        return {"status": "IGNORED_SELF"}

    public_access_config = request_elements.get('PublicAccessBlockConfiguration', {})
    if public_access_config:
        all_blocked = (
            public_access_config.get('BlockPublicAcls') is True and
            public_access_config.get('IgnorePublicAcls') is True and
            public_access_config.get('BlockPublicPolicy') is True and
            public_access_config.get('RestrictPublicBuckets') is True
        )
        if all_blocked:
            logger.info("Public access block settings are already strict. No action required.")
            return {"status": "CLEAN"}

    if not bucket_name:
        return {"status": "NOOP"}

    logger.info(f"Re-enabling Block Public Access on {bucket_name}...")
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        }
    )

    send_discord_alert(
        title="🪣 Critical: S3 Public Access Block Enforced",
        description=f"An attempt to weaken public access restrictions on `{bucket_name}` was blocked.",
        color=3066993,
        fields=[
            {"name": "S3 Bucket", "value": f"`{bucket_name}`", "inline": True},
            {"name": "Source IP", "value": f"`{source_ip}`", "inline": True},
            {"name": "Actor ARN", "value": f"```{caller_arn}```", "inline": False},
            {"name": "Mitigation Status", "value": "✅ Re-applied full S3 Block Public Access (all 4 flags True).", "inline": False}
        ]
    )
    return {"status": "REMEDIATED_S3", "bucket": bucket_name}


def lambda_handler(event, context):
    logger.info("Received event: %s", json.dumps(event))
    
    try:
        detail = event.get('detail', {})
        event_name = detail.get('eventName')

        if event_name == 'AuthorizeSecurityGroupIngress':
            return handle_sg_ingress(detail)
        elif event_name == 'StopLogging':
            return handle_stop_logging(detail)
        elif event_name in ['DeleteBucketPublicAccessBlock', 'PutBucketPublicAccessBlock']:
            return handle_s3_tampering(detail)
        else:
            logger.info(f"Unhandled event name: {event_name}")
            return {"status": "IGNORED"}

    except Exception as e:
        logger.error(f"Error executing remediation: {str(e)}", exc_info=True)
        raise e