---
title: VPC Flow Log Anomaly — Investigation Runbook
last-updated: 2024-01-15
owner: secops@example.local
severity-tier: P2
---

# VPC Flow Log Anomaly — Investigation Runbook

For investigating anomalous traffic patterns in VPC flow logs: unusual outbound volume, connections to known-bad IPs, traffic from EC2 instances to unexpected destinations.

## When to use this

- A detection rule fires on flow log data (large egress, connection to TI feed match)
- Manual review of flow logs spots an oddity worth investigating
- Post-incident: pull flow logs to map blast radius for a confirmed compromise

## Prerequisites

- VPC flow logs enabled (CloudWatch Logs or S3 destination)
- Athena or CloudWatch Logs Insights access
- IAM permissions to look up the suspect ENI / instance

## Procedure

### Step 1 — Pull the relevant flow log window

If logs go to S3 + Athena:

```sql
SELECT srcaddr, dstaddr, srcport, dstport, protocol, bytes, action
FROM vpc_flow_logs
WHERE start >= to_unixtime(current_timestamp - interval '24' hour)
  AND interface_id = '<eni-id>'
  AND action = 'ACCEPT'
ORDER BY bytes DESC
LIMIT 100;
```

If logs go to CloudWatch Logs:

```
fields @timestamp, srcAddr, dstAddr, srcPort, dstPort, bytes, action
| filter interfaceId = '<eni-id>'
| sort bytes desc
| limit 100
```

### Step 2 — Resolve the suspect IPs

Are they external? Internal? Known-good (your CDN, your APM vendor)? Check against:

- Your CIDR block inventory (internal ranges)
- Your vendor allowlist (Datadog, PagerDuty, Stripe, etc.)
- A threat-intel feed for known malicious IPs

If you have an enrichment pipeline, use it; otherwise spot-check the top destinations manually.

### Step 3 — Identify the source resource

The ENI ID maps to either an EC2 instance, a Lambda function (in VPC), an RDS instance, an EKS pod, or a NAT gateway:

```bash
aws ec2 describe-network-interfaces --network-interface-ids <eni-id> \
  --query 'NetworkInterfaces[0].[Attachment.InstanceId,Description,InterfaceType]'
```

### Step 4 — Check the source resource's IAM and recent activity

If the source is an EC2 instance with an instance role:

```bash
# Find the role attached
aws ec2 describe-instances --instance-ids <instance-id> \
  --query 'Reservations[].Instances[].IamInstanceProfile.Arn'

# Check the role's recent CloudTrail activity
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=<role-name> \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --max-results 50
```

If you find the role's credentials being used from outside the instance — that's instance credential exfiltration. Trigger runbook 07.

If the source has an IAM user attached (some legacy patterns), pull the user's recent keys:

```bash
aws iam list-access-keys --username <username>
```

### Step 5 — Decide

- Known-good destination, low bytes, expected pattern: close as benign with a note explaining what made it look anomalous
- Known-bad destination OR unexpected pattern with sensitive source: trigger runbook 07 (Compromised EC2) or 06 (Suspicious AssumeRole) as appropriate
- Inconclusive: collect more data (lookup the destination ASN, sample more time windows) and re-triage

## Verification

- Triage decision documented (TP / FP / inconclusive) with evidence
- For TP cases, follow-on runbook (07 / 06 / 01) opened
- Detection rule tuned if FP (allowlist add OR threshold adjustment)

## Escalation

- Confirmed exfil to known-bad destination from production resource: page CISO immediately
- Suspect data exfiltration of customer data: data-protection lead + breach-notification playbook

## Notes / known gotchas

- VPC flow logs do not capture payload content. You see SOURCE → DESTINATION : BYTES; you do not see WHAT was transferred. For payload inspection, you need GuardDuty (limited) or a packet capture appliance.
- "REJECT" actions can be more interesting than ACCEPTs — they show what an attacker TRIED to reach. Don't filter them out reflexively.
- Lambda-in-VPC flow logs report on the ENI in your subnet, not on the Lambda's separate Hyperplane ENI. If a Lambda's outbound looks weird, the flow log won't show it directly — check the function's CloudWatch logs instead.
