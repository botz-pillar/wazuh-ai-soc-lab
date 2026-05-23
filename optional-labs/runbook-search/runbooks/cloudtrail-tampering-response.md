---
title: CloudTrail Tampering — Response Runbook
last-updated: 2026-03-15
owner: secops@example.local
severity-tier: P1
---

# CloudTrail Tampering — Response Runbook

For when CloudTrail is found stopped, deleted, modified to drop events, or its logging-target S3 bucket has been tampered with. **Treat as a confirmed incident** — attackers stopping logging is a strong indicator they were doing something they didn't want logged.

## When to use this

- CloudWatch alarm fires on `StopLogging`, `DeleteTrail`, or `UpdateTrail` API calls
- GuardDuty `Stealth:IAMUser/CloudTrailLoggingDisabled` finding
- A scheduled audit shows CloudTrail not delivering for the last N hours
- The trail's S3 bucket has unexpected `DeleteObject` calls on log files

## Prerequisites

- IAM permissions to read trail status, modify trail, read S3 logs
- CloudWatch Logs / S3 Inventory access
- Authority to declare a security incident

## Procedure

### Step 1 — Snapshot current state (DO NOT modify yet)

```bash
aws cloudtrail describe-trails --output json > /tmp/trails-snapshot-$(date -u +%Y%m%dT%H%M%SZ).json
aws cloudtrail get-trail-status --name <trail-name> --output json > /tmp/trail-status-snapshot.json
aws s3 ls s3://<trail-bucket>/AWSLogs/<account-id>/CloudTrail/<region>/ \
  --recursive --summarize > /tmp/trail-bucket-listing.txt
```

These files are forensics evidence. Hash them (`shasum -a 256`) and put them somewhere preserved for the post-incident write-up.

### Step 2 — Identify what was modified, by whom, when

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging \
  --start-time $(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ) \
  --max-results 50

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteTrail \
  --start-time $(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ) \
  --max-results 50

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateTrail \
  --start-time $(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ) \
  --max-results 50
```

Note the `userIdentity.arn`, `sourceIPAddress`, and `userAgent` of every result. **The principal that stopped/modified the trail is your suspect** — treat any other recent activity from that principal as suspicious.

### Step 3 — Re-enable logging

If trail is stopped:

```bash
aws cloudtrail start-logging --name <trail-name>
```

If trail is deleted, recreate from your IaC (Terraform / CloudFormation). Don't recreate by hand — the configuration drift between your IaC and the recreated trail is its own incident.

If `S3KeyPrefix` or filters were modified, restore from the IaC source-of-truth.

### Step 4 — Quarantine the suspect principal

If the principal who stopped/modified the trail is an IAM user: see runbook 01 (treat the user's keys as compromised).
If it's a role: identify which entity assumed the role (the suspect is the entity, not the role itself). Common patterns:

- An EC2 instance role: see runbook 07 (Compromised EC2 Instance Isolation) on the instance
- A cross-account role: page the principal owner in the source account
- A federated identity (SSO): page the federation administrator AND the human user

Attach a deny-all policy or rotate the credentials of the compromising principal until the investigation is complete.

### Step 5 — Backfill the gap

Logs are missing for the period the trail was off. Compensating controls:

- VPC flow logs (if enabled) for network-level activity
- S3 server access logs for data plane access
- Application-level logs on EC2 / containers
- CloudWatch metrics (anomalies in API call volume, IAM events) — won't give you per-event detail but indicates volume / shape

Document the gap explicitly in the post-incident write-up: "CloudTrail off from <T1> to <T2> due to <action> by <principal>; partial reconstruction from <other sources>."

### Step 6 — Forensics

Pull a complete CloudTrail timeline (now that logging is back) for the suspect principal in the 7 days BEFORE the tampering. Look for: privilege escalation, data exfiltration, persistence (CreateUser, CreateAccessKey, CreatePolicy, AttachUserPolicy), and removal of detection controls (DeleteAlarm, DisableConfigRule).

## Verification

- `aws cloudtrail get-trail-status --name <trail-name>` shows `IsLogging: true`
- New events are being delivered to the S3 bucket (check the latest `.json.gz` file's timestamp is < 15 min old)
- Suspect principal is denied / quarantined
- Forensics ticket filed with documented gap and reconstruction plan

## Escalation

- Tampering by a principal in your privileged tier (Administrator, SecurityAdmin, OrganizationAccountAccessRole): page CISO immediately
- Tampering across multiple accounts in your organization: this is an organization-level incident; engage your CIRT
- AWS Support escalation: open a Premium-tier case for additional log access (CloudTrail Insights data, S3 access logs from AWS-managed buckets)

## Notes / known gotchas

- A multi-region trail can be stopped in just one region but appear "still logging" in describe-trails. Always check `get-trail-status` per region.
- An organization trail in AWS Organizations can be modified only by the org-management account — if you see modifications coming from a member account, that's an even bigger red flag (something escalated cross-account).
- S3 lifecycle deletes on the trail bucket are NOT tampering. Check the bucket's lifecycle config before treating as malicious.
