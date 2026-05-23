---
title: EC2 IMDSv1 Detection & Migration — Hardening Runbook
last-updated: 2026-01-04
owner: cloud-platform@example.local
severity-tier: P3 (proactive hardening)
---

# EC2 IMDSv1 Detection & Migration

For migrating EC2 instances from IMDSv1 (vulnerable to SSRF / credential exfiltration via the `169.254.169.254` metadata endpoint) to IMDSv2 (token-bound; mitigates the SSRF class).

This is hardening, not incident response. Run on a cadence (quarterly is reasonable) or in response to a finding/audit.

## When to use this

- AWS Security Hub finding: `[EC2.8] EC2 instances should use Instance Metadata Service Version 2 (IMDSv2)`
- Audit / pentest result flagging IMDSv1
- Quarterly hardening sweep
- After a confirmed SSRF incident — verify IMDSv2 enforcement on adjacent instances

## Prerequisites

- IAM permissions: `ec2:Describe*`, `ec2:ModifyInstanceMetadataOptions`
- For Auto Scaling Group instances: `autoscaling:UpdateAutoScalingGroup` and the launch-template/launch-config write permissions
- Owners notified that IMDSv1 will be turned off on their instances (some old SDKs / some ancient CLI versions don't support v2)

## Procedure

### Step 1 — Inventory IMDSv1 usage

```bash
aws ec2 describe-instances \
  --query 'Reservations[].Instances[?MetadataOptions.HttpTokens==`optional`].[InstanceId,Tags[?Key==`Name`].Value|[0]]' \
  --output table
```

`HttpTokens: optional` means IMDSv1 is allowed. `HttpTokens: required` means IMDSv2 only. The query returns instances still allowing v1.

For Auto Scaling Groups:

```bash
aws ec2 describe-launch-templates \
  --query 'LaunchTemplates[].LaunchTemplateName' --output text
# Then for each:
aws ec2 describe-launch-template-versions \
  --launch-template-name <name> \
  --query 'LaunchTemplateVersions[].LaunchTemplateData.MetadataOptions'
```

### Step 2 — Verify the instance can use v2

Connect to the instance (SSM Session Manager preferred). Test:

```bash
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/instance-id
```

If both calls succeed, v2 works on this instance. If they fail, check the SDK version on the instance — boto3 < 1.12, AWS SDK for Java 1.x < 1.11.678, and similar old SDKs may need an update.

### Step 3 — Enforce v2 on the running instance

```bash
aws ec2 modify-instance-metadata-options \
  --instance-id <instance-id> \
  --http-tokens required \
  --http-endpoint enabled \
  --http-put-response-hop-limit 1
```

`HttpPutResponseHopLimit 1` blocks the metadata endpoint from being reachable through containers/Docker on the instance — protects against pivot attacks where a compromised container queries the host's metadata. Set to `2` only if you specifically need container-level access to instance role credentials.

### Step 4 — Update launch templates / launch configs

For Auto Scaling Groups, modify the launch template so newly-launched instances are IMDSv2-only:

```bash
aws ec2 create-launch-template-version \
  --launch-template-name <name> \
  --source-version <current-version> \
  --launch-template-data '{
    "MetadataOptions": {
      "HttpTokens": "required",
      "HttpEndpoint": "enabled",
      "HttpPutResponseHopLimit": 1
    }
  }'
```

Then update the ASG to use the new version:

```bash
aws autoscaling update-auto-scaling-group \
  --auto-scaling-group-name <asg-name> \
  --launch-template LaunchTemplateName=<name>,Version='$Latest'
```

### Step 5 — Verify

After 24 hours (give applications time to surface failures):

```bash
aws ec2 describe-instances \
  --query 'Reservations[].Instances[?MetadataOptions.HttpTokens==`optional`].InstanceId' \
  --output text
```

Should return empty.

## Verification

- All instances report `HttpTokens: required`
- All launch templates updated; ASG using latest version
- No application errors in CloudWatch / Datadog tied to metadata calls in the 24hr window after enforcement

## Escalation

- Application errors after enforcement: revert that single instance with `--http-tokens optional`, file a ticket with the app owner to update their SDK, retry in 1 week
- Inability to enforce on > 5% of fleet: escalate to platform engineering for SDK-update planning

## Notes / known gotchas

- Hop limit of 1 breaks container-level metadata access. If you run containers that need the instance role's credentials, you have three options: (a) use ECS/EKS task roles instead, (b) raise hop limit to 2, (c) inject creds into the container at launch. (a) is preferred.
- Spot instances inherit the launch template's metadata options at launch; in-flight spot interruptions don't change them.
- Some AMIs (very old Amazon Linux 1, ancient Ubuntu 16.04) have IMDSv2 issues. Retire those AMIs before forcing v2 fleet-wide.
