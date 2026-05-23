---
title: Compromised EC2 Instance — Isolation Runbook
last-updated: 2026-02-26
owner: secops@example.local
severity-tier: P1
---

# Compromised EC2 Instance — Isolation Runbook

For a confirmed-compromised or strongly-suspected EC2 instance. The objective: stop the bleeding while preserving forensic state.

## When to use this

- GuardDuty `Backdoor:EC2/*`, `Trojan:EC2/*`, or `UnauthorizedAccess:EC2/*` finding
- Anti-malware on the instance reports active infection
- The instance role's credentials are seen used from outside the instance (`UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.*`)
- Network detection shows C2 traffic from the instance

## Prerequisites

- EC2 + VPC + IAM permissions
- A pre-built "quarantine" security group with NO ingress and NO egress (create now if you don't have one)
- SSM Session Manager set up for the instance (preferred over SSH for forensics access)
- Authority to take an instance offline

## Procedure

### Step 1 — Decide: snapshot first or isolate first?

**Default: snapshot first.** Volatile memory is lost when the instance stops; isolating via security group preserves the running state. But if exfiltration is actively in progress, isolation comes first.

### Step 2 — Snapshot (preserves disk state)

```bash
# Find attached EBS volumes
aws ec2 describe-instances --instance-ids <instance-id> \
  --query 'Reservations[].Instances[].BlockDeviceMappings[].Ebs.VolumeId' --output text

# Snapshot each volume
for VOL in <vol-1> <vol-2>; do
  aws ec2 create-snapshot --volume-id $VOL \
    --description "FORENSICS: incident <ticket-id> on $(date -u +%Y-%m-%dT%H:%M:%SZ)"
done
```

Tag snapshots with the incident ticket ID immediately. They will be your evidence.

### Step 3 — Isolate via security group

Replace the instance's security groups with the quarantine SG (no ingress, no egress, except the SSM Session Manager endpoint if you want forensics access):

```bash
aws ec2 modify-instance-attribute \
  --instance-id <instance-id> \
  --groups <quarantine-sg-id>
```

The instance is now network-isolated. SSH won't work; if you need shell access, use SSM Session Manager (which uses an AWS-internal channel separate from VPC ingress rules).

### Step 4 — Revoke the instance's role credentials (if applicable)

If the instance has an instance profile, those credentials may still be usable from wherever they were exfiltrated. Two options:

```bash
# Option A: detach the instance profile (instance now has no AWS credentials)
aws ec2 disassociate-iam-instance-profile --association-id <association-id>

# Option B: rotate by attaching a deny-all inline policy to the role
aws iam put-role-policy \
  --role-name <role-name> \
  --policy-name DENY-ALL-INCIDENT-<ticket-id> \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]
  }'
```

Option A is cleaner if no other instances use the same role. Option B if multiple instances share the role and you only want to revoke this one's exfiltrated session.

### Step 5 — Forensics access

```bash
aws ssm start-session --target <instance-id>
```

Once shell:

- Capture process list: `ps auxf > /tmp/ps.txt`
- Capture network state: `ss -anp > /tmp/netstat.txt; lsof -i > /tmp/lsof.txt`
- Capture recent shell history: `cat /home/*/.bash_history`
- Capture cron jobs: `for u in $(cut -d: -f1 /etc/passwd); do crontab -u $u -l 2>/dev/null; done`
- Capture systemd unit changes: `systemctl list-unit-files --state=enabled`

Copy outputs off the instance via S3 (use a forensics bucket with restricted access) — do NOT try to email or SCP off; the network is locked down.

### Step 6 — Post-isolation triage

- Pull CloudTrail for the instance role's activity for the last 14 days
- Pull VPC flow logs for the instance's ENI for the last 7 days; look for outbound to known-bad IPs
- File full incident ticket: timeline, indicators, blast radius, snapshot IDs

### Step 7 — Decide: terminate or rebuild?

Default: **terminate after forensics complete.** Do not return a compromised instance to service. If the workload requires rebuilding, build from a known-clean AMI; do not re-image from the compromised instance.

## Verification

- Instance has only the quarantine SG attached
- Instance role detached or has the deny-all policy attached
- All EBS volumes snapshotted and tagged with incident ID
- No new outbound traffic from the instance (check VPC flow logs after 15 min)

## Escalation

- Backdoor / Trojan finding on a production instance: page CISO + infra owner immediately
- Confirmed credential exfiltration: trigger runbook 06 (Suspicious AssumeRole) on every role the instance role could AssumeRole to

## Notes / known gotchas

- Quarantine SG must allow OUTBOUND to `ssm.<region>.amazonaws.com`, `ec2messages.<region>.amazonaws.com`, and `ssmmessages.<region>.amazonaws.com` if you want SSM Session Manager to keep working. Test your quarantine SG before you need it.
- Stopping the instance (vs. isolating) loses memory state. Don't stop unless directed by the forensics lead.
- Auto Scaling Groups will replace a terminated instance. Suspend ASG processes (`aws autoscaling suspend-processes --auto-scaling-group-name <asg> --scaling-processes Launch`) before terminating, or you'll fight the ASG.
