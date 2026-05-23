---
title: Secrets Manager Unexpected Rotation — Response Runbook
last-updated: 2026-03-08
owner: secops@example.local
severity-tier: P2
---

# Secrets Manager Unexpected Rotation — Response

For when a Secrets Manager secret rotates outside its scheduled window, or its automatic-rotation Lambda fires unexpectedly. Rotation events that look "wrong" can indicate either a misconfigured rotation Lambda OR an attacker triggering rotation to lock out legitimate users.

## When to use this

- CloudWatch alarm on `secretsmanager:RotateSecret` outside the scheduled window
- Application errors immediately after a rotation (apps holding the old credential)
- Audit shows a rotation triggered by an unexpected principal

## Prerequisites

- Secrets Manager + IAM read permissions
- Knowledge of the secret's rotation schedule + which downstream apps use it

## Procedure

### Step 1 — Identify the rotation event and principal

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=RotateSecret \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --max-results 50
```

Note: principal, sourceIPAddress, the secret ARN, the rotation Lambda ARN. Cross-reference principal against the expected rotation schedule.

### Step 2 — Check the secret's current state

```bash
aws secretsmanager describe-secret --secret-id <secret-arn>

aws secretsmanager list-secret-version-ids --secret-id <secret-arn> --include-deprecated
```

You should see `AWSCURRENT`, `AWSPREVIOUS`, possibly `AWSPENDING`. If the rotation completed mid-action, `AWSPENDING` may exist alongside `AWSCURRENT`.

### Step 3 — Decide: legitimate or hostile?

**Legitimate** (close as known): rotation triggered by your scheduled rotation Lambda, principal is the rotation Lambda's role, source IP is `AWS Internal`, time matches schedule.

**Hostile or suspicious**: principal is an IAM user / different role; sourceIPAddress is external; time is off-schedule; or rotation Lambda was modified recently.

If hostile:

### Step 4a — Restore the previous version

If apps are broken because they're holding the old credential, point them at `AWSPREVIOUS`:

```bash
aws secretsmanager get-secret-value --secret-id <secret-arn> --version-stage AWSPREVIOUS
```

OR restore by promoting `AWSPREVIOUS` back to `AWSCURRENT`:

```bash
aws secretsmanager update-secret-version-stage \
  --secret-id <secret-arn> \
  --version-stage AWSCURRENT \
  --move-to-version-id <previous-version-id> \
  --remove-from-version-id <current-version-id>
```

### Step 4b — Investigate the principal

Trigger runbook 01 (IAM Access Key Compromise) on the principal that triggered the rotation.

### Step 4c — Check what else they touched

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=<principal-username> \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --max-results 100
```

A hostile rotation is rarely the only action. Look for: secret-value reads (`GetSecretValue`), other secrets touched, IAM persistence, log tampering.

### Step 5 — Hardening (post-incident)

- Tighten the secret's resource policy to limit which principals can call `RotateSecret`
- Enable CloudWatch alarms on every `RotateSecret` event for the secret, not just off-schedule ones
- Verify the rotation Lambda's role has only the permissions it needs (`secretsmanager:UpdateSecretVersionStage`, the specific backend permissions, NOT `secretsmanager:*`)

## Verification

- Apps relying on the secret are working with the correct version
- Hostile principal contained
- Detection coverage updated for similar future events

## Escalation

- Hostile rotation on a secret holding production database credentials: page DBA + CISO immediately
- Hostile rotation across multiple secrets in a short window: organization-level incident

## Notes / known gotchas

- A rotation Lambda that fails midway can leave the secret in `AWSPENDING` state. Some apps will pick up `AWSPENDING` if the rotation is in progress; this is documented behavior, not an attack.
- If the rotation is genuinely benign but the schedule is wrong, fix the rotation schedule first, then close the alert. Don't chase ghost-attacks from misconfigured rotation cadence.
- `secretsmanager:GetSecretValue` calls are NOT logged in CloudTrail by default at the data-plane level — make sure you have CloudTrail Data Events enabled for Secrets Manager OR you're working with whatever logging your KMS key emits.
