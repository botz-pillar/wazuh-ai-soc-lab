---
title: IAM Access Key Compromise — Response Runbook
last-updated: 2025-11-04
owner: secops@example.local
severity-tier: P1
---

# IAM Access Key Compromise — Response Runbook

For when an AWS IAM access key has been confirmed leaked (public repo, paste site, AWS-emitted compromise alert) or strongly suspected leaked (anomalous use from new IP / outside business hours / from outside expected geographic region).

> **AWS-emitted signal:** if AWS has attached the `AWSCompromisedKeyQuarantineV3` policy automatically, the key is already known-leaked. Treat as confirmed. Skip Step 1 (verification) and start at Step 2 (rotation).

## When to use this

- A bot or AWS Health alert says a key is leaked
- A teammate reports finding their key in a public commit
- Anomalous CloudTrail activity tied to an access key (`GetCallerIdentity` from a never-before-seen IP)
- Audit shows a key that hasn't been rotated in > 365 days AND is widely distributed

## Prerequisites

- IAM read/write in the affected account (or the ability to page someone who has it)
- CloudTrail readable for the last 14 days
- A communication channel to the user/service that owns the key

## Procedure

### Step 1 — Verify the leak

Pull the access key's recent activity to confirm scope:

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA...EXAMPLE \
  --max-results 50
```

Note the IPs, eventNames, and time range. If you see calls from outside your VPC/office IP space, the key is compromised. Document the first attacker call's `eventID` — you will reference it in the post-incident write-up.

### Step 2 — Disable the key (do this BEFORE deletion)

```bash
aws iam update-access-key \
  --user-name <username> \
  --access-key-id AKIA...EXAMPLE \
  --status Inactive
```

`Inactive` is reversible if you're wrong; `Delete` is not. Always disable first.

### Step 3 — Identify and notify the owner

```bash
aws iam list-access-keys --user-name <username>
```

If the user is human, page them. If the key belongs to a service (CI runner, application), find the service owner from your `infrastructure-owners` source-of-truth and notify them. Include: which key, why disabled, what they need to do (rotate to a new key, update wherever it was deployed).

### Step 4 — Rotate

Once the owner has prepared to swap in a new key:

```bash
aws iam create-access-key --user-name <username>
```

Hand the new `AccessKeyId` and `SecretAccessKey` to the owner via your secure channel (1Password share, vault, etc.). **Never paste secrets in Slack or email.**

### Step 5 — Delete the old key

After the owner confirms the new key is deployed and the old key has not been used in 24 hours:

```bash
aws iam delete-access-key \
  --user-name <username> \
  --access-key-id AKIA...EXAMPLE
```

### Step 6 — Forensics + post-incident

- Pull a CloudTrail timeline for the compromised key and any roles it could AssumeRole to. Look for: `s3:GetObject` on sensitive buckets, `iam:Create*` (persistence), `cloudtrail:StopLogging` (cover-up).
- File a brief write-up in `incidents/<YYYY-MM-DD>-iam-key-<username>.md` with the timeline, blast radius, and containment timeline.

## Verification

- `aws iam list-access-keys --user-name <username>` shows the old key absent
- The new key works for the service it was deployed to
- No CloudTrail events for the compromised AccessKeyId in the last 24 hours

## Escalation

- If the key had Administrator or PowerUser privileges, or if the leak window was > 4 hours: page on-call security lead and CISO
- If you find AWS-side `AWSCompromisedKeyQuarantineV3` attachment: this counts as a confirmed leak; engage AWS Support (Premium tier) for additional log access

## Notes / known gotchas

- An IAM user can have at most 2 access keys. If the user already has 2, disable + delete one before creating a replacement.
- For root-account access keys: don't rotate; **delete and never replace**. Use IAM users / roles instead.
- If the key was used by a Lambda function via env var, check function configuration (`aws lambda get-function-configuration --function-name <fn>`) for the leaked key text, not just the env var name.
