---
title: S3 Public-Bucket Exposure — Response Runbook
last-updated: 2026-01-22
owner: secops@example.local
severity-tier: P1 (with sensitive data) / P2 (without)
---

# S3 Public-Bucket Exposure — Response Runbook

For when an S3 bucket is found unintentionally world-readable or world-writable. Triggers: AWS Config rule fires, GuardDuty `Policy:S3/BucketAnonymousAccessGranted`, IAM Access Analyzer finding, external researcher disclosure, or a teammate spots it during review.

## When to use this

- A bucket is publicly accessible AND it shouldn't be
- A bucket policy grants `Principal: "*"` for `s3:GetObject` or worse, `s3:PutObject`
- ACL on the bucket grants `URI: http://acs.amazonaws.com/groups/global/AllUsers`

If the bucket is intentionally public (a static website, a public data set), this runbook does NOT apply — verify intent before locking down.

## Prerequisites

- IAM permissions to read bucket policy + ACL, modify both, and enable Block Public Access
- S3 access logs enabled for the bucket (or CloudTrail Data Events)

## Procedure

### Step 1 — Confirm exposure

```bash
aws s3api get-bucket-policy --bucket <bucket-name>
aws s3api get-bucket-acl --bucket <bucket-name>
aws s3api get-public-access-block --bucket <bucket-name>
```

Look for `Principal: "*"` in the policy or `URI: AllUsers/AuthenticatedUsers` in the ACL grants. Confirm `BlockPublicAccess` is disabled or partially disabled.

### Step 2 — Assess blast radius (BEFORE locking down)

```bash
# What's in the bucket?
aws s3 ls s3://<bucket-name> --recursive --summarize | tail -5

# Who's accessed it lately?
aws s3api get-bucket-logging --bucket <bucket-name>
# Then read the logging-target bucket for the last 14 days of access.
```

Document: object count, total size, presence of any obvious sensitive-content indicators (filenames containing `pii`, `ssn`, `customer`, `prod`, `backup`). If you find such indicators or if access logs show non-allowlisted IPs reading objects, escalate to data-protection lead before continuing.

### Step 3 — Lock down (account-level Block Public Access first, then bucket-level)

```bash
# Account-level — covers ALL buckets in the account
aws s3control put-public-access-block \
  --account-id <account-id> \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Bucket-level — for this specific bucket
aws s3api put-public-access-block \
  --bucket <bucket-name> \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

Account-level Block Public Access overrides any bucket policy or ACL — this is the kill switch.

### Step 4 — Remove the offending policy / ACL

```bash
# Remove a permissive bucket policy entirely
aws s3api delete-bucket-policy --bucket <bucket-name>

# OR: replace with a policy that only allows your VPC endpoints / specific IAM principals
# (use your team's standard bucket-policy template)
```

### Step 5 — Notify and document

- If sensitive data was exposed: notify data-protection lead AND legal AND, if customer data, follow your breach-notification playbook (jurisdiction-dependent, often 72hr).
- Pull S3 server access logs for the bucket for the last 30 days. Cross-reference IPs against your allowlist.
- File an incident ticket with: bucket name, exposure window (from logs/Config history), object count, observed external accesses, locked-down timestamp.

## Verification

- `aws s3api get-public-access-block --bucket <bucket-name>` shows all four flags `true`
- `aws s3api get-bucket-policy` returns no permissive `Principal: "*"` (or the bucket has no policy)
- Test from a non-AWS network: `curl https://<bucket-name>.s3.amazonaws.com/test-object` should return 403, not the object

## Escalation

- Sensitive data exposed (customer PII, financial records, security config): page CISO AND data-protection lead immediately
- Public-write access (not just read): assume tampering until proven otherwise; engage forensics before deleting anything

## Notes / known gotchas

- Block Public Access is the kill switch. If you only fix the bucket policy and leave BPA off, a future misconfiguration can re-expose. Fix BPA at account level first.
- S3 access logs have ~1hr lag. If you locked down 5 minutes ago, the logs aren't there yet — check again in an hour for the full picture.
- A bucket with `Principal: "*"` AND `Condition: aws:SourceVpc` is NOT public — the condition restricts to your VPC. Read the full statement before lockdown; you may be locking down something legitimate.
