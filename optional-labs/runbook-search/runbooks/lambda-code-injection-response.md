---
title: Lambda Code Injection / Tampering — Response Runbook
last-updated: 2026-03-02
owner: secops@example.local
severity-tier: P1
---

# Lambda Code Injection / Tampering — Response

For when a Lambda function's code, environment variables, or layers have been modified by an unexpected principal — supply-chain compromise, malicious-PR-merged, leaked-key-used, or insider misuse.

## When to use this

- CloudTrail shows `lambda:UpdateFunctionCode` or `lambda:UpdateFunctionConfiguration` from an unexpected principal
- The function's deployed code hash differs from your IaC-tracked hash
- Function output is anomalous (egress to unfamiliar destinations, secrets in logs, API calls outside the function's documented behavior)

## Prerequisites

- Lambda permissions (`lambda:Get*`, `lambda:Update*`, `lambda:DeleteFunction`)
- IaC source-of-truth for the function (Terraform / SAM / CDK)
- CloudTrail readable for the last 30 days

## Procedure

### Step 1 — Snapshot current state

```bash
aws lambda get-function --function-name <fn-name> --query 'Code.Location' --output text \
  | xargs curl -o /tmp/fn-suspect.zip

aws lambda get-function-configuration --function-name <fn-name> > /tmp/fn-config-suspect.json
```

Hash both for the forensics chain (`shasum -a 256 /tmp/fn-suspect.zip`).

### Step 2 — Identify the modification

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=<fn-name> \
  --start-time $(date -u -d '14 days ago' +%Y-%m-%dT%H:%M:%SZ) \
  --max-results 50
```

Look for `UpdateFunctionCode`, `UpdateFunctionConfiguration`, `PublishLayerVersion` events. Note the principal. Triage the principal as compromised (runbook 01) until proven otherwise.

### Step 3 — Disable the function

Two options depending on whether you want to preserve invocation history vs stop now:

```bash
# Option A: set reserved concurrency to 0 (function exists but cannot run)
aws lambda put-function-concurrency \
  --function-name <fn-name> \
  --reserved-concurrent-executions 0

# Option B: remove all event source mappings (function exists but no triggers)
aws lambda list-event-source-mappings --function-name <fn-name> \
  --query 'EventSourceMappings[].UUID' --output text \
  | xargs -I{} aws lambda delete-event-source-mapping --uuid {}
```

Option A is faster + reversible.

### Step 4 — Restore from IaC source-of-truth

Do NOT manually edit the function back. Re-deploy from the IaC pipeline that owns the function. This ensures you get exactly the version your repo says was production, plus a clean audit trail.

```bash
# Example with Terraform
cd <iac-repo>
terraform apply -target=aws_lambda_function.<fn-name>
```

Verify post-restore:

```bash
aws lambda get-function --function-name <fn-name> --query 'Configuration.CodeSha256'
# Compare to the SHA256 your IaC pipeline produced
```

### Step 5 — Investigate blast radius

The function may have run with the malicious code for some window. During that window:

- What did the function read? (CloudTrail for the function role's activity in the window)
- What did the function write? (S3 / DynamoDB / SNS targets the function had write access to)
- What downstream systems consumed the function's output? (Step Functions, EventBridge rules, API Gateway responses to clients)

If the function processed customer data, follow the breach-notification playbook.

### Step 6 — Re-enable

After the investigation closes:

```bash
aws lambda delete-function-concurrency --function-name <fn-name>
# or recreate event source mappings from IaC
```

Verify with a synthetic invocation against a known-good payload.

## Verification

- Function CodeSha256 matches the IaC-pipeline-produced hash
- Function metrics are normal post-re-enable
- The principal that modified the function is contained
- Incident ticket has timeline + blast-radius assessment

## Escalation

- Customer-data-handling Lambda compromised: page CISO + data-protection lead immediately
- Function had IAM `*` on critical resources (KMS keys, IAM, CloudTrail): treat as account-level compromise

## Notes / known gotchas

- A `UpdateFunctionCode` from your CI/CD role is normal IF it correlates to a recent merge in the function's repo. Always cross-reference event time with the merge log, not just the role name.
- Layer modifications can be more subtle than function code. Run `aws lambda get-function-configuration --query 'Layers'` and verify each layer ARN against IaC.
- `aws lambda update-function-configuration --environment Variables=...` can plant secrets that exfiltrate via logs. Always check env var diffs in incident response, not just code diffs.
