---
title: GuardDuty Critical Finding — Triage Runbook
last-updated: 2026-02-08
owner: secops@example.local
severity-tier: P1
---

# GuardDuty Critical Finding — Triage Runbook

For Amazon GuardDuty findings of severity 7.0+ (HIGH/CRITICAL). These are the findings that page on-call.

## When to use this

- GuardDuty has emitted a HIGH or CRITICAL severity finding via EventBridge → SNS → PagerDuty (or your equivalent path)
- The finding type is one of: `UnauthorizedAccess:*`, `Trojan:*`, `Backdoor:*`, `CryptoCurrency:*`, `PenTest:*`, `Recon:*` from non-internal sources

## Prerequisites

- Read access to the GuardDuty console in the affected region
- Read access to CloudTrail and the affected resource (EC2, S3, IAM)
- Authority to either dismiss the finding (true positive false-alarm) or escalate (true positive)

## Procedure

### Step 1 — Pull the full finding

```bash
aws guardduty get-findings \
  --detector-id <detector-id> \
  --finding-ids <finding-id> \
  --region <region>
```

Read the `Service.Action`, `Resource`, and `Service.Count` fields. The Action field tells you what type of bad behavior (NETWORK_CONNECTION, AWS_API_CALL, PORT_PROBE, etc.). The Resource field tells you the affected entity. The Count tells you how many times it happened (>1 means this isn't an anomaly blip).

### Step 2 — Classify (true positive vs false positive)

GuardDuty findings are notoriously high-precision but not 100%. Common false-positive shapes:

- **Pen-testing engagements** — schedule announced ahead of time should be in your `pentest-active` calendar. If yes, classify FP and link the engagement ticket.
- **Vendor health checks** — known IPs from monitoring vendors (Datadog, Pingdom). Maintain an allowlist; check before classifying TP.
- **Tor exit node + a single connection** — could be a real user using Tor for personal reasons. If only one connection and no follow-on activity, often FP. If repeated or paired with anomalous AWS API calls, TP.

### Step 3 — Containment (if TP)

- For a compromised EC2 instance: see runbook 07 (Compromised EC2 Instance Isolation).
- For a compromised IAM access key: see runbook 01 (IAM Access Key Compromise).
- For S3 anomalous access: see runbook 03 (S3 Public-Bucket Exposure).
- For lateral-movement findings (`UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.*`): assume both the EC2 instance AND the role the instance assumed are compromised. Quarantine both.

### Step 4 — Document

In every case:

- Mark the finding `ARCHIVED` after triage with a `Note` explaining the call:
  ```bash
  aws guardduty update-findings-feedback \
    --detector-id <detector-id> \
    --finding-ids <finding-id> \
    --feedback USEFUL \
    --comments "TP — see incident IR-2026-0408"
  ```
- File an incident ticket linking the finding ID and your follow-on actions.

## Verification

- The finding is `ARCHIVED` with a note
- For TP cases, the linked containment runbook reports complete
- No follow-on findings of the same shape from the same resource in the next 4 hours

## Escalation

- More than 3 critical findings on the same resource within 1 hour: page security lead
- Any finding type starting with `Backdoor:EC2/` or `Trojan:` on a production resource: page security lead AND infra owner immediately, do not wait for triage to complete

## Notes / known gotchas

- GuardDuty doesn't auto-correlate. Two findings on the same resource may be the same incident or two different incidents. Read the Action+Resource together.
- A finding for `Recon:IAMUser/UserPermissions` is often the FIRST signal of a key compromise — pair this runbook with runbook 01 immediately, don't wait for an explicit "Unauthorized" finding.
