---
title: Suspicious AssumeRole — Investigation Runbook
last-updated: 2026-02-19
owner: secops@example.local
severity-tier: P2
---

# Suspicious AssumeRole — Investigation Runbook

For investigating an `sts:AssumeRole` event that looks anomalous: from a never-before-seen principal, outside business hours, into a privileged role, or as the first call after a long inactive window for the source principal.

## When to use this

- CloudWatch alarm on `AssumeRole` into a sensitive role (Admin, BreakGlass, CrossAccountAdmin)
- GuardDuty `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` finding
- Detection rule fires on AssumeRole from an unfamiliar IP / userAgent
- Audit shows a role being assumed by a principal not in the role's expected-callers list

## Prerequisites

- CloudTrail readable for the last 14 days
- IAM read access to the role and its trust policy
- Authority to disable a user / detach a role policy if needed

## Procedure

### Step 1 — Pull the AssumeRole event and immediate context

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --max-results 50 \
  --query 'Events[?contains(CloudTrailEvent, `<role-name>`)]'
```

Note: the `userIdentity.arn` of the caller (who assumed), `sourceIPAddress`, `userAgent`, and the resulting session name in `responseElements`. Save those — you will use them as pivot terms.

### Step 2 — Check the role's trust policy

```bash
aws iam get-role --role-name <role-name> --query 'Role.AssumeRolePolicyDocument'
```

Verify the calling principal is permitted by the trust policy. If a principal that wasn't in the trust policy successfully assumed the role, you have a bigger problem (something else allowed it — a recent policy change you missed). Cross-reference against `iam:UpdateAssumeRolePolicy` events in the last 30 days.

### Step 3 — Check what the assumed-role session DID

The session name from Step 1 is your key. All API calls made under the assumed role will appear in CloudTrail with `userIdentity.principalId` matching the role's principalId AND `userIdentity.sessionContext.sessionIssuer.arn` matching the role's ARN, and `userIdentity.arn` ending in `:<session-name>`.

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=<session-name> \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --max-results 200
```

Look for: data-plane reads (`s3:GetObject` on sensitive buckets), persistence (`iam:Create*`, `iam:Attach*`), detection-control tampering (`cloudtrail:StopLogging`, `config:DeleteConfigRule`), or unusual cross-region calls.

### Step 4 — Investigate the calling principal

If the caller was a human IAM user: check their recent activity for compromise indicators (see runbook 01).
If the caller was an EC2 instance role: see runbook 07 (Compromised EC2 Instance Isolation) on the instance.
If the caller was a cross-account principal: page the source account's owner.

### Step 5 — Containment (if confirmed compromise)

**Revoke active sessions** using the AWS-documented `AWSRevokeOlderSessions` pattern — attach an inline policy to the role that denies all actions when the session token was issued before "now":

```bash
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
aws iam put-role-policy \
  --role-name <role-name> \
  --policy-name AWSRevokeOlderSessions \
  --policy-document "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [{
      \"Effect\": \"Deny\",
      \"Action\": \"*\",
      \"Resource\": \"*\",
      \"Condition\": {
        \"DateLessThan\": {\"aws:TokenIssueTime\": \"${NOW}\"}
      }
    }]
  }"
```

This is what the IAM console's "Revoke active sessions" button does. Sessions issued before `NOW` are denied; new sessions assumed after this point work normally. Remove the policy after the incident closes.

Other containment moves:
- Disable the calling principal's credentials (runbook 01 if it's an IAM user).
- For a service role: detach from the resource (e.g., disassociate the IAM instance profile from a compromised EC2 instance — runbook 07).
- File an incident ticket linking all event IDs.

### Step 6 — Document and update detections

If this turned out to be a true positive, add the IPs / userAgents observed to your IOC list. If false positive, add the calling principal to the role's expected-callers allowlist so the same alarm doesn't fire next time.

## Verification

- The assumed-role session's `last-active` timestamp is in the past and not recurring
- No follow-on AssumeRole calls from the same caller in the last 4 hours
- Detection rule documented as TP/FP

## Escalation

- Privilege escalation observed (CreateUser, AttachUserPolicy with Admin): page CISO immediately
- AssumeRole into the org-management account from a member account: organization-level incident; engage CIRT

## Notes / known gotchas

- A single AssumeRole event without follow-on activity is not necessarily an incident; could be an automation that was about to do work and got interrupted. Look at session activity, not just the AssumeRole call itself.
- Service-linked roles (those starting with `AWSServiceRoleFor*`) get assumed by the AWS service automatically; don't chase those unless the activity under them is anomalous.
- Cross-account AssumeRole legitimately happens for vendors (Snowflake, Datadog, etc.). Maintain a vendor-role inventory so you don't burn cycles on routine access.
