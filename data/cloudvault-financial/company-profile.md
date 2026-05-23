# CloudVault Financial — Company Profile

> This is your client briefing. Read this before you start any course. You'll reference it throughout the entire curriculum.

---

## Company Overview

**CloudVault Financial** is a mid-size wealth management firm headquartered in Austin, TX with offices in Denver and Charlotte. Founded in 2014, they manage approximately $2.1B in client assets for high-net-worth individuals and small institutional clients.

**Employees:** ~200 (150 in Austin, 25 each in Denver and Charlotte)
**Annual revenue:** ~$18M
**Industry:** Financial services — wealth management and financial advisory
**Clients:** ~800 high-net-worth individuals, 15 institutional clients (pension funds, endowments)

---

## Why You're Here

CloudVault Financial is growing fast and their security hasn't kept pace. They recently onboarded three large institutional clients who require SOC 2 Type II compliance. Their first audit is in 6 months.

You've been brought on as the security lead to modernize their security operations. The CISO (Dana Chen) hired you specifically because you know how to use AI to move fast. The security team is small — just you, one junior analyst (Marcus Webb), and a part-time compliance consultant.

**Your mandate from Dana:**
1. Get visibility into what's happening across the cloud environment (they're flying blind)
2. Build detection and response capabilities (today it's "someone notices something in an email")
3. Prepare for the SOC 2 audit (currently tracking compliance in spreadsheets)
4. Do it with a 3-person team and a limited budget (open-source tools preferred)

---

## People

| Name | Role | Notes |
|------|------|-------|
| **Dana Chen** | CISO | Reports to CEO. 12 years in security, came from a Fortune 500. Smart but stretched thin across strategy, board reporting, and vendor management. Needs you to own the technical side. |
| **You** | Security Lead | New hire. This is your engagement. |
| **Marcus Webb** | Junior Security Analyst | 1 year experience. Eager but green. Handles ticket triage and basic monitoring. Needs mentoring and better tools. |
| **Rachel Torres** | Compliance Consultant | Part-time (15 hrs/week). Manages the SOC 2 spreadsheet. Knows the frameworks but not the infrastructure. Frustrated that engineering won't give her evidence. |
| **James Park** | VP of Engineering | Runs a 40-person engineering team. Cooperative but protective of his team's time. Will push back if security requests slow down deployments. |
| **Priya Sharma** | DevOps Lead | Reports to James. Manages all AWS infrastructure. Your best ally on the engineering side — she cares about security but hasn't had time to implement it properly. |

---

## Technology Stack

### Cloud Infrastructure (AWS — us-east-1)
- **Account ID:** 471923845612 (fictional)
- **VPC:** 10.0.0.0/16 with public and private subnets across 2 AZs
- **Compute:**
  - `web-prod-01`, `web-prod-02` — Public-facing web servers (nginx + Node.js), t3.medium
  - `app-prod-01` — Application server (internal API), t3.large
  - `finance-server-01` — Financial data processing (sensitive PII + financial records), m5.large
  - `dev-server-01` — Development/staging, t3.small (this one has problems)
- **Database:** RDS PostgreSQL (Multi-AZ) — `cloudvault-prod-db`
- **Storage:**
  - `cloudvault-client-docs` — Client financial documents (HIGHLY SENSITIVE)
  - `cloudvault-app-assets` — Application static assets (public)
  - `cloudvault-backups` — Database backups (sensitive)
  - `cloudvault-logs` — Centralized log bucket (newly created, mostly empty)
- **Other:** Lambda functions for report generation, CloudFront for the client portal, Route 53

### Security (Current State — Before You Arrived)
- **GuardDuty:** Enabled 6 months ago. Findings go to an email inbox nobody checks regularly. 47 unreviewed findings.
- **CloudTrail:** Enabled (management events only). Logs go to `cloudvault-logs` S3 bucket. No one analyzes them.
- **IAM:** 23 IAM users. At least 5 have admin access who shouldn't. 3 service accounts with overly broad permissions. No MFA on 4 accounts.
- **Security Groups:** `sg-web-public` allows 0.0.0.0/0 on ports 80/443 (expected). `sg-dev` allows 0.0.0.0/0 on port 22 (NOT expected — Priya "temporarily" opened it 8 months ago).
- **No SIEM.** No centralized alerting. No automation. No incident response plan.
- **Encryption:** S3 buckets use SSE-S3 (default). RDS encrypted at rest. No KMS key rotation policy.

### Productivity & Communication
- Google Workspace (Gmail, Drive, Docs, Sheets)
- Slack (primary communication)
- Jira (engineering project management)
- Confluence (documentation — sparse and outdated)

---

## Compliance Posture

**Required:** SOC 2 Type II (Trust Services Criteria: Security, Availability, Confidentiality)
**Status:** Tracking in a Google Sheet. Rachel (compliance consultant) estimates they're ~40% compliant. Major gaps in logging, monitoring, access reviews, incident response, and change management.
**Audit timeline:** First observation period begins in ~3 months. Type II report expected in ~9 months.
**Other frameworks on the radar:** Exploring FedRAMP Moderate for a potential government pension fund client (future — not urgent).

---

## Known Issues (What You'll Discover)

These are the problems buried in the data. Members will find them through the courses:

1. **The 3am S3 access** — IAM user `svc-report-gen` is accessing `cloudvault-client-docs` at 3:17 AM daily. This is actually a Lambda function using a service account, but the access pattern looks suspicious until you investigate. Teaches: not everything that looks bad is bad.

2. **The root login** — Someone logged into the root account from an IP geolocated to Romania at 11:42 PM on a Tuesday. Root doesn't have MFA. This is a real finding. Teaches: critical alerts, root account security.

3. **The open security group** — `sg-dev` has SSH open to 0.0.0.0/0. It's been that way for 8 months. There are SSH brute force attempts in the logs. None have succeeded (yet). Teaches: misconfigurations as attack surface.

4. **The overpermissioned service accounts** — `svc-backup-agent` has full S3 admin permissions when it only needs read/write to `cloudvault-backups`. Teaches: least privilege, IAM reviews.

5. **The unreviewed GuardDuty findings** — 47 findings, 6 months of accumulated alerts. 3 are high-severity (cryptocurrency mining recon, unauthorized API calls, DNS exfiltration attempt). 12 are medium. The rest are low/informational. Teaches: alert fatigue, prioritization.

6. **The incident** — A sequence hidden in the CloudTrail data: an attacker used a leaked access key (from `dev-server-01`, which has overly permissive IAM) to enumerate S3 buckets, assume a more privileged role, and download files from `cloudvault-client-docs`. Teaches: full attack chain reconstruction, incident response.

---

## How This Maps to Courses

| Course | What You're Doing at CloudVault |
|--------|-------------------------------|
| 1: Start Here | Read the briefing, assess the environment, find your first issues |
| 2: AI Quick Wins | Triage the backlog — 47 findings, compliance gaps, write reports for Dana |
| 3: Wazuh + AI | Deploy centralized monitoring so you're not flying blind |
| 4: Shuffle | Automate response so Marcus isn't manually handling every alert |
| 5: Attack Range | Test whether your detection and response actually works |
| 6: Portfolio | Package the CloudVault engagement for your professional portfolio |
| 7: Eramba GRC | Build the compliance program Rachel has been begging for |
| 8: Bring AI to Work | Take what you learned at CloudVault to YOUR real company |
