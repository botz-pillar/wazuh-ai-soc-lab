# CloudVault Financial — Security Profile for NotebookLM

> This document provides CloudVault Financial's complete security context for NotebookLM queries. Upload this alongside the SOC 2 Trust Services Criteria to get CloudVault-specific compliance answers.

---

## Company Overview

CloudVault Financial is a mid-size wealth management firm headquartered in Austin, TX with offices in Denver and Charlotte. ~200 employees, ~$2.1B in client assets under management, ~800 HNW individuals and 15 institutional clients.

Industry: Financial services — wealth management and financial advisory.
Revenue: ~$18M annually.

---

## Technology Stack

### Cloud Infrastructure (AWS — us-east-1)
- Account ID: 471923845612
- VPC: 10.0.0.0/16, public and private subnets across 2 AZs
- Compute: 5 EC2 instances (web-prod-01, web-prod-02, app-prod-01, finance-server-01, dev-server-01)
- Database: RDS PostgreSQL (Multi-AZ)
- Storage: 4 S3 buckets (cloudvault-client-docs [SENSITIVE], cloudvault-app-assets [public], cloudvault-backups [sensitive], cloudvault-logs)
- Other: Lambda functions, CloudFront, Route 53

### Productivity
- Google Workspace (Gmail, Drive, Docs, Sheets)
- Slack (primary communication)
- Jira (engineering project management)
- Confluence (documentation — sparse)

---

## Security Team

| Name | Role | Responsibilities |
|------|------|-----------------|
| Dana Chen | CISO | Strategy, board reporting, vendor management |
| Security Lead (you) | Security Lead | Technical security operations, incident response, compliance |
| Marcus Webb | Junior Security Analyst | Ticket triage, basic monitoring |
| Rachel Torres | Compliance Consultant (PT) | SOC 2 program management, control documentation |

---

## Current Security Controls

### What's In Place
- **CloudTrail:** Enabled (management events), logs to S3 bucket
- **GuardDuty:** Enabled 6 months ago, findings forwarded to email (not actively reviewed)
- **RDS:** Multi-AZ, encrypted at rest
- **S3:** SSE-S3 default encryption on all buckets
- **MFA:** Enabled for dana.chen and marcus.webb only
- **IAM:** 23 IAM users, role-based access partially implemented

### What's Missing
- **No SIEM** — No centralized log aggregation or correlation
- **No SOAR** — No automated incident response
- **No vulnerability scanning** — No regular scans, no patch management process
- **No incident response plan** — Response is ad-hoc
- **No formal change management** — Terraform used but no approval process
- **No vendor risk management** — No questionnaire process, no vendor assessments
- **No data classification** — Client financial data not formally classified
- **No endpoint protection** — No MDM, no software whitelisting
- **Incomplete MFA** — 4 IAM users without MFA, including VP Engineering and root account

---

## Known Security Issues (Discovered During Assessment)

### Critical
1. **Root account compromise** — Root console login from Tor exit node (Romania) without MFA on 2026-04-02. Attacker created root access key and enumerated IAM users.
2. **Contractor data exfiltration** — dev-contractor-01 escalated privileges via AssumeRole to CloudVaultAdminRole, downloaded 6 client financial documents and a database backup. Created backdoor IAM user (svc-monitoring-agent) with admin access.

### High
3. **Open security groups** — sg-dev allows SSH (22) and RDP (3389) from 0.0.0.0/0. Has been open for 8+ months.
4. **Overpermissioned service accounts** — svc-backup-agent has s3:* on all buckets (only needs cloudvault-backups). Contractor IAM policy included sts:AssumeRole to admin roles.
5. **DNS exfiltration indicators** — dev-server-01 making DNS queries consistent with DNS tunneling (data.suspicious-domain.xyz).
6. **Cryptocurrency mining** — dev-server-01 queried pool.minexmr.com, indicating possible cryptominer.

### Medium
7. **No MFA enforcement** — james.park (VP Engineering, has admin access) logs in without MFA from various locations.
8. **Public S3 bucket** — cloudvault-app-assets has public read access via bucket policy. Intentional for static assets but S3 block public access is disabled at the account level.
9. **SSH brute force** — 247 failed SSH attempts against dev-server-01 in 24 hours from 8 unique IPs.

### Informational
10. **Intern account** — intern-2026 has console access without MFA, broader permissions than needed.
11. **Service account false positives** — svc-report-gen accesses cloudvault-client-docs at 3:17 AM daily (legitimate Lambda function).

---

## Compliance Posture

### SOC 2 Type II
- **Status:** Required by institutional clients. First audit expected in ~9 months.
- **Current assessment:** ~15% of controls compliant, ~50% have gaps, ~35% unknown
- **Major gap areas:** Logging/monitoring (CC4, CC7), access control (CC6), incident response (CC7.4), change management (CC8), risk assessment (CC3), vendor management (CC9)
- **Compliance consultant:** Rachel Torres (15 hrs/week), managing tracker in spreadsheets

### Other Frameworks
- Exploring FedRAMP Moderate for potential government pension fund client (future, not urgent)

---

## Incident History

### Contractor Data Breach (April 2026)
- **Date:** 2026-04-03, 19:30-19:58 UTC (28 minutes)
- **Actor:** dev-contractor-01 (external contractor with development access)
- **Method:** IAM reconnaissance → privilege escalation (AssumeRole to admin) → S3 data exfiltration
- **Data accessed:** 6 client financial documents (Peterson Trust, Morrison Family, Chen Holdings, Wellington Partners, Nakamura Estate) + database backup
- **Persistence:** Created backdoor IAM user (svc-monitoring-agent) with admin access + additional access key
- **Anti-forensics:** Attempted to stop/delete CloudTrail (failed — trail is protected)
- **Status:** Contained (access keys disabled, backdoor user deleted, security groups closed)
- **Notification status:** Clients not yet notified. Legal counsel engagement pending.

---

## Remediation Priorities (In Progress)

1. Deploy SIEM (Wazuh) for centralized monitoring
2. Deploy SOAR (Shuffle) for automated response
3. Enforce MFA on all IAM users
4. Implement least-privilege IAM policies
5. Close all unnecessary inbound ports
6. Establish formal incident response plan
7. Build SOC 2 compliance program in Eramba
8. Implement change management process
9. Start vendor risk management program
10. Deploy vulnerability scanning
