# Vendor Security Evaluation Guide

> Reference guide for evaluating vendor security posture. Upload to NotebookLM alongside vendor questionnaire responses for AI-assisted analysis.

---

## When to Evaluate

Evaluate vendor security before:
- Onboarding any new SaaS tool or service
- Renewing contracts with existing vendors who process sensitive data
- Expanding scope of an existing vendor relationship
- Any vendor change that affects compliance (SOC 2, FedRAMP, HIPAA, etc.)

---

## Evaluation Framework

### Tier 1: Must-Have (Deal-Breakers)

These are non-negotiable for any vendor processing sensitive data:

**Data Encryption**
- Encryption at rest (AES-256 or equivalent)
- Encryption in transit (TLS 1.2+)
- Key management practices documented

**Access Control**
- Multi-factor authentication supported
- Role-based access control
- SSO integration (SAML 2.0 or OIDC)

**Compliance**
- SOC 2 Type II report available (Type I is a yellow flag — they're early in their journey)
- Relevant industry compliance (HIPAA BAA if healthcare data, FedRAMP if government)
- Regular third-party penetration testing (within last 12 months)

**Data Handling**
- Customer data segregation (logical or physical)
- Data residency options (where is data stored geographically?)
- Data deletion upon contract termination (written policy)
- No unauthorized data sharing

**Incident Response**
- Documented incident response plan
- Customer notification within 24 hours (72 hours is common but slow)
- History of data breaches disclosed

### Tier 2: Important (Influence Decision)

**Infrastructure Security**
- Cloud provider and deployment model
- Network segmentation
- WAF and DDoS protection
- Vulnerability management program (scan frequency, patch timelines)

**Employee Security**
- Background checks
- Security awareness training
- Principle of least privilege for internal access
- Number of employees with production access

**Business Continuity**
- Uptime SLA (99.9% minimum)
- Disaster recovery plan (tested)
- RTO and RPO defined and reasonable
- Backup strategy

**Change Management**
- Formal change management process
- Code review and testing before deployment
- Rollback capabilities

### Tier 3: Nice-to-Have (Differentiators)

- Bug bounty program
- SOC 3 or ISO 27001 certification
- Cyber insurance
- Customer security assessment program
- Dedicated customer success manager with security background
- Transparent security practices (public security page, changelog)

---

## Red Flags

Watch for these in vendor questionnaire responses:

- **"We follow industry best practices"** — without specifics, this means nothing
- **"Encrypted using the latest standards"** — ask: which algorithm? Which TLS version?
- **No SOC 2 report** — "we're pursuing it" means they don't have it yet
- **"Customer data is never accessed"** — unrealistic. Better answer: "access is logged and restricted to authorized support staff"
- **72-hour incident notification** — legal minimum in some jurisdictions, but 24 hours is the standard for responsible vendors
- **No penetration testing** — or "we do internal testing" without third-party validation
- **"We use [cloud provider] security"** — shared responsibility model means THEY are responsible for their configuration
- **Vague subprocessor list** — they should know exactly who touches your data

---

## Evaluation Output

After review, produce:

1. **Risk rating:** Low / Medium / High / Unacceptable
2. **Key findings:** Top 3-5 concerns from the questionnaire
3. **Follow-up questions:** Specific items that need clarification
4. **Recommendation:** Approve / Approve with conditions / Reject
5. **Conditions (if applicable):** What must change before approval

---

## For CloudVault Financial Specifically

When evaluating vendors for CloudVault, pay special attention to:

- **SOC 2 alignment** — CloudVault is pursuing SOC 2 Type II. Vendors should be at least as mature.
- **FedRAMP readiness** — CloudVault is exploring government clients. Vendors on the FedRAMP path are preferred.
- **Financial data handling** — CloudVault processes client financial records and PII. Vendors must demonstrate appropriate data handling.
- **Data residency** — US-based storage preferred for regulatory simplicity.
- **Integration security** — How does the vendor's API authenticate? Is data encrypted between CloudVault and the vendor?
