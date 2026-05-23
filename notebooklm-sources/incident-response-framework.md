# Incident Response Framework

> Based on NIST SP 800-61 Rev. 2 (Computer Security Incident Handling Guide). Adapted for cloud-native environments using AWS services.

---

## IR Phases

### Phase 1: Preparation

**Before an incident happens:**

- Documented incident response plan (who does what)
- IR team roster with contact information and escalation paths
- Communication templates (internal notification, customer notification, regulatory notification)
- Tooling ready: SIEM access, log sources configured, forensic tools available
- Playbooks for common incident types (data breach, ransomware, unauthorized access, DDoS)
- Regular tabletop exercises (quarterly recommended)
- Relationships established with legal counsel, law enforcement contacts, forensic firms

**For AWS environments specifically:**
- CloudTrail enabled in all regions (management AND data events for sensitive buckets)
- GuardDuty enabled
- VPC Flow Logs enabled
- S3 access logging enabled for sensitive buckets
- CloudWatch alarms for critical thresholds
- IAM access analyzer configured
- AWS Config rules for compliance monitoring

### Phase 2: Detection and Analysis

**Identify that an incident is occurring:**

Detection sources in AWS:
- GuardDuty findings (unauthorized access, malware, data exfiltration)
- CloudTrail anomalies (unusual API calls, new regions, privilege escalation)
- CloudWatch alarms (CPU spikes, unusual network traffic, billing anomalies)
- VPC Flow Logs (unexpected traffic patterns, data transfer volumes)
- S3 access logs (unusual access patterns, bulk downloads)
- External reports (customer complaints, threat intelligence, law enforcement notification)
- Employee reports (phishing, suspicious behavior, social engineering)

**Analysis workflow:**

1. **Triage:** Is this a real incident or a false positive? Assign initial severity.
   - Critical: Active data breach, ransomware, compromised privileged account
   - High: Unauthorized access to sensitive systems, active exploitation attempt
   - Medium: Policy violation, suspicious activity requiring investigation
   - Low: Minor policy violation, informational alert

2. **Scope:** What systems, data, and users are affected?
   - Which AWS accounts and regions?
   - Which EC2 instances, S3 buckets, databases?
   - Which IAM users or roles were involved?
   - What data was potentially accessed or exfiltrated?
   - What's the time window?

3. **Impact:** What's the business impact?
   - Customer data exposure (triggers notification requirements)
   - Financial loss (direct or regulatory)
   - Operational disruption
   - Reputational risk
   - Regulatory exposure (SOC 2, GDPR, state breach notification laws)

### Phase 3: Containment

**Stop the bleeding — limit the damage without destroying evidence.**

Short-term containment (immediate):
- Disable compromised IAM access keys: `aws iam update-access-key --user-name USER --access-key-id KEYID --status Inactive`
- Revoke active sessions: `aws iam put-user-policy --user-name USER --policy-name DenyAll --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'`
- Isolate compromised instances (modify security group to deny all traffic): `aws ec2 modify-instance-attribute --instance-id i-xxx --groups sg-isolate`
- Block known malicious IPs via NACLs or security groups
- Disable any backdoor accounts discovered

Long-term containment (stabilize):
- Rotate all potentially compromised credentials
- Patch exploited vulnerabilities
- Implement additional monitoring on affected systems
- Preserve evidence (snapshot EBS volumes, export CloudTrail logs to isolated bucket)

**Evidence preservation (critical):**
- DO NOT terminate or reboot compromised instances until forensic images are captured
- Snapshot EBS volumes: `aws ec2 create-snapshot --volume-id vol-xxx --description "IR evidence"`
- Export CloudTrail logs to a separate, locked-down S3 bucket
- Screenshot relevant console pages (GuardDuty findings, CloudTrail events)
- Document everything with timestamps

### Phase 4: Eradication

**Remove the threat completely:**

- Delete backdoor accounts, access keys, and roles created by the attacker
- Remove unauthorized security group rules
- Patch vulnerabilities that enabled the attack
- Rebuild compromised instances from known-good AMIs (don't just clean them — rebuild)
- Rotate ALL credentials that could have been exposed
- Verify no additional persistence mechanisms (scheduled tasks, Lambda functions, EC2 user data scripts)

### Phase 5: Recovery

**Restore normal operations:**

- Bring cleaned/rebuilt systems back online gradually
- Monitor closely for signs of re-compromise (the attacker may try again)
- Verify system integrity before reconnecting to production
- Restore from backups if necessary (verify backup integrity first)
- Update monitoring to catch the specific attack pattern if it recurs
- Communicate with stakeholders that normal operations have resumed

### Phase 6: Post-Incident Activity

**Learn from it:**

1. **Incident report:** Complete documentation of what happened, when, how, impact, and response
2. **Root cause analysis:** What allowed this to happen? (Not just the vulnerability — the systemic gap)
3. **Lessons learned meeting:** What went well? What was difficult? What needs to change?
4. **Remediation tracking:** Assign and track all improvement actions with deadlines
5. **Metric updates:** Update incident metrics (MTTD, MTTR, incidents by type/severity)
6. **Plan updates:** Revise the IR plan based on lessons learned
7. **Training:** Address any skill gaps identified during the response

---

## Communication During Incidents

### Internal Communication

**Immediate (within 1 hour):**
- IR team members
- CISO / Security leadership
- Affected system owners

**Within 4 hours:**
- CEO / Executive leadership (for High/Critical incidents)
- Legal counsel (if data breach suspected)
- PR / Communications (if external communication may be needed)

**Within 24 hours:**
- Board of directors (for Critical incidents)
- All-staff communication (if warranted)

### External Communication

**Regulatory notification:**
- Varies by jurisdiction and data type
- GDPR: 72 hours to supervisory authority
- US state breach notification laws: varies (30-90 days typically)
- SEC: 4 business days for material cybersecurity incidents (public companies)
- PCI DSS: within 72 hours to card brands

**Customer notification:**
- Required when personal data is confirmed compromised
- Should include: what happened, what data was affected, what you're doing about it, what they should do
- Tone: honest, clear, non-defensive

**Law enforcement:**
- Consider engaging for criminal activity (data theft, ransomware, insider threats)
- Preserve evidence for potential prosecution
- FBI IC3 for cyber crime: ic3.gov

---

## Incident Types and Quick-Reference Playbooks

### Unauthorized Access (Compromised Credentials)
1. Identify compromised account(s)
2. Disable access keys and revoke sessions
3. Check CloudTrail for all actions taken by the compromised account
4. Identify any persistence mechanisms created
5. Assess what data was accessed
6. Rotate credentials, close access gaps
7. Root cause: how were credentials compromised?

### Data Exfiltration
1. Identify what data was accessed/downloaded
2. Contain: revoke access, isolate affected systems
3. Determine the scope: how much data, how sensitive, how many individuals affected
4. Engage legal for breach notification assessment
5. Preserve evidence of the exfiltration
6. Notify affected parties as required
7. Root cause: why could this data be accessed?

### Ransomware
1. Isolate affected systems immediately (network-level isolation)
2. Determine scope: what's encrypted, what's still clean
3. DO NOT pay the ransom (consult with legal and law enforcement)
4. Check backup integrity — can you restore?
5. Rebuild affected systems from clean images
6. Restore data from backups
7. Root cause: initial access vector?

### Cryptomining
1. Identify affected instances
2. Isolate and snapshot for evidence
3. Terminate the mining process
4. Rebuild instance from clean AMI
5. Assess: was this the only compromise, or a symptom of broader access?
6. Root cause: how did the attacker get compute access?
