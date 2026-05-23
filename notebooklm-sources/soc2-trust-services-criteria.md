# SOC 2 Trust Services Criteria — Reference Guide

> Based on the AICPA Trust Services Criteria (2017, updated 2022). This document summarizes the control requirements for SOC 2 Type II reporting across all five Trust Services Categories.

---

## Overview

SOC 2 is a framework for evaluating an organization's controls related to security, availability, processing integrity, confidentiality, and privacy. It's based on the Trust Services Criteria published by the AICPA.

A SOC 2 Type II report evaluates both the **design** of controls (are they appropriate?) and their **operating effectiveness** (did they work consistently over a period of time, typically 6-12 months?).

---

## CC Series: Common Criteria (Required for all SOC 2 reports)

### CC1 — Control Environment

**CC1.1:** The entity demonstrates a commitment to integrity and ethical values.
- Evidence: Code of conduct, ethics policies, employee acknowledgment records
- What auditors look for: documented values, enforcement mechanisms, tone from the top

**CC1.2:** The board of directors demonstrates independence from management and exercises oversight of the development and performance of internal control.
- Evidence: Board meeting minutes, audit committee charter, independent board members
- What auditors look for: regular board meetings, security discussions in minutes, oversight of IT risks

**CC1.3:** Management establishes, with board oversight, structures, reporting lines, and appropriate authorities and responsibilities in the pursuit of objectives.
- Evidence: Organizational charts, job descriptions, RACI matrices, security team charter
- What auditors look for: clear security responsibilities, reporting structure to senior leadership

**CC1.4:** The entity demonstrates a commitment to attract, develop, and retain competent individuals in alignment with objectives.
- Evidence: Job descriptions with security requirements, training programs, security certifications, performance reviews
- What auditors look for: security-related hiring criteria, ongoing training, competency assessments

**CC1.5:** The entity holds individuals accountable for their internal control responsibilities in the pursuit of objectives.
- Evidence: Performance reviews that include security objectives, disciplinary procedures, accountability frameworks
- What auditors look for: consequences for control failures, recognition for security contributions

### CC2 — Communication and Information

**CC2.1:** The entity obtains or generates and uses relevant, quality information to support the functioning of internal control.
- Evidence: Threat intelligence feeds, vulnerability reports, security metrics dashboards, risk assessments
- What auditors look for: regular security information gathering, quality data sources, decision-making based on data

**CC2.2:** The entity internally communicates information, including objectives and responsibilities for internal control, necessary to support the functioning of internal control.
- Evidence: Security awareness training records, policy distribution records, team meeting notes, security bulletins
- What auditors look for: regular communication to all staff, security awareness program, policy acknowledgments

**CC2.3:** The entity communicates with external parties regarding matters affecting the functioning of internal control.
- Evidence: Customer security communications, vendor security requirements, regulatory filings, breach notification procedures
- What auditors look for: external communication policies, customer notification procedures, regulatory compliance

### CC3 — Risk Assessment

**CC3.1:** The entity specifies objectives with sufficient clarity to enable the identification and assessment of risks relating to objectives.
- Evidence: Security objectives documentation, risk appetite statement, security strategy
- What auditors look for: clear, measurable security objectives tied to business goals

**CC3.2:** The entity identifies risks to the achievement of its objectives across the entity and analyzes risks as a basis for determining how the risks should be managed.
- Evidence: Risk register, risk assessment methodology, threat modeling results, vulnerability assessments
- What auditors look for: comprehensive risk identification, regular risk assessments, documented risk analysis

**CC3.3:** The entity considers the potential for fraud in assessing risks to the achievement of objectives.
- Evidence: Fraud risk assessment, segregation of duties analysis, insider threat program
- What auditors look for: consideration of fraudulent activity, controls against internal threats

**CC3.4:** The entity identifies and assesses changes that could significantly impact the system of internal control.
- Evidence: Change management procedures, IT change advisory board records, risk assessment for changes
- What auditors look for: process for assessing risk of changes, approval workflows

### CC4 — Monitoring Activities

**CC4.1:** The entity selects, develops, and performs ongoing and/or separate evaluations to ascertain whether the components of internal control are present and functioning.
- Evidence: Continuous monitoring tools, SIEM alerts, security dashboards, internal audits, penetration test results
- What auditors look for: automated monitoring, regular assessments, SIEM deployment, alert review process

**CC4.2:** The entity evaluates and communicates internal control deficiencies in a timely manner to those parties responsible for taking corrective action, including senior management and the board of directors, as appropriate.
- Evidence: Deficiency tracking system, escalation procedures, management reports, remediation timelines
- What auditors look for: timely identification and communication of issues, remediation tracking

### CC5 — Control Activities

**CC5.1:** The entity selects and develops control activities that contribute to the mitigation of risks to the achievement of objectives to acceptable levels.
- Evidence: Control catalog, control mapping to risks, control effectiveness testing results
- What auditors look for: controls that address identified risks, evidence of effectiveness

**CC5.2:** The entity also selects and develops general control activities over technology to support the achievement of objectives.
- Evidence: IT general controls documentation, access controls, change management, backup procedures
- What auditors look for: technology controls covering access, changes, operations, and backup/recovery

**CC5.3:** The entity deploys control activities through policies that establish what is expected and in procedures that put policies into action.
- Evidence: Security policies, standard operating procedures, policy review dates, employee acknowledgments
- What auditors look for: documented policies, procedures that implement them, regular reviews

### CC6 — Logical and Physical Access Controls

**CC6.1:** The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events.
- Evidence: Firewall rules, network segmentation documentation, access control lists, encryption configurations, security group configurations
- What auditors look for: defense in depth, network segmentation, encryption at rest and in transit

**CC6.2:** Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users whose access is administered by the entity.
- Evidence: User provisioning procedures, access request forms, approval workflows, onboarding checklists
- What auditors look for: formal access request and approval process, manager authorization

**CC6.3:** The entity authorizes, modifies, or removes access to data, software, functions, and other protected information assets based on roles, responsibilities, or the system design and changes, giving consideration to the concepts of least privilege and segregation of duties.
- Evidence: Role-based access control documentation, access review records, deprovisioning procedures, principle of least privilege implementation
- What auditors look for: regular access reviews, timely deprovisioning, least privilege enforcement

**CC6.4:** The entity restricts physical access to facilities and protected information assets to authorized personnel.
- Evidence: Physical access logs, badge access records, visitor logs, data center security documentation
- What auditors look for: controlled physical access, visitor management, data center security (or cloud provider attestation)

**CC6.5:** The entity discontinues logical and physical protections over physical assets only after the ability to read or recover data and software from those assets has been diminished and is no longer required.
- Evidence: Asset disposal procedures, data destruction records, certificate of destruction
- What auditors look for: documented disposal process, verification of data destruction

**CC6.6:** The entity implements logical access security measures to protect against threats from sources outside its system boundaries.
- Evidence: Firewall configurations, IDS/IPS, WAF, DDoS protection, endpoint protection, email security
- What auditors look for: perimeter security, threat detection, incident prevention controls

**CC6.7:** The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes, and protects it during transmission, movement, or removal.
- Evidence: TLS/SSL certificates, VPN configurations, data transfer policies, DLP controls
- What auditors look for: encryption in transit, authorized data transfer procedures

**CC6.8:** The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software.
- Evidence: Antimalware deployment, endpoint protection, application whitelisting, software installation policies
- What auditors look for: malware protection, software management controls

### CC7 — System Operations

**CC7.1:** To meet its objectives, the entity uses detection and monitoring procedures to identify changes to configurations that result in the introduction of new vulnerabilities, and susceptibilities to newly discovered vulnerabilities.
- Evidence: Configuration management database, change detection tools, vulnerability scanning results, patch management records
- What auditors look for: configuration monitoring, regular vulnerability scanning, patch management process

**CC7.2:** The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts, natural disasters, and errors affecting the entity's ability to meet its objectives; anomalies are analyzed to determine whether they represent security events.
- Evidence: SIEM deployment, monitoring dashboards, alert rules, log review procedures, anomaly detection
- What auditors look for: centralized monitoring, defined alert thresholds, log retention, review process

**CC7.3:** The entity evaluates security events to determine whether they could or have resulted in a failure of the entity to meet its objectives (security incidents) and, if so, takes actions to prevent or address such failures.
- Evidence: Incident classification criteria, triage procedures, incident tickets, escalation procedures
- What auditors look for: defined incident classification, triage process, documented responses

**CC7.4:** The entity responds to identified security incidents by executing a defined incident response program to understand, contain, remediate, and communicate security incidents, as appropriate.
- Evidence: Incident response plan, IR team roster, communication templates, post-incident reviews, tabletop exercise records
- What auditors look for: documented IR plan, tested procedures, communication plans, lessons learned

**CC7.5:** The entity identifies, develops, and implements activities to recover from identified security incidents.
- Evidence: Recovery procedures, business continuity plan, disaster recovery plan, backup restoration tests
- What auditors look for: documented recovery procedures, tested backups, defined RTOs/RPOs

### CC8 — Change Management

**CC8.1:** The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures to meet its objectives.
- Evidence: Change management policy, change advisory board records, change tickets, testing documentation, approval workflows, deployment records
- What auditors look for: formal change process, testing before deployment, approval requirements, documentation

### CC9 — Risk Mitigation

**CC9.1:** The entity identifies, selects, and develops risk mitigation activities for risks arising from potential business disruptions.
- Evidence: Business impact analysis, vendor risk assessments, third-party security reviews, vendor contracts with security requirements
- What auditors look for: vendor risk management program, regular vendor assessments, contractual security requirements

**CC9.2:** The entity assesses and manages risks associated with vendors and business partners.
- Evidence: Vendor security questionnaires, vendor SOC reports review, vendor risk register, ongoing monitoring
- What auditors look for: vendor due diligence, regular reassessment, contractual protections

---

## Additional Criteria (Selected based on services provided)

### A Series — Availability

**A1.1:** The entity maintains, monitors, and evaluates current processing capacity and use of system components to manage capacity demand and to enable the implementation of additional capacity to help meet its objectives.
- Evidence: Capacity monitoring dashboards, auto-scaling configurations, capacity planning documents

**A1.2:** The entity authorizes, designs, develops or acquires, implements, operates, approves, maintains, and monitors environmental protections, software, data backup processes, and recovery infrastructure to meet its objectives.
- Evidence: Backup procedures, backup testing records, DR plan, infrastructure redundancy documentation

**A1.3:** The entity tests recovery plan procedures supporting system recovery to meet its objectives.
- Evidence: DR test results, backup restoration tests, failover test records, test schedules

### C Series — Confidentiality

**C1.1:** The entity identifies and maintains confidential information to meet the entity's objectives related to confidentiality.
- Evidence: Data classification policy, data inventory, confidential data handling procedures

**C1.2:** The entity disposes of confidential information to meet the entity's objectives related to confidentiality.
- Evidence: Data retention policy, disposal procedures, disposal records, certificate of destruction

### PI Series — Processing Integrity

**PI1.1-PI1.3:** The entity implements policies and procedures over system processing to result in products, services, and reporting to meet the entity's objectives.
- Evidence: Input validation, processing controls, output reconciliation, error handling procedures, QA processes

### P Series — Privacy

**P1.1-P8.1:** Privacy criteria covering notice, choice and consent, collection, use and retention, access, disclosure, quality, and monitoring.
- Evidence: Privacy policy, consent mechanisms, data subject access request procedures, data processing agreements, privacy impact assessments
