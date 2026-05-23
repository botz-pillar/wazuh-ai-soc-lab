# runbook-search — sanitized AWS-incident runbook corpus

Course 09 Lesson 6 (RAG Over Your Runbooks) corpus.

**Learning objective:** after working with this corpus you'll have built a RAG skill that answers from runbooks with citations, refuses cleanly on out-of-corpus questions, and catches a planted-stale runbook via *independent* freshness + eval checks.

## What's here

- **`runbooks/`** — 10 sanitized AWS-incident-response runbooks, markdown, hand-written
- **`PLANTED.md`** — self-grading sheet documenting which runbook contains the planted-outdated issues (do NOT show this to Claude)
- **`EVAL-EXAMPLES.md`** — 4 worked Q/A pairs across the question taxonomy; templates for the 20-Q/A eval suite the lesson asks you to write

## The 10 runbooks

| File | Topic | Last updated |
|---|---|---|
| `iam-access-key-compromise.md` | IAM access key compromise response | 2025-11-04 |
| `guardduty-critical-finding.md` | GuardDuty HIGH/CRITICAL finding triage | 2026-02-08 |
| `s3-public-bucket-exposure.md` | S3 public-bucket lockdown | 2026-01-22 |
| `ec2-imdsv1-detection.md` | EC2 IMDSv1 → IMDSv2 migration | 2026-01-04 |
| `cloudtrail-tampering-response.md` | CloudTrail stop/delete/modify response | 2026-03-15 |
| `suspicious-assumerole-investigation.md` | Anomalous AssumeRole triage | 2026-02-19 |
| `compromised-ec2-isolation.md` | EC2 instance isolation (network + IAM) | 2026-02-26 |
| `lambda-code-injection-response.md` | Lambda function tampering response | 2026-03-02 |
| `vpc-flow-log-anomaly.md` | VPC flow log triage **— PLANTED OUTDATED** | 2024-01-15 |
| `secrets-manager-rotation-anomaly.md` | Unexpected Secrets Manager rotation | 2026-03-08 |

Filenames are semantic, not numbered — adding/removing/reordering runbooks does not ripple through references in lessons or eval suites.

Each runbook follows the same structure: frontmatter (title / last-updated / owner / severity-tier) + sections for *When to use this*, *Prerequisites*, *Procedure*, *Verification*, *Escalation*, *Notes / known gotchas*. Chunking by H2 (the lesson's default chunker) gives clean retrieval units.

## How the lesson uses this

L6 Step 1 has students copy the runbooks into their workbench:

```bash
cp lab-data/runbook-search/runbooks/*.md tools/runbook-search/fixtures/runbooks/
```

Subsequent steps build the embedding pipeline, the RAG skill with citations, the 20-Q/A eval, and the freshness check. **`vpc-flow-log-anomaly.md` contains a planted staleness** — both an old `last-updated` date AND an incorrect AWS CLI flag — that the freshness check + eval should catch (Step 6 of the lesson). See `PLANTED.md` for the answer key.

## Severity tiers

The runbooks tag themselves with `severity-tier: P1/P2/P3` in frontmatter. The intended meaning:

| Tier | Meaning |
|---|---|
| **P1** | Page on-call security NOW (or sooner). Active or imminent compromise. |
| **P2** | Investigate during business hours. Suspicious enough to triage today, not page-now. |
| **P3** | Backlog / proactive hardening. No active threat; quarterly sweep. |

Adapt to your org's escalation chain when forking — these are starter labels, not gospel.

## Platform notes

The runbooks use GNU `date -u -d 'N days ago'` syntax for time-window flags. **macOS BSD `date` does not support `-d`.** macOS users: `brew install coreutils` and substitute `gdate`, or run from a Linux shell (Cloud Shell, EC2 jumphost, Docker container).

## Sanitization

All runbooks are written for a fictional org. There are no real:

- Org / customer names
- IPs (only example ranges: `198.51.100.0/24`, `203.0.113.0/24`, `10.0.0.0/16`)
- Email addresses (`*@example.local`)
- Account IDs (`<account-id>` placeholders)

That said, the PII-sanitization step in the lesson (Step 4) is still load-bearing: when students replace the corpus with their own org's runbooks, sanitization at ingest is the gate.

## Why hand-written instead of generated

These runbooks are reusable beyond AI-CSL. A practitioner who never takes the course can fork this directory as a starter for their own org's runbook library. Generating them with Claude would have produced shaped-correct but credibility-lower content; hand-writing makes them transferable.

## Adding to the corpus

If you fork lab-data and add runbooks to your own corpus, the lesson's tooling chunks by H2. Match the structure (`## When to use this`, `## Procedure`, etc.) so the chunks land on meaningful boundaries. The freshness check looks at frontmatter `last-updated`; keep yours current.
