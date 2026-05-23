# 20-Q/A Eval — Worked Examples

A *good* eval suite probes the corpus the way an auditor probes your runbook library: did the right facts come back, with the right citations, and did the system refuse cleanly when asked something it shouldn't know?

This file shows 4 worked Q/A pairs spanning the question taxonomy. Use them as templates. Your eval suite (per Course 09 Lesson 6 Step 5) should have ~20 pairs distributed across these categories.

---

## Category 1 — Recall (CLI flag / command syntax)

These probe specific facts the corpus must get right.

```python
{
    "question": "What AWS CLI command lists access keys for an IAM user?",
    "must_contain": ["aws iam list-access-keys", "--user-name"],
    "must_cite_chunk_containing": "aws iam list-access-keys --user-name",
    "category": "recall",
}
```

This question is the planted-issue catch. The eval will return both the correct answer (from `iam-access-key-compromise.md`) AND the wrong answer (from `vpc-flow-log-anomaly.md` — `--username`). The student's RAG implementation has to disambiguate (top-k scoring, recency weighting, voting across chunks).

---

## Category 2 — Decision criteria

These probe the *judgment* a runbook encodes, not just the syntax.

```python
{
    "question": "When investigating a compromised EC2 instance, should I snapshot the disk first or isolate the instance from the network first?",
    "must_contain": ["snapshot first", "default"],
    "must_not_contain": ["always isolate first"],
    "must_cite_chunk_containing": "Default: snapshot first",
    "category": "decision",
}
```

Tests whether the model retrieves the actual decision rule (snapshot first by default, isolate first only if exfil is active) and not a paraphrase that loses the nuance.

---

## Category 3 — Cross-runbook reference

Probes whether top-k retrieval surfaces the right *graph* of runbooks, not a single chunk.

```python
{
    "question": "If I find that CloudTrail was stopped by a principal, what runbook should I trigger next?",
    "must_contain": ["iam-access-key-compromise", "IAM"],
    "must_cite_chunk_containing": "iam-access-key-compromise",
    "category": "cross-runbook",
}
```

Tests retrieval over the cross-references `cloudtrail-tampering-response.md` makes to `iam-access-key-compromise.md`.

---

## Category 4 — Out-of-corpus refusal (REQUIRED — at least 3 of these)

These probe the "I don't know" guardrail. The skill MUST refuse to answer; if it confidently invents a procedure for a topic not in the corpus, your hard-threshold tuning is wrong.

```python
{
    "question": "What's the procedure for restoring a dropped Aurora PostgreSQL database from a point-in-time snapshot?",
    "must_refuse": True,
    "category": "out-of-corpus",
    "rationale": "RDS / Aurora is not in the corpus. Skill must say 'I don't know' and tell the user to escalate to on-call DBA.",
}

{
    "question": "How do I rotate a KMS key that's been disclosed?",
    "must_refuse": True,
    "category": "out-of-corpus",
}

{
    "question": "What's the SOC 2 control evidence schema for AWS access reviews?",
    "must_refuse": True,
    "category": "out-of-corpus",
    "rationale": "Compliance content is not in this corpus.",
}
```

If your skill answers these confidently, your cosine threshold is too low. The lesson's default 0.55 is calibrated against this corpus + bge-small-en-v1.5 embeddings; if you change either, retune.

---

## What goes in your remaining ~16 questions

Distribute across the 10 runbooks roughly proportional to their content surface (each runbook has ~6 distinct probe surfaces — when-to-use, prerequisite, CLI/flag, decision rule, verification, escalation). Suggested distribution:

- **Recall (8 questions):** specific CLI flags / commands per runbook (one per runbook, skip the planted runbook — that one's caught by Category 1's question).
- **Decision criteria (4 questions):** judgment calls from `guardduty-critical-finding.md`, `s3-public-bucket-exposure.md`, `suspicious-assumerole-investigation.md`, `secrets-manager-rotation-anomaly.md`.
- **Cross-runbook (2 questions):** trigger-graph traversals like the `cloudtrail-tampering-response.md` → `iam-access-key-compromise.md` example above.
- **Gotcha (2 questions):** edge cases from the "Notes / known gotchas" sections (the Hyperplane ENI gotcha in `vpc-flow-log-anomaly.md`, the BPA-as-kill-switch in `s3-public-bucket-exposure.md`).
- **Refusal (3+ questions):** topics deliberately not covered (RDS, KMS, compliance, SOC 2, etc.).

Total: 19-20.

---

## How to grade your eval

Three pass conditions per question:

1. **Citation resolves.** The cited `source_path:line_range` opens to a real chunk in your corpus. The lesson's citation validator handles this automatically; if it fails, your model fabricated a citation.
2. **`must_contain` strings appear in the answer text.** Substring match, case-insensitive.
3. **`must_not_contain` strings are absent.**

For refusal questions, success is the model returning a refusal phrase ("I don't know," "this isn't covered in the runbooks," "escalate to on-call") AND not citing any chunk above the threshold.

CI fails the build if any single question fails any condition. Re-embed + re-run after corpus changes.
