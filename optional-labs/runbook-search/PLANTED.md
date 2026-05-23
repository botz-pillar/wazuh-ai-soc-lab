# Planted Issues — Self-Grading Sheet

**Do not paste this file into Claude during the lesson.** It leaks the answer key. Use only after Step 6 (planted-outdated exercise) to verify your investigation found everything.

---

## Planted runbook: `vpc-flow-log-anomaly.md`

This runbook contains TWO planted issues. The lesson's eval suite + freshness check should both fire.

### Issue 1 — Stale `last-updated` date (freshness check)

The frontmatter's `last-updated` is **2024-01-15**, more than 12 months old at course launch (2026-05). The freshness check (Step 4 of the lesson) should flag this runbook as overdue.

### Issue 2 — Outdated AWS CLI flag (eval-suite catch)

In Step 4, the runbook says:

```bash
aws iam list-access-keys --username <iam-user>
```

The correct flag is `--user-name` (with hyphen). This is a real-world staleness pattern: an old runbook from when someone misremembered the flag, or copied from a 3rd-party doc that had it wrong, never got corrected.

The lesson's 20-Q/A eval should include a question like *"What command lists access keys for an IAM user?"* with the expected answer including `--user-name`. If the RAG skill answers using `vpc-flow-log-anomaly.md`'s text, it will return the wrong flag — the eval catches it.

### What "passing" the planted exercise looks like

After running the freshness check + eval suite:

1. Freshness check output flags `vpc-flow-log-anomaly.md` (and ONLY that runbook) as overdue.
2. The eval question about IAM access key listing returns the WRONG answer when the model retrieves `vpc-flow-log-anomaly.md`'s chunk; you (the student) update the runbook to use `--user-name`, re-embed, and re-run; the eval now passes.
3. Your captured "outdated runbook" finding (lesson Step 7) documents both issues with the eventID-equivalent for runbooks (the file path + line range).

### What's NOT planted (don't chase ghosts)

The other 9 runbooks are clean. They are intended to be reasonable, current AWS-incident-response runbooks. Their `last-updated` dates are within 12 months of 2026-05. Their commands and flags are correct as of AWS CLI v2.x in 2026.

If your eval flags issues in runbooks other than `vpc-flow-log-anomaly.md`, either:
- You found a real bug in a runbook (please open a PR — see CONTRIBUTING in the lab-data repo)
- Your eval question is over-fit (a common gotcha — read the question, decide if it's a real expectation or a paraphrase artifact)
