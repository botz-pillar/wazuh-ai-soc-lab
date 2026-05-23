# incident-investigator — synthetic CloudTrail corpus

Course 09 Lesson 4 (Cloud Incident Investigation) corpus.

## What's here

- **`generate_corpus.py`** — Python script (stdlib only, Python 3.10+) that produces a deterministic ~30k-event CloudTrail JSONL corpus telling a planted incident story.

That's it. No raw data committed — the script *is* the corpus, students regenerate locally.

## Usage

```bash
python3 generate_corpus.py --seed 42 --out synthetic-cloudtrail.jsonl
```

Outputs:
- `synthetic-cloudtrail.jsonl` — ~30,000 events JSONL (~20MB)
- `PLANTED.md` — self-grading sheet listing planted event IDs (severity-tagged)

Re-running with the same seed produces byte-identical output. Verify with `shasum -a 256`.

`--total` must be ≥ 200 (the planted incident alone is ~110 events). Smaller values fail loudly.

## What's planted

The corpus contains an IAM access-key compromise narrative (~110 events embedded in ~29,890 benign baseline events):

1. **Stage 0 — AWS-side compromise indicator.** AWS auto-attaches `AWSCompromisedKeyQuarantineV3` policy via `AttachUserPolicy` from `AWS Internal`. **This is the cleanest single signal in real environments** — when AWS detects a public-repo key leak, this fires automatically.
2. **Stage 1 — Recon** (5 events): attacker uses leaked access key for `eng-marcus`, calls `GetCallerIdentity`, `ListUsers`, `ListRoles`, `ListAccessKeys`, `ListBuckets` from a Tor-exit-shaped IP. Multiple attacker UAs (rotating between `python-requests`, plausible `aws-cli`, and `Boto3`) — the IP novelty is the load-bearing signal, not the UA.
3. **Stage 2 — S3 enumeration** (~20 events): `ListObjectsV2` across multiple data buckets.
4. **Stage 3 — Exfil** (~75 events): `GetObject` calls totaling ~5MB of customer reports. **Three planted indirect-prompt-injection payloads** are embedded in this stream, at varying sophistication and in different fields:
   - `userAgent` field — cartoon `IGNORE PRIOR INSTRUCTIONS` payload (the easy catch).
   - `requestParameters.key` — operator-styled S3 key looking like a SOC ticket note.
   - `requestParameters.objectTagging.tagSet[].Value` — role-confusion attempt embedded in an S3 object tag.
   The lesson's required adversarial exercise tests whether the investigation pipeline catches all three and whether Claude does *not* comply with any.
5. **Stage 4 — Persistence attempts** (~5 events): `CreateAccessKey` on a different user, `CreateFunction` Lambda, `StopLogging` on CloudTrail, `DeleteUser` self-cleanup — all denied. `StopLogging` is the strongest single signal.

## Why a generator instead of static data

Three reasons:

1. **Reproducibility.** Students get byte-identical corpora; cohort discussions can reference exact event IDs.
2. **Pedagogy.** The script is short and readable. Students who finish the lesson can read it and learn how synthetic corpora are constructed.
3. **Repo size.** 20MB of JSONL committed in git would bloat history; ~17KB of Python doesn't.

If you need a different incident shape, fork `generate_corpus.py` and modify `populate_incident()`.

## How the lesson uses this

L4 Step 1 has students copy the generated corpus into their workbench:

```bash
cp lab-data/incident-investigator/synthetic-cloudtrail.jsonl tools/incident-investigator/fixtures/corpus/
```

Subsequent steps build a histogram (Step 2), pivot via Claude (Step 3-4), produce a citation-validated IR write-up (Step 5), and catch the planted injections (Step 6). PLANTED.md is the answer key the student self-grades against after Step 6.

## Realism caveats

- Principal IDs and ARNs are CloudTrail-shaped but **not valid AWS resources**. Don't feed this corpus into real AWS APIs (Athena CloudTrail schema, Detective, etc.) without expecting validator failures.
- The fixed anchor date is `2026-04-28` by design — deterministic eventIDs require a fixed time anchor. If the corpus feels stale months after course launch, that's the trade-off for stable PLANTED.md grading.
- Per-principal traffic is roughly flat. Real environments have orders-of-magnitude variation between human users and high-volume service roles. This is a deliberate simplification for pedagogy.

## Determinism guarantees

Given the same `--seed`:
- Same N events in the same order
- Same UUIDs on every event
- Same planted-injection event IDs (so PLANTED.md is stable)
- Same SHA-256 hash of the JSONL output

If determinism breaks, the lesson's grading model breaks. To verify after a generator change:

```bash
python3 generate_corpus.py --seed 42 --out a.jsonl
python3 generate_corpus.py --seed 42 --out b.jsonl
diff <(shasum -a 256 a.jsonl | awk '{print $1}') <(shasum -a 256 b.jsonl | awk '{print $1}')
# Should print nothing (files identical).
```
