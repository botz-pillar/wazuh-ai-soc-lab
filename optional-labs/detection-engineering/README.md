# detection-engineering — labeled Windows/Sysmon corpus

Course 09 Lesson 3 (AI-Augmented Detection Engineering) corpus.

**Learning objective:** after working with this corpus you'll have written 2 Sigma rules with measured FP rates against a labeled ground-truth — the discipline of "AI authors, deterministic tools convert, ground-truth labels validate."

## What's here

- **`generate_corpus.py`** — Python script (stdlib only) that produces a deterministic ~5000-event labeled JSONL corpus
- **`labels.yaml`** — static reference documenting the 8 MITRE ATT&CK techniques planted in the corpus

That's it. No raw data committed — students regenerate locally.

## Why JSON-native instead of EVTX-ATTACK-SAMPLES directly

The lesson's intended source-of-inspiration is Bousseaden's [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES). We don't ship that directly because:

1. **Binary EVTX is friction.** Adding `.evtx → JSONL` conversion (via `python-evtx` / `evtxECmd`) is a setup hurdle that doesn't serve the pedagogy.
2. **EVTX-ATTACK-SAMPLES has no benign baseline OR benign near-misses.** To measure FP rate meaningfully you need both. Synthesizing them keeps everything in one corpus.
3. **Sigma rules don't care about wire format.** A Sigma rule targets field names; pySigma converts to the SIEM dialect. JSON or EVTX is invisible to the rule.

If you want to extend with real EVTX data, clone EVTX-ATTACK-SAMPLES, convert to JSONL, and concatenate. The labeling schema (`_labels.{technique, malicious, near_miss}`) is the contract.

## Usage

```bash
# Generate the labeled corpus (with _labels for grading):
python3 generate_corpus.py --seed 42 --out windows-sysmon.jsonl

# Generate WITHOUT labels — feed this version to Claude during FP analysis:
python3 generate_corpus.py --seed 42 --strip-labels --out for-llm.jsonl
```

Re-running with the same seed produces byte-identical output.

`--total` controls corpus size. Default 5000; minimum 500.

## What's in the corpus

A 5000-event corpus at default settings contains roughly:

| Class | Count | Description |
|---|---|---|
| Benign baseline | ~4860 | Normal Windows/Sysmon activity (process / network / registry / DNS) across 50+ hosts and 30+ users |
| **Benign near-misses** | ~64 | **Legitimate activity that LOOKS attack-shaped** — MDM-issued PowerShell `-EncodedCommand`, app-installer `schtasks`, Spotify/Slack/Teams Run-key autorun, login-script SMB `net use`, etc. **This is the FP surface that makes FP-rate measurement meaningful.** |
| Labeled malicious | ~80 | 8 MITRE ATT&CK techniques × ~8 events each, with **2-3 variant shapes per technique** so rules must match the *technique* not the *constants* |

## Event ID coverage

Each technique emits the Sysmon event ID(s) real Sigma rules for that technique target:

| EID | Type | Used by |
|---|---|---|
| 1 | ProcessCreation | T1059.001, T1003.001, T1218.005, T1053.005, T1547.001 (paired), T1021.002 (paired), T1555.003 + most benign |
| 3 | NetworkConnect | T1021.002 (paired with the process event) + benign baseline |
| 13 | RegistryEvent (Value Set) | T1547.001 (paired with the process event) + benign baseline + near-misses |
| 22 | DnsQuery | T1071.004 + benign baseline + near-misses |

T1547.001 and T1021.002 each emit **paired events** (process + registry / process + network) — students learn that some techniques span multiple event IDs and that a complete detection joins on `host` + timestamp window.

Each EID 1 event also carries `process.original_file_name` and `process.hash.sha256` so Sigma rules can target renamed-binary scenarios (real Sigma rules do).

## Technique variants

Variants per technique force students to write *patterns* rather than *string matches*:

- **T1059.001** — three variants: `-EncodedCommand`, `-enc` short-form, `IEX (New-Object Net.WebClient).DownloadString(...)`. Different parents (cmd, Office apps, explorer).
- **T1003.001** — three variants: `comsvcs.dll MiniDump`, **renamed-procdump scenario** (Image is `update-helper.exe` but `OriginalFileName` is `procdump.exe`), PowerShell `Out-Minidump`. Multiple users (SYSTEM, admins, service account).
- **T1218.005** — varied parents (WINWORD, EXCEL, OUTLOOK, chrome, cmd, explorer); varied URL shapes (named domains + random subdomains on cheap TLDs).
- **T1053.005** — two variants: `schtasks.exe` with three trigger types and three `/tr` shapes; PowerShell `Register-ScheduledTask`.
- **T1547.001** — two variants (reg.exe, PowerShell Set-ItemProperty), HKCU OR HKLM, multiple Run-key value names; **emits both process AND registry (EID 13) events**.
- **T1021.002** — varied target (workstation OR DC OR file-server), varied auth user (compromised admin OR specific user), C$/ADMIN$/subpath share variants; **emits both process AND network (EID 3) events**.
- **T1071.004** (renamed from T1071.001 — DNS protocol C2 is the .004 sub-technique) — varied length, query type (TXT/A/AAAA), domain.
- **T1555.003** — three browsers (Chrome/Edge/Brave), three tools (cmd, xcopy, PowerShell Copy-Item).

## Anti-leak discipline (IMPORTANT)

**Strip `_labels` before sending events to the LLM during FP analysis.** Use the `--strip-labels` flag:

```bash
python3 generate_corpus.py --seed 42 --strip-labels --out for-llm.jsonl
```

If Claude sees the labels, it will trivially "achieve" 100% FP-classification accuracy by reading the ground truth. The lesson's discipline is "LLM suggests TP/FP; ground truth validates the LLM's suggestions" — not the reverse. The strip-labels mode enforces that boundary.

The corpus also avoids identity-leakage tells: `alice.admin` and other admin users appear in BOTH benign and malicious events, so a rule keyed to user-name alone won't trivially separate the two.

## How the lesson uses this

L3 Step 2 has students copy the corpus into their workbench:

```bash
python3 generate_corpus.py --seed 42 --out tools/detection-engine/fixtures/log-corpus/windows-sysmon.jsonl
```

Subsequent steps build a pySigma + DuckDB query pipeline (Step 3), the `fp-analyst` Claude subagent (Step 4), the FP-rate measurement loop (Step 5), and finally tune Sigma rules to ship with documented FP rates (Steps 6-7).

**Recommended pick-2 strategy** (so the second rule teaches transfer, not repetition):
- Pick **one command-line technique** (T1059.001, T1003.001, T1053.005, T1547.001, T1555.003) → teaches `process.command_line` keyword/regex authoring
- Pick **one structurally different technique** from {T1218.005 (parent-process pivot), T1071.004 (DNS field shape, EID 22), T1021.002 (cross-EID join)} → teaches a different rule shape

## Realism caveats

- Sysmon-shaped fields are simplified. Real Sysmon has more fields (`process.entity_id`, `network.direction`, `file.code_signature.*`, etc.).
- Benign events are simpler than production reality. A real EDR agent emits ~1M events/host/day; this corpus is sparser. **FP rates measured here are pedagogical** — your rule's FP rate on this corpus is "did pySigma fire correctly against the known surface" not "this rule will work in production."
- The benign near-misses are realistic but not exhaustive. Real fleets have hundreds of attack-shaped legitimate behaviors. The 64 near-misses in this corpus exist to teach the *concept* of FP surface, not to simulate a production fleet.
- The corpus uses **fictional** internal IPs, hostnames, usernames, and domains. Don't feed real telemetry into production tooling using this as a reference shape.

## Determinism guarantees

Same seed → same N events → same labeled-malicious / near-miss event shapes → same SHA-256 hash. Verify after generator changes:

```bash
python3 generate_corpus.py --seed 42 --out a.jsonl
python3 generate_corpus.py --seed 42 --out b.jsonl
shasum -a 256 a.jsonl b.jsonl
# Same hash on both lines.
```
