# CHANGELOG — ai-csl-data

> Updates to AI-CSL training datasets. Check this file after pulling to see what's new.

Format: one entry per meaningful update, newest at the top. Entries describe what course(s) the data supports.

---

## 2026-04-14

### Added
- **CHANGELOG.md** (this file) — track dataset additions going forward, so lab members see what's new at a glance.
- **"Last Updated" header** on README.md.

---

## Prior history

See `git log` for all changes before 2026-04-14. This file tracks ongoing updates going forward.

Existing datasets (as of 2026-04-14):
- `cloudvault-financial/company-profile.md` — Client briefing (read first)
- `cloudvault-financial/cloudtrail-week1.json` — Week 1 logs (Course 1)
- `cloudvault-financial/guardduty-findings-month1.json` — 47 findings (Course 2)
- `cloudvault-financial/soc2-compliance-tracker.csv` — 200 SOC 2 controls (Courses 2, 7)
- `cloudvault-financial/vendor-questionnaire.md` — 50-question vendor review (Course 2)
- `cloudvault-financial/remediation-review/` — Code review exercise files (Course 2)
- `cloudvault-financial/incident-sequence.json` — Attack chain (Courses 2, 5) [coming soon]
- `notebooklm-sources/` — NotebookLM source material (Course 1 bonus)

---

## Versioning Note

Version pinning (`v1/`, `v2/` subdirectories) not yet needed — Josh is the only consumer today. Once lab members start pulling in volume and courses are published, consider versioning so a dataset tweak doesn't break a live course. Revisit before Course 1 public launch.
