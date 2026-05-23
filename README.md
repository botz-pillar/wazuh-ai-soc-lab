# Wazuh AI SOC Lab

> **Run a real SOC investigation on AWS — with an AI partner that actually pulls its weight.**
>
> Two hours. Costs about a coffee in AWS compute. You stand up production-grade Wazuh SIEM with a Model Context Protocol (MCP) server wired in, then run a six-phase investigation: baseline → hunt → tripwire → response. By the end you've produced a SOC 2 evidence package on real lab infrastructure and seen what an AI security partner looks like when it's wired into the tools you actually use.

**CloudVault Financial was breached. You ran the IR. The remediation looks clean, but three persistence categories from your report were never confirmed eliminated — and SOC 2 evidence collection starts in a few weeks. Dana (CISO) brings in Mateo, a senior SOC analyst, to help you stand up a SIEM, baseline the environment, hunt for what's left behind, and produce the audit package.**

That's the setup. The repo is the lab. Pair Wazuh 4.9 with the [gensecaihq/Wazuh-MCP-Server](https://github.com/gensecaihq/Wazuh-MCP-Server), launch Claude Code, and Mateo guides you through the investigation in natural language — while you verify everything yourself. No black boxes.

---

## What you'll do

Six phases of investigation, one continuous ~2-hour session:

| # | Phase | What happens |
|---|---|---|
| 1 | 🛡️ Stand up the SIEM | Bootstrap deploys everything. Mateo briefs you on the case, walks Wazuh architecture, previews the MCP. You log in, tour the dashboard, run your first query. |
| 2 | 🎯 Baseline the environment | Exercise four MITRE TTPs on `dev-server-01` matching the pattern classes from your IR report. Investigate the resulting chain manually. Confirm SIEM coverage before hunting. First update to Dana. |
| 3 | 🔗 Threat-model the MCP, plug it in | Inspect what bootstrap pre-installed. Three concrete failure modes + mitigations (stolen JWT, prompt injection, supply chain). Re-run the baseline investigation through natural language. AI-drafted CISO update, human-verified. |
| 4 | 🎯 The backdoor hunt | Four structured hunts against the three persistence categories from the IR report (account, listener, scheduler) plus an AI-verification drill. Hunt log becomes SOC 2 evidence. |
| 5 | ⚡ Tripwires and response | Write custom rule 100001 — the CloudVault client-data tripwire Dana asked for. Validate with `wazuh-logtest`. Deploy, trigger, verify. Take a duration-based active response. |
| 6 | 🧹 Close the case | Compressed end-to-end IR on a fresh alert. Evidence package for Dana and the SOC 2 audit (CC7.1 / CC7.2). Personal artifact for interviews. `terraform destroy` with verification. |

---

## What's in this repo

The core lab:

- **`terraform/`** — Wazuh manager + 3 CloudVault agents on AWS, deploys in ~20 min
- **`scripts/`** — `bootstrap.sh` (one-command deploy), `doctor.sh` (health check), start/stop helpers
- **`docs/`** — architecture, costs, MCP server setup, custom detection rules, troubleshooting
- **`lab-guide/`** — step-by-step walkthrough independent of the AI co-pilot
- **`mcp/`** — MCP-specific notes (active response patterns, direct Wazuh API fallback)
- **`.claude/skills/course-3-instructor/SKILL.md`** — the Mateo playbook (1,200+ lines). Auto-loads in Claude Code. The product.

The scenario:

- **`data/cloudvault-financial/`** — the breach narrative + supporting datasets (CloudTrail, GuardDuty, SOC 2 tracker, remediation-review files, attack chain)
- **`notebooklm-sources/`** — drop these into [NotebookLM](https://notebooklm.google.com) and you've got a queryable "CloudVault security brain" alongside the lab (SOC 2 criteria, IR framework, vendor evaluation guide, full CloudVault security profile)

For going deeper:

- **`wazuh-mcp/sandbox/`** — single-node Wazuh on Docker, runs on a 16 GB laptop. MCP development + testing without AWS.
- **`wazuh-mcp/abuse-harness/`** — 6-pattern adversarial test suite for any MCP server. Prompt-injection-via-resource, tool spam / rate-limit, input validation, auth-bypass + stack-trace leak, structured-error compliance, write-tool authority gating. Useful if you're building MCP servers and want to know they'll hold up.
- **`optional-labs/`** — three bonus practice corpora that pair with the core lab:
  - **`detection-engineering/`** — labeled Windows/Sysmon corpus generator (~5,000 events, 8 MITRE techniques planted). Practice writing Sigma rules with a measured false-positive rate against ground truth.
  - **`incident-investigator/`** — synthetic CloudTrail corpus (~30k events) with a planted IAM-access-key-compromise narrative. Includes three indirect-prompt-injection payloads embedded in the data — test whether your AI-augmented investigation pipeline catches them and refuses to comply.
  - **`runbook-search/`** — 10 sanitized AWS incident-response runbooks (IAM compromise, GuardDuty triage, S3 exposure, CloudTrail tampering, EC2 isolation, etc.). Build a RAG-with-citations skill on top. One runbook is planted-stale to exercise your freshness check.

---

## Quick start

**Two paths.** Local install is the default. Codespaces is there if you can't (or don't want to) install the toolchain on your machine — school computer, work laptop, hostile environment.

### Path A — Local (default)

**Prerequisites** (5 min): AWS account + CLI configured, Terraform ≥ 1.5, an EC2 key pair in your target region, [Claude Code](https://docs.claude.com/claude-code) CLI. Full checklist below.

```bash
# 1. Clone
git clone https://github.com/botz-pillar/wazuh-ai-soc-lab.git
cd wazuh-ai-soc-lab

# 2. Configure Terraform (your public IP, your EC2 key name)
cp terraform/terraform.tfvars.example terraform/terraform.tfvars
$EDITOR terraform/terraform.tfvars

# 3. Deploy (one command — bootstraps S3 state, Terraform, Wazuh, MCP, .mcp.json)
./scripts/bootstrap.sh

# 4. Launch Claude Code in the lab directory
claude

# 5. Start the investigation
# > Start the lab
```

### Path B — Codespaces (no local install)

GitHub Codespaces gives you a pre-built environment with Terraform, AWS CLI, Docker, and Claude Code already installed.

1. **Add AWS keys to Codespaces user secrets** at <https://github.com/settings/codespaces>. Set `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` (use the lab IAM user — see [docs/IAM-LAB-POLICY.md](docs/IAM-LAB-POLICY.md)). Scope them to this repo.
2. **Launch the Codespace** — green Code button on this repo → **Codespaces** tab → **Create codespace on main**. ~2 min to build.
3. **Inside the Codespace**, follow steps 2-5 from Path A. The `bootstrap.sh` script handles S3 state automatically — Codespaces are ephemeral, so state lives in S3, not on the container.
4. **Dashboard access:** the Codespace forwards port 443 (Wazuh dashboard) and 3000 (MCP) via SSH tunnels to the manager. Mateo will walk you through the tunnel command when you reach Phase 1.

Mateo takes it from there. Total deploy time ~20-25 min (Terraform ~2 min, Wazuh install ~15 min, MCP install ~3 min, agent registration ~5 min — mostly parallel). Mateo teaches during the wait, so there's no dead time.

---

## How it works (reference)

```
   Your laptop                                       AWS
 ┌──────────────────┐                   ┌─────────────────────────────────┐
 │                  │                   │                                 │
 │  Claude Code     │ ── HTTPS :443 ──► │   Wazuh Manager (t3.large)      │
 │  + Mateo skill   │ ── HTTP  :3000 ─► │   ├─ Manager / Indexer          │
 │  + Wazuh MCP     │ ── SSH   :22  ──► │   ├─ Dashboard                  │
 │    (auto-wired)  │                   │   └─ MCP Server (Docker :3000)  │
 │                  │                   │                                 │
 │  Browser         │ ── HTTPS :443 ──► │   CloudVault agents (t3.micro)  │
 │  (dashboard tour)│                   │   ├─ web-server-01  10.0.1.20   │
 │                  │                   │   ├─ app-server-01  10.0.1.30   │
 └──────────────────┘                   │   └─ dev-server-01  10.0.1.40   │
                                        │                                 │
                                        └─────────────────────────────────┘
```

The MCP server runs on the manager. `bootstrap.sh` installs it, fetches a bearer token, and writes `.mcp.json` in this repo. When you launch Claude Code here, the MCP auto-mounts — no manual setup.

---

## Cost

| Resource | Hourly | 2h session | A weekend (if you forget) |
|---|---|---|---|
| Manager (t3.large) | $0.083 | $0.17 | $4.00 |
| 3× agents (t3.micro) | $0.031 | $0.06 | $1.50 |
| EBS (~90 GB gp3) | ~$0.012 | $0.02 | $0.60 |
| Elastic IP (while running) | free | free | free |
| **Running** | **~$0.126/hr** | **~$0.25** | **~$6** |

**Always `terraform destroy` when done.** Set up an AWS Budget Alert at $10 if you haven't already.

---

## Commands you'll use

| Command | What it does |
|---|---|
| `./scripts/bootstrap.sh` | Deploy everything (Terraform + Wazuh install + MCP install + .mcp.json) |
| `./scripts/doctor.sh` | Health check: prereqs, AWS, EC2, Wazuh services, MCP, agents, alerts |
| `./scripts/stop-lab.sh` | Stop compute (EBS still billed at ~$0.01/hr) |
| `./scripts/start-lab.sh` | Resume stopped instances |
| `cd terraform && terraform destroy` | Nuke everything. Always run when done. |

---

## Documentation

- [Architecture](docs/architecture.md) — detailed network + data flow
- [Costs](docs/costs.md) — full cost breakdown + cost-saving tips
- [MCP Server Setup](docs/mcp-server-setup.md) — what bootstrap.sh did on your behalf + manual install reference
- [Custom Detection Rules](docs/custom-detection-rules.md) — Wazuh rule syntax primer, standalone
- [Troubleshooting](docs/troubleshooting.md) — common issues including MCP-specific ones
- [`lab-guide/`](lab-guide/) — five-step manual walkthrough (no AI co-pilot)

---

## Prerequisites checklist

- [ ] AWS account with billing enabled
- [ ] `aws configure` works (SSO or long-lived keys, either is fine)
- [ ] Terraform ≥ 1.5 installed (`brew install terraform` on macOS)
- [ ] An EC2 key pair created in your target region (default: `us-east-1`)
- [ ] Private key saved at `~/.ssh/<keyname>.pem` with `chmod 600`
- [ ] [Claude Code](https://docs.claude.com/claude-code) CLI installed (`npm i -g @anthropic-ai/claude-code`)
- [ ] An AWS Budget Alert at $10 (Billing → Budgets → Create budget)

---

## About

Built by **[Josh Botz](https://www.linkedin.com/in/joshthebotz/)** — cloud security + AI agent security practitioner. Background in FedRAMP / ConMon, Fortune 500 + IC work. Currently focused on agent security: detection, red-team, and the tooling that makes it useful. Connect on [LinkedIn](https://www.linkedin.com/in/joshthebotz/) — happy to talk about how AI shows up in real security work.

---

## Support + contributing

- **Lab issues** (deploy, Terraform, MCP wiring, anything broken): [open a GitHub Issue](https://github.com/botz-pillar/wazuh-ai-soc-lab/issues/new)
- **MCP server bugs upstream**: [gensecaihq/Wazuh-MCP-Server](https://github.com/gensecaihq/Wazuh-MCP-Server/issues)
- **Pull requests welcome.** This lab originated from a curriculum I built — it works, but every environment is a little different. If you find a bug or have a fix, send it in.

---

## License

MIT. Use it in your own training, workshops, client demos, whatever. Attribution appreciated but not required.
