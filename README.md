# PROJECT OMEGA

**Autonomous-Threat Defense Platform — v5.0.0**

[![CI](https://github.com/MuneneGeo/project-omega/actions/workflows/ci.yml/badge.svg)](https://github.com/MuneneGeo/project-omega/actions/workflows/ci.yml) ![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue) ![License: MIT](https://img.shields.io/badge/license-MIT-green) ![Dependencies: none](https://img.shields.io/badge/dependencies-none-brightgreen)


AI agents are making attacks cheaper, faster and more adaptive. A human tries a payload, thinks, and tries another; an agent does that hundreds of times, learns from every error message, and moves within hours of a vulnerability being published.

PROJECT OMEGA is built to **understand and counter autonomous attackers**. It shows you:
- who is attacking: an LLM-driven agent, a classic scanner, a scripted bot or a human;
- how their payloads evolved;
- which IPs belong to the same actor;
- whether they are hitting weaknesses you already know about.

Then it **deceives** them with honeytokens and CVE-bait, **shields** you with virtual patches pushed to your WAF, **proves** what happened with forensic evidence, and **tracks the trend** over time.

Vulnerability scanning is just one of Omega's sensors. Omega can also ingest results from Nuclei, ZAP, Burp, Trivy and Semgrep, and turn them into attack paths, protection and evidence.

It is a single, zero-dependency Python file that you drop on a server and run.

```
python3 project_omega.py selftest
```

> ⚠️ **Defensive, authorized use only.** Run Omega only against systems you own or have explicit written permission to test. Scanning third-party systems without permission is illegal in most jurisdictions. Deception (honeytokens, decoys, bait) belongs only on your own assets. Omega never exploits targets and never "hacks back".

---

## Table of contents

1. [What Omega does](#what-omega-does)
2. [What changed in v5](#what-changed-in-v5)
3. [Requirements & installation](#requirements--installation)
4. [Quick start](#quick-start)
5. [All commands at a glance](#all-commands-at-a-glance)
6. [Command reference (full options)](#command-reference-full-options)
7. [AI analyst setup](#ai-analyst-setup)
8. [Practice lab (step by step)](#practice-lab-step-by-step)
9. [Real-world deployment](#real-world-deployment)
10. [How detection works](#how-detection-works)
11. [Reports & outputs](#reports--outputs)
12. [Limitations](#limitations)
13. [Project status](#project-status)

---

## What Omega does

### 1. Understand autonomous attackers
- **Agent fingerprinting.** Every client is classified as an *LLM-driven agent*, *classic scanner*, *scripted bot*, *self-identified AI agent* or *human / browser*, with a confidence level and the behavioural evidence behind it. The traits it looks for:
  - **Think-time rhythm:** pauses that match model-inference time between adaptive attempts.
  - **Error-driven mutation:** each payload is refined right after an error response.
  - **Natural-language artifacts** inside payloads.
  - **Read-then-act sequences:** fetching robots.txt or API docs, then targeting exactly what they describe.
  - **Tooling:** the HTTP client or scanner in use.
- **Payload lineage trees.** A family tree of each attacker's attempts. You can watch an agent go from `UNION SELECT null` to `null,null` to a WAF-evasion variant after being blocked. A scanner's identical repeats are collapsed, so the difference is obvious.
- **Campaign clustering.** Groups clients that share payload shapes, or identical attack paths with the same tooling, into one actor across rotating IPs, so you block the campaign rather than a single address.
- **Kill-chain staging and early warning.** Each attacker is placed at RECON → PROBING → EXPLOITATION → POSSIBLE COMPROMISE. You're alerted at the first two stages, before damage is done.
- **Autonomous-threat trends** (`trends`). Month by month, it reports:
  - the share of your clients that are autonomous;
  - LLM agents versus scanners;
  - campaigns, bait hits and honeytoken hits;
  - your **exposure window**: the time from a CVE's publication to the first probe for it in *your* traffic.

### 2. Deceive them
- **Honeytokens and decoy files** (`deceive`). Fake credentials are planted in decoy `.env` and config files. Reading a decoy is flagged; *using* a token anywhere (URL, body or headers) is a critical alert and an instant ban.
- **CVE-bait endpoints.** Omega serves decoy paths of actively exploited CVEs for products you *don't* run. Anyone probing them is hunting fresh exploits, and they get a fake management console while you watch. Bait comes from live threat intel when available, with a built-in seed list otherwise.
- **Decoy maze and canary paths.** Suspected bots get an endless decoy directory in which every link is a trap.

### 3. Protect, at machine speed
- **Live protection** with `guard` (reverse proxy) or `OmegaMiddleware` (Flask/Django), in monitor or enforce mode.
- **Virtual patching** (`vpatch`). One narrow rule per confirmed vulnerability (endpoint + parameter + attack class), active only until a later assessment shows the issue fixed, then **retired automatically**: scan → shield → fix → verify → unshield.
- **Vulnerability ↔ live-attack fusion.** Requests are linked to the findings of your last assessment. *"F-02 (confirmed SQL injection on /item) is under attack right now"* outranks generic noise.
- **WAF integration** (`waf`). Exports virtual patches and blocked actors to **nginx**, **ModSecurity**, **Cloudflare** (dry run, or `--apply` via API) and **AWS WAF**. Omega makes your existing WAF smarter instead of replacing it.
- **Detection & signatures:**
  - RCE and injection detection with multi-layer decoding (base64, hex, URL, gzip …) and evasion alerts;
  - a self-learning anomaly model trained on your traffic;
  - threat intel from CISA KEV, NVD and EPSS, plus advisories and patches you import;
  - anonymised **community signatures**.

### 4. Know your weaknesses
- **Verified exposure scan** (`scan`).
  - **Safe mode:** detects issues but never exploits them.
  - **Re-verified findings:** every active finding is confirmed by an independent second check before it is reported.
  - **Separated signals:** anything that cannot be verified is listed under "needs manual verification" and kept out of the score.
  - **Evidence:** each finding carries its raw HTTP transcript and, optionally, a screenshot.
- **Ingestion** (`ingest`). Imports **Nuclei**, **ZAP**, **Burp** and **SARIF** (Trivy, Semgrep, CodeQL …) results, de-duplicates them, and feeds them into everything below.
- **Attack-path reconstruction.** Chains findings into paths that reach sensitive resources (server control, database, secrets, cloud, account takeover), and names the fix that breaks the most paths.
- **Supply-chain audit** (`supply`). Typosquats, OSV.dev vulnerabilities and malicious packages, dependency confusion, lockfile integrity, malicious install scripts, CI/CD workflow risks, Dockerfiles, and SBOM output.
- **Server integrity.** Webshell scanning and a file-integrity baseline.

### 5. Secure your own AI features (`aisec`)
Mapped to the **OWASP Top 10 for LLM Applications (2025)**:
- **Indirect prompt injection** in content your AI reads (RAG documents, web pages), including invisible Unicode tag characters, which are decoded and shown, white-on-white or zero-size text, and comment injections.
- **MCP server and tool audit:**
  - tool poisoning and tool shadowing;
  - unpinned auto-installed packages;
  - plaintext secrets;
  - whole-filesystem or shell access;
  - remote servers over plain HTTP.
- **LLM output firewall.** Detects and, in enforce mode, strips zero-click exfiltration (markdown image beacons), secrets and active HTML from chat responses, live in `guard --llm-endpoint`.

### 6. Prove it and respond
- **Forensic evidence vault.** Hashed, timestamped, read-only evidence with a hash-chained chain of custody, a sealed manifest (optional HMAC), verification and export.
- **Response playbooks** (`respond`). A plan with human approval per action covers: blocking actors (nginx or Cloudflare), deploying virtual patches, rotation/investigation checklists and webhook notifications. Every action is logged and recorded in the chain of custody. It also produces an incident timeline.
- **Detection validation** (`validate`). Replays a safe attack corpus offline or against your own guard/WAF, and reports what is detected, what is *blocked*, and what slips through.
- **Exports** (`export`). **SARIF** for code-scanning tools, **STIX 2.1** for threat-intel platforms, **CEF** for SIEMs.
- **History.** New, persisting, resolved and regressed findings, mean time to remediate, exposure trends, and continuous assessment (`assess`).

### 7. Extend
- **Plugins.** Drop `.py` files in `./omega_plugins` (or `$OMEGA_PLUGINS`) to add detection rules, attack-path chain rules or scan checks. `plugins new NAME` writes a template.

---

## What changed in v5

| Change | Why |
|---|---|
| Repositioned from "scanner" to **autonomous-threat defense platform** | Scanning is a crowded space; understanding and countering AI-driven attackers is not |
| **Added:** agent fingerprinting, payload lineage, campaigns, trends, exposure windows | See *how* attackers behave, not just *what* they send |
| **Added:** honeytokens, decoy files, CVE-bait | Catch attackers early and with certainty |
| **Added:** virtual patching + fusion + WAF push | Turn findings into protection at machine speed |
| **Added:** `aisec` (RAG, MCP, output firewall) | Secure the AI features you ship |
| **Added:** `ingest`, `validate`, `respond`, `export`, `signatures`, `plugins` | Work with your existing tools and processes |
| **Added:** NoSQL-injection detection | Gap found by the validation corpus |
| **Removed:** built-in "known-bad packages" list | Hand-kept lists go stale and mislead; OSV.dev (`supply --osv`) is authoritative |
| **Reshaped:** `guard` | Still ideal for labs and small sites; for production, use `waf` to push rules into nginx, ModSecurity, Cloudflare or AWS WAF |
| **Kept as one file**, plus plugins | Drop-in portability is a core strength; plugins give extensibility without a package split |

---

## Requirements & installation

- **Python 3.8+** (developed and tested on 3.12)
- **No third-party packages.** Standard library only.
- **Network access is optional.** It is only needed for `intel update`, `--osv`, `--epss` and the AI analyst.
- **Git** (optional): only needed if you want to clone instead of downloading a ZIP.

### Option A: Clone with Git (recommended)

**Linux (Debian/Ubuntu/Kali)**
```bash
sudo apt update && sudo apt install -y git python3
git clone https://github.com/MuneneGeo/project-omega.git
cd project-omega
python3 project_omega.py selftest
```

**macOS**
```bash
brew install git python        # or install Xcode command line tools: xcode-select --install
git clone https://github.com/MuneneGeo/project-omega.git
cd project-omega
python3 project_omega.py selftest
```

**Windows (PowerShell or Command Prompt)**

1. Install [Git for Windows](https://git-scm.com/download/win) and [Python](https://www.python.org/downloads/). Tick **"Add Python to PATH"** in the installer.
2. Open PowerShell and run:
```powershell
git clone https://github.com/MuneneGeo/project-omega.git
cd project-omega
python project_omega.py selftest
```
On Windows use `python` (or `py`) instead of `python3`. For the best experience, run Omega inside **WSL** (Ubuntu), where all commands in this README work exactly as written.

### Option B: Download without Git

1. Open the repository page on GitHub.
2. Click the green **Code** button, then **Download ZIP**.
3. Unzip it, open a terminal in the extracted folder, and run `python3 project_omega.py selftest` (`python` on Windows).

Or from a terminal:
```bash
curl -L -o omega.zip https://github.com/MuneneGeo/project-omega/archive/refs/heads/main.zip
unzip omega.zip && cd project-omega-main
```
(Windows PowerShell: `Invoke-WebRequest -Uri https://github.com/MuneneGeo/project-omega/archive/refs/heads/main.zip -OutFile omega.zip` then `Expand-Archive omega.zip .`)

### Option C: Download just the one file

Omega is a single file, so this also works:
```bash
curl -O https://raw.githubusercontent.com/MuneneGeo/project-omega/main/project_omega.py
python3 project_omega.py selftest
```

### Verify it works

`selftest` should end with:
```
Result: ALL PASSED
```

### Update to the latest version
```bash
cd project-omega
git pull
```

### Optional: run it from anywhere (Linux/macOS)
```bash
chmod +x project_omega.py
sudo ln -s "$PWD/project_omega.py" /usr/local/bin/omega
omega selftest
```

### Optional: use a virtual environment
Not required (there are no dependencies), but it keeps optional extras such as Playwright (screenshots) separate:
```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install playwright && playwright install chromium
```

> **Note:** the examples in the rest of this README use `python3`. On Windows, replace it with `python`.

---

## Quick start

```bash
# 1. Who is attacking me, and how? (agents, campaigns, payload lineage, kill-chain)
python3 project_omega.py logs /var/log/nginx/access.log --html attacks.html --json attacks.json

# 2. What can they exploit? (verified findings + attack paths) - own sites / written permission only
python3 project_omega.py scan https://mysite.com --authorized --json scan.json --html scan.html --save-assets assets.json
#    ...or bring your existing scanners' results
python3 project_omega.py ingest nuclei.jsonl zap.json --target https://mysite.com --json scan.json --html scan.html

# 3. Shield and deceive
python3 project_omega.py vpatch generate scan.json
python3 project_omega.py deceive init --assets assets.json
python3 project_omega.py guard --upstream http://127.0.0.1:3000 --vpatch omega_vpatches.json \
        --deception omega_deception.json --findings scan.json --llm-endpoint /api/chat
#    ...or push the protection into your WAF
python3 project_omega.py waf nginx --vpatch omega_vpatches.json --logs-report attacks.json

# 4. Prove the defenses work, respond, and track the trend
python3 project_omega.py validate --target http://127.0.0.1:8000
python3 project_omega.py respond plan --logs-report attacks.json --scan-report scan.json
python3 project_omega.py logs /var/log/nginx/access.log --history omega_history.db && python3 project_omega.py trends --html trends.html
```

## All commands at a glance

Every command is run as `python3 project_omega.py <command> [options]`. Run `python3 project_omega.py <command> -h` for the full options of any one.

The **Runs** column tells you what to expect:
- **once** — it does the job, saves its files, and gives you your prompt back.
- **stays open** — it keeps running and watching until you press `Ctrl+C`.

### Start here

| Command | What it does, in plain words | Example | Runs |
|---|---|---|---|
| `selftest` | Checks the tool itself works. Run this first. | `python3 project_omega.py selftest` | once |
| `lab` | Prints a safe step-by-step practice guide. | `python3 project_omega.py lab` | once |
| `string` | Tells you if one URL, log line or payload is an attack, and decodes it. | `python3 project_omega.py string "/api?q=' OR 1=1--"` | once |

### See who is attacking you (reads your logs — safe, touches nothing)

| Command | What it does, in plain words | Example | Runs |
|---|---|---|---|
| `logs` | Reads your web server's access log and shows who attacked, what they tried, whether it worked, and whether they're a human, a bot or an AI agent. | `python3 project_omega.py logs /var/log/nginx/access.log --html attackers.html` | once |
| `tail` | Same idea, but follows the log live in your terminal as new requests arrive. | `python3 project_omega.py tail /var/log/nginx/access.log` | stays open |
| `dashboard` | Shows your log as a live **web page** in your browser (charts, attacker list) instead of terminal text. | `python3 project_omega.py dashboard --log /var/log/nginx/access.log` | stays open |

### Find your weaknesses

| Command | What it does, in plain words | Example | Runs |
|---|---|---|---|
| `scan` | Checks a website for vulnerabilities (SQL injection, XSS, exposed files, weak TLS…) and takes screenshots as proof. **Your own site or written permission only.** | `python3 project_omega.py scan https://mysite.com --authorized --screenshots --evidence case1 --html report.html` | once |
| `ingest` | Imports results from other scanners (Nuclei, ZAP, Burp, Trivy) and turns them into Omega's reports and attack paths. | `python3 project_omega.py ingest nuclei.jsonl zap.json --html combined.html` | once |
| `supply` | Checks your code's dependencies for supply-chain attacks (malicious or typo-squatted packages). | `python3 project_omega.py supply ./my-app --osv` | once |
| `files` | Scans a web folder for webshells and backdoors left by attackers. | `python3 project_omega.py files /var/www/html --recent 7` | once |
| `baseline` | Records a fingerprint of every file, so you can detect changes later. | `python3 project_omega.py baseline /var/www/html` | once |
| `verify` | Compares your files against that fingerprint and lists anything added or changed. | `python3 project_omega.py verify /var/www/html` | once |

### Protect the site live

| Command | What it does, in plain words | Example | Runs |
|---|---|---|---|
| `guard` | Sits in front of your app and blocks (or just alerts on) attacks in real time, with a live dashboard. | `python3 project_omega.py guard --upstream http://127.0.0.1:3000 --dashboard` | stays open |
| `vpatch` | Turns confirmed findings from a scan into precise blocking rules. | `python3 project_omega.py vpatch generate scan.json` | once |
| `waf` | Exports those blocking rules for your real firewall (nginx, Cloudflare, AWS, ModSecurity). | `python3 project_omega.py waf nginx --vpatch omega_vpatches.json` | once |
| `deceive` | Plants fake credentials and decoy files so attackers trip an alarm; also sets fake endpoints that catch exploit hunters. | `python3 project_omega.py deceive init` | once |

### Stay current and get early warning

| Command | What it does, in plain words | Example | Runs |
|---|---|---|---|
| `intel` | Downloads the latest list of vulnerabilities attackers are actively exploiting (CISA, NVD, EPSS). | `python3 project_omega.py intel update` | once |
| `watch` | Warns you when a newly-exploited vulnerability affects software *you* run, or when someone starts probing for it. | `python3 project_omega.py watch --assets assets.json --logs /var/log/nginx/access.log` | once |
| `train` | Learns what your normal traffic looks like, so Omega can spot never-seen-before attacks. | `python3 project_omega.py train clean_week.log` | once |
| `signatures` | Shares or imports anonymised attack patterns with other Omega users (no private data). | `python3 project_omega.py signatures import partner_bundle.json` | once |

### Secure your AI features (if your site has a chatbot, RAG, or MCP tools)

| Command | What it does, in plain words | Example | Runs |
|---|---|---|---|
| `aisec docs` | Scans documents your AI reads for hidden "prompt injection" instructions. | `python3 project_omega.py aisec docs ./knowledge_base` | once |
| `aisec mcp` | Audits MCP server configs and tools for poisoning and over-broad permissions. | `python3 project_omega.py aisec mcp config.json` | once |
| `aisec output` | Checks chatbot replies for data-stealing links and leaked secrets. | `python3 project_omega.py aisec output reply.txt` | once |

### Report, prove and respond

| Command | What it does, in plain words | Example | Runs |
|---|---|---|---|
| `report` | Turns a saved JSON result into a clean HTML report you can print to PDF. | `python3 project_omega.py report scan.json --html report.html` | once |
| `vault` | Your evidence locker: verify nothing was tampered with, list items, export a case, track chain of custody. | `python3 project_omega.py vault verify case1` | once |
| `history` | Shows how your security changed over time: new, fixed and recurring issues, and time-to-fix. | `python3 project_omega.py history --html trend.html` | once |
| `assess` | Re-scans a site automatically on a schedule and records the history. | `python3 project_omega.py assess https://mysite.com --authorized --every 6h` | stays open |
| `trends` | A monthly "autonomous threat report": how many attackers are AI-driven, campaigns, exposure windows. | `python3 project_omega.py trends --html threats.html` | once |
| `respond` | Builds an incident response plan (block IPs, rotate secrets, notify) that you approve step by step. | `python3 project_omega.py respond plan --logs-report attackers.json` | once |
| `export` | Converts results for other tools: SARIF (GitHub), STIX (threat-intel platforms), CEF (SIEMs). | `python3 project_omega.py export scan.json --sarif out.sarif` | once |
| `validate` | Tests whether your defenses actually block a set of sample attacks. | `python3 project_omega.py validate --target http://127.0.0.1:8000` | once |

### Extend it

| Command | What it does, in plain words | Example | Runs |
|---|---|---|---|
| `plugins` | Lists your plugins, or creates a template so you can add your own detection rules. | `python3 project_omega.py plugins list` | once |

> **Two reminders.** Commands that read logs or files are completely safe to run anytime. Commands that test a live site (`scan`, `validate`, `assess`, `guard`) must only point at systems you own or have **written permission** to test, which is what the `--authorized` flag confirms.

---

## Command reference (full options)

Every command is run as:

```
python3 project_omega.py <command> [arguments] [options]
```

Global options: `-h` / `--help` (works on every command too, e.g. `scan -h`) and `--version`.

### Cheat sheet: "I want to…"

| I want to… | Command |
|---|---|
| Watch attacks live in my browser | `guard --upstream http://127.0.0.1:3000 --dashboard` (or `dashboard --log access.log`) |
| See which attackers are AI agents, campaigns, payload evolution | `logs access.log --html attacks.html` |
| Catch attackers with honeytokens and CVE-bait | `deceive init`, then `guard … --deception omega_deception.json` |
| Shield confirmed vulnerabilities until they're fixed | `vpatch generate scan.json`, then `guard … --vpatch omega_vpatches.json` |
| Push protections into my WAF | `waf nginx --vpatch omega_vpatches.json --logs-report attacks.json` |
| Use Nuclei/ZAP/Burp/Trivy results | `ingest nuclei.jsonl zap.json --html combined.html` |
| Test whether my defenses block attacks | `validate --target http://127.0.0.1:8000` |
| Check AI features (RAG docs, MCP, chat output) | `aisec docs ./kb`, `aisec mcp config.json`, `guard … --llm-endpoint /api/chat` |
| Monthly autonomous-threat report | `logs … --history omega_history.db`, then `trends --html report.html` |
| Respond to an incident with approvals | `respond plan --logs-report attacks.json`, then `respond execute omega_response_plan.json` |
| Send results to GitHub / SIEM / TIP | `export scan.json --sarif x.sarif`, `export attacks.json --stix x.json --cef x.cef` |
| Check my website for vulnerabilities | `scan https://mysite.com --authorized --html report.html` |
| Full evidence-backed assessment | `scan https://mysite.com --authorized --screenshots --evidence case1 --history omega_history.db --html report.html` |
| Re-assess automatically on a schedule | `assess https://mysite.com --authorized --every 6h --evidence-dir vaults` |
| See trends, fixed and recurring issues | `history --html trend.html` |
| Prove evidence hasn't been altered | `vault verify case1` |
| Record a hand-over of evidence | `vault custody case1 --custody-action TRANSFERRED --actor "Me" --note "To legal"` |
| Package evidence for delivery | `vault export case1` |
| See who is attacking me in my logs | `logs /var/log/nginx/access.log --html attacks.html` |
| Watch my log file live for attacks | `tail /var/log/nginx/access.log` |
| Protect a web app in real time | `guard --upstream http://127.0.0.1:3000 --port 8000` |
| Teach Omega what my normal traffic looks like | `train clean_access.log` |
| Download the latest exploited-CVE knowledge | `intel update` |
| Learn from an advisory, patch or news article | `intel import advisory.txt` |
| Check if a product version has known CVEs | `intel match --product apache:http_server --ver 2.4.49` |
| Get warned when my stack becomes exploitable | `watch --assets assets.json --logs access.log` |
| Check my code's dependencies for supply-chain attacks | `supply ./my-app --osv --html supply.html` |
| Find webshells/backdoors on my server | `files /var/www/html --html webshells.html` |
| Detect unexpected file changes | `baseline /var/www/html`, then later `verify /var/www/html` |
| Analyse one suspicious string or file | `string "<payload>" --show-layers` |
| Turn a saved JSON report into a nice HTML report | `report scan.json` |
| Learn step by step in a safe lab | `lab` |
| Check the tool works | `selftest` |

### Shared AI options

These options are available on `logs`, `scan`, `files`, `supply`, `string` and `intel`. They do nothing unless `--ai` is given.

| Option | Default | What it does |
|---|---|---|
| `--ai` | off | Sends the highest-risk detections to an AI model for a second opinion: verdict, intent, MITRE ATT&CK techniques, AI-agent likelihood and fix steps |
| `--ai-provider {anthropic,openai,ollama}` | `anthropic` (or env `OMEGA_AI_PROVIDER`) | Which AI service to use. `ollama` runs a local model, so nothing leaves your machine |
| `--ai-model NAME` | provider default (or env `OMEGA_AI_MODEL`) | Override the model name |
| `--ai-max-calls N` | `20` | Hard cap on AI calls per run (cost control) |
| `--ai-top N` | `8` | Maximum number of items sent for AI review |
| `--no-redact` | redaction on | Stop removing secrets, tokens and emails before data is sent (not recommended) |

---

### `scan`: web & cloud vulnerability scanner

**What it does:** checks a website for security weaknesses without exploiting them, and maps the results to the OWASP Top 10. It:

1. Checks TLS/HTTPS and security headers.
2. Crawls the site.
3. Looks for exposed secrets and files: `.git`, `.env`, backups, debug consoles, leaked API keys.
4. Sends harmless probes for XSS, SQL errors, template injection and open redirects.
5. Checks CORS, HTTP methods and GraphQL.
6. Finds referenced cloud storage.
7. Matches detected software versions against known CVEs.

**When to use it:** on sites you own or have written permission to test, before launch, after changes, or on a schedule.

```
scan TARGET [options]
```

| Argument / option | Default | What it does |
|---|---|---|
| `TARGET` | required | URL to scan, e.g. `http://localhost:3000` |
| `--authorized` | off | Confirms you own the target or have written permission. Required for anything except localhost, private IPs and `*.vulnweb.com` |
| `--passive` | off | No input probes at all: only observes headers, pages and files |
| `--cloud` | off | Tests cloud storage the site references (S3/GCS/Azure/Firebase) for public listing |
| `--post-forms` | off | Also probes POST forms. **Can create data**, so avoid it in production |
| `--cookie "NAME=value; …"` | none | Session cookie for scanning logged-in areas |
| `--header "Name: value"` | none | Extra request header (repeatable), e.g. a bug-bounty identification header |
| `--rate N` | 20 local / 3 remote | Maximum requests per second |
| `--max-pages N` | `40` | Maximum pages to crawl |
| `--max-params N` | `30` | Maximum parameters to probe |
| `--max-requests N` | `700` | Total request budget for the scan |
| `--insecure` | off | Skip TLS certificate verification (self-signed lab certificates) |
| `--epss` | off | Fetch EPSS exploit-probability scores for matched CVEs (online) |
| `--intel FILE` | `omega_intel.json` | Threat-intel database to use for CVE matching |
| `--save-assets FILE` | none | Save the detected software stack, for use with `watch` |
| `--json FILE` | none | Save the full machine-readable report |
| `--html FILE` | none | Save a self-contained HTML report (print to PDF from a browser) |
| `--evidence DIR` | none | Create a sealed forensic evidence vault (case folder) at DIR |
| `--case-id ID` | auto (`OMEGA-<UTC time>`) | Case identifier recorded in the vault |
| `--examiner NAME` | env `OMEGA_EXAMINER` / OS user | Examiner recorded in the chain of custody |
| `--screenshots` | off | Capture browser screenshots of the homepage and each finding's proof-of-concept page |
| `--max-screenshots N` | `12` | Maximum finding screenshots |
| `--history DB` | none | Record this assessment in a history database (new / persisting / resolved / regressed) |

What the scan output contains:
- verified findings, each with an ID (`F-01`…), a confidence level, evidence IDs and an HTTP transcript;
- a "Needs manual verification" list (`T-01`…);
- attack paths, with the fix that breaks the most of them;
- the change since the last run (if `--history` is used);
- the OWASP coverage matrix (in the HTML report).

```bash
python3 project_omega.py scan http://localhost:3000 --screenshots --evidence case1 --history omega_history.db --html report.html
python3 project_omega.py scan http://localhost:3000
python3 project_omega.py scan https://mysite.com --authorized --rate 1 --html report.html --save-assets assets.json
python3 project_omega.py scan http://localhost:8080 --cookie "PHPSESSID=abc; security=low" --json dvwa.json
python3 project_omega.py scan https://mysite.com --authorized --passive --cloud --epss --ai
```
**Exit code:** `1` if overall risk is CRITICAL, `2` if the target was refused as unauthorized, otherwise `0`.

---

### `logs`: attack analysis of access logs

**What it does:** reads web-server access logs (Apache/Nginx combined format, or JSON lines) and finds attackers. For each client it reports:

- a risk score and an Autonomy Index (how likely the attacker is automated or AI-driven);
- a kill-chain stage (recon → probing → exploitation → possible compromise);
- an **agent classification** (LLM-driven agent / classic scanner / scripted bot / human) with behavioural evidence, and a **payload lineage tree**;
- every detection, with evidence.

It also groups IPs into **campaigns**, measures **exposure windows**, and can produce a ready-made block list.

**When to use it:** after an incident, as a daily or weekly review, or to tune Omega before switching on blocking.

```
logs LOGFILE [LOGFILE ...] [options]
```

| Argument / option | Default | What it does |
|---|---|---|
| `LOGFILE …` | required | One or more log files (rotated files like `access.log*` work too) |
| `--model FILE` | none | Anomaly model from `train`; adds detection of never-seen-before payloads |
| `--intel FILE` | `omega_intel.json` | Threat intel to use, if the file exists (learned endpoints and rules) |
| `--robots FILE` | none | Your robots.txt; flags clients that read it and then visit disallowed paths |
| `--canary PATH` | none | Honeypot path prefix such as `/omega-trap/` (repeatable); any hit is critical |
| `--json FILE` | none | Save the full report as JSON |
| `--html FILE` | none | Save an HTML report |
| `--blocklist FILE` | none | Write nginx `deny` lines and iptables commands for high-risk clients |
| `--evidence DIR` | none | Acquire the original log files (hashed, read-only) plus the analysis into a sealed evidence vault |
| `--case-id ID` / `--examiner NAME` | auto / OS user | Case details for the evidence vault |
| `--findings FILE` | none | Scan/ingest report: flag **live attacks on your known vulnerabilities** (fusion) |
| `--vpatch FILE` | none | Report requests that your virtual patches would block |
| `--deception FILE` | none | Detect decoy-file reads, CVE-bait probes and honeytoken use |
| `--history DB` | none | Record traffic statistics for `trends` |
| `--block-threshold N` | `70` | Minimum risk score to include a client in the block list (autonomy ≥ 70 is always included) |
| `--top N` | `15` | How many clients to show on screen |
| `--min-score N` | `20` | Hide clients below this risk score on screen |

```bash
python3 project_omega.py logs /var/log/nginx/access.log
python3 project_omega.py logs access.log* --model omega_model.json --robots robots.txt --canary /omega-trap/ --html attacks.html
python3 project_omega.py logs access.log --blocklist /etc/nginx/omega_block.conf --block-threshold 80
```
**Exit code:** `1` if any client is CRITICAL.

---

### `tail`: live log monitoring

**What it does:** follows a log file as it grows and prints alerts in real time: per-request attacks plus behaviour alerts such as burst rates, machine-regular timing and multi-vector probing. Press Ctrl+C to stop and see a full report.

**When to use it:** to watch a server live without putting anything in the traffic path.

```
tail LOGFILE [options]
```

| Argument / option | Default | What it does |
|---|---|---|
| `LOGFILE` | required | Log file to follow |
| `--alert N` | `60` | Print an alert for requests with risk ≥ N |
| `--model FILE` | none | Anomaly model from `train` |
| `--intel FILE` | `omega_intel.json` | Threat intel, if present |
| `--robots FILE` | none | robots.txt for violation detection |
| `--canary PATH` | none | Honeypot path prefix (repeatable) |
| `--from-start` | off | Read the file from the beginning instead of only new lines |

```bash
python3 project_omega.py tail /var/log/nginx/access.log
python3 project_omega.py tail access.log --alert 40 --canary /omega-trap/ --from-start
```

---

### `guard`: protective reverse proxy

**What it does:** sits in front of a web application and inspects every request live.

- **Monitor mode** only alerts.
- **Enforce mode** blocks attacks, bans clients that hit canary paths or behave like autonomous agents, and sends suspected bots into a decoy maze.

It also writes an access log you can analyse later with `logs`. Ctrl+C (or SIGTERM) prints a report.

**When to use it:** in labs, to watch your own attacks get detected; or in front of a small or medium site, behind nginx.

```
guard --upstream URL [options]
```

| Option | Default | What it does |
|---|---|---|
| `--upstream URL` | required | The application to protect, e.g. `http://127.0.0.1:3000` |
| `--host ADDR` | `127.0.0.1` | Address to listen on |
| `--port N` | `8000` | Port to listen on |
| `--monitor` | off | Alert only, never block |
| `--block-threshold N` | `60` | Block requests with risk ≥ N (enforce mode) |
| `--alert N` | `35` | Log an alert for requests with risk ≥ N |
| `--canary PATH` | `/omega-trap/` | Honeypot path prefix (repeatable); hitting it bans the client |
| `--no-deception` | off | Disable the decoy maze for suspected bots |
| `--tarpit SECONDS` | `0.5` | Delay before serving decoy pages (wastes bots' time) |
| `--trust-xff` | off | Use `X-Forwarded-For` as the client IP. Only enable behind a trusted proxy that overwrites the header, or to simulate clients in a lab |
| `--model FILE` | none | Anomaly model from `train` |
| `--intel FILE` | `omega_intel.json` | Threat intel, if present |
| `--log FILE` | `omega_guard.log` | Access log written by the proxy |
| `--vpatch FILE` | none | Enforce virtual patches (blocks regardless of risk score) |
| `--deception FILE` | none | Serve decoy files and CVE-bait pages; ban clients that use honeytokens |
| `--findings FILE` | none | Alert on live attacks against vulnerabilities from your last assessment |
| `--llm-endpoint PATH` | none | Check responses of this chat/LLM endpoint for exfiltration and secrets; sanitise in enforce mode (repeatable) |
| `--dashboard` | off | Serve the **live web dashboard** (see `dashboard` below); the private link is printed at start |
| `--dashboard-port N` | `8300` | Dashboard port |
| `--dashboard-host ADDR` | `127.0.0.1` | Keep the default unless the dashboard sits behind HTTPS and a VPN |
| `--dashboard-token TOKEN` | random | Fixed access token (default: a new random token at every start) |

```bash
python3 project_omega.py guard --upstream http://localhost:8080 --port 8000 --monitor --dashboard
#    then open the dashboard link printed in the terminal to watch the attacks live
python3 project_omega.py guard --upstream http://127.0.0.1:3000 --trust-xff --model omega_model.json --block-threshold 50
```

---

### `train`: learn your normal traffic

**What it does:** builds an anomaly model from logs of normal traffic. It automatically keeps only clean requests (low risk, non-error status). The model then flags payloads that don't look like anything your site normally receives, catching novel attacks that no signature knows.

**When to use it:** once you have a week or so of logs you believe are clean. Retrain when your site changes a lot.

```
train LOGFILE [LOGFILE ...] [--out FILE]
```

| Argument / option | Default | What it does |
|---|---|---|
| `LOGFILE …` | required | Logs of normal traffic (needs at least 50 clean requests; 200+ recommended, thousands is better) |
| `--out FILE` | `omega_model.json` | Where to save the model |

```bash
python3 project_omega.py train /var/log/nginx/access.log.1 /var/log/nginx/access.log.2 --out omega_model.json
```
Use the model with `--model` on `logs`, `tail`, `guard` and `watch`.

---

### `intel`: threat intelligence

**What it does:** maintains Omega's knowledge of real-world vulnerabilities. It is **optional**: Omega works offline with built-in knowledge. It has four actions:

| Action | What it does |
|---|---|
| `intel update` | Downloads CISA KEV (vulnerabilities actively exploited in the wild) and recent NVD CVEs (with affected version ranges), and learns vulnerable endpoints from CVE descriptions |
| `intel status` | Shows what is in the database: counts, last update, recent KEV additions, learned rules |
| `intel import FILE …` | Learns from any advisory, patch diff or news article saved as a file: CVE IDs, fixed versions, vulnerable endpoints. With `--ai`, also writes new detection rules, which are tested against normal traffic before use |
| `intel match` | Looks up known vulnerabilities for one product and version |

```
intel {update,status,import,match} [FILES ...] [options]
```

| Option | Default | What it does |
|---|---|---|
| `FILES …` | none | Files to learn from (for `import`) |
| `--intel FILE` | `omega_intel.json` | Database file to read and write |
| `--days N` | `30` | How many days of NVD CVEs to download (max 120) |
| `--sources LIST` | `kev,nvd` | Which sources to update from |
| `--nvd-key KEY` | env `NVD_API_KEY` | Free NVD API key for much faster updates |
| `--product VENDOR:PRODUCT` | none | Product to look up (for `match`), e.g. `apache:http_server`, `php:php`, `jquery:jquery` |
| `--ver VERSION` | none | Version to look up (for `match`) |
| `--epss` | off | Also fetch EPSS exploit-probability scores (for `match`) |

```bash
python3 project_omega.py intel update --days 60
python3 project_omega.py intel status
python3 project_omega.py intel import vendor_advisory.txt security_fix.diff --ai
python3 project_omega.py intel match --product apache:http_server --ver 2.4.49 --epss
```

---

### `watch`: early warning

**What it does:** compares your software inventory against the latest threat intel. It alerts you, with a **NEW** tag, when a vulnerability affecting your exact versions appears or becomes actively exploited. With `--logs`, it also flags clients that are already doing recon or probing against your stack. It refreshes intel first unless `--offline` is set. Designed to run daily from cron.

```
watch --assets FILE [options]
```

| Option | Default | What it does |
|---|---|---|
| `--assets FILE` | required | Inventory from `scan --save-assets` (repeatable) |
| `--logs FILE` | none | Access logs to check for recon/probing (repeatable) |
| `--model FILE` | none | Anomaly model for the log check |
| `--offline` | off | Don't refresh intel; use cached and built-in knowledge |
| `--days N` | `7` | NVD look-back window for the refresh |
| `--intel FILE` | `omega_intel.json` | Threat-intel database |

```bash
python3 project_omega.py watch --assets assets.json
python3 project_omega.py watch --assets assets.json --logs /var/log/nginx/access.log
```
**Exit code:** `1` when there is a new severity ≥ 9 vulnerability or a newly exploited CVE for your products, which makes it easy to trigger an email from cron.

---

### `supply`: supply-chain attack scan

**What it does:** audits a software project for supply-chain risks:

- **Packages:** typosquatted names, and live vulnerability and malicious-package data from OSV.dev (`--osv`).
- **Dependency confusion:** private package names pulled from public registries.
- **Lockfile problems:** plain-HTTP downloads, missing integrity hashes, wildcard versions.
- **Malicious installed code:** install scripts, credential stealers, worms, wallet hijackers, `.pth` abuse.
- **Risky CI/CD workflows.**
- **Dockerfile issues.**

It supports npm, yarn, pip, Pipenv, Poetry, uv, Composer, Bundler and Go modules.

```
supply PROJECT_DIR [options]
```

| Argument / option | Default | What it does |
|---|---|---|
| `PROJECT_DIR` | required | Root folder of the project |
| `--osv` | off | Query OSV.dev for known vulnerabilities and malicious-package advisories (online) |
| `--shallow` | off | Skip the deep code scan of installed packages (faster) |
| `--site-packages DIR` | none | Also scan a Python environment's site-packages (`.pth` abuse and code) |
| `--internal-prefix PREFIX` | none | Your private package prefix, e.g. `@acme/` or `acme-` (repeatable); detects dependency confusion |
| `--allow-registry HOST` | none | Extra trusted registry host (repeatable) |
| `--sbom FILE` | none | Write a CycloneDX software bill of materials |
| `--json FILE` | none | Save the full report as JSON |
| `--html FILE` | none | Save an HTML report |
| `--min-severity N` | `3` | Hide findings below this severity on screen |
| `--top N` | `12` | Findings shown per category on screen |

```bash
python3 project_omega.py supply ./my-app --osv
python3 project_omega.py supply . --osv --internal-prefix @acme/ --sbom sbom.json --html supply.html
python3 project_omega.py supply ./api --site-packages ./venv/lib/python3.12/site-packages --ai
```
**Exit code:** `1` if any finding has severity ≥ 9 (ideal for failing CI builds).

---

### `files`: webshell & backdoor scanner

**What it does:** scans a web root for webshells and backdoors:

- obfuscated `eval(base64_decode(…))` code, and code that executes request input;
- known webshell families;
- server code hidden inside images;
- double-extension uploads like `shell.php.jpg`;
- malicious `.htaccess` rules.

Base64-wrapped shells are decoded and checked too.

```
files WEBROOT [options]
```

| Argument / option | Default | What it does |
|---|---|---|
| `WEBROOT` | required | Folder to scan, e.g. `/var/www/html` |
| `--recent N` | none | Also flag suspicious files modified in the last N days |
| `--json FILE` | none | Save results as JSON |
| `--html FILE` | none | Save an HTML report |
| `--top N` | `50` | Files shown on screen |

```bash
python3 project_omega.py files /var/www/html --recent 7 --html webshells.html --ai
```
**Exit code:** `1` if any file is CRITICAL.

---

### `baseline` and `verify`: file integrity

**What they do:** `baseline` records a SHA-256 fingerprint of every file in a folder. `verify` later compares the folder against that record and lists added, modified and removed files. New or changed files are automatically scanned for webshells.

```
baseline WEBROOT [--out FILE]
verify WEBROOT [--baseline FILE]
```

| Option | Default | What it does |
|---|---|---|
| `--out FILE` | `omega_baseline.json` | Where `baseline` saves the fingerprints |
| `--baseline FILE` | `omega_baseline.json` | Which baseline `verify` compares against |

```bash
python3 project_omega.py baseline /var/www/html --out baseline.json     # after each legitimate deploy
python3 project_omega.py verify /var/www/html --baseline baseline.json  # e.g. hourly from cron
```
**Exit code (`verify`):** `1` if any file was added or modified.

---

### `string`: analyse a single payload

**What it does:** runs one string or file through all of Omega's engines: web-attack rules, webshell rules and supply-chain code rules. It shows the risk score, every detection and, optionally, each decoded layer. Useful for checking a suspicious URL, header, log line or script.

```
string TEXT [options]
```

| Argument / option | Default | What it does |
|---|---|---|
| `TEXT` | required | The text to analyse; use `-` to read from stdin |
| `--file` | off | Treat `TEXT` as a file path and analyse the file's contents |
| `--show-layers` | off | Print every decoded layer (base64, hex, URL encoding, …) |

```bash
python3 project_omega.py string "/api?q=c3lzdGVtKCdpZCcp" --show-layers
python3 project_omega.py string suspicious.js --file --ai
grep "198.51.100.66" access.log | python3 project_omega.py string -
```
**Exit code:** `1` if risk ≥ 60.

---

### `assess`: continuous assessment

**What it does:** runs the full `scan` pipeline on a schedule, records each run in the history database, and writes timestamped JSON/HTML reports. It can seal one evidence vault per run. When new or regressed findings at or above `--alert-severity` appear, it prints them and runs your `--alert-cmd`, for example a script that emails or posts to Slack.

```
assess TARGET [options]
```

| Option | Default | What it does |
|---|---|---|
| `TARGET` | required | URL to assess |
| `--every INTERVAL` | `24h` | Interval between runs: `30m`, `6h`, `1d`, … |
| `--once` | off | Run one assessment and exit (use from cron) |
| `--history DB` | `omega_history.db` | History database |
| `--out-dir DIR` | `omega_reports` | Folder for timestamped `scan_<time>.json/.html` reports |
| `--evidence-dir DIR` | none | Create and seal one evidence vault per run under DIR |
| `--screenshots`, `--max-screenshots N` | off, `12` | Screenshot evidence per run |
| `--alert-severity N` | `7` | Alert on new/regressed findings with severity ≥ N |
| `--alert-cmd "CMD"` | none | Command run on alerts. It receives env vars `OMEGA_TARGET`, `OMEGA_NEW_COUNT`, `OMEGA_SUMMARY` and `OMEGA_REPORT` |
| scan options | same as `scan` | `--authorized`, `--passive`, `--cloud`, `--cookie`, `--header`, `--rate`, `--max-pages`, `--max-params`, `--max-requests`, `--insecure`, `--epss`, `--intel`, `--save-assets`, AI options |

```bash
python3 project_omega.py assess https://mysite.com --authorized --every 6h --evidence-dir vaults --alert-cmd "./notify.sh"
python3 project_omega.py assess http://localhost:3000 --once          # from cron
```
**Exit code (`--once`):** `1` if new/regressed findings reached the alert severity.

---

### `history`: historic tracking

**What it does:** reads the history database and shows, per target:
- every assessment run, with risk, findings, exposure and attack paths;
- currently open findings, with when they were first seen and how many times;
- how many findings have been resolved, and the mean time to remediate.

With `--html`, it writes a trend report with charts.

```
history [--history DB] [--target URL] [--html FILE]
```

| Option | Default | What it does |
|---|---|---|
| `--history DB` | `omega_history.db` | History database |
| `--target URL` | all targets | Only show this target |
| `--html FILE` | none | Write an HTML trend report |

```bash
python3 project_omega.py history
python3 project_omega.py history --target https://mysite.com --html trend.html
```

---

### `vault`: forensic evidence vault

**What it does:** manages evidence vaults created by `scan --evidence`, `assess --evidence-dir` or `logs --evidence`.

| Action | What it does |
|---|---|
| `vault verify CASE` | Re-hashes every item, checks the hash-chained custody log and the seal (and the HMAC, if `OMEGA_VAULT_KEY` is set). Records the verification in the custody log. Exit code `1` on any integrity failure |
| `vault list CASE` | Lists every evidence item with its ID, category, capture time and hash |
| `vault custody CASE` | Without options, prints the chain of custody. With `--custody-action`, records a new entry |
| `vault export CASE` | Zips the case, computes the zip's SHA-256 and records the export in the custody log |
| `vault report CASE` | (Re)generates the visual `VAULT_INDEX.html` case report |

| Option | What it does |
|---|---|
| `--actor NAME` | Person performing the action (recorded in the custody log) |
| `--custody-action ACTION` | Action to record, e.g. `TRANSFERRED`, `ACCESSED`, `REVIEWED`, `RECEIVED` |
| `--item E-0007` | Evidence item the entry concerns (default: whole case) |
| `--note TEXT` | Details, e.g. who received it and how |
| `--out PATH` | Zip path for `export`, or HTML path for `report` |

```bash
python3 project_omega.py vault verify case1
python3 project_omega.py vault custody case1 --custody-action TRANSFERRED --actor "A. Analyst" --note "To legal (J. Doe), encrypted USB"
python3 project_omega.py vault custody case1                       # show the full chain of custody
python3 project_omega.py vault export case1 --out case1.zip --actor "A. Analyst"
OMEGA_VAULT_KEY="long-secret" python3 project_omega.py scan http://localhost:3000 --evidence case2   # HMAC-signed seal
```

---

### `dashboard`: live web dashboard

**What it does:** shows what Omega sees in your browser, refreshing every 3 seconds.

| Panel | Content |
|---|---|
| Stat cards | Requests, flagged, blocked, banned now, clients, LLM agents, scanners, campaigns, bait/honeytoken hits, virtual-patch blocks |
| Traffic | Requests and flagged requests per interval |
| Live events | Every alert, block, ban, bait hit and LLM-output sanitisation, with filters (all / blocks / alerts / deception). A block replaces its own alert, so there are no duplicates |
| Attack categories | What attackers are trying most |
| Campaigns | Groups of IPs acting as one actor |
| Clients | Top clients by risk, each with level, **agent type**, **kill-chain stage**, top detection and last seen. With `guard`, each row has **Ban / Unban** buttons |

There are two ways to run it:
- **Live with protection:** `guard … --dashboard`. Ban/Unban buttons are active.
- **Read-only for any access log:** `dashboard --log FILE`. It reads the whole file and then follows new lines; `--from-end` shows only new lines.

```
dashboard --log FILE [--from-end] [--port 8300] [--host 127.0.0.1] [--token T] [--alert 35]
          [--findings FILE] [--vpatch FILE] [--deception FILE] [--model FILE] [--intel FILE]
```

```bash
python3 project_omega.py guard --upstream http://127.0.0.1:3000 --dashboard          # open the printed link
python3 project_omega.py dashboard --log /var/log/nginx/access.log                     # read-only view of a log
```

**Security design.** The dashboard shows attacker-controlled data, so it is locked down:
- **Private by default.** It listens only on `127.0.0.1` and opens through a **secret link** printed in the terminal, which sets an HttpOnly, SameSite=Strict session cookie. Without the cookie, everything returns 401.
- **No script injection.** All attacker data is inserted as plain text (never as HTML), under a strict Content-Security-Policy with no inline scripts. It's also protected against being framed by other sites.
- **Forgery-proof actions.** Ban/Unban requires the session cookie, a custom header that other websites can't send, and a matching Origin. IP addresses are validated.
- **Remote viewing.** Use an SSH tunnel (`ssh -L 8300:127.0.0.1:8300 server`) rather than exposing the port.

---

### `deceive`: honeytokens, decoy files, CVE-bait

**What it does:** creates a private **deception kit** (`omega_deception.json`). It contains:
- **six honeytokens:** decoy AWS key and secret, API key, database password, admin username and admin password;
- **four decoy files** that contain those tokens (`/.env.backup`, `/backup/config.php.bak`, `/old/.env`, `/admin/credentials.txt`);
- **CVE-bait endpoints:** paths of recent or actively exploited CVEs for products you don't run. They are taken from live intel when available, plus a built-in seed list.

When `guard` (or the middleware) runs with `--deception`:
- decoy files and bait pages are served to anyone who requests them;
- any use of a honeytoken bans the client instantly;
- `logs --deception` reports the same events from your access logs.

```
deceive {init,files,show} [options]
```

| Action / option | Default | What it does |
|---|---|---|
| `init` | | Create a new kit (new random tokens each time) |
| `files` | | Write the decoy files to `--out-dir`, for placing in your web root |
| `show` | | List tokens (truncated), where they are planted, and bait endpoints |
| `--deception FILE` | `omega_deception.json` | Kit file. **Keep it private**: it's what recognises your tokens |
| `--intel FILE` | `omega_intel.json` | Use live intel (after `intel update`) to choose bait endpoints |
| `--assets FILE` | none | `assets.json` from `scan --save-assets`, so products you actually run are never used as bait |
| `--out-dir DIR` | `omega_decoys` | Destination for `files` |

```bash
python3 project_omega.py deceive init --assets assets.json
python3 project_omega.py guard --upstream http://127.0.0.1:3000 --deception omega_deception.json
```
Place decoys only at paths where **no real file exists**. Access logs normally don't record auth headers, so token use in headers is caught live by `guard`/middleware. `logs` sees tokens used in URLs or bodies.

---

### `vpatch`: virtual patches

**What it does:** turns the confirmed and firm findings of a `scan` or `ingest` report into narrow blocking rules:

| Finding type | Patch |
|---|---|
| SQL injection, XSS, template injection, JSONP, open redirect | Blocks malicious values **only on the vulnerable endpoint and parameter**; normal values pass |
| Exposed files, admin panels, directory listing, GraphQL introspection | Blocks the exact path |

Re-running `generate` on a newer report keeps patches for issues that still exist and **retires** patches whose vulnerability is gone (only after a complete scan).

```
vpatch {generate,list} [SCAN_REPORT.json] [--vpatch FILE]
```

| Argument / option | Default | What it does |
|---|---|---|
| `generate SCAN_REPORT.json` | | Create or update patches from a report |
| `list` | | Show active patches and the retired count |
| `--vpatch FILE` (alias `--out`) | `omega_vpatches.json` | Patch file |

```bash
python3 project_omega.py vpatch generate scan.json
python3 project_omega.py guard --upstream http://127.0.0.1:3000 --vpatch omega_vpatches.json
python3 project_omega.py waf nginx --vpatch omega_vpatches.json
```
Virtual patches are deliberately strict on the vulnerable parameter. They buy time; they don't replace fixing the code.

---

### `waf`: push rules into your WAF

**What it does:** exports virtual patches and blocked actors to your existing WAF. Actors come from `--logs-report`: high-risk clients plus every IP of every campaign.

| Target | Output |
|---|---|
| `nginx` | `map` blocks plus `if` lines, with URL-encoding-aware regexes (nginx matches raw arguments); `deny` lines for actors |
| `modsecurity` | `SecRule` chains per patch, plus `@ipMatch` deny rules |
| `cloudflare` | Custom-rule expressions and IP blocks. Dry run by default; `--apply --zone ID` with env `CF_API_TOKEN` pushes them through the API. Rules already present are skipped |
| `aws` | AWS WAFv2 rule JSON (byte-match statements with URL-decode + lowercase), plus the IP list |

```
waf {nginx,modsecurity,cloudflare,aws} [--vpatch FILE] [--logs-report FILE] [--block-threshold 70] [--out FILE] [--zone ID --apply]
```

```bash
python3 project_omega.py waf nginx --vpatch omega_vpatches.json --logs-report attacks.json
CF_API_TOKEN=... python3 project_omega.py waf cloudflare --zone ZONE_ID --apply
```
Cloudflare's regex `matches` operator needs a plan with regex support (Business+). Review generated rules before applying them.

---

### `ingest`: use other scanners as sensors

**What it does:** imports results from other tools and processes them like Omega's own findings. The format is auto-detected:

| Format | Tools |
|---|---|
| JSON lines | Nuclei (`-jsonl`) |
| JSON with `site` | OWASP ZAP JSON report |
| XML | Burp Suite issue export |
| SARIF | Trivy, Semgrep, CodeQL, … |

It maps severities, confidence and CWE → OWASP categories, de-duplicates across tools, and then:
- builds attack paths (using CWE → attacker capabilities);
- produces an HTML/JSON report;
- tracks findings in history;
- seals the original outputs in an evidence vault (optional).

```
ingest FILE... [--target URL] [--json FILE] [--html FILE] [--history DB] [--evidence DIR] [--case-id ID] [--examiner NAME]
```

```bash
python3 project_omega.py ingest nuclei.jsonl zap.json trivy.sarif --target https://mysite.com --html combined.html --history omega_history.db
python3 project_omega.py vpatch generate combined.json      # if you also saved --json combined.json
```

---

### `validate`: would your defenses catch it?

**What it does:** runs a corpus of 24 safe attack test strings across 15 classes, plus 8 benign controls:
- **Offline** (no `--target`): through the detection engine.
- **Online** (`--target`): against **your own** guard, WAF or staging site, counting blocks (403/406/429).

Benign controls run first, so an attack burst that gets the replay IP banned can't skew the results. The output shows, per class, what was **detected**, what was **blocked**, and what slipped through. A "△" marks attacks that were detected but not blocked, which is a policy gap.

```
validate [--target URL] [--authorized] [--rate 10] [--model FILE] [--intel FILE] [--json FILE] [--html FILE]
```

```bash
python3 project_omega.py validate
python3 project_omega.py validate --target http://127.0.0.1:8000 --html validation.html
```
**Exit code:** `0` when detection ≥ 90 % with no false positives, otherwise `1`. Use it in CI after changing rules.

---

### `aisec`: secure your AI features

**What it does:** finds AI-specific risks and maps them to the OWASP Top 10 for LLM Applications (2025).

| Action | Input | Finds |
|---|---|---|
| `docs` | Files or folders (.txt .md .html .json .csv .xml .yaml …) that an AI system reads (RAG corpora, crawled pages) | Hidden instructions in invisible Unicode tag characters (decoded and shown), zero-width and bidi tricks, visually hidden HTML text, instructions in HTML comments, encoded injections, exfiltration beacons |
| `mcp` | MCP config JSON (`mcpServers`), plus optional saved `tools/list` output per server with `--tools` | Tool poisoning (descriptions that inject or steer other tools), tool-name shadowing, unpinned `npx -y`/`uvx` packages, plaintext secrets, whole-filesystem or shell access, plain-HTTP remote servers |
| `output` | A file of model output, or `-` for stdin | Markdown/HTML image beacons, encoded data in links, known exfiltration hosts, secrets, system-prompt leakage, hidden Unicode |

```
aisec {docs,mcp,output} PATH... [--tools FILE] [--json FILE] [--html FILE]
```

```bash
python3 project_omega.py aisec docs ./knowledge_base --html rag_audit.html
python3 project_omega.py aisec mcp ~/.config/Claude/claude_desktop_config.json --tools tools_docs.json
python3 project_omega.py guard --upstream http://127.0.0.1:3000 --llm-endpoint /api/chat     # live output firewall
```
**Exit code:** `1` if any issue has severity ≥ 8.

---

### `trends`: autonomous-threat report

**What it does:** reads the traffic statistics recorded by `logs … --history DB` and reports them per month:
- requests and clients;
- the share of clients that are autonomous;
- LLM agents, scanners and bots;
- campaigns, bait hits and honeytoken hits;
- the median **exposure window** (days from CVE publication to the first probe in your traffic).

```
trends [--history DB] [--html FILE]
```

```bash
python3 project_omega.py logs /var/log/nginx/access.log.1 --history omega_history.db     # e.g. daily from cron
python3 project_omega.py trends --html autonomous_threats.html
```

---

### `signatures`: anonymised community sharing

**What it does:** `export` builds a bundle from a logs report. It contains one-way **payload-shape hashes** of attack traffic (with agent class and attack categories) plus your validated learned rules. It never contains IP addresses, hostnames, URLs or raw payloads.

`import` adds a bundle to your intel database:
- shapes are counted by how many contributors reported them;
- rules are re-validated (ReDoS and benign-traffic checks) before use;
- duplicate bundles are ignored.

Afterwards, `logs`/`guard` flag attack traffic whose shape matches a community-reported campaign.

```
signatures {export,import} [BUNDLE] [--logs-report FILE] [--out FILE] [--intel FILE]
```

```bash
python3 project_omega.py signatures export --logs-report attacks.json --out my_bundle.json
python3 project_omega.py signatures import partner_bundle.json
```

---

### `respond`: response playbooks

**What it does:** turns analysis into approved action, in three steps:

1. **`plan`** builds a reviewable action list from a logs report (and optionally a scan report):
   - block high-risk clients and campaign IPs;
   - investigate possible compromises;
   - deploy virtual patches, preferring vulnerabilities **under live attack**;
   - rotate exposed secrets;
   - investigate honeytoken use;
   - notify.
2. **`execute`** asks for approval for **each** action (or `--yes`) and performs it:
   - nginx deny file, or Cloudflare IP blocks;
   - writing virtual patches;
   - rotation/investigation checklists;
   - a Slack/Teams-compatible webhook notification.

   Every action is logged to `omega_response_log.jsonl`, and to the vault's chain of custody when `--vault` is given.
3. **`timeline`** builds an incident timeline (HTML) from attacker activity, assessments, custody entries and response actions.

| Option | Default | What it does |
|---|---|---|
| `--logs-report` / `--scan-report` | none | Inputs for `plan` and `timeline` |
| `--out FILE` | `omega_response_plan.json` / `omega_incident_timeline.html` | Output |
| `--yes` | off | Approve all actions without asking |
| `--dry-run` | off | Show actions without executing |
| `--actor NAME` | OS user | Recorded as the approver |
| `--nginx-deny FILE` | `omega_block.conf` | Where IP blocks are appended |
| `--cloudflare-zone ID` | none | Block IPs in Cloudflare instead (env `CF_API_TOKEN`) |
| `--webhook URL` | none | Incoming-webhook URL for the notification |
| `--vpatch-out FILE` | `omega_vpatches.json` | Where deployed patches are written |
| `--vault DIR` | none | Record actions in the case's chain of custody; include custody in the timeline |

```bash
python3 project_omega.py respond plan --logs-report attacks.json --scan-report scan.json
python3 project_omega.py respond execute omega_response_plan.json --vault case1 --webhook https://hooks.slack.com/...
python3 project_omega.py respond timeline --logs-report attacks.json --scan-report scan.json --vault case1
```

---

### `export`: SARIF, STIX 2.1, CEF

**What it does:** converts reports for other platforms:

| Format | From | Use |
|---|---|---|
| `--sarif FILE` | scan, ingest or supply report | GitHub code scanning and other SARIF consumers |
| `--stix FILE` | logs report | Threat-intel platforms: indicators for attacker IPs, campaign objects, "indicates" relationships |
| `--cef FILE` | any report | SIEM ingestion (one CEF event per detection/finding) |

```bash
python3 project_omega.py export scan.json --sarif scan.sarif
python3 project_omega.py export attacks.json --stix attacks.stix.json --cef attacks.cef
```

---

### `plugins`: extend Omega

**What it does:** `list` shows loaded plugins. `new NAME` writes a template to `./omega_plugins/NAME.py`. Plugins load automatically from `./omega_plugins` or the folders in `$OMEGA_PLUGINS` (set `OMEGA_NO_PLUGINS=1` to disable). A plugin can define:

| Hook | Effect |
|---|---|
| `OMEGA_RULES` | Extra detection rules `(id, category, severity, regex, description)` |
| `OMEGA_CHAIN_RULES` | Extra attack-path chain rules |
| `omega_scan_check(scanner)` | Custom check run at the end of every `scan` (use `scanner.c.fetch` and `scanner.add`) |

```bash
python3 project_omega.py plugins new acme-rules
python3 project_omega.py plugins list
```
Plugins are Python code: only load files you wrote or trust.

---

### `report`: convert JSON to HTML

**What it does:** turns any JSON report saved by `scan`, `logs`, `supply` or `files` into a self-contained HTML report (print it to PDF from your browser). It detects the report type automatically.

```
report JSON_FILE [--html FILE]
```

| Argument / option | Default | What it does |
|---|---|---|
| `JSON_FILE` | required | A JSON report produced with `--json` |
| `--html FILE` | same name with `.html` | Output path |

```bash
python3 project_omega.py report scan.json
python3 project_omega.py report attacks.json --html monday_attacks.html
```

---

### `lab`: practice guide

**What it does:** prints a short step-by-step guide for practising safely with deliberately vulnerable apps such as Juice Shop and DVWA. It has no options.

```bash
python3 project_omega.py lab
```

---

### `selftest`: built-in tests

**What it does:** runs Omega's built-in test suite. It covers:

- the attack signatures and decoder (against malicious and benign samples);
- the anomaly model;
- typosquat checks;
- agent fingerprinting, payload lineage and campaign clustering;
- virtual patching, deception, fusion and WAF-export regex correctness;
- AI-security checks, ingestion, exports and detection validation;
- the AI-analyst safety rules;
- threat-intel version matching;
- learned-rule validation and kill-chain early warnings.

It has no options.

```bash
python3 project_omega.py selftest      # should end with "Result: ALL PASSED"
```
**Exit code:** `1` if any test fails.

---

### Python API: `OmegaMiddleware`

**What it does:** gives Flask/Django apps the same protection as `guard`, without a separate proxy.

```python
from project_omega import OmegaMiddleware, AnomalyModel

app.wsgi_app = OmegaMiddleware(
    app.wsgi_app,
    block_threshold=70,          # block requests with risk >= 70
    alert_threshold=35,          # log alerts for risk >= 35
    canary_paths=["/omega-trap/"],
    model=AnomalyModel.load("omega_model.json"),   # optional
    enforce=True,                # False = monitor only
    deception=True,              # decoy maze for suspected bots
    tarpit_seconds=1.5,          # use 0 on servers with few workers
    trust_forwarded=False,       # True only behind a trusted reverse proxy
)
```

---

## AI analyst setup

The AI analyst is optional. Add `--ai` to `logs`, `scan`, `files`, `supply`, `string` or `intel import`.

```bash
export ANTHROPIC_API_KEY=...                   # default provider
# or
export OPENAI_API_KEY=... ; use --ai-provider openai
# or a fully local model (no data leaves your machine):
--ai-provider ollama
```

**Optional environment variables**

| Variable | Purpose |
|---|---|
| `OMEGA_AI_PROVIDER` | `anthropic`, `openai` or `ollama` |
| `OMEGA_AI_MODEL` | Override the model name (check your provider's current model list) |
| `OMEGA_AI_ENDPOINT` | Custom API endpoint |
| `NVD_API_KEY` | Faster NVD intel updates |

**How the analyst is hardened**
- **Untrusted data is fenced.** Attacker-controlled data is wrapped in random-nonce markers, and the model is instructed never to follow it.
- **Output is validated.** Responses are checked against a strict JSON schema.
- **Secrets are redacted.** API keys, JWTs, passwords and emails are removed before anything is sent. `--no-redact` disables this.
- **Escalate-only.** The AI may raise a score but never lower it. A payload that tries to manipulate the analyst is itself escalated.
- **Learned rules are tested.** Rules the AI writes for `intel import` are checked for ReDoS and false positives before use.
- **Cost is capped.** `--ai-max-calls` (default 20) limits calls, and results are cached in `.omega_ai_cache.json`.

---

## Practice lab (step by step)

Use deliberately vulnerable apps that you run yourself. You need Docker for the first two.

```bash
# 1. Verify the tool
python3 project_omega.py selftest

# 2. Start practice apps (separate terminals)
docker run --rm -p 3000:3000 bkimminich/juice-shop          # OWASP Juice Shop
docker run --rm -p 8080:80  vulnerables/web-dvwa             # DVWA: admin / password,
                                                             # click "Create / Reset Database", set security = Low
# or, with no Docker at all:
curl -O https://raw.githubusercontent.com/stamparm/DSVW/master/dsvw.py && pip install lxml && python3 dsvw.py

# 3. (Optional) load live threat intel
python3 project_omega.py intel update

# 4. Scan
python3 project_omega.py scan http://localhost:3000 --json juice.json --save-assets assets.json
python3 project_omega.py scan http://localhost:8080 --cookie "PHPSESSID=<yours>; security=low"

# 5. Watch attacks live: browse via port 8000 and do the exercises
python3 project_omega.py guard --upstream http://localhost:8080 --port 8000 --monitor

# 6. Forensics on what you did
python3 project_omega.py logs omega_guard.log

# 7. Protection mode: re-run step 5 without --monitor and retry the exercises

# 8. Early warning: import an advisory, then request the endpoint it names
python3 project_omega.py intel import advisory.txt
python3 project_omega.py watch --assets assets.json --logs omega_guard.log

# 9. Supply chain of a deliberately vulnerable codebase
git clone https://github.com/juice-shop/juice-shop
python3 project_omega.py supply juice-shop --osv
```

**Reference result (DSVW).** The scan found SQL injection in 3 parameters, reflected XSS, JSONP injection, DOM-XSS, an open redirect, stack-trace disclosure and cookie and header weaknesses, without crashing the app. Guard detected 26 of DSVW's 27 published attack examples live, with zero alerts on normal browsing.

---

## Real-world deployment

Roll out in phases so nothing breaks.

### Week 1: visibility only
```bash
python3 project_omega.py scan https://staging.yoursite.com --authorized
python3 project_omega.py scan https://yoursite.com --authorized --passive --rate 1 --max-requests 300 --save-assets assets.json
python3 project_omega.py logs /var/log/nginx/access.log* --json report.json
python3 project_omega.py supply /path/to/app --osv --sbom sbom.json
python3 project_omega.py baseline /var/www/html --out baseline.json
python3 project_omega.py train /var/log/nginx/access.log.1 --out omega_model.json   # a clean week of logs
```
- **Logins:** use a dedicated low-privilege test account for authenticated scans.
- **Firewall:** allow-list your scanner IP in your WAF, or expect it to get blocked.

### Weeks 2–3: monitor live traffic
**nginx:**
```nginx
location / {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;   # overwrite, never append (prevents IP spoofing)
}
```
Behind Cloudflare or another CDN, configure nginx's `real_ip` module with the CDN's IP ranges first.

**systemd** (`/etc/systemd/system/omega-guard.service`):
```ini
[Unit]
Description=Project Omega guard
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/omega/project_omega.py guard --upstream http://127.0.0.1:3000 \
  --port 8000 --trust-xff --monitor --model /opt/omega/omega_model.json --log /var/log/omega/guard.log
Restart=always
User=omega

[Install]
WantedBy=multi-user.target
```

### Week 4+: enforce
Remove `--monitor` once alerts show no false positives against real users. Add the AI-agent trap: put `Disallow: /omega-trap/` in robots.txt and a hidden link to that path in your pages.

### Deception, virtual patches and WAF integration
```bash
python3 project_omega.py deceive init --assets assets.json        # once; keep the kit private
python3 project_omega.py vpatch generate scan.json                # after each assessment
python3 project_omega.py waf nginx --vpatch omega_vpatches.json --logs-report attacks.json --out /etc/nginx/omega.conf
python3 project_omega.py validate --target https://staging.mysite.com --authorized   # confirm the rules block
```

### Automation
```cron
0 5 * * *  cd /opt/omega && python3 project_omega.py intel update
30 5 * * * cd /opt/omega && python3 project_omega.py watch --assets assets.json --logs /var/log/nginx/access.log || echo "new critical risk" | mail -s "OMEGA ALERT" you@example.com
0 * * * *  cd /opt/omega && python3 project_omega.py verify /var/www/html --baseline baseline.json || echo "files changed" | mail -s "OMEGA FILES" you@example.com
0 3 * * 0  cd /opt/omega && python3 project_omega.py logs /var/log/nginx/access.log.1 --blocklist /etc/nginx/omega_block.conf
```
Review the blocklist before including it in nginx. Re-run `baseline` after every legitimate deploy.

**CI (GitHub Actions):**
```yaml
- name: Omega supply-chain check
  run: python3 project_omega.py supply . --osv --json omega-supply.json
```

---

## How detection works

```
request ─► multi-layer decoder ─► signature rules (+ learned intel rules)
                                 ─► anomaly model (learned baseline)
                                 ─► advisory-endpoint watchlist
        ─► per-client profile ─► behaviour engine ─► Risk Score + Autonomy Index
                                                  ─► kill-chain stage + early warning
        ─► (optional) AI analyst ─► escalate-only verdict fusion
```

- **Risk score.** Each finding has a severity from 1 to 10. Request and client risk is `8 × highest severity + 1.5 × each additional finding`, capped at 100.
- **Autonomy Index.** It combines behavioural traits: regular timing, multi-vector probing, payload mutation, robots violations, canary hits, scripted user agents and UA rotation.
- **Anomaly model.** It abstracts letters and digits into a "shape" (new words look normal) and scores unusual punctuation, control and Unicode patterns against a threshold learned from your traffic.

---

## Reports & outputs

### Downloadable reports
```bash
python3 project_omega.py scan http://localhost:3000 --json scan.json --html scan.html
python3 project_omega.py logs access.log --html attacks.html
python3 project_omega.py supply ./app --osv --html supply.html --sbom sbom.json
python3 project_omega.py files /var/www/html --html webshells.html
python3 project_omega.py report scan.json --html scan.html          # convert a saved JSON report later
python3 project_omega.py scan http://localhost:3000 > scan.txt      # plain-text console report
```
To get a PDF, open the HTML report in any browser and choose **Print → Save as PDF**. Print styles are built in, so it comes out clean.

| Report | Main sections |
|---|---|
| Web vulnerability assessment (`scan`) | Executive summary, early warnings, OWASP Top 10 chart, technology stack, detailed findings with fixes, remediation checklist, AI plan, scope & methodology |
| Attack traffic analysis (`logs`) | Summary, attack categories, kill-chain stages, client table, per-attacker evidence and AI verdicts, recommended actions with a ready `deny` list |
| Supply-chain security (`supply`) | Summary, malicious-code alert, findings by category, details with AI second opinions, hardening checklist |
| Webshell & backdoor scan (`files`) | Summary and per-file evidence |
| Evidence vault index (`VAULT_INDEX.html`) | Integrity status, evidence by category, screenshot gallery with hashes, full manifest, chain-of-custody timeline |
| History & trends (`history --html`) | Per-target gauge, open/resolved counts, mean time to remediate, risk/exposure/attack-path trend, open findings, run log |

The scan report now also includes these sections:
- attack path reconstruction (graph, paths, where to cut);
- change since the last run, with a trend chart;
- per-finding confidence, history status, evidence IDs, embedded screenshot and HTTP transcript;
- needs manual verification;
- the OWASP coverage matrix;
- forensic evidence details.


| Level | Score |
|---|---|
| CRITICAL | ≥ 80 |
| HIGH | ≥ 60 |
| MEDIUM | ≥ 35 |
| LOW | > 0 |

| Command | Non-zero exit when |
|---|---|
| `logs`, `scan`, `files` | Any CRITICAL result (`scan` returns 2 if it refuses an unauthorized target) |
| `supply` | Any finding of severity ≥ 9 |
| `watch` | New severity ≥ 9 vulnerability, or newly exploited CVE for your stack |
| `verify` | Files added or modified |
| `string` | Risk ≥ 60 |
| `selftest` | Any test failed |

**Files Omega writes**

| File | Contents |
|---|---|
| `--html` reports | Self-contained human-readable reports (print to PDF) |
| `--json` reports | Full machine-readable results |
| `--blocklist` | nginx `deny` lines and iptables commands |
| `--sbom` | CycloneDX 1.5 SBOM |
| `omega_intel.json` | Threat-intel database |
| `omega_model.json` | Anomaly model |
| `omega_baseline.json` | File-integrity hashes |
| `omega_guard.log` | Combined-format access log from `guard` |
| `.omega_ai_cache.json` | AI response cache |
| `--evidence` vault folder | Sealed forensic case: evidence files, manifest, chain of custody, seal, `VAULT_INDEX.html` |
| `omega_history.db` | SQLite history of all assessments and finding states |
| `omega_reports/` | Timestamped reports written by `assess` |

---

## Limitations

- **Not a replacement for a mature WAF**, professional penetration testing, or timely patching. Run Omega alongside Cloudflare, ModSecurity with the OWASP Core Rule Set, or AWS WAF.
- **No scanner finds every vulnerability.** Business-logic flaws, broken authorization (IDOR) and multi-step issues need manual testing. Safe mode deliberately does not exploit, so blind and time-based vulnerabilities are not confirmed by `scan`.
- **DOM-XSS never appears in server logs**, because browsers don't send URL fragments. The scanner looks for it in client-side code instead.
- **`guard` has proxy limits.** It buffers full responses and does not support WebSockets or streaming. It suits small and medium sites; for high-traffic or real-time apps, use log mode with blocklists.
- **Signatures can be evaded.** The anomaly model and AI analyst reduce this, but don't eliminate it. Expect some tuning per site, which is what monitor mode is for.
- **False positives can be reduced, not eliminated.** Verified findings are re-tested independently and unverified signals are kept out of the score, but version-based component findings can still be wrong if your vendor backports patches. Every finding includes its evidence so you can check it.
- **Attack paths are estimates.** The likelihoods prioritise fixes; they don't prove a path is exploitable, and real attackers may find chains the rules don't model.
- **The vault is tamper-evident, not tamper-proof.** Someone with write access could rebuild an entire vault with new hashes. For strong assurance, set `OMEGA_VAULT_KEY` (HMAC seal) and send the export's SHA-256 to a third party or ticket system at collection time.
- **Screenshots need extra software.** They require Playwright (`pip install playwright && playwright install chromium`) or a local Chrome/Chromium/Edge. Cookies are applied only with Playwright.
- **History depends on comparable runs.** Comparing scans with very different scope (pages, budget) can show findings as resolved simply because they weren't reached. Keep `assess` settings consistent.
- **Agent classification is probabilistic.** It is based on behaviour and reported with a confidence level. A careful human can look like a bot, and a well-built agent can imitate a human. Access logs with 1-second timestamps also blur think-time measurements; `guard` measures them precisely.
- **Deception visibility depends on where you watch.** Honeytokens used in headers are only visible to `guard`/middleware, because access logs don't contain auth headers. CVE-bait from the built-in seed list should be checked against products you actually run (`deceive init --assets`).
- **WAF exports need review.** nginx matches raw (URL-encoded) arguments, so its rules are encoding-aware approximations; ModSecurity, `guard` and the middleware decode properly. Cloudflare regex rules need a plan with regex support.
- **Plugins are code** and run with Omega's privileges.
- **The AI analyst sends data to an external provider** unless you use Ollama. Check your privacy obligations (e.g. GDPR).
- **IP bans need real client IPs.** If many users share one address (NAT, CDN without `real_ip`), bans can affect all of them.

---

## Project status

Version 5.0.0. Built as a learning and defensive toolkit. It is tested with the built-in self-tests, a purpose-built vulnerable app and DSVW, but it has **not** been battle-tested on large production traffic. Test in staging first and roll out in monitor mode.

Released under the [MIT License](LICENSE). See [SECURITY.md](SECURITY.md) to report vulnerabilities and [CONTRIBUTING.md](CONTRIBUTING.md) to contribute.
