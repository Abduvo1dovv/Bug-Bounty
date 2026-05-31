# Super Monster

```
  ____                         __  __                 _
 / ___| _   _ _ __   ___ _ __|  \/  | ___  _ __  ___| |_ ___ _ __
 \___ \| | | | '_ \ / _ \ '__| |\/| |/ _ \| '_ \/ __| __/ _ \ '__|
  ___) | |_| | |_) |  __/ |  | |  | | (_) | | | \__ \ ||  __/ |
 |____/ \__,_| .__/ \___|_|  |_|  |_|\___/|_| |_|___/\__\___|_|
             |_|

  Bug Bounty Intelligence & Correlation Engine v1.0.0
```

## Overview

**Super Monster** is a Python 3.11+ bug bounty intelligence and correlation engine that integrates
with the [Monster](../monster/README.md) web scanner's JSON output format. It provides multi-target
correlation, AI-based prioritization, automatic retest scheduling, and attack path planning to
maximize bug bounty earnings and minimize duplicates.

Super Monster transforms raw scan findings into actionable intelligence by detecting attack chains
across multiple hosts, scoring findings by real-world exploitability, and generating elite reports
ready for submission to HackerOne, Bugcrowd, or any bug bounty platform.

---

## Features

### 1. Multi-Target Finding Correlation

Detect attack chains that span multiple hosts and subdomains. The correlator identifies
relationships between findings (e.g., SSRF on `api.target.com` combined with cloud metadata
exposure on `internal.target.com`) and chains them into compound vulnerabilities with
boosted severity ratings.

- 12 built-in correlation rules covering auth bypass chains, SSRF-to-cloud, XSS-to-ATO, and more
- Confidence scoring from 0.0 to 1.0 for each detected chain
- Cross-domain and same-endpoint correlation detection
- Chain length multipliers (2x to 2.5x bonus for multi-step chains)

### 2. AI-Based Priority Scoring

A weighted formula incorporating 5 key factors ranks every finding by actionability:

| Factor               | Weight | Description                                      |
|----------------------|--------|--------------------------------------------------|
| CVSS Base Score      | 25%    | Industry-standard vulnerability severity         |
| Exploitability       | 20%    | Attack vector, complexity, privileges needed     |
| Business Impact      | 25%    | Impact on authentication, payments, PII          |
| Bug Bounty Value     | 15%    | Estimated payout based on platform data          |
| Correlation Bonus    | 15%    | Bonus from being part of an attack chain         |

The prioritizer uses real bug bounty payout data from HackerOne, Bugcrowd, Intigriti,
Synack, and YesWeHack to estimate earnings potential for each finding.

### 3. Automatic Retest Scheduling

Verify whether findings persist over time with configurable retest strategies:

- **full** - Retest all findings in the database
- **critical_only** - Only retest CRITICAL and HIGH severity findings
- **oldest_first** - Prioritize findings that haven't been checked recently
- **random_sample** - Test a random subset for spot-checking

Retest intervals are severity-based: CRITICAL (24h), HIGH (72h), MEDIUM (7d), LOW (14d).

### 4. Attack Path Planning

Generate step-by-step exploitation scenarios from correlated findings. The attack planner
produces numbered playbooks showing:

- Prerequisites for each exploitation step
- Tools and techniques required
- Expected outcomes and evidence to collect
- Risk assessment and detection likelihood
- Proof-of-concept templates

### 5. Temporal Diff Analysis

Compare two scan runs over time to identify:

- New findings that appeared since the last scan
- Findings that were fixed (no longer present)
- Findings that regressed (previously fixed, now back)
- Changes in severity or scope
- New subdomains and attack surface expansion

### 6. Multi-Channel Notifications

Alert on important events through multiple channels:

- **Console** - Colored terminal output with severity indicators
- **File log** - Append events to a structured log file
- **Discord** - Webhook integration with embedded messages
- **Slack** - Webhook integration with Block Kit formatting
- **Telegram** - Bot API integration with Markdown messages

Event types: `NEW_CRITICAL`, `FINDING_FIXED`, `NEW_SUBDOMAIN`, `STALE_FINDING`, `ATTACK_CHAIN_DETECTED`

### 7. Elite Reporting

Generate professional reports in multiple formats:

- **JSON** - Machine-readable full data export for automation pipelines
- **Markdown** - Human-readable with tables, ASCII graphs, and correlation maps
- **HTML** - Styled dark-theme interactive report with severity badges

Report sections include correlation maps, attack path visualizations, priority-ranked finding
lists, retest history timelines, business impact assessments, and HackerOne/Bugcrowd submission
templates.

---

## Installation

Super Monster requires Python 3.11+ and has a single external dependency: `colorama`.

```bash
# Navigate to the Bug-Bounty repository root
cd Bug-Bounty

# Install dependencies (just colorama)
pip install -r requirements.txt

# Verify installation
python -m super_monster --version
```

The `requirements.txt` at the repository root contains:

```
colorama>=0.4.6
```

No additional setup is required. Super Monster uses only the Python standard library
plus colorama for colored terminal output.

---

## Usage

### Show Help

```bash
python -m super_monster --help
```

Output:
```
usage: super_monster [-h] [--version] {correlate,retest,prioritize,plan,diff,full} ...

Super Monster v1.0.0 - Bug Bounty Intelligence Engine

positional arguments:
  {correlate,retest,prioritize,plan,diff,full}
    correlate           Cross-target finding correlation
    retest              Retest findings for persistence
    prioritize          Score and rank findings by priority
    plan                Generate attack plans
    diff                Compare two scan reports
    full                Run complete pipeline

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
```

---

### `correlate` - Cross-Target Correlation

Analyze findings across multiple targets to detect attack chains.

```bash
# Basic correlation from Monster output directory
python -m super_monster correlate --input ./monster_output/reports

# With custom database path
python -m super_monster correlate --input ./monster_output/reports --db ./my_findings.json

# Specify minimum confidence threshold
python -m super_monster correlate --input ./monster_output/reports --min-confidence 0.7
```

---

### `retest` - Retest Findings

Schedule and execute retests to verify if findings still exist.

```bash
# Full retest of all findings
python -m super_monster retest --db ./findings.db --strategy full

# Only retest critical findings
python -m super_monster retest --db ./findings.db --strategy critical_only

# Retest oldest findings first
python -m super_monster retest --db ./findings.db --strategy oldest_first

# Random sampling for spot checks
python -m super_monster retest --db ./findings.db --strategy random_sample --sample-size 10
```

**Strategies:**

| Strategy        | Description                                          |
|-----------------|------------------------------------------------------|
| `full`          | Retest every finding in the database                 |
| `critical_only` | Only CRITICAL and HIGH severity                      |
| `oldest_first`  | Findings not checked in the longest time             |
| `random_sample` | Random subset for quick verification                 |

---

### `prioritize` - Score and Rank Findings

Apply the weighted scoring formula to rank findings by actionability.

```bash
# Prioritize from database
python -m super_monster prioritize --db ./findings.db

# Output top 20 findings only
python -m super_monster prioritize --db ./findings.db --top 20

# Export priority list to file
python -m super_monster prioritize --db ./findings.db --output ./priority_list.json
```

---

### `plan` - Generate Attack Plans

Create step-by-step exploitation playbooks from correlated findings.

```bash
# Generate attack plans for all chains
python -m super_monster plan --db ./findings.db --output ./attack_plans

# Plan for a specific chain ID
python -m super_monster plan --db ./findings.db --chain-id auth_bypass_chain_001

# Include PoC templates
python -m super_monster plan --db ./findings.db --output ./attack_plans --include-poc
```

---

### `diff` - Compare Two Scans

Analyze differences between scan runs to track vulnerability lifecycle.

```bash
# Compare old and new scan results
python -m super_monster diff --old ./reports/scan_week1.json --new ./reports/scan_week2.json

# Output diff to file
python -m super_monster diff \
  --old ./reports/monster_report_target_20260501.json \
  --new ./reports/monster_report_target_20260515.json \
  --output ./diff_report.json
```

---

### `full` - Run Complete Pipeline

Execute the entire pipeline: ingest, correlate, prioritize, plan, and report.

```bash
# Full pipeline with defaults
python -m super_monster full --input ./monster_output/reports --output ./super_output

# Full pipeline with custom options
python -m super_monster full \
  --input ./monster_output/reports \
  --output ./super_output \
  --format json,markdown,html \
  --notify
```

This runs the following stages in sequence:

1. **Ingest** - Load Monster JSON reports into FindingDB
2. **Correlate** - Detect attack chains across findings
3. **Prioritize** - Score and rank all findings
4. **Plan** - Generate attack plans for detected chains
5. **Report** - Output results in all configured formats

---

## Output Examples

### Priority-Ranked Findings (Terminal)

```
======================================================================
  PRIORITIZED FINDINGS (Top 10)
======================================================================

 #1  [CRITICAL] SQL Injection in /api/v2/users?id=
     Score: 9.45/10.0 | CVSS: 9.8 | Chain: sqli_data_exfil
     Domain: api.target.com (Tier 1 - Critical)
     Bounty Estimate: $15,000 - $50,000
     Status: NEW | First seen: 2026-05-28

 #2  [CRITICAL] Authentication Bypass via JWT None Algorithm
     Score: 9.21/10.0 | CVSS: 9.1 | Chain: auth_bypass_chain
     Domain: auth.target.com (Tier 1 - Critical)
     Bounty Estimate: $10,000 - $30,000
     Status: NEW | First seen: 2026-05-28

 #3  [HIGH] SSRF in /api/proxy?url= (Cloud Metadata Accessible)
     Score: 8.67/10.0 | CVSS: 8.6 | Chain: ssrf_to_cloud
     Domain: api.target.com (Tier 1 - Critical)
     Bounty Estimate: $5,000 - $15,000
     Status: NEW | First seen: 2026-05-28

 #4  [HIGH] Stored XSS in User Profile Bio Field
     Score: 7.83/10.0 | CVSS: 7.5 | Chain: xss_to_account_takeover
     Domain: www.target.com (Tier 3 - Medium)
     Bounty Estimate: $2,000 - $7,500
     Status: NEW | First seen: 2026-05-29
```

Severity colors in the terminal:
- **CRITICAL** - Bright red with bold
- **HIGH** - Red
- **MEDIUM** - Yellow
- **LOW** - Cyan
- **INFO** - White/gray

### Correlation Map (ASCII)

```
======================================================================
  ATTACK CHAIN: auth_bypass_chain (Confidence: 0.87)
======================================================================

  [JWT None Algo]──────►[Auth Bypass]──────►[Admin Panel Access]
       │                      │                      │
   auth.target.com      api.target.com      admin.target.com
   CRITICAL (9.1)       CRITICAL (9.3)       HIGH (8.1)

  Chain Impact: CRITICAL
  Chain Description: Authentication weakness enables unauthorized data access
  Recommended Action: Submit as single chain for maximum bounty impact
```

### Diff Analysis Output

```
======================================================================
  TEMPORAL DIFF: Week 1 vs Week 2
======================================================================

  [+] NEW FINDINGS (3):
      + [CRITICAL] RCE via deserialization in /api/import
      + [HIGH] New subdomain: staging.target.com
      + [MEDIUM] CORS wildcard on api-v2.target.com

  [-] FIXED FINDINGS (2):
      - [HIGH] SSRF in /proxy endpoint (FIXED)
      - [MEDIUM] Missing CSP header on www.target.com (FIXED)

  [~] CHANGED FINDINGS (1):
      ~ [MEDIUM->HIGH] XSS upgraded (now stored, was reflected)

  Summary: +3 new | -2 fixed | ~1 changed | 15 unchanged
```

---

## Architecture

### Module Pipeline

Super Monster follows a linear pipeline architecture where each module transforms
data and passes it to the next stage:

```
                        Super Monster Pipeline
  ================================================================

  Monster JSON Reports
        |
        v
  +-------------------+
  |    FindingDB       |  Ingest, normalize, deduplicate, fingerprint
  +-------------------+
        |
        v
  +-------------------+
  |    Correlator      |  Detect chains, cross-reference targets
  +-------------------+
        |
        v
  +-------------------+
  |    Prioritizer     |  Score, rank, estimate bounty value
  +-------------------+
        |
        v
  +-------------------+
  |   AttackPlanner    |  Generate exploitation playbooks
  +-------------------+
        |
        v
  +-------------------+
  |     Reporter       |  JSON / Markdown / HTML output
  +-------------------+
        |
        v
  +-------------------+
  |   Notification     |  Console / File / Webhook alerts
  +-------------------+
```

### Data Flow Diagram

```
  [Monster Scanner]
        |
        | JSON reports (findings[], recon_summary, metadata)
        v
  [finding_db.py] ─────► Normalized Finding objects with fingerprints
        |                 Deduplication via SHA-256 content hashing
        |
        v
  [correlator.py] ─────► AttackChain objects with confidence scores
        |                 12 rule-based chain detection patterns
        |
        v
  [prioritizer.py] ────► PrioritizedFinding objects with scores
        |                 5-factor weighted scoring formula
        |
        v
  [attack_planner.py] ─► AttackPlan objects with step-by-step guides
        |                 PoC templates and tool recommendations
        |
        v
  [diff_engine.py] ────► DiffResult objects (new/fixed/changed)
        |                 Temporal comparison between scan runs
        |
        v
  [reporter.py] ───────► JSON, Markdown, HTML report files
        |                 Correlation maps, priority tables, templates
        |
        v
  [notification.py] ───► Alerts to console, file, Discord, Slack, Telegram
                          Event-driven with configurable thresholds
```

### Module Responsibilities

| Module              | Role                                                    |
|---------------------|---------------------------------------------------------|
| `config.py`         | All constants, weights, thresholds, color definitions   |
| `finding_db.py`     | Finding storage, normalization, dedup, lifecycle mgmt   |
| `correlator.py`     | Chain detection across findings using rule patterns     |
| `prioritizer.py`    | 5-factor scoring, ranking, bounty estimation            |
| `attack_planner.py` | Exploitation playbook generation from chains            |
| `diff_engine.py`    | Temporal comparison between two scan runs               |
| `retester.py`       | Retest scheduling, strategy selection, status tracking  |
| `notification.py`   | Multi-channel alerting (console, file, webhooks)        |
| `reporter.py`       | Report generation (JSON, Markdown, HTML dark theme)     |
| `main.py`           | CLI controller, argparse, pipeline orchestration        |
| `__main__.py`       | Module entry point (`python -m super_monster`)          |
| `__init__.py`       | Package metadata, version, exports                      |

---

## Configuration

### Environment Variables

Configure webhook notifications via environment variables:

```bash
# Discord webhook URL
export SM_DISCORD_WEBHOOK="https://discord.com/api/webhooks/123456/abcdef"

# Slack webhook URL
export SM_SLACK_WEBHOOK="https://hooks.slack.com/services/T00/B00/xxxxx"

# Telegram Bot API
export SM_TELEGRAM_WEBHOOK="https://api.telegram.org/bot<TOKEN>/sendMessage"
export SM_TELEGRAM_CHAT_ID="123456789"
```

These are read by the `NotificationManager` at runtime. If not set, webhook
notifications are silently skipped.

### Scoring Weights Customization

The priority scoring formula uses these default weights (defined in `config.py`):

```python
SCORING_WEIGHTS = {
    "cvss_base": 0.25,         # CVSS v3.1 base score
    "exploitability": 0.20,    # Attack vector/complexity
    "business_impact": 0.25,   # Impact on critical assets
    "bug_bounty_value": 0.15,  # Estimated payout
    "correlation_bonus": 0.15, # Bonus from chain membership
}
```

All weights must sum to 1.0. Adjust these in `config.py` to match your
personal bounty hunting strategy. For example, if you prioritize quick wins:

```python
SCORING_WEIGHTS = {
    "cvss_base": 0.20,
    "exploitability": 0.30,    # Emphasize easy exploits
    "business_impact": 0.15,
    "bug_bounty_value": 0.25,  # Emphasize payout
    "correlation_bonus": 0.10,
}
```

### Domain Tier Classification

Domains are automatically classified into 5 tiers based on keyword matching:

| Tier   | Description                              | Multiplier | Example Subdomains          |
|--------|------------------------------------------|------------|-----------------------------|
| Tier 1 | Payment, auth, core API                  | 3.0x       | pay., auth., api., admin.   |
| Tier 2 | User data, internal tools, databases     | 2.0x       | user., db., internal., mail.|
| Tier 3 | Public web apps, services                | 1.5x       | www., app., shop., blog.    |
| Tier 4 | Development, staging, test               | 1.0x       | dev., staging., test., qa.  |
| Tier 5 | Static assets, marketing, legacy         | 0.5x       | static., assets., legacy.   |

The tier multiplier directly affects the business impact component of the priority score.
Findings on Tier 1 (critical infrastructure) score 6x higher than Tier 5 (static assets).

### Retest Intervals

Retest scheduling is severity-based with configurable intervals:

| Severity | Initial Retest | Follow-up   | Max Retests | Escalation After |
|----------|----------------|-------------|-------------|------------------|
| CRITICAL | 24 hours       | 48 hours    | 10          | 3 failed fixes   |
| HIGH     | 72 hours       | 7 days      | 7           | 4 failed fixes   |
| MEDIUM   | 7 days         | 14 days     | 5           | 5 failed fixes   |
| LOW      | 14 days        | 28 days     | 3           | 3 failed fixes   |
| INFO     | 30 days        | 60 days     | 2           | 2 failed fixes   |

After the escalation threshold, the finding is flagged for manual review and
a notification is dispatched on all configured channels.

### Notification Thresholds

| Level      | Min Severity | Min CVSS | Channels              | Timing        |
|------------|--------------|----------|-----------------------|---------------|
| Immediate  | CRITICAL     | 9.0      | Webhook, Email, Slack | Instant       |
| Urgent     | HIGH         | 7.0      | Webhook, Slack        | Within 1 hour |
| Standard   | MEDIUM       | 4.0      | Email                 | Daily digest  |
| Low Priority | LOW        | 0.0      | Email                 | Weekly summary|

Additional controls:
- `batch_threshold`: 5 (batch notifications when more than 5 pending)
- `max_notifications_per_hour`: 20
- `quiet_hours`: 23:00 - 07:00 (notifications held until morning)

---

## File Listing

```
super_monster/
|-- __init__.py          Package metadata, version (1.0.0), exports
|-- __main__.py          Entry point for `python -m super_monster`
|-- main.py              CLI controller with argparse subcommands
|-- config.py            All configuration constants and scoring parameters
|-- finding_db.py        Finding normalization, storage, deduplication engine
|-- correlator.py        Cross-target correlation and chain detection
|-- prioritizer.py       5-factor priority scoring and ranking
|-- attack_planner.py    Exploitation playbook and PoC generation
|-- diff_engine.py       Temporal diff analysis between scan runs
|-- retester.py          Retest scheduling with multiple strategies
|-- notification.py      Multi-channel notification dispatch
|-- reporter.py          Elite report generation (JSON, MD, HTML)
|-- README.md            This documentation file
```

### Module Details

**`__init__.py`** - Package initialization with version string, author info, and `__all__`
exports. Provides the `VERSION` constant used throughout the package.

**`__main__.py`** - Minimal entry point that imports and calls `main()` from `main.py`.
Enables `python -m super_monster` execution.

**`main.py`** - The CLI controller. Defines the argparse parser with all subcommands
(`correlate`, `retest`, `prioritize`, `plan`, `diff`, `full`). Handles banner display,
pipeline orchestration, timing, and error reporting.

**`config.py`** - Central configuration module containing scoring weights, domain tier
definitions, correlation rules, retest intervals, notification thresholds, CVSS metrics,
CWE mappings, bounty payout estimates, color definitions, and the finding lifecycle state
machine. All constants are documented with inline comments.

**`finding_db.py`** - The `FindingDB` class and `Finding` dataclass. Handles loading Monster
JSON reports, normalizing findings into a standard format, generating SHA-256 fingerprints
for deduplication, tracking finding lifecycle states (new, reported, fixed, regressed), and
persisting the database to JSON.

**`correlator.py`** - The `Correlator` class. Applies 12 correlation rules to detect attack
chains. Each rule specifies required and optional finding types, confidence thresholds, and
severity boosts. Produces `AttackChain` objects with confidence scores.

**`prioritizer.py`** - The `Prioritizer` class. Applies the 5-factor weighted scoring formula
to each finding. Considers domain tier, chain membership, exploitability metrics, and
platform-specific bounty estimates. Outputs ranked findings with scores.

**`attack_planner.py`** - The `AttackPlanner` class. Takes correlated chains and generates
step-by-step exploitation playbooks. Each plan includes prerequisites, tools needed,
expected outcomes, risk assessment, and PoC code templates.

**`diff_engine.py`** - The `DiffEngine` class. Compares two Monster JSON reports (old vs new)
and categorizes findings as new, fixed, changed, or unchanged. Tracks severity changes,
scope expansion, and subdomain discovery.

**`retester.py`** - The `Retester` class. Manages retest scheduling with four strategies
(full, critical_only, oldest_first, random_sample). Tracks retest history, determines
which findings are due, and updates finding status based on results.

**`notification.py`** - The `NotificationManager` class. Dispatches alerts through console
(colored), file (plain text log), and webhooks (Discord/Slack/Telegram). Supports event
types, batching, quiet hours, and rate limiting.

**`reporter.py`** - The `SuperReporter` class. Generates comprehensive reports in three
formats. JSON includes all raw data. Markdown includes ASCII correlation maps, tables,
and attack path trees. HTML uses a dark theme with styled severity badges, interactive
sections, and is ready for sharing.

---

## Integration with Monster Scanner

Super Monster is designed as a post-processing layer for the Monster web scanner. The
integration workflow is:

### Step 1: Run Monster Scans

```bash
# Scan multiple targets with Monster
python -m monster --target pay.target.com --output ./monster_output
python -m monster --target auth.target.com --output ./monster_output
python -m monster --target api.target.com --output ./monster_output
```

Monster produces JSON reports in `./monster_output/reports/` with the format:

```json
{
  "report_metadata": {
    "target": "pay.target.com",
    "scan_date": "2026-05-28T14:30:00",
    "scanner_version": "2.0.0",
    "scan_duration": "00:15:32"
  },
  "executive_summary": {
    "total_findings": 12,
    "critical": 2,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1
  },
  "findings": [
    {
      "finding_type": "sqli",
      "severity": "CRITICAL",
      "title": "SQL Injection in user lookup",
      "description": "...",
      "url": "https://pay.target.com/api/users?id=1",
      "evidence": "Error: You have an error in your SQL syntax...",
      "remediation": "Use parameterized queries",
      "cvss_score": 9.8,
      "cwe_id": "CWE-89"
    }
  ],
  "recon_summary": {
    "subdomains_found": ["pay.target.com", "api.target.com"],
    "technologies": ["nginx", "PHP", "MySQL"],
    "open_ports": [80, 443, 8080]
  }
}
```

### Step 2: Run Super Monster

```bash
# Process all Monster reports through the full pipeline
python -m super_monster full \
  --input ./monster_output/reports \
  --output ./super_output
```

### Step 3: Review Output

Super Monster produces:

```
super_output/
|-- correlations.json       Detected attack chains
|-- priorities.json         Ranked findings with scores
|-- attack_plans/           Exploitation playbooks per chain
|   |-- auth_bypass_chain_001.md
|   |-- ssrf_to_cloud_002.md
|-- reports/
|   |-- super_report.json   Full machine-readable report
|   |-- super_report.md     Human-readable Markdown report
|   |-- super_report.html   Dark-theme HTML report
|-- notifications.log       Event log
```

### Continuous Monitoring Workflow

For ongoing bug bounty programs, run Monster on a schedule and use Super Monster
to track changes over time:

```bash
# Weekly scan and diff
python -m monster --target *.target.com --output ./scans/week_$(date +%V)

# Compare with previous week
python -m super_monster diff \
  --old ./scans/week_21/reports/*.json \
  --new ./scans/week_22/reports/*.json

# Retest previously found vulnerabilities
python -m super_monster retest --db ./findings.db --strategy critical_only
```

---

## Quick Start Example

```bash
# 1. Install
pip install colorama

# 2. Run Monster scans (or use existing reports)
python -m monster --target example.com --output ./monster_output

# 3. Run the full Super Monster pipeline
python -m super_monster full \
  --input ./monster_output/reports \
  --output ./super_output

# 4. Check priorities
python -m super_monster prioritize --db ./super_monster_findings.json --top 10

# 5. Generate attack plan for the top chain
python -m super_monster plan --db ./super_monster_findings.json --output ./plans

# 6. Compare with a future scan
python -m super_monster diff \
  --old ./monster_output/reports/scan_old.json \
  --new ./monster_output/reports/scan_new.json
```

---

## License

MIT License. See the repository root for full license text.

---

## Version History

- **v1.0.0** - Initial release with full pipeline: correlation, prioritization,
  attack planning, diff analysis, retest scheduling, notifications, and elite reporting.
