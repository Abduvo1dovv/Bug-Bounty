"""
Super Monster v1.0.0 - Advanced Bug Bounty Intelligence & Correlation Engine

A professional multi-target correlation, prioritization, and attack planning toolkit
for bug bounty hunters. Integrates with Monster v2.0.0 output to provide:

- Cross-target finding correlation and chain detection
- Automatic retest scheduling and verification
- AI-based (rule-based) severity prioritization
- Attack plan generation with exploitation paths
- Temporal diff analysis between scan runs
- Notification dispatch (webhook, email, Slack)
- Elite reporting with executive summaries

Usage:
    python -m super_monster --help
    python -m super_monster full --input ./monster_output/reports --output ./super_output
    python -m super_monster correlate --input ./monster_output/reports --db ./findings.db
    python -m super_monster prioritize --db ./findings.db
    python -m super_monster plan --db ./findings.db --output ./attack_plans
    python -m super_monster retest --db ./findings.db
    python -m super_monster diff --old report1.json --new report2.json

Dependencies:
    - Python 3.11+
    - colorama (terminal colors)

Integration:
    Reads Monster v2.0.0 JSON report format:
    {
        "report_metadata": {...},
        "executive_summary": {...},
        "findings": [...],
        "recon_summary": {...}
    }
"""

VERSION = "1.0.0"
__version__ = VERSION
__author__ = "Super Monster Security Team"
__license__ = "MIT"

__all__ = [
    "VERSION",
    "__version__",
    "config",
    "finding_db",
    "main",
]
