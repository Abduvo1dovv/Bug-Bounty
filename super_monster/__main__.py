"""
Entry point for running Super Monster as a module.

Usage:
    python -m super_monster --help
    python -m super_monster full --input ./monster_output/reports --output ./super_output
    python -m super_monster correlate --input ./monster_output/reports
    python -m super_monster prioritize --db ./findings.db
    python -m super_monster plan --db ./findings.db
    python -m super_monster retest --db ./findings.db
    python -m super_monster diff --old report1.json --new report2.json
"""

import sys

from super_monster.main import main

if __name__ == "__main__":
    sys.exit(main())
